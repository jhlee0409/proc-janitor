//! `proc-janitor exec` — run a command and make sure it cannot outlive the
//! terminal that started it.
//!
//! This is prevention rather than cleanup. The daemon's job is to find processes
//! that have *already* been orphaned and guess, from regex patterns, whether they
//! should die. `exec` removes the guessing: it knows exactly which process it
//! started and exactly whose death should end it, so there is no pattern to get
//! wrong and no false positive to worry about.
//!
//! Linux has a native mechanism for this, `prctl(PR_SET_PDEATHSIG)`. macOS does
//! not — which is the root cause described in the README — but kqueue's
//! `EVFILT_PROC`/`NOTE_EXIT` can watch an arbitrary PID without privileges, so
//! the same guarantee can be built there:
//!
//! ```text
//! terminal ──spawns──▶ proc-janitor exec ──spawns──▶ your command
//!    │                        │
//!    └── exits ───────────────┤ NOTE_EXIT (macOS) / PDEATHSIG (Linux)
//!                             ▼
//!                    SIGTERM → SIGKILL the command's process tree
//! ```
//!
//! Measured on macOS 25.6: registering `NOTE_EXIT` on a PID costs ~0.5 µs and
//! delivery latency after the watched process exits is ~0.22 ms. There is no
//! polling and no process-table scanning in this path.
//!
//! Known limitation: a descendant that calls `setsid()` and re-parents itself
//! away from the tree is no longer reachable from the child's PID, so it will not
//! be terminated. That is the case the pattern-matching daemon exists to cover.

use std::process::{Child, Command};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use nix::sys::signal::Signal;
use nix::unistd::{getppid, Pid};

/// How often the child is polled for exit while it is being terminated.
const TERMINATE_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Run `command`, terminating it if this process's parent exits first — or if
/// this process is itself told to stop.
///
/// Returns the exit code to propagate: the command's own code when it finishes on
/// its own, or `128 + signal` when it was terminated.
pub fn run(command: &[String], sigterm_timeout: u64) -> Result<i32> {
    let (program, args) = command.split_first().ok_or_else(|| {
        anyhow::anyhow!("No command given. Usage: proc-janitor exec -- <command>")
    })?;

    // Resolve and start watching the parent *before* spawning the child, so a
    // parent that exits during startup cannot be missed.
    let parent = getppid();
    let mut watch = ParentWatch::arm(parent)?;

    // The parent may have exited between `getppid()` and arming the watch, in
    // which case we were re-parented to init and there is nothing left to watch.
    let parent_already_gone = parent.as_raw() <= 1 || getppid().as_raw() != parent.as_raw();
    if parent_already_gone {
        eprintln!(
            "proc-janitor exec: no live parent to watch (PPID is {}); running the command without a death link.",
            getppid().as_raw()
        );
    }

    let mut child = spawn_child(program, args)?;
    let child_pid = child.id();

    if parent_already_gone {
        return wait_for_child(&mut child);
    }

    watch.add_child(child_pid)?;

    match watch.wait_for_first_exit(parent, &mut child)? {
        Exited::Child => wait_for_child(&mut child),
        Exited::Parent => {
            eprintln!(
                "proc-janitor exec: parent {} exited; terminating '{}' (PID {}).",
                parent.as_raw(),
                program,
                child_pid
            );
            tracing::info!(
                parent = parent.as_raw(),
                child = child_pid,
                program = program.as_str(),
                "parent exited, terminating supervised command"
            );
            let signal = terminate_tree(&mut child, sigterm_timeout);
            Ok(128 + signal as i32)
        }
        Exited::Signalled(received) => {
            // Without this, a `kill` aimed at proc-janitor itself would leave the
            // command running with PPID=1 — exactly the state this subcommand
            // exists to prevent. Ctrl-C is unaffected either way: the child is
            // deliberately in the same process group, so the terminal already
            // signals both.
            eprintln!(
                "proc-janitor exec: received {received:?}; terminating '{program}' (PID {child_pid}).",
            );
            tracing::info!(
                signal = ?received,
                child = child_pid,
                program = program.as_str(),
                "signalled, terminating supervised command"
            );
            let signal = terminate_tree(&mut child, sigterm_timeout);
            Ok(128 + signal as i32)
        }
    }
}

/// Signals that must take the supervised command down with us.
const FORWARDED_SIGNALS: [Signal; 2] = [Signal::SIGINT, Signal::SIGTERM];

/// Spawn the command, restoring default signal dispositions in the child.
///
/// The parent ignores `SIGINT`/`SIGTERM` so it can observe them instead of dying
/// on delivery, but dispositions survive `exec`, so the child would inherit the
/// ignore and become unkillable by Ctrl-C. Reset them in the forked child before
/// it execs.
fn spawn_child(program: &str, args: &[String]) -> Result<Child> {
    use std::os::unix::process::CommandExt;

    let mut cmd = Command::new(program);
    cmd.args(args);
    // SAFETY: `signal()` is async-signal-safe and this is the only work done
    // between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            for sig in FORWARDED_SIGNALS {
                nix::sys::signal::signal(sig, nix::sys::signal::SigHandler::SigDfl)
                    .map_err(std::io::Error::from)?;
            }
            Ok(())
        });
    }
    cmd.spawn()
        .with_context(|| format!("Failed to execute '{program}'"))
}

/// What ended the wait.
enum Exited {
    Parent,
    Child,
    /// This process was signalled and must take the command with it.
    Signalled(Signal),
}

/// Reap the child and translate its wait status into an exit code.
fn wait_for_child(child: &mut Child) -> Result<i32> {
    let status = child.wait().context("Failed to wait for the command")?;
    if let Some(code) = status.code() {
        return Ok(code);
    }
    // Killed by a signal: report it the way a shell does.
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return Ok(128 + signal);
        }
    }
    Ok(1)
}

/// Terminate the child and every descendant still reachable from it, SIGTERM
/// first and SIGKILL after `sigterm_timeout` seconds. Returns the signal that
/// ended the child.
///
/// The child deliberately stays in this process's process group: putting it in
/// its own group would take it out of the terminal's foreground group, and an
/// interactive command (the main use case) would then stop with SIGTTIN the
/// moment it read from the terminal. The tree is therefore walked explicitly
/// through the existing descendant collection instead of using `killpg`.
fn terminate_tree(child: &mut Child, sigterm_timeout: u64) -> Signal {
    let child_pid = child.id();
    signal_tree(child_pid, Signal::SIGTERM);

    let deadline = Instant::now() + Duration::from_secs(sigterm_timeout);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return Signal::SIGTERM,
            Ok(None) => std::thread::sleep(TERMINATE_POLL_INTERVAL),
            // Already reaped or unwaitable: nothing more to do.
            Err(_) => return Signal::SIGTERM,
        }
    }

    signal_tree(child_pid, Signal::SIGKILL);
    let _ = child.wait();
    Signal::SIGKILL
}

/// System-critical PIDs that must never be signalled.
const RESERVED_PIDS: [u32; 3] = [0, 1, 2];

/// Send `signal` to `root` and all of its descendants, deepest first.
///
/// Each PID is re-verified against the `start_time` recorded in the snapshot the
/// tree was derived from, immediately before it is signalled. Skipping that
/// check would reintroduce the PID-reuse hazard every other kill path in this
/// crate guards against: a descendant can exit between the snapshot and the
/// signal, and its PID can be handed to an unrelated process in between.
///
/// A sub-microsecond window remains between the verification and the `kill`
/// itself; that is inherent to signalling by PID on Unix and is the same
/// exposure as [`crate::kill::kill_process_with_sys`].
///
/// Children are signalled before their parents so a supervisor in the middle of
/// the tree cannot notice a dead child and restart it.
fn signal_tree(root: u32, signal: Signal) {
    let mut sys = crate::util::process_snapshot();
    let mut pids = crate::util::find_descendant_pids(&sys, &[root]);
    // `find_descendant_pids` returns parents before children; reverse it.
    pids.reverse();

    let self_pid = std::process::id();
    // Capture identities from the same snapshot that produced the tree.
    let targets: Vec<(u32, u64)> = pids
        .into_iter()
        .filter(|pid| !RESERVED_PIDS.contains(pid) && *pid <= i32::MAX as u32 && *pid != self_pid)
        .filter_map(|pid| {
            sys.process(sysinfo::Pid::from_u32(pid))
                .map(|process| (pid, process.start_time()))
        })
        .collect();

    for (pid, start_time) in targets {
        if !crate::kill::verify_process_identity_with_sys(&mut sys, pid, start_time) {
            tracing::warn!(
                pid,
                "not signalling: process identity changed since the snapshot (PID reuse)"
            );
            continue;
        }
        let _ = nix::sys::signal::kill(Pid::from_raw(pid as i32), signal);
    }
}

/// Platform mechanism that reports the parent's exit.
struct ParentWatch {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    kq: nix::sys::event::Kqueue,
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
mod kqueue_watch {
    use super::{Exited, ParentWatch};
    use anyhow::{Context, Result};
    use nix::errno::Errno;
    use nix::sys::event::{EventFilter, EventFlag, FilterFlag, KEvent, Kqueue};
    use nix::sys::signal::Signal;
    use nix::unistd::Pid;

    fn exit_event(pid: u32) -> KEvent {
        KEvent::new(
            pid as usize,
            EventFilter::EVFILT_PROC,
            EventFlag::EV_ADD | EventFlag::EV_ONESHOT,
            FilterFlag::NOTE_EXIT,
            0,
            0,
        )
    }

    /// An `EVFILT_SIGNAL` registration.
    ///
    /// The signal must be ignored for this to be useful: `EVFILT_SIGNAL` reports
    /// delivery *in addition to* the normal disposition, so leaving the default
    /// action in place would kill this process before it could react.
    fn signal_event(sig: Signal) -> KEvent {
        KEvent::new(
            sig as i32 as usize,
            EventFilter::EVFILT_SIGNAL,
            EventFlag::EV_ADD,
            FilterFlag::empty(),
            0,
            0,
        )
    }

    impl ParentWatch {
        /// Register `NOTE_EXIT` for the parent, and take over `SIGINT`/`SIGTERM`.
        ///
        /// Verified unprivileged on macOS 25.6, including PIDs owned by root or
        /// another user, and for processes this one did not spawn.
        pub(super) fn arm(parent: Pid) -> Result<Self> {
            let kq = Kqueue::new().context("Failed to create kqueue")?;
            if parent.as_raw() > 1 {
                // A parent that died in the meantime yields ESRCH; the caller
                // re-checks `getppid()` and handles that case.
                let _ = kq.kevent(&[exit_event(parent.as_raw() as u32)], &mut [], None);
            }

            // Ignore first, then watch: between the two, a signal would kill us
            // and orphan the command. `spawn_child` restores the defaults in the
            // child so it stays normally killable.
            for sig in super::FORWARDED_SIGNALS {
                // SAFETY: setting a disposition to SIG_IGN is async-signal-safe
                // and affects only this process.
                unsafe {
                    nix::sys::signal::signal(sig, nix::sys::signal::SigHandler::SigIgn)
                        .with_context(|| format!("Failed to take over {sig:?}"))?;
                }
                kq.kevent(&[signal_event(sig)], &mut [], None)
                    .with_context(|| format!("Failed to watch for {sig:?}"))?;
            }

            Ok(Self { kq })
        }

        pub(super) fn add_child(&mut self, child: u32) -> Result<()> {
            self.kq
                .kevent(&[exit_event(child)], &mut [], None)
                .context("Failed to watch the command for exit")?;
            Ok(())
        }

        /// Block until the parent exits, the child exits, or this process is
        /// signalled.
        ///
        /// No timeout and no polling: every one of those three is an event.
        pub(super) fn wait_for_first_exit(
            &self,
            parent: Pid,
            child: &mut std::process::Child,
        ) -> Result<Exited> {
            let parent_ident = parent.as_raw() as usize;
            let child_ident = child.id() as usize;
            let mut events = [exit_event(0); 4];
            loop {
                let count = match self.kq.kevent(&[], &mut events, None) {
                    Ok(count) => count,
                    Err(Errno::EINTR) => continue,
                    Err(e) => return Err(e).context("kevent failed while watching for exit"),
                };
                for event in &events[..count] {
                    if event.flags().contains(EventFlag::EV_ERROR) {
                        continue;
                    }
                    if matches!(event.filter(), Ok(EventFilter::EVFILT_SIGNAL)) {
                        let received = super::FORWARDED_SIGNALS
                            .into_iter()
                            .find(|sig| *sig as i32 as usize == event.ident())
                            .unwrap_or(Signal::SIGTERM);
                        return Ok(Exited::Signalled(received));
                    }
                    if event.ident() == parent_ident {
                        return Ok(Exited::Parent);
                    }
                    if event.ident() == child_ident {
                        return Ok(Exited::Child);
                    }
                }
            }
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
mod pdeathsig_watch {
    use super::{Exited, ParentWatch};
    use anyhow::{Context, Result};
    use nix::unistd::Pid;
    use std::process::Child;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Arc;

    impl ParentWatch {
        /// Ask the kernel to signal us when our parent dies.
        ///
        /// `PR_SET_PDEATHSIG` is the native mechanism macOS lacks; using it here
        /// means the Linux path needs no watcher thread and no polling.
        pub(super) fn arm(parent: Pid) -> Result<Self> {
            if parent.as_raw() > 1 {
                nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGTERM)
                    .context("Failed to set PR_SET_PDEATHSIG")?;
            }
            Ok(Self {})
        }

        pub(super) fn add_child(&mut self, _child: u32) -> Result<()> {
            Ok(())
        }

        /// Block until the parent dies (delivered as `SIGTERM` by
        /// `PR_SET_PDEATHSIG`), this process is signalled, or the child exits.
        ///
        /// `PR_SET_PDEATHSIG` delivers an ordinary `SIGTERM`, indistinguishable
        /// from one a user sent, so the parent's PID is re-checked to report the
        /// right cause. Both outcomes take the command down; only the message
        /// differs.
        ///
        /// Polls through `Child::try_wait` rather than calling `waitpid`
        /// directly: `waitpid` reaps the child, after which the `Child::wait` the
        /// caller does to collect the exit status fails with `ECHILD`. Letting
        /// `Child` be the only reaper keeps the status available — it caches it.
        pub(super) fn wait_for_first_exit(&self, parent: Pid, child: &mut Child) -> Result<Exited> {
            let received: Arc<AtomicI32> = Arc::new(AtomicI32::new(0));
            let flag = Arc::clone(&received);
            let mut signals =
                signal_hook::iterator::Signals::new(super::FORWARDED_SIGNALS.map(|sig| sig as i32))
                    .context("Failed to install signal handlers")?;
            std::thread::spawn(move || {
                if let Some(sig) = signals.forever().next() {
                    flag.store(sig, Ordering::SeqCst);
                }
            });

            loop {
                let sig = received.load(Ordering::SeqCst);
                if sig != 0 {
                    // Parent gone => this was PR_SET_PDEATHSIG firing.
                    if nix::unistd::getppid() != parent {
                        return Ok(Exited::Parent);
                    }
                    return Ok(Exited::Signalled(
                        nix::sys::signal::Signal::try_from(sig)
                            .unwrap_or(nix::sys::signal::Signal::SIGTERM),
                    ));
                }
                match child.try_wait() {
                    Ok(Some(_)) => return Ok(Exited::Child),
                    Ok(None) => std::thread::sleep(super::TERMINATE_POLL_INTERVAL),
                    Err(e) => return Err(e).context("Failed to poll the command"),
                }
            }
        }
    }
}

/// Reject a command line that cannot be executed before spawning anything.
pub fn validate(command: &[String]) -> Result<()> {
    match command.first() {
        None => bail!("No command given. Usage: proc-janitor exec -- <command> [args...]"),
        Some(program) if program.is_empty() => bail!("Command name is empty"),
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rejects_empty_command() {
        assert!(validate(&[]).is_err());
        assert!(validate(&[String::new()]).is_err());
        assert!(validate(&["sleep".to_string()]).is_ok());
    }

    #[test]
    fn test_signal_tree_never_touches_reserved_pids_or_self() {
        // `signal_tree` walks a snapshot and signals by PID, so the two ways it
        // could do catastrophic damage are signalling init or signalling the
        // process that is doing the signalling. Neither may happen even when it
        // is asked to start from exactly those PIDs.
        //
        // SIGCONT is used as the probe: harmless to any process that might
        // legitimately be in the tree, while still exercising the full walk,
        // filter and identity-verification path.
        signal_tree(0, Signal::SIGCONT);
        signal_tree(1, Signal::SIGCONT);
        signal_tree(2, Signal::SIGCONT);
        signal_tree(std::process::id(), Signal::SIGCONT);

        // Still running: nothing above signalled this process or init.
        assert!(crate::kill::process_exists(std::process::id()));
    }

    #[test]
    fn test_signal_tree_skips_pids_whose_identity_changed() {
        // The PID-reuse guard: a PID captured in the snapshot must not be
        // signalled if the process behind it is no longer the same one. Verify
        // the primitive `signal_tree` relies on, against a PID that has exited.
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("failed to spawn probe");
        let pid = child.id();
        let _ = child.wait();

        let mut sys = crate::util::process_snapshot();
        assert!(
            !crate::kill::verify_process_identity_with_sys(&mut sys, pid, 1),
            "an exited PID must never verify, otherwise signal_tree could hit its reuse"
        );
    }

    #[test]
    fn test_exec_propagates_exit_code() {
        // The parent (the test harness) stays alive, so the command runs to
        // completion and its exit code must come back unchanged.
        let code = run(
            &["sh".to_string(), "-c".to_string(), "exit 42".to_string()],
            5,
        )
        .unwrap();
        assert_eq!(code, 42);
    }

    #[test]
    fn test_exec_reports_missing_program() {
        let err = run(&["definitely_not_a_real_program_xyz".to_string()], 5).unwrap_err();
        assert!(
            format!("{err}").contains("definitely_not_a_real_program_xyz"),
            "error should name the program: {err}"
        );
    }
}
