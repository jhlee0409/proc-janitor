//! Event-driven waiting for the daemon loop.
//!
//! The daemon has to poll to *discover* processes — macOS offers no unprivileged
//! process-creation event (`EndpointSecurity` needs an entitlement, and kqueue's
//! `NOTE_TRACK` returns `ENOTSUP` on macOS 25.6, verified) — but it does not have
//! to poll to *react*. Once a process is known, kqueue's
//! `EVFILT_PROC`/`NOTE_EXIT` reports its exit in about 0.22 ms, unprivileged,
//! for any PID including ones this process never spawned.
//!
//! So the loop keeps its periodic scan as a discovery pass and a safety net, and
//! additionally sleeps on:
//!
//! - the **parents** of processes that match a target pattern but are not yet
//!   orphans — their exit is the exact moment a process *becomes* an orphan; and
//! - **tracked orphans** themselves — so one that exits on its own is dropped
//!   from the grace-period map immediately instead of at the next tick.
//!
//! The grace period is unchanged: it still runs from the first sighting of a
//! process as an orphan. Waking on the parent's exit only makes that first
//! sighting prompt instead of up to `scan_interval` late.
//!
//! On platforms without kqueue this degrades to the plain interval sleep the
//! daemon has always used.

use anyhow::Result;

/// Why [`ExitWaiter::wait`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    /// A watched process exited — rescan now.
    ProcessExited,
    /// Woken explicitly through a [`Waker`] (a signal arrived).
    Woken,
    /// Nothing happened before the timeout elapsed.
    TimedOut,
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
mod imp {
    use super::Wake;
    use anyhow::{Context, Result};
    use nix::errno::Errno;
    use nix::sys::event::{EventFilter, EventFlag, FilterFlag, KEvent, Kqueue};
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::Duration;

    /// Upper bound on simultaneously watched PIDs.
    ///
    /// A pathologically broad target pattern could otherwise ask for a watch on
    /// every process on the machine. Registration is cheap (measured 0.29 ms for
    /// 652 PIDs) but not free, and exceeding the cap is a configuration smell
    /// worth reporting rather than absorbing silently.
    const MAX_WATCHES: usize = 1024;

    /// Identifier of the `EVFILT_USER` event used to interrupt a blocked wait.
    const WAKE_IDENT: usize = 0;

    /// A `NOTE_EXIT` registration for `pid`.
    ///
    /// `EV_ONESHOT` because a process only exits once: the kernel drops the
    /// registration as it fires, so there is nothing to clean up afterwards.
    pub(super) fn exit_event(pid: u32, flags: EventFlag) -> KEvent {
        KEvent::new(
            pid as usize,
            EventFilter::EVFILT_PROC,
            flags,
            FilterFlag::NOTE_EXIT,
            0,
            0,
        )
    }

    /// Interrupts a blocked [`ExitWaiter`] from another thread.
    #[derive(Clone)]
    pub struct Waker {
        kq: Arc<Kqueue>,
    }

    impl Waker {
        /// Wake the waiter. Safe to call when nothing is waiting: `EVFILT_USER`
        /// latches, so the next `wait` returns immediately.
        pub fn wake(&self) {
            let trigger = KEvent::new(
                WAKE_IDENT,
                EventFilter::EVFILT_USER,
                EventFlag::EV_ENABLE,
                FilterFlag::NOTE_TRIGGER,
                0,
                0,
            );
            let _ = self.kq.kevent(&[trigger], &mut [], None);
        }
    }

    pub struct ExitWaiter {
        kq: Arc<Kqueue>,
        registered: HashSet<u32>,
        capped: bool,
    }

    impl ExitWaiter {
        pub fn new() -> Result<Self> {
            let kq = Kqueue::new().context("Failed to create kqueue")?;
            // Self-pipe equivalent: a user event another thread can trigger.
            let wake = KEvent::new(
                WAKE_IDENT,
                EventFilter::EVFILT_USER,
                EventFlag::EV_ADD | EventFlag::EV_CLEAR,
                FilterFlag::empty(),
                0,
                0,
            );
            kq.kevent(&[wake], &mut [], None)
                .context("Failed to register the wake event")?;
            Ok(Self {
                kq: Arc::new(kq),
                registered: HashSet::new(),
                capped: false,
            })
        }

        pub fn waker(&self) -> Waker {
            Waker {
                kq: Arc::clone(&self.kq),
            }
        }

        /// Compute the changes that bring the kernel's watch list in line with
        /// `pids`, and record the new list as registered.
        fn pending_changes(&mut self, pids: &[u32]) -> Vec<KEvent> {
            let wanted: HashSet<u32> = pids
                .iter()
                .copied()
                .filter(|pid| *pid > 1)
                .take(MAX_WATCHES)
                .collect();

            if pids.len() > MAX_WATCHES && !self.capped {
                self.capped = true;
                tracing::warn!(
                    watched = MAX_WATCHES,
                    requested = pids.len(),
                    "too many processes to watch for exit; the excess is covered by the \
                     periodic scan only. Narrow your target patterns."
                );
            }

            let changes: Vec<KEvent> = wanted
                .difference(&self.registered)
                .map(|pid| exit_event(*pid, EventFlag::EV_ADD | EventFlag::EV_ONESHOT))
                .chain(
                    self.registered
                        .difference(&wanted)
                        .map(|pid| exit_event(*pid, EventFlag::EV_DELETE)),
                )
                .collect();

            self.registered = wanted;
            changes
        }

        pub fn wait(&mut self, pids: &[u32], timeout: Duration) -> Wake {
            let changes = self.pending_changes(pids);

            let ts = nix::libc::timespec {
                tv_sec: timeout.as_secs() as nix::libc::time_t,
                tv_nsec: timeout.subsec_nanos() as nix::libc::c_long,
            };
            let mut events = [exit_event(0, EventFlag::empty()); 16];

            // Registration and waiting are the *same* call on purpose. A
            // separate registration call returns already-pending events in its
            // own eventlist — a process that exits while it is being registered
            // is reported there and nowhere else, so splitting the two silently
            // drops exactly the notification this module exists to deliver.
            // Failed changes (ESRCH for an already-exited PID) come back as
            // EV_ERROR entries in the same list and are skipped below.
            let count = match self.kq.kevent(&changes, &mut events, Some(ts)) {
                Ok(count) => count,
                // A signal arrived: the caller re-checks its flags either way.
                Err(Errno::EINTR) => return Wake::Woken,
                Err(e) => {
                    tracing::warn!("kevent failed ({e}); falling back to the interval sleep");
                    std::thread::sleep(timeout);
                    return Wake::TimedOut;
                }
            };

            if count == 0 {
                return Wake::TimedOut;
            }

            // A process exit outranks a wake: it means there is something new to
            // scan, whereas a wake only means "re-check your flags".
            let mut exited = false;
            let mut woken = false;
            for event in &events[..count] {
                if event.flags().contains(EventFlag::EV_ERROR) {
                    continue;
                }
                match event.filter() {
                    Ok(EventFilter::EVFILT_PROC) => {
                        // Fired registrations are consumed by EV_ONESHOT.
                        self.registered.remove(&(event.ident() as u32));
                        exited = true;
                    }
                    Ok(EventFilter::EVFILT_USER) => woken = true,
                    _ => {}
                }
            }

            match (exited, woken) {
                (true, _) => Wake::ProcessExited,
                (false, true) => Wake::Woken,
                (false, false) => Wake::TimedOut,
            }
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
mod imp {
    use super::Wake;
    use anyhow::Result;
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    /// Interrupts a blocked [`ExitWaiter`] from another thread.
    #[derive(Clone)]
    pub struct Waker {
        state: Arc<(Mutex<bool>, Condvar)>,
    }

    impl Waker {
        pub fn wake(&self) {
            let (lock, cvar) = &*self.state;
            let mut woken = lock.lock().unwrap_or_else(|e| e.into_inner());
            *woken = true;
            cvar.notify_all();
        }
    }

    /// Interval sleep, interruptible by a [`Waker`].
    ///
    /// Without kqueue there is no unprivileged way to be told that an arbitrary
    /// PID exited, so this is the plain periodic behaviour. Linux's own answer to
    /// the underlying problem is `PR_SET_PDEATHSIG`, which `proc-janitor exec`
    /// uses directly.
    pub struct ExitWaiter {
        state: Arc<(Mutex<bool>, Condvar)>,
    }

    impl ExitWaiter {
        pub fn new() -> Result<Self> {
            Ok(Self {
                state: Arc::new((Mutex::new(false), Condvar::new())),
            })
        }

        pub fn waker(&self) -> Waker {
            Waker {
                state: Arc::clone(&self.state),
            }
        }

        pub fn wait(&mut self, _pids: &[u32], timeout: Duration) -> Wake {
            let (lock, cvar) = &*self.state;
            let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            let (mut woken, result) = cvar
                .wait_timeout(guard, timeout)
                .unwrap_or_else(|e| e.into_inner());
            if *woken {
                *woken = false;
                return Wake::Woken;
            }
            if result.timed_out() {
                Wake::TimedOut
            } else {
                Wake::Woken
            }
        }
    }
}

pub use imp::{ExitWaiter, Waker};

/// Convenience constructor so callers do not need to name the platform module.
pub fn waiter() -> Result<ExitWaiter> {
    ExitWaiter::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only the kqueue-gated tests spawn probe processes.
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    use std::process::Command;
    use std::time::{Duration, Instant};

    #[test]
    fn test_timeout_when_nothing_happens() {
        let mut waiter = waiter().unwrap();
        let start = Instant::now();
        let outcome = waiter.wait(&[], Duration::from_millis(300));
        assert_eq!(outcome, Wake::TimedOut);
        assert!(
            start.elapsed() >= Duration::from_millis(250),
            "wait returned early: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn test_waker_interrupts_a_long_wait() {
        let mut waiter = waiter().unwrap();
        let waker = waiter.waker();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            waker.wake();
        });
        let start = Instant::now();
        let outcome = waiter.wait(&[], Duration::from_secs(30));
        assert_eq!(outcome, Wake::Woken);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "waker did not interrupt the wait: {:?}",
            start.elapsed()
        );
    }

    /// The point of the module: a watched process exiting must end the wait long
    /// before the interval does.
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    #[test]
    fn test_watched_process_exit_ends_the_wait() {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("sleep 0.2; exit 0")
            .spawn()
            .expect("failed to spawn probe");
        let pid = child.id();

        let mut waiter = waiter().unwrap();
        let start = Instant::now();
        let outcome = waiter.wait(&[pid], Duration::from_secs(30));
        let elapsed = start.elapsed();
        let _ = child.wait();

        assert_eq!(outcome, Wake::ProcessExited);
        assert!(
            elapsed < Duration::from_secs(5),
            "exit notification took {elapsed:?}, expected milliseconds"
        );
    }

    /// Registrations must not accumulate: a PID dropped from the watch list is
    /// deregistered, and a fired one is forgotten.
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    #[test]
    fn test_watch_list_shrinks_again() {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("sleep 10")
            .spawn()
            .expect("failed to spawn probe");
        let pid = child.id();

        let mut waiter = waiter().unwrap();
        assert_eq!(
            waiter.wait(&[pid], Duration::from_millis(50)),
            Wake::TimedOut
        );
        // Dropping the PID from the list must not report a spurious exit.
        assert_eq!(waiter.wait(&[], Duration::from_millis(50)), Wake::TimedOut);

        let _ = child.kill();
        let _ = child.wait();
        // The process died while unwatched, so this still just times out.
        assert_eq!(waiter.wait(&[], Duration::from_millis(50)), Wake::TimedOut);
    }
}
