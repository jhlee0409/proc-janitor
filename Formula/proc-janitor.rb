class ProcJanitor < Formula
  desc "Automatic orphan process cleanup daemon for macOS"
  homepage "https://github.com/jhlee0409/proc-janitor"
  url "https://github.com/jhlee0409/proc-janitor/archive/refs/tags/v0.5.1.tar.gz"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  service do
    run [opt_bin/"proc-janitor", "start", "--foreground"]
    keep_alive true
    log_path var/"log/proc-janitor.log"
    error_log_path var/"log/proc-janitor.err"
  end

  test do
    assert_match "proc-janitor", shell_output("#{bin}/proc-janitor --version")
    assert_match "No orphaned processes", shell_output("#{bin}/proc-janitor scan 2>&1", 0)
  end
end
