//! Low-level PTY allocation and management
//!
//! Provides platform-specific PTY handling for Unix-like systems

use crate::PtyError;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::pty::{openpty, OpenptyResult, Winsize};
use nix::unistd::{fork, setsid, ForkResult};
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use tokio::io::{AsyncRead, AsyncWrite};

/// RAII wrapper for file descriptors
#[derive(Debug)]
struct OwnedFd(RawFd);

impl OwnedFd {
    /// Create a new OwnedFd from a raw file descriptor
    fn new(fd: RawFd) -> Self {
        Self(fd)
    }

    /// Extract the inner file descriptor, consuming self without closing it
    fn into_raw(self) -> RawFd {
        let fd = self.0;
        std::mem::forget(self);
        fd
    }
}

impl AsRawFd for OwnedFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        // Only close if fd is valid
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

/// A pseudo-terminal pair
pub struct Pty {
    /// Master file descriptor
    master: PtyMaster,

    /// Slave file descriptor  
    slave: Option<OwnedFd>,
}

/// Master side of a PTY
pub struct PtyMaster {
    fd: Option<OwnedFd>,
}

impl Pty {
    /// Allocate a new PTY pair
    pub fn new() -> Result<Self, PtyError> {
        let winsize = Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        let OpenptyResult { master, slave } = openpty(Some(&winsize), None)
            .map_err(|e| PtyError::AllocationFailed(format!("openpty failed: {e}")))?;

        let master_fd = master.into_raw_fd();
        let slave_fd = slave.into_raw_fd();

        // Set non-blocking mode on master
        fcntl(master_fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
            .map_err(|e| PtyError::AllocationFailed(format!("Failed to set non-blocking: {e}")))?;

        Ok(Self {
            master: PtyMaster {
                fd: Some(OwnedFd::new(master_fd)),
            },
            slave: Some(OwnedFd::new(slave_fd)),
        })
    }

    /// Resize the PTY
    pub fn resize(&mut self, rows: u16, cols: u16) -> Result<(), PtyError> {
        let winsize = Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        if let Some(ref fd) = self.master.fd {
            unsafe {
                let ret = libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &winsize as *const _);
                if ret < 0 {
                    return Err(PtyError::IoError(io::Error::last_os_error()));
                }
            }
        } else {
            return Err(PtyError::IoError(io::Error::other(
                "Master FD is not available",
            )));
        }

        Ok(())
    }

    /// Get the master side of the PTY
    pub fn master(&self) -> &PtyMaster {
        &self.master
    }

    /// Take ownership of the master side
    pub fn take_master(mut self) -> PtyMaster {
        // Drop slave FD (closes it automatically)
        self.slave = None;

        // Take ownership of master
        PtyMaster {
            fd: self.master.fd.take(),
        }
    }

    /// Spawn a process in the PTY
    pub fn spawn(mut self, mut command: Command) -> Result<PtyProcess, PtyError> {
        // Take ownership of slave FD
        let slave_owned = self
            .slave
            .take()
            .ok_or_else(|| PtyError::IoError(io::Error::other("Slave FD already taken")))?;

        // Get raw slave FD for child process (unused in parent)
        let _slave_fd = slave_owned.as_raw_fd();

        // Take ownership of master FD
        let master_fd = self
            .master
            .fd
            .take()
            .ok_or_else(|| PtyError::IoError(io::Error::other("Master FD already taken")))?;

        let master = PtyMaster {
            fd: Some(master_fd),
        };

        // Fork a new process
        match unsafe { fork() }.map_err(|e| PtyError::SpawnFailed(format!("Fork failed: {e}")))? {
            ForkResult::Parent { child } => {
                // In parent process
                // slave_owned will be dropped here, closing the FD automatically
                drop(slave_owned);

                Ok(PtyProcess {
                    master: Some(master),
                    child_pid: child,
                })
            }
            ForkResult::Child => {
                // In child process
                // Close master FD
                drop(master);

                // Extract slave FD without closing (needed for dup2)
                let slave_raw = slave_owned.into_raw();

                // Create new session (this also creates a new process group)
                setsid().expect("setsid failed");

                // Set up slave as stdin/stdout/stderr
                unsafe {
                    libc::dup2(slave_raw, 0);
                    libc::dup2(slave_raw, 1);
                    libc::dup2(slave_raw, 2);
                    libc::close(slave_raw);
                }

                // Set controlling terminal
                unsafe {
                    if libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0) < 0 {
                        panic!("TIOCSCTTY failed: {}", io::Error::last_os_error());
                    }
                }

                // Make this process group the foreground process group
                unsafe {
                    let pgid = libc::getpgrp();
                    if libc::tcsetpgrp(0, pgid) < 0 {
                        // This might fail in some environments, but that's OK
                        eprintln!("tcsetpgrp failed: {}", io::Error::last_os_error());
                    }
                }

                // Execute the command
                let err = command.exec();
                eprintln!("Failed to execute command: {err}");
                std::process::exit(1);
            }
        }
    }
}

// Drop implementation is no longer needed - OwnedFd handles cleanup automatically

/// A process running in a PTY
pub struct PtyProcess {
    master: Option<PtyMaster>,
    child_pid: nix::unistd::Pid,
}

impl PtyProcess {
    /// Get the process ID
    pub fn pid(&self) -> nix::unistd::Pid {
        self.child_pid
    }

    /// Get the master PTY
    pub fn master(&self) -> &PtyMaster {
        self.master.as_ref().expect("Master PTY already taken")
    }

    /// Take ownership of the master PTY
    pub fn take_master(mut self) -> PtyMaster {
        // Take the master, leaving None in its place
        // This prevents Drop from being called on self since we're consuming it
        let master = self.master.take().expect("Master PTY already taken");

        // Forget self to prevent Drop from running
        std::mem::forget(self);

        master
    }

    /// Wait for the process to exit
    pub fn wait(&self) -> Result<i32, PtyError> {
        use nix::sys::wait::{waitpid, WaitStatus};

        match waitpid(self.child_pid, None)
            .map_err(|e| PtyError::IoError(io::Error::from_raw_os_error(e as i32)))?
        {
            WaitStatus::Exited(_, code) => Ok(code),
            WaitStatus::Signaled(_, signal, _) => Ok(128 + signal as i32),
            _ => Ok(-1),
        }
    }

    /// Try to wait for the process to exit without blocking
    pub fn try_wait(&self) -> Result<Option<i32>, PtyError> {
        use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

        match waitpid(self.child_pid, Some(WaitPidFlag::WNOHANG))
            .map_err(|e| PtyError::IoError(io::Error::from_raw_os_error(e as i32)))?
        {
            WaitStatus::Exited(_, code) => Ok(Some(code)),
            WaitStatus::Signaled(_, signal, _) => Ok(Some(128 + signal as i32)),
            WaitStatus::StillAlive => Ok(None),
            _ => Ok(Some(-1)),
        }
    }

    /// Kill the process
    pub fn kill(&self) -> Result<(), PtyError> {
        nix::sys::signal::kill(self.child_pid, nix::sys::signal::Signal::SIGTERM)
            .map_err(|e| PtyError::IoError(io::Error::from_raw_os_error(e as i32)))
    }
}

impl PtyMaster {
    /// Check if this PtyMaster still owns a file descriptor
    pub fn has_fd(&self) -> bool {
        self.fd.is_some()
    }
}

impl AsRawFd for PtyMaster {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_ref().map(|fd| fd.as_raw_fd()).unwrap_or(-1)
    }
}

// Drop implementation is no longer needed - OwnedFd handles cleanup automatically

/// Async wrapper for PTY master
pub struct AsyncPtyMaster {
    inner: tokio::io::unix::AsyncFd<std::fs::File>,
}

impl AsyncPtyMaster {
    /// Create from a PtyMaster
    pub fn new(mut master: PtyMaster) -> io::Result<Self> {
        // Take ownership of the file descriptor
        let owned_fd = master
            .fd
            .take()
            .ok_or_else(|| io::Error::other("Master FD already taken"))?;

        // Extract raw fd without closing
        let fd = owned_fd.into_raw();

        // Create std::fs::File from raw FD (already non-blocking)
        let file = unsafe { std::fs::File::from_raw_fd(fd) };

        // Use AsyncFd for proper async handling of non-blocking FD
        let inner = tokio::io::unix::AsyncFd::new(file)?;

        Ok(Self { inner })
    }
}

impl AsyncRead for AsyncPtyMaster {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        loop {
            let mut guard = match self.inner.poll_read_ready(cx) {
                std::task::Poll::Ready(Ok(guard)) => guard,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            match guard.try_io(|inner| {
                use std::io::Read;
                let unfilled = buf.initialize_unfilled();
                match inner.get_ref().read(unfilled) {
                    Ok(n) => {
                        buf.advance(n);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }) {
                Ok(Ok(())) => return std::task::Poll::Ready(Ok(())),
                Ok(Err(e)) => return std::task::Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for AsyncPtyMaster {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.inner.poll_write_ready(cx) {
                std::task::Poll::Ready(Ok(guard)) => guard,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            match guard.try_io(|inner| {
                use std::io::Write;
                inner.get_ref().write(buf)
            }) {
                Ok(result) => return std::task::Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        loop {
            let mut guard = match self.inner.poll_write_ready(cx) {
                std::task::Poll::Ready(Ok(guard)) => guard,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            match guard.try_io(|inner| {
                use std::io::Write;
                inner.get_ref().flush()
            }) {
                Ok(result) => return std::task::Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // PTYs don't need shutdown
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn test_pty_allocation() {
        let pty = Pty::new().unwrap();
        assert!(pty.master.as_raw_fd() > 0);
        assert!(pty.slave.as_ref().map(|fd| fd.as_raw_fd()).unwrap_or(-1) > 0);
    }

    #[test]
    fn test_pty_resize() {
        let mut pty = Pty::new().unwrap();
        pty.resize(30, 100).unwrap();
    }

    #[test]
    fn test_pty_spawn_echo() {
        let pty = Pty::new().unwrap();
        let mut cmd = Command::new("echo");
        cmd.arg("Hello, PTY!");

        let process = pty.spawn(cmd).unwrap();
        let exit_code = process.wait().unwrap();
        assert_eq!(exit_code, 0);
    }
}
