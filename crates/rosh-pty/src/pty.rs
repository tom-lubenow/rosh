//! Low-level PTY allocation and management
//! 
//! Provides platform-specific PTY handling for Unix-like systems

use crate::PtyError;
use std::os::unix::io::{AsRawFd, RawFd, FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use nix::unistd::{ForkResult, fork, setsid};
use nix::pty::{openpty, OpenptyResult, Winsize};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use tokio::io::{AsyncRead, AsyncWrite};
use std::io;

/// A pseudo-terminal pair
pub struct Pty {
    /// Master file descriptor
    master: PtyMaster,
    
    /// Slave file descriptor  
    slave: RawFd,
}

/// Master side of a PTY
pub struct PtyMaster {
    fd: RawFd,
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
            .map_err(|e| PtyError::AllocationFailed(format!("openpty failed: {}", e)))?;
        
        let master_fd = master.into_raw_fd();
        let slave_fd = slave.into_raw_fd();
        
        // Set non-blocking mode on master
        fcntl(master_fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
            .map_err(|e| PtyError::AllocationFailed(format!("Failed to set non-blocking: {}", e)))?;
        
        Ok(Self {
            master: PtyMaster { fd: master_fd },
            slave: slave_fd,
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
        
        unsafe {
            let ret = libc::ioctl(self.master.fd, libc::TIOCSWINSZ, &winsize as *const _);
            if ret < 0 {
                return Err(PtyError::IoError(io::Error::last_os_error()));
            }
        }
        
        Ok(())
    }
    
    /// Get the master side of the PTY
    pub fn master(&self) -> &PtyMaster {
        &self.master
    }
    
    /// Take ownership of the master side
    pub fn take_master(mut self) -> PtyMaster {
        // Close slave FD
        unsafe {
            libc::close(self.slave);
        }
        // Mark slave as invalid so Drop doesn't close it again
        self.slave = -1;
        
        // Take ownership of master
        let master = PtyMaster { fd: self.master.fd };
        // Mark master FD as invalid
        self.master.fd = -1;
        
        master
    }
    
    /// Spawn a process in the PTY
    pub fn spawn(mut self, mut command: Command) -> Result<PtyProcess, PtyError> {
        let slave_fd = self.slave;
        let master_fd = self.master.fd;
        
        // Mark FDs as invalid so Drop doesn't close them
        self.slave = -1;
        self.master.fd = -1;
        
        let master = PtyMaster { fd: master_fd };
        
        // Fork a new process
        match unsafe { fork() }.map_err(|e| PtyError::SpawnFailed(format!("Fork failed: {}", e)))? {
            ForkResult::Parent { child } => {
                // In parent process
                // Close slave FD as we don't need it
                unsafe {
                    libc::close(slave_fd);
                }
                
                Ok(PtyProcess {
                    master,
                    child_pid: child,
                })
            }
            ForkResult::Child => {
                // In child process
                // Close master FD
                unsafe {
                    libc::close(master.fd);
                }
                
                // Create new session
                setsid().expect("setsid failed");
                
                // Set up slave as stdin/stdout/stderr
                unsafe {
                    libc::dup2(slave_fd, 0);
                    libc::dup2(slave_fd, 1);
                    libc::dup2(slave_fd, 2);
                    libc::close(slave_fd);
                }
                
                // Set controlling terminal
                unsafe {
                    if libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0) < 0 {
                        panic!("TIOCSCTTY failed: {}", io::Error::last_os_error());
                    }
                }
                
                // Execute the command
                let err = command.exec();
                eprintln!("Failed to execute command: {}", err);
                std::process::exit(1);
            }
        }
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        if self.slave != -1 {
            unsafe {
                libc::close(self.slave);
            }
        }
        // Master will be dropped by its own Drop impl
    }
}

/// A process running in a PTY
pub struct PtyProcess {
    master: PtyMaster,
    child_pid: nix::unistd::Pid,
}

impl PtyProcess {
    /// Get the process ID
    pub fn pid(&self) -> nix::unistd::Pid {
        self.child_pid
    }
    
    /// Get the master PTY
    pub fn master(&self) -> &PtyMaster {
        &self.master
    }
    
    /// Take ownership of the master PTY
    pub fn take_master(self) -> PtyMaster {
        self.master
    }
    
    /// Wait for the process to exit
    pub fn wait(&self) -> Result<i32, PtyError> {
        use nix::sys::wait::{waitpid, WaitStatus};
        
        match waitpid(self.child_pid, None)
            .map_err(|e| PtyError::IoError(io::Error::from_raw_os_error(e as i32)))? {
            WaitStatus::Exited(_, code) => Ok(code),
            WaitStatus::Signaled(_, signal, _) => Ok(128 + signal as i32),
            _ => Ok(-1),
        }
    }
    
    /// Kill the process
    pub fn kill(&self) -> Result<(), PtyError> {
        nix::sys::signal::kill(self.child_pid, nix::sys::signal::Signal::SIGTERM)
            .map_err(|e| PtyError::IoError(io::Error::from_raw_os_error(e as i32)))
    }
}

impl AsRawFd for PtyMaster {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for PtyMaster {
    fn drop(&mut self) {
        if self.fd != -1 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

/// Async wrapper for PTY master
pub struct AsyncPtyMaster {
    inner: tokio::fs::File,
}

impl AsyncPtyMaster {
    /// Create from a PtyMaster
    pub fn new(master: PtyMaster) -> io::Result<Self> {
        let fd = master.as_raw_fd();
        // Prevent Drop from closing the FD
        std::mem::forget(master);
        
        // Create tokio File from raw FD
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let inner = tokio::fs::File::from_std(file);
        
        Ok(Self { inner })
    }
}

impl AsyncRead for AsyncPtyMaster {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AsyncPtyMaster {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
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
        assert!(pty.slave > 0);
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