//! TTY plumbing. Opens a PTY pair, hands the slave to the child as stdio,
//! puts the host terminal into raw mode, and shovels bytes between
//! host stdin/stdout and the master fd until EOF.
//!
//! Window-size changes propagate via SIGWINCH → TIOCSWINSZ on the master.

use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::io::RawFd;
use crate::{Error, Result};

pub struct PtyPair {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

pub fn open() -> Result<PtyPair> {
    use nix::pty::{openpty, OpenptyResult, Winsize};
    let ws = current_winsize().unwrap_or(Winsize {
        ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0,
    });
    let OpenptyResult { master, slave } = openpty(Some(&ws), None)
        .map_err(Error::Nix)?;
    Ok(PtyPair { master, slave })
}

pub fn current_winsize() -> Option<nix::pty::Winsize> {
    use nix::libc::{ioctl, TIOCGWINSZ, winsize, STDIN_FILENO};
    let mut ws: winsize = unsafe { std::mem::zeroed() };
    let r = unsafe { ioctl(STDIN_FILENO, TIOCGWINSZ, &mut ws) };
    if r != 0 { return None; }
    Some(nix::pty::Winsize {
        ws_row: ws.ws_row, ws_col: ws.ws_col,
        ws_xpixel: ws.ws_xpixel, ws_ypixel: ws.ws_ypixel,
    })
}

pub fn set_winsize(master_fd: RawFd, ws: &nix::pty::Winsize) {
    use nix::libc::{ioctl, TIOCSWINSZ};
    unsafe { ioctl(master_fd, TIOCSWINSZ, ws as *const _); }
}

/// Put stdin into raw mode; restore on drop.
pub struct RawGuard {
    fd: RawFd,
    saved: Option<nix::sys::termios::Termios>,
}

impl RawGuard {
    pub fn new() -> Result<Self> {
        use nix::sys::termios::{tcgetattr, tcsetattr, SetArg, LocalFlags, InputFlags, OutputFlags, ControlFlags, SpecialCharacterIndices as Cc};
        let fd = std::io::stdin().as_raw_fd();
        let saved = match tcgetattr(unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) }) {
            Ok(t) => Some(t),
            Err(_) => return Ok(Self { fd, saved: None }),
        };
        let mut raw = saved.clone().unwrap();
        raw.input_flags &= !(InputFlags::IGNBRK | InputFlags::BRKINT | InputFlags::PARMRK
            | InputFlags::ISTRIP | InputFlags::INLCR | InputFlags::IGNCR
            | InputFlags::ICRNL | InputFlags::IXON);
        raw.output_flags &= !OutputFlags::OPOST;
        raw.local_flags &= !(LocalFlags::ECHO | LocalFlags::ECHONL | LocalFlags::ICANON
            | LocalFlags::ISIG | LocalFlags::IEXTEN);
        raw.control_flags &= !(ControlFlags::CSIZE | ControlFlags::PARENB);
        raw.control_flags |= ControlFlags::CS8;
        raw.control_chars[Cc::VMIN as usize] = 1;
        raw.control_chars[Cc::VTIME as usize] = 0;
        let _ = tcsetattr(unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) }, SetArg::TCSANOW, &raw);
        Ok(Self { fd, saved })
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        if let Some(saved) = &self.saved {
            use nix::sys::termios::{tcsetattr, SetArg};
            let _ = tcsetattr(unsafe { std::os::fd::BorrowedFd::borrow_raw(self.fd) }, SetArg::TCSANOW, saved);
        }
    }
}

/// Run the bidirectional forwarding loop. Returns when `child_pid` exits.
/// Forwards host stdin → master, master → host stdout. Propagates SIGWINCH.
pub fn forward(master: OwnedFd, child_pid: nix::unistd::Pid) -> Result<i32> {
    use nix::sys::wait::{waitpid, WaitStatus, WaitPidFlag};
    use std::os::unix::io::AsRawFd;
    use std::time::Duration;

    let _raw = RawGuard::new();
    let mfd = master.as_raw_fd();

    // Set both FDs to non-blocking.
    let stdin_fd = std::io::stdin().as_raw_fd();
    set_nonblocking(mfd);
    set_nonblocking(stdin_fd);

    let mut buf = [0u8; 8192];
    loop {
        // Has child exited?
        match waitpid(child_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => return Ok(128 + sig as i32),
            Ok(_) => {}
            Err(nix::errno::Errno::ECHILD) => return Ok(0),
            Err(e) => return Err(Error::Nix(e)),
        }

        let mut fds = [
            nix::poll::PollFd::new(unsafe { std::os::fd::BorrowedFd::borrow_raw(mfd) }, nix::poll::PollFlags::POLLIN),
            nix::poll::PollFd::new(unsafe { std::os::fd::BorrowedFd::borrow_raw(stdin_fd) }, nix::poll::PollFlags::POLLIN),
        ];
        let _ = nix::poll::poll(&mut fds, 100u16);

        if fds[0].revents().map_or(false, |r| r.contains(nix::poll::PollFlags::POLLIN)) {
            let n = unsafe { libc::read(mfd, buf.as_mut_ptr() as _, buf.len()) };
            if n > 0 {
                let _ = std::io::stdout().write_all(&buf[..n as usize]);
                let _ = std::io::stdout().flush();
            } else if n == 0 {
                // PTY EOF — child closed it.
                let st = waitpid(child_pid, None).ok();
                if let Some(WaitStatus::Exited(_, code)) = st { return Ok(code); }
                return Ok(0);
            }
        }
        if fds[1].revents().map_or(false, |r| r.contains(nix::poll::PollFlags::POLLIN)) {
            let n = unsafe { libc::read(stdin_fd, buf.as_mut_ptr() as _, buf.len()) };
            if n > 0 {
                let _ = unsafe { libc::write(mfd, buf.as_ptr() as _, n as usize) };
            }
        }
        // Resize propagation: every iteration, copy the host winsize to the master.
        if let Some(ws) = current_winsize() { set_winsize(mfd, &ws); }
        std::thread::sleep(Duration::from_millis(0));
    }
}

fn set_nonblocking(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}
