//! In-place restarts for zero-downtime upgrades.
//!
//! On `SIGHUP` the gateway drains its tunnels and re-executes its binary in
//! place: the process keeps its PID, so systemd sees no restart, and the new
//! program inherits the listening sockets and TUN devices. Connection
//! attempts during the handover queue in the kernel instead of failing, the
//! interfaces keep their addresses, routes and firewall rules, and clients
//! reconnect within a second to the same persisted leases.
//!
//! Sockets follow the systemd socket-activation protocol (`LISTEN_FDS` from
//! descriptor 3, `LISTEN_PID`) and are matched to the addresses the server
//! would bind, so a systemd socket unit works the same way. TUN devices are
//! named in `PORTA_INHERITED_TUNS` as `name=fd` pairs.

use parking_lot::Mutex;
use socket2::{Socket, Type};
use std::collections::HashMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::OnceLock;

pub const TUN_VARIABLE: &str = "PORTA_INHERITED_TUNS";
const FIRST_LISTEN_FD: RawFd = 3;
const MAX_INHERITED: usize = 64;

#[derive(Default)]
struct State {
    /// Inherited from the previous program, not yet claimed.
    sockets: Vec<Socket>,
    tuns: HashMap<String, OwnedFd>,
    /// Passed on to the next program at the next handover.
    passed_sockets: Vec<OwnedFd>,
    passed_tuns: Vec<(String, OwnedFd)>,
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(Mutex::default)
}

/// Claims the descriptors a previous program or systemd passed and removes
/// the variables that describe them, so that children do not see them.
/// Call once, early in `main`, before other descriptors are opened.
pub fn adopt_from_environment() {
    let listen_pid = std::env::var("LISTEN_PID").ok();
    let listen_fds = std::env::var("LISTEN_FDS").ok();
    let tuns = std::env::var(TUN_VARIABLE).ok();
    for name in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", TUN_VARIABLE] {
        std::env::remove_var(name);
    }
    let ours = listen_pid.is_some_and(|pid| pid == std::process::id().to_string());
    let mut state = state().lock();
    if ours {
        let count = listen_fds
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0)
            .min(MAX_INHERITED);
        for offset in 0..count {
            let fd = FIRST_LISTEN_FD + offset as RawFd;
            if let Some(fd) = claim(fd) {
                state.sockets.push(Socket::from(fd));
            }
        }
    }
    for pair in tuns
        .iter()
        .flat_map(|value| value.split(','))
        .take(MAX_INHERITED)
    {
        let Some((name, fd)) = pair.split_once('=') else {
            continue;
        };
        let Some(fd) = fd.parse::<RawFd>().ok().and_then(claim) else {
            continue;
        };
        state.tuns.insert(name.to_owned(), fd);
    }
    if !state.sockets.is_empty() || !state.tuns.is_empty() {
        tracing::info!(
            sockets = state.sockets.len(),
            interfaces = ?state.tuns.keys().collect::<Vec<_>>(),
            "adopted descriptors from the previous gateway process"
        );
    }
}

/// Takes ownership of an inherited descriptor and marks it close-on-exec.
fn claim(fd: RawFd) -> Option<OwnedFd> {
    if fd < FIRST_LISTEN_FD {
        return None;
    }
    // SAFETY: F_GETFD only queries whether `fd` is open.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return None;
    }
    // SAFETY: the descriptor is open and was passed for this process to own;
    // nothing else in the process refers to it.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: setting FD_CLOEXEC on an owned descriptor.
    unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    Some(owned)
}

/// An inherited socket of `kind` bound to `address`, if any. An unspecified
/// address matches any inherited address on the same port.
pub fn take_socket(kind: Type, address: SocketAddr) -> Option<Socket> {
    let mut state = state().lock();
    let index = state.sockets.iter().position(|socket| {
        socket.r#type().is_ok_and(|actual| actual == kind)
            && socket
                .local_addr()
                .ok()
                .and_then(|local| local.as_socket())
                .is_some_and(|local| {
                    local.port() == address.port()
                        && (address.ip().is_unspecified() || local.ip() == address.ip())
                })
    })?;
    Some(state.sockets.remove(index))
}

/// The inherited TUN device called `name`, if any.
pub fn take_tun(name: &str) -> Option<OwnedFd> {
    state().lock().tuns.remove(name)
}

/// Closes inherited descriptors nothing claimed.
pub fn release_unclaimed() {
    let mut state = state().lock();
    if !state.sockets.is_empty() || !state.tuns.is_empty() {
        tracing::warn!(
            sockets = state.sockets.len(),
            interfaces = state.tuns.len(),
            "closing inherited descriptors that this configuration does not use"
        );
    }
    state.sockets.clear();
    state.tuns.clear();
}

/// Keeps a listening socket for the next program.
pub fn pass_socket(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    let fd = fd.try_clone_to_owned()?;
    state().lock().passed_sockets.push(fd);
    Ok(())
}

/// Keeps a TUN device for the next program.
pub fn pass_tun(name: &str, fd: BorrowedFd<'_>) -> std::io::Result<()> {
    let fd = fd.try_clone_to_owned()?;
    let mut state = state().lock();
    state.passed_tuns.retain(|(existing, _)| existing != name);
    state.passed_tuns.push((name.to_owned(), fd));
    Ok(())
}

/// The program and arguments to re-execute, captured at startup: after an
/// upgrade replaces the binary, `/proc/self/exe` names the deleted file.
#[derive(Clone, Debug)]
pub struct Program {
    path: PathBuf,
    arguments: Vec<OsString>,
}

impl Program {
    pub fn current() -> std::io::Result<Self> {
        let mut arguments = std::env::args_os();
        let invoked = arguments.next().map(PathBuf::from);
        let path = match invoked {
            Some(path) if path.is_absolute() => path,
            _ => std::env::current_exe()?,
        };
        Ok(Self {
            path,
            arguments: arguments.collect(),
        })
    }

    /// Replaces this process with a fresh copy of the program that inherits
    /// the passed sockets and TUN devices. Returns only on failure, after
    /// which the process must exit: descriptors may have been rearranged.
    pub fn exec(&self) -> std::io::Error {
        use std::os::unix::process::CommandExt;

        let (sockets, tuns) = {
            let mut state = state().lock();
            (
                std::mem::take(&mut state.passed_sockets),
                std::mem::take(&mut state.passed_tuns),
            )
        };
        // Move every descriptor out of the target range first, so that
        // placing one cannot overwrite another that is still to be placed.
        let total = sockets.len() + tuns.len();
        let mut staged = Vec::with_capacity(total);
        for fd in sockets.iter().chain(tuns.iter().map(|(_, fd)| fd)) {
            match duplicate_above(fd.as_fd(), FIRST_LISTEN_FD + total as RawFd) {
                Ok(fd) => staged.push(fd),
                Err(error) => return error,
            }
        }
        let mut tun_names = Vec::with_capacity(tuns.len());
        for (index, fd) in staged.iter().enumerate() {
            let target = FIRST_LISTEN_FD + index as RawFd;
            // SAFETY: dup2 onto a fixed descriptor number. Whatever held that
            // number is replaced; the process execs or exits right after.
            if unsafe { libc::dup2(fd.as_raw_fd(), target) } < 0 {
                return std::io::Error::last_os_error();
            }
            if index >= sockets.len() {
                tun_names.push(format!("{}={target}", tuns[index - sockets.len()].0));
            }
        }
        let error = std::process::Command::new(&self.path)
            .args(&self.arguments)
            .env("LISTEN_PID", std::process::id().to_string())
            .env("LISTEN_FDS", sockets.len().to_string())
            .env(TUN_VARIABLE, tun_names.join(","))
            .exec();
        drop(staged);
        error
    }
}

fn duplicate_above(fd: BorrowedFd<'_>, minimum: RawFd) -> std::io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC returns a new descriptor that this function owns.
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `duplicate` is a fresh descriptor owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, Protocol};

    #[test]
    fn inherited_sockets_match_type_and_address() {
        let listener = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        listener
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
            .unwrap();
        let address = listener.local_addr().unwrap().as_socket().unwrap();
        let datagram = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        datagram.bind(&address.into()).unwrap();
        {
            let mut state = state().lock();
            state.sockets.push(listener);
            state.sockets.push(datagram);
        }
        assert!(take_socket(
            Type::STREAM,
            SocketAddr::from(([127, 0, 0, 2], address.port()))
        )
        .is_none());
        let wildcard = SocketAddr::from(([0, 0, 0, 0], address.port()));
        let udp = take_socket(Type::DGRAM, wildcard).unwrap();
        assert_eq!(udp.r#type().unwrap(), Type::DGRAM);
        let tcp = take_socket(Type::STREAM, address).unwrap();
        assert_eq!(tcp.local_addr().unwrap().as_socket(), Some(address));
        assert!(take_socket(Type::STREAM, address).is_none());

        pass_socket(tcp.as_fd()).unwrap();
        pass_tun("porta0", udp.as_fd()).unwrap();
        pass_tun("porta0", udp.as_fd()).unwrap();
        let state = state().lock();
        assert_eq!(state.passed_tuns.len(), 1);
        assert_eq!(state.passed_sockets.len(), 1);
    }

    #[test]
    fn claims_only_open_descriptors_above_stdio() {
        assert!(claim(1).is_none());
        assert!(claim(1_000_000).is_none());
    }
}
