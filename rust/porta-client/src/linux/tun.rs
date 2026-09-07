use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;

const TUN_PATH: &CStr = c"/dev/net/tun";

#[derive(Clone)]
pub struct Tun {
    name: String,
    mtu: u16,
    descriptor: Arc<AsyncFd<OwnedFd>>,
}

impl Tun {
    pub fn open(name: &str, mtu: u16) -> io::Result<Self> {
        validate_name(name)?;
        if !(576..=9000).contains(&mtu) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("MTU {mtu} is outside 576..9000"),
            ));
        }
        let descriptor = unsafe {
            libc::open(
                TUN_PATH.as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let mut request = MaybeUninit::<libc::ifreq>::zeroed();
        let request = unsafe { request.assume_init_mut() };
        for (target, source) in request
            .ifr_name
            .iter_mut()
            .zip(name.as_bytes().iter().copied())
        {
            *target = source as libc::c_char;
        }
        request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        if unsafe {
            libc::ioctl(
                descriptor.as_raw_fd(),
                libc::TUNSETIFF,
                std::ptr::from_mut(&mut *request),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let actual = unsafe { CStr::from_ptr(request.ifr_name.as_ptr()) }
            .to_str()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "TUN name is not UTF-8"))?
            .to_owned();
        Ok(Self {
            name: actual,
            mtu,
            descriptor: Arc::new(AsyncFd::new(descriptor)?),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub async fn read_packet(&self) -> io::Result<Vec<u8>> {
        let mut packet = vec![0_u8; usize::from(self.mtu) + 256];
        loop {
            let mut ready = self.descriptor.readable().await?;
            match ready.try_io(|descriptor| {
                let read = unsafe {
                    libc::read(
                        descriptor.get_ref().as_raw_fd(),
                        packet.as_mut_ptr().cast(),
                        packet.len(),
                    )
                };
                if read < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(read as usize)
                }
            }) {
                Ok(Ok(0)) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(Ok(length)) => {
                    packet.truncate(length);
                    return Ok(packet);
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => {}
            }
        }
    }

    pub async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot write an empty TUN packet",
            ));
        }
        if packet.len() > usize::from(self.mtu) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "packet length {} exceeds TUN MTU {}",
                    packet.len(),
                    self.mtu
                ),
            ));
        }
        loop {
            let mut ready = self.descriptor.writable().await?;
            match ready.try_io(|descriptor| {
                let written = unsafe {
                    libc::write(
                        descriptor.get_ref().as_raw_fd(),
                        packet.as_ptr().cast(),
                        packet.len(),
                    )
                };
                if written < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(written as usize)
                }
            }) {
                Ok(Ok(length)) if length == packet.len() => return Ok(()),
                Ok(Ok(length)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!("TUN wrote {length} of {} bytes", packet.len()),
                    ));
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => {}
            }
        }
    }
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() >= libc::IFNAMSIZ
        || name == "lo"
        || !name
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-' | b'.'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Linux TUN interface name",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_linux_interface_names() {
        for valid in ["porta0", "Porta", "vpn.test_1"] {
            assert!(validate_name(valid).is_ok(), "{valid}");
        }
        for invalid in ["", "lo", "has space", "1234567890123456", "eth0;reboot"] {
            assert!(validate_name(invalid).is_err(), "{invalid}");
        }
    }
}
