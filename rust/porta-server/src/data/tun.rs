use super::router::PacketDevice;
use std::future::Future;
use std::io;
use std::pin::Pin;
use thiserror::Error;

pub const MIN_MTU: usize = 576;
pub const MAX_MTU: usize = 9000;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN interface name is required")]
    EmptyName,
    #[error("invalid TUN interface name {0:?}")]
    InvalidName(String),
    #[error("MTU {0} is outside 576..9000")]
    InvalidMtu(usize),
    #[error("native TUN devices are unsupported on this operating system")]
    Unsupported,
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },
}

fn validate(name: &str, mtu: usize) -> Result<(), TunError> {
    if name.is_empty() {
        return Err(TunError::EmptyName);
    }
    let valid_name = name.len() < 16
        && name
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-' | b'.'));
    if !valid_name {
        return Err(TunError::InvalidName(name.to_owned()));
    }
    if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
        return Err(TunError::InvalidMtu(mtu));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::net::UdpSocket;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::fs::OpenOptionsExt;
    use tokio::io::unix::AsyncFd;

    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const SIOCSIFMTU: libc::c_ulong = 0x8922;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    #[cfg(target_pointer_width = "64")]
    const IFREQ_DATA_SIZE: usize = 24;
    #[cfg(target_pointer_width = "32")]
    const IFREQ_DATA_SIZE: usize = 16;

    #[repr(C)]
    union IfReqData {
        flags: libc::c_short,
        mtu: libc::c_int,
        padding: [u8; IFREQ_DATA_SIZE],
    }

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        data: IfReqData,
    }

    impl IfReq {
        fn new(name: &str) -> Self {
            let mut request = Self {
                name: [0; libc::IFNAMSIZ],
                data: IfReqData {
                    padding: [0; IFREQ_DATA_SIZE],
                },
            };
            for (target, source) in request.name.iter_mut().zip(name.bytes()) {
                *target = source as libc::c_char;
            }
            request
        }

        fn actual_name(&self) -> String {
            let length = self
                .name
                .iter()
                .position(|value| *value == 0)
                .unwrap_or(self.name.len());
            String::from_utf8_lossy(
                &self.name[..length]
                    .iter()
                    .map(|value| *value as u8)
                    .collect::<Vec<_>>(),
            )
            .into_owned()
        }
    }

    pub struct NativeTun {
        fd: AsyncFd<File>,
        name: String,
        mtu: usize,
    }

    impl NativeTun {
        pub fn open(name: &str, mtu: usize) -> Result<Self, TunError> {
            validate(name, mtu)?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open("/dev/net/tun")
                .map_err(|source| TunError::Io {
                    context: "open /dev/net/tun",
                    source,
                })?;
            let mut request = IfReq::new(name);
            request.data.flags = IFF_TUN | IFF_NO_PI;
            ioctl(file.as_raw_fd(), TUNSETIFF, &mut request).map_err(|source| TunError::Io {
                context: "configure TUNSETIFF",
                source,
            })?;
            let actual_name = request.actual_name();
            set_mtu(&actual_name, mtu)?;
            Self::from_file(file, actual_name, mtu).map_err(|source| TunError::Io {
                context: "register TUN with async runtime",
                source,
            })
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn mtu(&self) -> usize {
            self.mtu
        }

        pub async fn read_packet(&self) -> io::Result<Vec<u8>> {
            let mut packet = vec![0; self.mtu + 1];
            loop {
                let mut ready = self.fd.readable().await?;
                match ready.try_io(|inner| {
                    let mut file = inner.get_ref();
                    file.read(&mut packet)
                }) {
                    Ok(Ok(0)) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "TUN device closed",
                        ));
                    }
                    Ok(Ok(length)) if length > self.mtu => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("TUN packet length {length} exceeds MTU {}", self.mtu),
                        ));
                    }
                    Ok(Ok(length)) => {
                        packet.truncate(length);
                        return Ok(packet);
                    }
                    Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Err(error)) => return Err(error),
                    Err(_) => continue,
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
            if packet.len() > self.mtu {
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
                let mut ready = self.fd.writable().await?;
                match ready.try_io(|inner| {
                    let mut file = inner.get_ref();
                    file.write(packet)
                }) {
                    Ok(Ok(length)) if length == packet.len() => return Ok(()),
                    Ok(Ok(length)) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            format!("TUN wrote {length} of {} packet bytes", packet.len()),
                        ));
                    }
                    Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Err(error)) => return Err(error),
                    Err(_) => continue,
                }
            }
        }

        pub fn close(self) -> io::Result<()> {
            drop(self);
            Ok(())
        }

        fn from_file(file: File, name: String, mtu: usize) -> io::Result<Self> {
            Ok(Self {
                fd: AsyncFd::new(file)?,
                name,
                mtu,
            })
        }
    }

    impl PacketDevice for NativeTun {
        fn read_packet(&self) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + '_>> {
            Box::pin(NativeTun::read_packet(self))
        }

        fn write_packet<'a>(
            &'a self,
            packet: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
            Box::pin(NativeTun::write_packet(self, packet))
        }

        fn name(&self) -> &str {
            NativeTun::name(self)
        }
    }

    fn set_mtu(name: &str, mtu: usize) -> Result<(), TunError> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|source| TunError::Io {
            context: "open interface configuration socket",
            source,
        })?;
        let mut request = IfReq::new(name);
        request.data.mtu = mtu as libc::c_int;
        ioctl(socket.as_raw_fd(), SIOCSIFMTU, &mut request).map_err(|source| TunError::Io {
            context: "configure TUN MTU",
            source,
        })
    }

    fn ioctl(fd: RawFd, operation: libc::c_ulong, request: &mut IfReq) -> io::Result<()> {
        // The kernel ABI requires a mutable ifreq pointer; all fields are initialized above.
        let result = unsafe { libc::ioctl(fd, operation, request as *mut IfReq) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;

        fn pair(mtu: usize) -> (NativeTun, UnixStream) {
            let (device, peer) = UnixStream::pair().unwrap();
            device.set_nonblocking(true).unwrap();
            let owned: OwnedFd = device.into();
            let file = File::from(owned);
            (
                NativeTun::from_file(file, "fake0".to_owned(), mtu).unwrap(),
                peer,
            )
        }

        #[tokio::test]
        async fn reads_into_an_owned_packet_buffer() {
            let (device, mut peer) = pair(1300);
            let expected = vec![0x45, 0, 0, 20];
            peer.write_all(&expected).unwrap();
            let packet = device.read_packet().await.unwrap();
            assert_eq!(packet, expected);
            assert_eq!(packet.capacity(), 1301);
        }

        #[tokio::test]
        async fn writes_without_packet_copy_or_headroom() {
            let (device, mut peer) = pair(1300);
            let packet = [0x45, 0, 0, 20];
            device.write_packet(&packet).await.unwrap();
            let mut received = [0; 4];
            peer.read_exact(&mut received).unwrap();
            assert_eq!(received, packet);
        }

        #[tokio::test]
        async fn enforces_packet_boundaries() {
            let (device, _) = pair(576);
            assert_eq!(
                device.write_packet(&[]).await.unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                device.write_packet(&vec![0; 577]).await.unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }

        #[tokio::test]
        async fn close_releases_the_device_file() {
            let (device, mut peer) = pair(1300);
            device.close().unwrap();
            let mut byte = [0; 1];
            assert_eq!(peer.read(&mut byte).unwrap(), 0);
        }

        #[test]
        fn ifreq_matches_linux_abi() {
            #[cfg(target_pointer_width = "64")]
            assert_eq!(std::mem::size_of::<IfReq>(), 40);
            #[cfg(target_pointer_width = "32")]
            assert_eq!(std::mem::size_of::<IfReq>(), 32);
        }
    }
}

#[cfg(target_os = "linux")]
pub use native::NativeTun;

#[cfg(not(target_os = "linux"))]
pub struct NativeTun;

#[cfg(not(target_os = "linux"))]
impl NativeTun {
    pub fn open(name: &str, mtu: usize) -> Result<Self, TunError> {
        validate(name, mtu)?;
        Err(TunError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_name_and_mtu_without_root() {
        assert!(matches!(validate("", 1300), Err(TunError::EmptyName)));
        assert!(matches!(
            validate("invalid/name", 1300),
            Err(TunError::InvalidName(_))
        ));
        assert!(matches!(
            validate("interface-name-too-long", 1300),
            Err(TunError::InvalidName(_))
        ));
        assert!(matches!(
            validate("tun0", 575),
            Err(TunError::InvalidMtu(575))
        ));
        assert!(validate("tun0", 1300).is_ok());
        assert!(matches!(
            NativeTun::open("", 1300),
            Err(TunError::EmptyName)
        ));
        assert!(matches!(
            NativeTun::open("tun0", 575),
            Err(TunError::InvalidMtu(575))
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn reports_unsupported_platform() {
        assert!(matches!(
            NativeTun::open("tun0", 1300),
            Err(TunError::Unsupported)
        ));
    }
}
