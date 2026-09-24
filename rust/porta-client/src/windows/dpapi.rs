use std::ptr;

use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
    CRYPT_INTEGER_BLOB,
};

pub fn protect(data: &[u8], machine: bool, description: &str) -> std::io::Result<Vec<u8>> {
    crypt(data, machine, Some(description))
}

pub fn unprotect(data: &[u8]) -> std::io::Result<Vec<u8>> {
    crypt(data, false, None)
}

fn crypt(data: &[u8], machine: bool, description: Option<&str>) -> std::io::Result<Vec<u8>> {
    if data.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "protected data is empty",
        ));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "protected data is too large",
            )
        })?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let description = description.map(wide);
    let mut flags = CRYPTPROTECT_UI_FORBIDDEN;
    if machine {
        flags |= CRYPTPROTECT_LOCAL_MACHINE;
    }
    let success = unsafe {
        if let Some(description) = description.as_ref() {
            CryptProtectData(
                &input,
                description.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                flags,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                flags,
                &mut output,
            )
        }
    };
    if success == 0 {
        return Err(std::io::Error::from_raw_os_error(unsafe {
            GetLastError() as i32
        }));
    }
    if output.pbData.is_null() || output.cbData == 0 {
        if !output.pbData.is_null() {
            unsafe { LocalFree(output.pbData.cast()) };
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DPAPI returned no data",
        ));
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(result)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
