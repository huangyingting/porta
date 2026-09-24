use std::ffi::{c_void, OsString};
use std::fs::{self, File};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetSecurityDescriptorSacl,
    GetTokenInformation, IsValidAcl, IsWellKnownSid, TokenUser, WinBuiltinAdministratorsSid,
    WinHighLabelSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, INHERITED_ACE, LABEL_SECURITY_INFORMATION,
    OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED, SYSTEM_MANDATORY_LABEL_ACE,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
    WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_RoamingAppData, SHGetKnownFolderPath,
};

pub fn program_data() -> std::io::Result<PathBuf> {
    known_folder(&FOLDERID_ProgramData)
}

pub fn roaming_app_data() -> std::io::Result<PathBuf> {
    known_folder(&FOLDERID_RoamingAppData)
}

pub fn system_directory() -> std::io::Result<PathBuf> {
    let mut buffer = vec![0_u16; 32_768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err(std::io::Error::last_os_error());
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(String::from_utf16(&buffer).map_err(
        |error| std::io::Error::new(std::io::ErrorKind::InvalidData, error),
    )?))
}

pub fn network_state_path() -> std::io::Result<PathBuf> {
    let current = current_network_state_path()?;
    let legacy = roaming_app_data()?.join("Porta").join("network-state.json");
    match fs::symlink_metadata(&legacy) {
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "legacy network recovery state exists at {}; restore it with the previous Porta client before upgrading",
                legacy.display()
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(current),
        Err(error) => Err(error),
    }
}

pub fn current_network_state_path() -> std::io::Result<PathBuf> {
    Ok(program_data()?.join("Porta").join("network-state.json"))
}

pub fn prepare_admin_directory(path: &Path) -> std::io::Result<File> {
    let created = create_admin_directory(path)?;
    let probe = open_admin_probe(path, true)?;
    validate_directory_type(&probe)?;
    if !created {
        validate_adoptable_owner(&probe)?;
    }
    // Keep the strict probe until the compatible lifetime guard is secured.
    let directory = open_admin_path(path, true)?;
    validate_same_file(&probe, &directory)?;
    validate_directory_type(&directory)?;
    apply_admin_security(&directory, true)?;
    validate_admin_security(&directory, true)?;
    Ok(directory)
}

pub fn validate_admin_directory(directory: &File) -> std::io::Result<()> {
    validate_directory_type(directory)?;
    validate_admin_security(directory, true)
}

pub fn secure_new_admin_file(path: &Path, file: &File) -> std::io::Result<()> {
    validate_single_link_file(file)?;
    let security_handle = open_admin_path(path, false)?;
    validate_same_file(file, &security_handle)?;
    apply_admin_security(&security_handle, false)?;
    validate_admin_security(&security_handle, false)
}

pub fn adopt_admin_file(path: &Path, file: &File) -> std::io::Result<()> {
    validate_single_link_file(file)?;
    let security_handle = open_admin_path(path, false)?;
    validate_same_file(file, &security_handle)?;
    validate_adoptable_owner(&security_handle)?;
    apply_admin_security(&security_handle, false)?;
    validate_admin_security(&security_handle, false)
}

pub fn validate_admin_file(file: &File) -> std::io::Result<()> {
    validate_single_link_file(file)?;
    validate_admin_security(file, false)
}

pub fn validate_single_link_file(file: &File) -> std::io::Result<()> {
    let information = file_information(file)?;
    if information.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || information.nNumberOfLinks != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "privileged file must be a singly linked regular file",
        ));
    }
    Ok(())
}

fn validate_directory_type(file: &File) -> std::io::Result<()> {
    let information = file_information(file)?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "privileged directory must be a non-reparse directory",
        ));
    }
    Ok(())
}

fn file_information(file: &File) -> std::io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(information)
}

fn validate_same_file(left: &File, right: &File) -> std::io::Result<()> {
    let left = file_information(left)?;
    let right = file_information(right)?;
    if left.dwVolumeSerialNumber != right.dwVolumeSerialNumber
        || left.nFileIndexHigh != right.nFileIndexHigh
        || left.nFileIndexLow != right.nFileIndexLow
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "privileged path changed while it was secured",
        ));
    }
    Ok(())
}

fn create_admin_directory(path: &Path) -> std::io::Result<bool> {
    let descriptor = SecurityDescriptor::from_sddl("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let path = wide_path(path)?;
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } != 0 {
        return Ok(true);
    }
    let error = unsafe { GetLastError() };
    if error == ERROR_ALREADY_EXISTS {
        Ok(false)
    } else {
        Err(std::io::Error::from_raw_os_error(error as i32))
    }
}

fn open_admin_path(path: &Path, directory: bool) -> std::io::Result<File> {
    let path = wide_path(path)?;
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let access = READ_CONTROL
        | WRITE_DAC
        | WRITE_OWNER
        | FILE_READ_ATTRIBUTES
        | if directory { FILE_LIST_DIRECTORY } else { 0 };
    // Child-file renames need write sharing; omitting delete sharing still pins
    // the directory itself. The preparation probe excludes preexisting writers.
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

fn open_admin_probe(path: &Path, directory: bool) -> std::io::Result<File> {
    let path = wide_path(path)?;
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let access =
        READ_CONTROL | FILE_READ_ATTRIBUTES | if directory { FILE_LIST_DIRECTORY } else { 0 };
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

fn apply_admin_security(file: &File, directory: bool) -> std::io::Result<()> {
    let descriptor = SecurityDescriptor::from_sddl(if directory {
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)S:(ML;OICI;NW;;;HI)"
    } else {
        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NW;;;HI)"
    })?;
    let mut owner = null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut dacl_present = 0;
    let mut dacl = null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(descriptor.0, &mut dacl_present, &mut dacl, &mut defaulted)
    } == 0
        || dacl_present == 0
        || dacl.is_null()
    {
        return Err(std::io::Error::last_os_error());
    }
    let mut sacl_present = 0;
    let mut sacl = null_mut();
    if unsafe {
        GetSecurityDescriptorSacl(descriptor.0, &mut sacl_present, &mut sacl, &mut defaulted)
    } == 0
        || sacl_present == 0
        || sacl.is_null()
    {
        return Err(std::io::Error::last_os_error());
    }
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION
                | LABEL_SECURITY_INFORMATION,
            owner,
            null_mut(),
            dacl,
            sacl,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

fn validate_admin_security(file: &File, directory: bool) -> std::io::Result<()> {
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut sacl = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            &mut sacl,
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let descriptor = SecurityDescriptor(descriptor);
    let owner_is_admin = !owner.is_null()
        && (unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid) } != 0
            || unsafe { IsWellKnownSid(owner, WinLocalSystemSid) } != 0);
    let mut control = 0;
    let mut revision = 0;
    let control_valid =
        unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } != 0;
    if !owner_is_admin
        || !control_valid
        || control & SE_DACL_PROTECTED == 0
        || !admin_dacl(dacl, directory)?
        || !high_integrity_label(sacl)?
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "privileged path security does not match Porta's administrator-only policy",
        ));
    }
    Ok(())
}

fn validate_adoptable_owner(file: &File) -> std::io::Result<()> {
    let mut owner = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = SecurityDescriptor(descriptor);
    if owner.is_null()
        || !(unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid) } != 0
            || unsafe { IsWellKnownSid(owner, WinLocalSystemSid) } != 0
            || owner_is_current_user(owner)?)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "privileged path is owned by another user",
        ));
    }
    Ok(())
}

fn admin_dacl(dacl: *mut ACL, directory: bool) -> std::io::Result<bool> {
    if dacl.is_null() || unsafe { IsValidAcl(dacl) } == 0 {
        return Ok(false);
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if information.AceCount != 2 {
        return Ok(false);
    }
    let expected_flags = if directory {
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
    } else {
        0
    };
    let mut administrators = false;
    let mut system = false;
    for index in 0..information.AceCount {
        let mut raw: *mut c_void = null_mut();
        if unsafe { GetAce(dacl, index, &mut raw) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ace = unsafe { &*(raw.cast::<ACCESS_ALLOWED_ACE>()) };
        if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
            || ace.Header.AceFlags != expected_flags
            || ace.Header.AceFlags & INHERITED_ACE as u8 != 0
            || ace.Mask != FILE_ALL_ACCESS
        {
            return Ok(false);
        }
        let sid = (&ace.SidStart as *const u32).cast_mut().cast();
        if unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) } != 0 {
            if administrators {
                return Ok(false);
            }
            administrators = true;
        } else if unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0 {
            if system {
                return Ok(false);
            }
            system = true;
        } else {
            return Ok(false);
        }
    }
    Ok(administrators && system)
}

fn high_integrity_label(sacl: *mut ACL) -> std::io::Result<bool> {
    if sacl.is_null() || unsafe { IsValidAcl(sacl) } == 0 {
        return Ok(false);
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            sacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    for index in 0..information.AceCount {
        let mut raw: *mut c_void = null_mut();
        if unsafe { GetAce(sacl, index, &mut raw) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ace = unsafe { &*(raw.cast::<SYSTEM_MANDATORY_LABEL_ACE>()) };
        if ace.Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE as u8
            && ace.Mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP != 0
        {
            let sid = (&ace.SidStart as *const u32).cast_mut().cast();
            if unsafe { IsWellKnownSid(sid, WinHighLabelSid) } != 0 {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn owner_is_current_user(owner: PSID) -> std::io::Result<bool> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let token = Handle(token);
    let mut length = 0;
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut length) };
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || length == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let words = (length as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    Ok(unsafe { EqualSid(owner, user.User.Sid) } != 0)
}

fn wide_path(path: &Path) -> std::io::Result<Vec<u16>> {
    let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows path contains a null character",
        ));
    }
    encoded.push(0);
    Ok(encoded)
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> std::io::Result<Self> {
        let encoded = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                encoded.as_ptr(),
                SECURITY_DESCRIPTOR_REVISION,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn known_folder(id: &GUID) -> std::io::Result<PathBuf> {
    let mut raw = std::ptr::null_mut();
    let status = unsafe { SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut raw) };
    if status < 0 {
        return Err(std::io::Error::from_raw_os_error(status));
    }
    if raw.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "known folder path is unavailable",
        ));
    }
    let mut length = 0;
    while unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    let path = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(raw, length)
    }));
    unsafe { CoTaskMemFree(raw.cast()) };
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "known folder path is not absolute",
        ));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{FILE_ADD_FILE, FILE_SHARE_DELETE};

    #[test]
    fn directory_guard_rejects_preexisting_writable_handles() {
        let temporary = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let path = temporary.path().join("guarded");
        fs::create_dir(&path).unwrap();
        let encoded = wide_path(&path).unwrap();
        let handle = unsafe {
            CreateFileW(
                encoded.as_ptr(),
                FILE_ADD_FILE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        let writer = unsafe { File::from_raw_handle(handle.cast()) };

        let error = open_admin_probe(&path, true).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(ERROR_SHARING_VIOLATION as i32));

        drop(writer);
        let guard = open_admin_probe(&path, true).unwrap();
        fs::write(path.join("child"), b"ok").unwrap();
        drop(guard);
    }
}
