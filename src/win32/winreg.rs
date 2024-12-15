extern crate alloc;

use alloc::vec::Vec;
use core::ptr::null_mut;

use super::{
    def::{
        KeyValuePartialInformation, ObjectAttributes, UnicodeString, HANDLE, OBJ_CASE_INSENSITIVE,
        STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_OBJECT_NAME_NOT_FOUND,
    },
    ntdll::ntdll,
};

/// Opens a registry key and returns the handle.
///
/// This function initializes a `UnicodeString` and an `ObjectAttributes` structure,
/// and then calls the `NtOpenKey` syscall to open the specified registry key. The function
/// supports reading and enumerating subkeys.
///
/// # Parameters
/// - `key`: A string slice containing the path to the registry key that needs to be opened.
///
/// # Returns
/// - `Result<HANDLE, i32>`: A result containing the handle to the opened registry key if
///   successful, otherwise an error code (`NTSTATUS`) indicating the reason for failure.
///
/// # Details
/// This function uses the following NT API function:
/// - `NtOpenKey`: To open the registry key specified by the provided path.
pub unsafe fn nt_open_key(key: &str, desired_access: u32) -> Result<HANDLE, i32> {
    let mut key_handle: HANDLE = null_mut(); // Initialize the handle to null

    // Initialize the Unicode string for the registry key path.
    let mut key_name = UnicodeString::new();
    let utf16_string: Vec<u16> = key.encode_utf16().chain(Some(0)).collect(); // Convert the key string to UTF-16
    key_name.init(utf16_string.as_ptr()); // Initialize the UnicodeString structure

    // Initialize the object attributes for the registry key.
    let mut object_attributes = ObjectAttributes::new();
    ObjectAttributes::initialize(
        &mut object_attributes,
        &mut key_name,
        OBJ_CASE_INSENSITIVE, // Use case-insensitive name matching (0x40)
        null_mut(),           // No root directory
        null_mut(),           // No security descriptor
    );

    // Call NtOpenKey to open the registry key with the desired access rights.
    let ntstatus = ntdll().nt_open_key.run(
        &mut key_handle,        // Pointer to receive the key handle
        desired_access,         // Desired access: read or write
        &mut object_attributes, // Provide the object attributes for the key
    );

    // Check if the operation was successful
    if ntstatus != 0 {
        return Err(ntstatus); // Return the NTSTATUS error code if opening the key failed
    }

    Ok(key_handle) // Return the handle to the opened registry key
}

/// Reads a registry value of type `REG_DWORD` and returns its content as a `u32`.
///
/// This function initializes a `UnicodeString` for the value name,
/// and then calls the `NtQueryValueKey` syscall to retrieve the value data.
/// If the initial buffer size is insufficient, the function reallocates the buffer based on the
/// required length and retries the call until it either succeeds or fails with a different error.
///
/// # Parameters
/// - `key_handle`: The handle to the open registry key from which the value will be read.
/// - `value_name`: A string slice that specifies the name of the registry value to be read.
///
/// # Returns
/// - `Result<u32, i32>`: A result containing the value content as a `u32` (REG_DWORD) if successful, or an
///   error code (`NTSTATUS`) if the operation fails.
pub unsafe fn nt_query_value_key(key_handle: HANDLE, value_name: &str) -> Result<u32, i32> {
    // Convert the value name to a UTF-16 encoded string
    let value_utf16_string: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();

    // Initialize the UnicodeString structure for the value name
    let mut value_unicode = UnicodeString::new();
    value_unicode.init(value_utf16_string.as_ptr());

    let mut value_result_length: u32 = 0; // Variable to store the length of the value data
    let mut value_info: Vec<u8> = Vec::with_capacity(64); // Initial buffer to store value information
    let mut ntstatus;

    loop {
        // Call NtQueryValueKey to retrieve the value data
        ntstatus = ntdll().nt_query_value_key.run(
            key_handle,
            &value_unicode,
            2, // Query type: KeyValuePartialInformation
            value_info.as_mut_ptr() as *mut _,
            value_info.capacity() as u32,
            &mut value_result_length,
        );

        // Handle the different status codes
        if ntstatus == STATUS_OBJECT_NAME_NOT_FOUND {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        } else if ntstatus == STATUS_BUFFER_OVERFLOW || ntstatus == STATUS_BUFFER_TOO_SMALL {
            // The buffer was too small; resize it and retry
            value_info.reserve(value_result_length as usize);
            continue;
        } else if ntstatus != 0 {
            // Other errors
            return Err(ntstatus);
        } else {
            break; // Successfully retrieved the value data
        }
    }

    // Interpret the retrieved data as a KeyValuePartialInformation structure
    let value_info_ptr = value_info.as_ptr() as *const KeyValuePartialInformation;
    let value_info_ref = &*value_info_ptr;

    // Extract the data as a REG_DWORD (u32)
    let data_ptr = value_info_ref.data.as_ptr() as *const u32;
    let value = *data_ptr;

    Ok(value) // Return the value as a `u32`
}

/// Sets the value of a registry key.
///
/// This function initializes a `UnicodeString` for the value name
/// and then calls the `NtSetValueKey` syscall to set the specified value data
/// for the given registry key.
///
/// # Parameters
/// - `key_handle`: The handle to the open registry key where the value will be set.
/// - `value_name`: A string slice specifying the name of the registry value to be modified or created.
/// - `new_value`: A byte slice containing the new value data to be written to the registry key.
///
/// # Returns
/// - `i32`: The NTSTATUS code indicating the result of the operation. A value of 0 indicates success,
///   while any other value represents an error.
pub unsafe fn nt_set_value_key(key_handle: HANDLE, value_name: &str, new_value: &[u8]) -> i32 {
    // Convert the value name to a UTF-16 encoded string
    let mut value_name_ustr = UnicodeString::new();
    let value_name_utf16: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();
    value_name_ustr.init(value_name_utf16.as_ptr());

    // Call NtSetValueKey to set the value data
    ntdll().nt_set_value_key.run(
        key_handle,
        &value_name_ustr,
        0, // Reserved (always 0)
        4, // Data type: KeyValueBasicInformation (4 for REG_DWORD)
        new_value.as_ptr() as *mut _,
        new_value.len() as u32,
    )
}

/// Deletes a specific value from a registry key.
///
/// This function calls the `NtDeleteValueKey` syscall to delete a specific value from the given registry key.
///
/// # Parameters
/// - `key_handle`: The handle to the open registry key containing the value to be deleted.
/// - `value_name`: A string slice specifying the name of the registry value to delete.
///
/// # Returns
/// - `i32`: The NTSTATUS code indicating the result of the operation. A value of 0 indicates success,
///   while any other value represents an error.
pub unsafe fn nt_delete_value_key(key_handle: HANDLE, value_name: &str) -> i32 {
    // Convert the value name to a UTF-16 encoded string
    let value_name_utf16: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();

    // Initialize the UnicodeString structure for the value name
    let mut value_name_unicode = UnicodeString::new();
    value_name_unicode.init(value_name_utf16.as_ptr());

    // Call NtDeleteValueKey to delete the specified value
    ntdll()
        .nt_delete_value_key
        .run(key_handle, &value_name_unicode)
}
