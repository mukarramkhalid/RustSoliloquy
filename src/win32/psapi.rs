use core::{ffi::c_void, ptr::null_mut};

use super::{
    def::{ObjectAttributes, SecurityQualityOfService, HANDLE},
    ntdll::ntdll,
};

/// Duplicates an existing token into a new token with specified attributes.
///
/// This function duplicates an access token with the given impersonation level,
/// desired access rights, and token type. It uses the `SecurityQualityOfService`
/// structure to define the security parameters for the token.
///
/// # Arguments
/// * `existing_token_handle` - Handle to the existing token to be duplicated.
/// * `impersonation_level` - The impersonation level for the new token.
/// * `desired_access` - Access rights for the new token.
/// * `token_type` - The type of token to be created (e.g., primary or impersonation).
/// * `dup_token` - A mutable reference to store the handle of the duplicated token.
///
/// # Returns
/// * `i32` - NTSTATUS code indicating success or failure.
pub fn nt_duplicate_token(
    existing_token_handle: HANDLE,
    impersonation_level: u32,
    desired_access: u32,
    token_type: u32,
    dup_token: &mut HANDLE,
) -> i32 {
    // Initialize the SecurityQualityOfService structure with the specified impersonation level.
    let mut sqos = SecurityQualityOfService {
        length: core::mem::size_of::<SecurityQualityOfService>() as u32,
        impersonation_level,
        context_tracking_mode: 0, // Static tracking mode.
        effective_only: 0,        // Allow full delegation.
    };

    // Set up the ObjectAttributes structure with the security quality of service.
    let mut object_attributes = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: null_mut(),
        object_name: null_mut(),
        attributes: 0,
        security_descriptor: null_mut(),
        security_quality_of_service: &mut sqos as *mut _ as *mut c_void,
    };

    // Perform the token duplication using the NtDuplicateToken function from ntdll.
    unsafe {
        ntdll().nt_duplicate_token.run(
            existing_token_handle,
            desired_access,
            &mut object_attributes,
            0,
            token_type,
            dup_token,
        )
    }
}
