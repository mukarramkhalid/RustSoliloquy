use core::{
    cell::UnsafeCell,
    ffi::c_ulong,
    ffi::c_void,
    ptr::null_mut,
    sync::atomic::{AtomicBool, Ordering},
};

use alloc::{boxed::Box, vec::Vec};
use libc_print::libc_println;
use spin::RwLock;

use crate::{
    resolve_direct_syscalls,
    win32::{def::UnicodeString, ntdll::ntdll},
};

/// Maximum token size for security buffers in bytes.
pub const MAX_TOKEN_SIZE: usize = 12288;
/// Security buffer version.
pub const SECBUFFER_VERSION: c_ulong = 0;
/// Type identifier for a security token buffer.
pub const SECBUFFER_TOKEN: c_ulong = 2;
/// Status code indicating success.
pub const SEC_E_OK: u32 = 0x00000000;
/// Status code indicating that the operation requires additional steps.
pub const SEC_I_CONTINUE_NEEDED: c_ulong = 0x00090312;
/// Status code indicating completion of the operation with additional steps required.
pub const SEC_I_COMPLETE_AND_CONTINUE: c_ulong = 0x00090314;

/// Handle used for security contexts and credentials.
#[repr(C)]
pub struct SecHandle {
    pub dw_lower: usize, // Lower part of the handle.
    pub dw_upper: usize, // Upper part of the handle.
}

impl SecHandle {
    /// Returns a default (zero-initialized) instance of `SecHandle`.
    pub fn default() -> Self {
        SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        }
    }
}

/// Alias for `SecHandle` used for credentials.
pub type CredHandle = SecHandle;

/// Structure representing a security buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecBuffer {
    pub cb_buffer: u32,         // Size of the buffer in bytes.
    pub buffer_type: u32,       // Type of the buffer (e.g., SECBUFFER_TOKEN).
    pub pv_buffer: *mut c_void, // Pointer to the buffer data.
}

impl SecBuffer {
    /// Creates a new `SecBuffer` with the specified size and data pointer.
    pub fn new(pv_buffer: *mut c_void, size: u32) -> Self {
        SecBuffer {
            cb_buffer: size,
            buffer_type: SECBUFFER_TOKEN,
            pv_buffer,
        }
    }

    /// Returns a mutable slice of the buffer's contents.
    /// If the buffer is null, returns an empty slice.
    pub fn as_slice(&mut self) -> &mut [u8] {
        if self.pv_buffer.is_null() {
            return &mut [];
        }
        let buffer_ptr = self.pv_buffer as *mut u8;
        unsafe { core::slice::from_raw_parts_mut(buffer_ptr, self.cb_buffer as usize) }
    }

    /// Outputs the contents of the buffer to `stdout` for debugging.
    /// Returns `Ok(true)` on success or an error if the buffer is null.
    #[allow(dead_code)]
    pub fn to_stdout(self) -> Result<bool, Box<dyn core::error::Error>> {
        if self.pv_buffer.is_null() {
            return Err("client_token's pvBuffer is null".into());
        }

        let type1_len = self.cb_buffer;
        let type1_buffer_ptr = self.pv_buffer as *mut u8;

        // Safely interpret the buffer as a slice of bytes.
        let type_1 =
            unsafe { core::slice::from_raw_parts_mut(type1_buffer_ptr, type1_len as usize) };

        // Print the length and contents of the buffer in hexadecimal format.
        libc_println!(
            "SEC_BUFFER: ({}) {:02X?}",
            type1_len as usize,
            &type_1[..type1_len as usize]
        );

        Ok(true)
    }
}

/// Represents a security buffer descriptor for SSPI operations.
#[repr(C)]
pub struct SecBufferDesc {
    pub ul_version: u32,           // Version of the buffer descriptor.
    pub c_buffers: u32,            // Number of buffers in the descriptor.
    pub p_buffers: *mut SecBuffer, // Pointer to an array of security buffers.
}

impl SecBufferDesc {
    /// Creates a new `SecBufferDesc` with a single buffer.
    pub fn new(p_buffers: *mut SecBuffer) -> Self {
        SecBufferDesc {
            ul_version: SECBUFFER_VERSION,
            c_buffers: 1,
            p_buffers,
        }
    }

    /// Outputs the contents of all buffers in the descriptor for debugging.
    #[allow(dead_code)]
    pub fn to_stdout(&self) -> Result<bool, Box<dyn core::error::Error>> {
        let mut p_buffers = self.p_buffers;
        if p_buffers.is_null() {
            return Err("p_buffers is null".into());
        }

        for _ in 0..self.c_buffers {
            let buffer = unsafe { &mut *p_buffers };
            buffer.to_stdout()?;
            p_buffers = unsafe { p_buffers.add(1) };
        }

        Ok(true)
    }

    /// Collects the data from all buffers into a single `Vec<u8>`.
    /// Returns `None` if any buffer is null or empty.
    pub fn as_bytes(&self) -> Option<Vec<u8>> {
        if self.p_buffers.is_null() {
            return None;
        }

        let mut result: Vec<u8> = Vec::new();

        unsafe {
            let buffers = core::slice::from_raw_parts(
                self.p_buffers as *const SecBuffer,
                self.c_buffers as usize,
            );

            for sec_buffer in buffers.iter() {
                if sec_buffer.cb_buffer > 0 && !sec_buffer.pv_buffer.is_null() {
                    let buffer_data = core::slice::from_raw_parts(
                        sec_buffer.pv_buffer as *const u8,
                        sec_buffer.cb_buffer as usize,
                    );
                    result.extend_from_slice(buffer_data);
                } else {
                    return None;
                }
            }
        }

        Some(result)
    }
}

/// Represents a timestamp structure used in SSPI operations.
#[repr(C)]
pub struct TimeStamp {
    pub dw_low_date_time: u32,  // Low part of the timestamp.
    pub dw_high_date_time: u32, // High part of the timestamp.
}

impl TimeStamp {
    /// Returns a default (zero-initialized) instance of `TimeStamp`.
    pub fn default() -> Self {
        TimeStamp {
            dw_low_date_time: 0,
            dw_high_date_time: 0,
        }
    }
}

/// Function pointer for acquiring credentials handle.
pub type AcquireCredentialsHandleW = unsafe extern "system" fn(
    pszPrincipal: *mut u16,        // Principal name (optional).
    pszPackage: *mut u16,          // Security package name.
    fCredentialUse: u32,           // Credential use (e.g., inbound, outbound or both).
    pvLogonId: *mut c_void,        // Logon ID (optional).
    pAuthData: *mut c_void,        // Authentication data (optional).
    pGetKeyFn: *mut c_void,        // Key function (optional).
    pvGetKeyArgument: *mut c_void, // Key argument (optional).
    phCredential: *mut CredHandle, // Pointer to the credentials handle.
    ptsExpiry: *mut TimeStamp,     // Pointer to the expiration timestamp.
) -> i32;

/// Function pointer for initializing a security context.
pub type InitializeSecurityContextW = unsafe extern "system" fn(
    ph_credential: *mut SecHandle,  // Handle to the credentials.
    ph_context: *mut SecHandle,     // Handle to the current context.
    psz_target_name: *mut u16,      // Target name for the security context.
    f_context_req: u32,             // Context requirements flags.
    reserved1: u32,                 // Reserved, must be 0.
    target_data_rep: u32,           // Data representation on the target.
    p_input: *mut SecBufferDesc,    // Input buffers.
    reserved2: u32,                 // Reserved, must be 0.
    ph_new_context: *mut SecHandle, // Pointer to the new context handle.
    p_output: *mut SecBufferDesc,   // Output buffers.
    pf_context_attr: *mut u32,      // Pointer to attributes of the context.
    pts_expiry: *mut TimeStamp,     // Pointer to the expiration timestamp.
) -> i32;

/// Function pointer for accepting a security context.
pub type AcceptSecurityContext = unsafe extern "system" fn(
    ph_credential: *mut SecHandle,  // Handle to the credentials.
    ph_context: *mut SecHandle,     // Handle to the current context.
    p_input: *mut SecBufferDesc,    // Input buffers.
    f_context_req: u32,             // Context requirements flags.
    target_data_rep: u32,           // Data representation on the target.
    ph_new_context: *mut SecHandle, // Pointer to the new context handle.
    p_output: *mut SecBufferDesc,   // Output buffers.
    pf_context_attr: *mut u32,      // Pointer to attributes of the context.
    pts_expiry: *mut TimeStamp,     // Pointer to the expiration timestamp.
) -> u32;

/// Function pointer for deleting a security context.
pub type DeleteSecurityContext = unsafe extern "system" fn(phContext: *mut SecHandle) -> u32;

/// Function pointer for freeing a credentials handle.
pub type FreeCredentialsHandle = unsafe extern "system" fn(phCredential: *mut SecHandle) -> u32;

/// Function pointer for freeing a context buffer.
pub type FreeContextBuffer = unsafe extern "system" fn(pvContextBuffer: *mut c_void) -> u32;

/// Struct representing the `Sspicli` library, including its base address and function pointers.
pub struct Sspi {
    pub h_base: *mut u8,
    pub acquire_credentials_handle_w: Option<AcquireCredentialsHandleW>,
    pub initialize_security_context_w: Option<InitializeSecurityContextW>,
    pub accept_security_context: Option<AcceptSecurityContext>,
    pub delete_security_context: Option<DeleteSecurityContext>,
    pub free_credentials_handle: Option<FreeCredentialsHandle>,
    pub free_context_buffer: Option<FreeContextBuffer>,
}

impl Sspi {
    pub fn new() -> Self {
        Sspi {
            h_base: core::ptr::null_mut(),
            acquire_credentials_handle_w: None,
            initialize_security_context_w: None,
            accept_security_context: None,
            delete_security_context: None,
            free_credentials_handle: None,
            free_context_buffer: None,
        }
    }
}

/// Atomic flag to ensure initialization happens only once.
static INIT_SSPI: AtomicBool = AtomicBool::new(false);

/// Global mutable instance of the sspicli.
pub static mut SSPI: RwLock<UnsafeCell<Option<Sspi>>> = RwLock::new(UnsafeCell::new(None));

pub unsafe fn sspi() -> &'static Sspi {
    ensure_initialized();
    let lock = SSPI.read();
    (*lock.get()).as_ref().unwrap()
}

unsafe fn ensure_initialized() {
    // Check and call initialize if not already done.
    if !INIT_SSPI.load(Ordering::Acquire) {
        init_sspicli_funcs();
    }
}

pub unsafe fn init_sspicli_funcs() {
    // Check if initialization has already occurred.
    if !INIT_SSPI.load(Ordering::Acquire) {
        let mut sspi = Sspi::new();

        let dll_name = "sspicli.dll";
        let mut sspicli_dll_unicode = UnicodeString::new();
        let utf16_string: Vec<u16> = dll_name.encode_utf16().chain(Some(0)).collect();
        sspicli_dll_unicode.init(utf16_string.as_ptr());

        (ntdll().ldr_load_dll)(
            null_mut(),
            null_mut(),
            sspicli_dll_unicode,
            &mut sspi.h_base as *mut _ as *mut c_void,
        );

        if sspi.h_base.is_null() {
            return;
        }

        resolve_direct_syscalls!(
            sspi.h_base,
            [
                (
                    sspi.acquire_credentials_handle_w,
                    0xf0039100,
                    AcquireCredentialsHandleW
                ),
                (
                    sspi.initialize_security_context_w,
                    0x2b0bb38b,
                    InitializeSecurityContextW
                ),
                (
                    sspi.accept_security_context,
                    0xc9bbb892,
                    AcceptSecurityContext
                ),
                (
                    sspi.delete_security_context,
                    0x2128ecf5,
                    DeleteSecurityContext
                ),
                (
                    sspi.free_credentials_handle,
                    0x6cf6ffa1,
                    FreeCredentialsHandle
                ),
                (sspi.free_context_buffer, 0xd77b5586, FreeContextBuffer)
            ]
        );

        let sspi_lock = SSPI.write();
        *sspi_lock.get() = Some(sspi);

        // Set the initialization flag to true.
        INIT_SSPI.store(true, Ordering::Release);
    }
}
