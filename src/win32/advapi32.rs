use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

use alloc::vec::Vec;
use spin::RwLock;

use crate::{
    _print, resolve_direct_syscalls,
    win32::{def::UnicodeString, ntdll::ntdll},
};

/// Function type definition for `GetUserNameW`, retrieves the username of the current user.
pub type GetUserNameW = unsafe extern "system" fn(lpBuffer: *mut u16, lpnSize: *mut u32) -> i32;

/// Struct representing the `Advapi32` library, including its base address and function pointers.
pub struct Advapi32 {
    pub h_base: *mut u8, // Base address of the loaded `advapi32.dll`.
    pub get_user_name_w: Option<GetUserNameW>, // Pointer to the `GetUserNameW` function.
}

impl Advapi32 {
    /// Creates a new instance of `Advapi32` with null base address and no function pointers.
    pub fn new() -> Self {
        Self {
            h_base: core::ptr::null_mut(),
            get_user_name_w: None,
        }
    }
}

/// Atomic flag to ensure initialization happens only once.
static INIT_ADVAPI32: AtomicBool = AtomicBool::new(false);

/// Global mutable instance of advapi32.
pub static mut ADVAPI32: RwLock<UnsafeCell<Option<Advapi32>>> = RwLock::new(UnsafeCell::new(None));

/// Returns a static reference to the `Advapi32` instance, ensuring it is initialized before use.
pub unsafe fn advapi32() -> &'static Advapi32 {
    ensure_initialized(); // Ensure the `Advapi32` library and its functions are initialized.
    let lock = ADVAPI32.read(); // Acquire a read lock on the global `Advapi32` instance.
    (*lock.get()).as_ref().unwrap() // Return the initialized `Advapi32` instance.
}

/// Ensures the `Advapi32` library is initialized by checking and invoking the initialization function.
unsafe fn ensure_initialized() {
    if !INIT_ADVAPI32.load(Ordering::Acquire) {
        init_advapi32_funcs();
    }
}

/// Initializes the `Advapi32` library by loading the DLL and resolving function pointers.
pub unsafe fn init_advapi32_funcs() {
    // Check if initialization has already occurred.
    if !INIT_ADVAPI32.load(Ordering::Acquire) {
        let mut advapi32 = Advapi32::new();

        let dll_name = "advapi32.dll";
        let mut advapi32_dll_unicode = UnicodeString::new();
        let utf16_string: Vec<u16> = dll_name.encode_utf16().chain(Some(0)).collect(); // UTF-16 encoding of the DLL name.
        advapi32_dll_unicode.init(utf16_string.as_ptr()); // Initialize a `UnicodeString` with the DLL name.

        // Load the `advapi32.dll` library.
        (ntdll().ldr_load_dll)(
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            advapi32_dll_unicode,
            &mut advapi32.h_base as *mut _ as *mut core::ffi::c_void,
        );

        // Check if the DLL was successfully loaded.
        if advapi32.h_base.is_null() {
            _print!("[-] Failed to load Advapi32.dll\n");
            return;
        }

        // Resolve the function pointers for the `Advapi32` library.
        resolve_direct_syscalls!(
            advapi32.h_base,
            [(advapi32.get_user_name_w, 0xfca17e5c, GetUserNameW)] // Hash for `GetUserNameW`.
        );

        // Write the initialized `Advapi32` instance into the global storage.
        let lock = ADVAPI32.write();
        *lock.get() = Some(advapi32);

        // Set the initialization flag to indicate successful initialization.
        INIT_ADVAPI32.store(true, Ordering::Release);
    }
}
