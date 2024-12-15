use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

use spin::RwLock;

use crate::{_print, resolve_direct_syscalls, win32::ldrapi::ldr_module};

/// Function type definition for `WriteFile`, writes data to the specified file.
pub type WriteFile = unsafe extern "system" fn(
    hFile: *mut u8,
    lpBuffer: *const u8,
    nNumberOfBytesToWrite: u32,
    lpNumberOfBytesWritten: *mut u32,
    lpOverlapped: *mut u8,
) -> i32;

/// Struct representing the `Kernel32` library, including its base address and function pointers.
pub struct K32 {
    pub h_base: *mut u8,               // Base address of the loaded `kernel32.dll`.
    pub write_file: Option<WriteFile>, // Pointer to the `WriteFile` function.
}

impl K32 {
    /// Creates a new instance of `K32` with null base address and no function pointers.
    pub fn new() -> Self {
        Self {
            h_base: core::ptr::null_mut(),
            write_file: None,
        }
    }
}

/// Atomic flag to ensure initialization happens only once.
static INIT_K32: AtomicBool = AtomicBool::new(false);

/// Global mutable instance of kernel32.
pub static mut K32: RwLock<UnsafeCell<Option<K32>>> = RwLock::new(UnsafeCell::new(None));

/// Returns a static reference to the `K32` instance, ensuring it is initialized before use.
pub unsafe fn k32() -> &'static K32 {
    ensure_initialized();
    let lock = K32.read();
    (*lock.get()).as_ref().unwrap()
}

/// Ensures the `K32` library is initialized by checking and invoking the initialization function.
unsafe fn ensure_initialized() {
    if !INIT_K32.load(Ordering::Acquire) {
        init_k32_funcs();
    }
}

/// Initializes the `K32` library by loading the DLL and resolving function pointers.
pub unsafe fn init_k32_funcs() {
    if !INIT_K32.load(Ordering::Acquire) {
        let mut k32 = K32::new();

        // Load the `kernel32.dll` library.
        k32.h_base = ldr_module(0x6ddb9555); // Hash of "kernel32.dll".
        if k32.h_base.is_null() {
            _print!("[-] Failed to load kernel32.dll\n");
            return;
        }

        // Resolve the function pointers for the `Kernel32` library.
        resolve_direct_syscalls!(
            k32.h_base,
            [(k32.write_file, 0xf1d207d0, WriteFile)] // Hash for `WriteFile`.
        );

        // Write the initialized `K32` instance into the global storage.
        let lock = K32.write();
        *lock.get() = Some(k32);

        // Set the initialization flag to indicate successful initialization.
        INIT_K32.store(true, Ordering::Release);
    }
}
