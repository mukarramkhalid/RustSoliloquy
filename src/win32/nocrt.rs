use super::{k32::k32, ntdll::nt_get_last_error};

/// Sets the first `n` bytes of the block of memory pointed to by `s`
/// to the specified value `c` (interpreted as an unsigned char).
///
/// # Parameters
/// - `s`: A pointer to the block of memory to fill.
/// - `c`: The value to be set. Only the lower 8 bits of `c` are used.
/// - `n`: The number of bytes to be set to the value.
///
/// # Returns
/// A pointer to the memory area `s`.
#[no_mangle]
pub extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe { *s.add(i) = c as u8 };
    }
    s
}

/// Copies `n` bytes from memory area `src` to memory area `dest`.
/// The memory areas must not overlap.
///
/// # Parameters
/// - `dest`: A pointer to the destination array where the content is to be copied.
/// - `src`: A pointer to the source of data to be copied.
/// - `n`: The number of bytes to copy.
///
/// # Returns
/// A pointer to the destination `dest`.
#[no_mangle]
pub extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            *dest.add(i) = *src.add(i);
        }
    }
    dest
}

/// Copies `n` bytes from memory area `src` to memory area `dest`.
/// The memory areas may overlap.
///
/// # Parameters
/// - `dest`: A pointer to the destination array where the content is to be copied.
/// - `src`: A pointer to the source of data to be copied.
/// - `n`: The number of bytes to copy.
///
/// # Returns
/// A pointer to the destination `dest`.
#[no_mangle]
pub extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if src < dest as *const u8 {
        for i in (0..n).rev() {
            unsafe {
                *dest.add(i) = *src.add(i);
            }
        }
    } else {
        for i in 0..n {
            unsafe {
                *dest.add(i) = *src.add(i);
            }
        }
    }
    dest
}

/// Compares the first `n` bytes of the memory areas `s1` and `s2`.
///
/// # Parameters
/// - `s1`: A pointer to the first memory area.
/// - `s2`: A pointer to the second memory area.
/// - `n`: The number of bytes to compare.
///
/// # Returns
/// An integer less than, equal to, or greater than zero if the first `n` bytes of `s1`
/// is found, respectively, to be less than, to match, or be greater than the first `n` bytes of `s2`.
#[no_mangle]
pub extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let a = unsafe { *s1.add(i) };
        let b = unsafe { *s2.add(i) };
        if a != b {
            return a as i32 - b as i32;
        }
    }
    0
}

/// Computes the length of the string `s`, excluding the terminating null byte.
///
/// # Parameters
/// - `s`: A pointer to the null-terminated byte string to be examined.
///
/// # Returns
/// The number of bytes in the string pointed to by `s`, excluding the terminating null byte.
#[no_mangle]
pub extern "C" fn strlen(s: *const u8) -> usize {
    let mut count = 0;
    unsafe {
        while *s.add(count) != 0 {
            count += 1;
        }
    }
    count
}

/// A static variable required by some environments to indicate floating-point usage.
/// This is a placeholder to ensure compatibility.
#[export_name = "_fltused"]
static _FLTUSED: i32 = 0;

/// A placeholder function for the C++ exception handling frame handler.
/// This function is not yet implemented.
///
/// # Parameters
/// - `_: A placeholder parameter.
/// - `_: A placeholder parameter.
/// - `_: A placeholder parameter.
/// - `_: A placeholder parameter.
///
/// # Returns
/// This function currently returns an unimplemented!() macro.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 {
    unimplemented!()
}

/// A placeholder function for stack checking in some environments.
/// This function currently does nothing.
#[no_mangle]
pub extern "C" fn __chkstk() {}

/// Implements a minimal `_write` function for writing to the standard output.
#[no_mangle]
extern "C" fn _write(_fd: i32, buf: *const u8, count: usize) -> isize {
    unsafe {
        let mut written: u32 = 0;
        let handle = -11i32 as u32; // Handle for `STD_OUTPUT_HANDLE`.
        let mut status = 0;

        if let Some(write_file) = k32().write_file {
            status = write_file(
                handle as *mut u8,     // File handle.
                buf,                   // Data buffer pointer.
                count as u32,          // Number of bytes to write.
                &mut written,          // Pointer to track bytes written.
                core::ptr::null_mut(), // No overlapping operation.
            );
        }

        // Return status or the number of bytes written.
        if status < 0 {
            nt_get_last_error() as isize
        } else {
            written as isize
        }
    }
}

/// Macro for conditional printing using `libc_println`.
///
/// The macro takes a format string and optional arguments.
/// It will only print the message if the feature `debug` is enabled.
#[macro_export]
macro_rules! _print {
    ($($arg:tt)*) => {
        #[cfg(feature = "verbose")]
        {
            $crate::libc_println!($($arg)*);
        }
    };
}
