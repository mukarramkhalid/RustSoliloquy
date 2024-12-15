use core::ops::Div as _;

use alloc::{format, string::String, vec::Vec};

use crate::{_print, win32::def::UnicodeString};

/// Computes the DJB2 hash for the given buffer
pub fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter < buffer.len() {
        cur = buffer[iter];

        if cur == 0 {
            iter += 1;
            continue;
        }

        if cur >= (b'a') {
            cur -= 0x20;
        }

        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    hsh
}

/// Calculates the length of a C-style null-terminated string.
pub fn get_cstr_len(pointer: *const char) -> usize {
    let mut tmp: u64 = pointer as u64;

    unsafe {
        while *(tmp as *const u8) != 0 {
            tmp += 1;
        }
    }

    (tmp - pointer as u64) as _
}

/// Computes the length of a null-terminated wide string (UTF-16).
pub fn string_length_w(string: *const u16) -> usize {
    unsafe {
        let mut string2 = string;
        // Iterate through the wide string until a null character (0) is found.
        while !(*string2).is_null() {
            string2 = string2.add(1); // Move to the next character
        }
        // Calculate the length by finding the difference between pointers.
        string2.offset_from(string) as usize
    }
}

/// Trait to determine if a value is null.
trait IsNull {
    fn is_null(&self) -> bool;
}

/// Implements the `IsNull` trait for `u16` to check for a null value.
impl IsNull for u16 {
    fn is_null(&self) -> bool {
        *self == 0 // A null value is represented as 0 for UTF-16 strings.
    }
}

/// Converts a byte slice into a hexadecimal string representation.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    // Each byte is formatted as a two-character hexadecimal value.
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Converts a UTF-16 little-endian byte slice into a Rust `String`.
pub fn utf16_le_to_string(bytes: &[u8]) -> String {
    // Split the byte slice into 2-byte chunks, convert to u16, and decode as UTF-16.
    let utf16_pairs: Vec<u16> = bytes
        .chunks_exact(2) // Ensure each chunk is exactly 2 bytes
        .map(|chunk| u16::from_le_bytes(chunk.try_into().unwrap())) // Convert to u16
        .collect();
    String::from_utf16_lossy(&utf16_pairs) // Handle invalid UTF-16 gracefully
}

/// Converts a hexadecimal string into a vector of bytes.
#[allow(unused_variables)]
pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    // Ensure the hex string has an even number of characters.
    if hex.len() % 2 != 0 {
        _print!("Hex string must have an even number of characters");
        return None;
    }

    // Parse each pair of characters as a single byte.
    match hex
        .chars()
        .collect::<Vec<_>>() // Collect characters into a vector
        .chunks(2) // Process pairs of characters
        .map(|chunk| {
            let byte_str = format!("{}{}", chunk[0], chunk[1]);
            u8::from_str_radix(&byte_str, 16) // Parse as base-16
                .map_err(|_| format!("Invalid hex: {}", byte_str))
        })
        .collect()
    {
        Ok(value) => Some(value),
        Err(e) => {
            _print!("Error parsing hex string: {}", e);
            None
        }
    }
}

/// Converts a `UnicodeString` into a Rust `String`.
pub fn unicodestring_to_string(unicode_string: &UnicodeString) -> Option<String> {
    // Check if the length of the UnicodeString is zero or if the buffer is null.
    if unicode_string.length == 0 || unicode_string.buffer.is_null() {
        return None;
    }

    // Convert the raw UTF-16 buffer into a Rust slice.
    // SAFETY: The buffer is assumed to be valid and properly null-terminated.
    let slice = unsafe {
        core::slice::from_raw_parts(
            unicode_string.buffer,
            (unicode_string.length.div(2)) as usize,
        )
    };

    // Attempt to convert the UTF-16 slice into a Rust String.
    String::from_utf16(slice).ok()
}
