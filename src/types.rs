use core::ffi::c_void;
use core::fmt;

use alloc::{
    format,
    string::{String, ToString},
};

use crate::{
    _print,
    utils::{bytes_to_hex, utf16_le_to_string},
};

/// Represents the container for storing NTLM response.
pub struct Response {
    /// The internal string that stores all collected NTLM hashes
    pub value: String,
}

impl Response {
    /// Creates a new, empty `Result` container.
    pub fn new() -> Response {
        Response {
            value: String::new(),
        }
    }

    /// Adds a new NTLM hash to the container.
    ///
    /// The hash is appended to the `value` field followed by a newline.
    ///
    /// # Parameters
    /// - `value`: The NTLM hash to add.
    pub fn add(&mut self, value: &str) {
        self.value.push_str(value);
        self.value.push('\n');
    }
}

impl fmt::Display for Response {
    /// Formats the `Result` for display, outputting all NTLM hashes
    /// stored in the container, each on its own line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// Represents the parsed response of an NTLM authentication attempt.
#[derive(Debug, Default)]
pub struct NtlmResponse {
    /// The NTLM challenge used during the authentication process.
    pub challenge: String,
    /// The username extracted from the NTLM response.
    pub user_name: String,
    /// The domain associated with the user.
    pub domain: String,
    /// The first part of the NTLM response.
    pub resp1: String,
    /// The second part of the NTLM response.
    pub resp2: String,
    /// Indicates the NTLM version: `false` for NTLMv2, `true` for NTLMv1.
    pub version: bool,
}

/// Errors that can occur while parsing an NTLM response.
#[derive(Debug)]
pub enum NtlmError {
    /// The NTLM response message is shorter than expected.
    InvalidMessageLength,
    /// The offset or length of a field is invalid.
    InvalidOffsetLength(&'static str, usize),
}

impl fmt::Display for NtlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtlmError::InvalidMessageLength => write!(f, "Invalid NTLM response message length."),
            NtlmError::InvalidOffsetLength(field, length) => {
                write!(
                    f,
                    "Field '{}' has an invalid offset or length: {} bytes.",
                    field, length
                )
            }
        }
    }
}

impl core::error::Error for NtlmError {}

impl fmt::Display for NtlmResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format the NTLM response based on privilege level.
        if self.version {
            write!(
                f,
                "{}::{}:{}:{}:{}",
                self.user_name, self.domain, self.resp1, self.resp2, self.challenge
            )
        } else {
            write!(
                f,
                "{}::{}:{}:{}:{}",
                self.user_name, self.domain, self.challenge, self.resp1, self.resp2
            )
        }
    }
}

impl NtlmResponse {
    /// Parses an NTLM response message and constructs an `NtlmResponse` object.
    ///
    /// # Arguments
    /// * `message` - The raw NTLM response bytes.
    /// * `challenge` - The NTLM challenge used in the process.
    ///
    /// # Returns
    /// Returns `Ok(NtlmResponse)` if parsing succeeds, or an `Err(NtlmError)` otherwise.
    pub fn from_bytes(message: &[u8], challenge: &str) -> Result<Self, NtlmError> {
        if message.len() < 48 {
            return Err(NtlmError::InvalidMessageLength);
        }

        // Extract field lengths and offsets from the NTLM message.
        let lm_resp_len = u16::from_le_bytes(message[12..14].try_into().unwrap()) as usize;
        let lm_resp_off = u32::from_le_bytes(message[16..20].try_into().unwrap()) as usize;
        let nt_resp_len = u16::from_le_bytes(message[20..22].try_into().unwrap()) as usize;
        let nt_resp_off = u32::from_le_bytes(message[24..28].try_into().unwrap()) as usize;
        let domain_len = u16::from_le_bytes(message[28..30].try_into().unwrap()) as usize;
        let domain_off = u32::from_le_bytes(message[32..36].try_into().unwrap()) as usize;
        let user_len = u16::from_le_bytes(message[36..38].try_into().unwrap()) as usize;
        let user_off = u32::from_le_bytes(message[40..44].try_into().unwrap()) as usize;

        // Extract the various components of the NTLM response.
        let lm_resp = message
            .get(lm_resp_off..lm_resp_off + lm_resp_len)
            .ok_or(NtlmError::InvalidOffsetLength("LM response", lm_resp_len))?;
        let nt_resp = message
            .get(nt_resp_off..nt_resp_off + nt_resp_len)
            .ok_or(NtlmError::InvalidOffsetLength("NT response", nt_resp_len))?;
        let domain_bytes = message
            .get(domain_off..domain_off + domain_len)
            .ok_or(NtlmError::InvalidOffsetLength("Domain", domain_len))?;
        let user_bytes = message
            .get(user_off..user_off + user_len)
            .ok_or(NtlmError::InvalidOffsetLength("User", user_len))?;

        // Populate the NtlmResponse object.
        let mut result = NtlmResponse {
            challenge: challenge.to_string(),
            user_name: utf16_le_to_string(user_bytes),
            domain: utf16_le_to_string(domain_bytes),
            ..Default::default()
        };

        // Process NTLM response based on protocol version.
        match nt_resp_len {
            24 => {
                // NTLMv1 response.
                result.resp1 = bytes_to_hex(lm_resp);
                result.resp2 = bytes_to_hex(nt_resp);
                result.version = true;
            }
            len if len > 24 => {
                // NTLMv2 response.
                result.resp1 = bytes_to_hex(&nt_resp[0..16]);
                result.resp2 = bytes_to_hex(&nt_resp[16..]);
                result.version = false;
            }
            _ => {
                return Err(NtlmError::InvalidOffsetLength("NT response", nt_resp_len));
            }
        }

        Ok(result)
    }

    /// Checks if the NTLM response is valid.
    ///
    /// A response is considered valid if both the username and domain are non-empty.
    pub fn is_valid(&self) -> bool {
        !self.user_name.is_empty() && !self.domain.is_empty()
    }
}

/// Represents a Security Identifier (SID).
#[derive(Default, Debug, Clone)]
pub struct Sid {
    /// The string representation of the SID.
    pub value: String,
}

impl Sid {
    /// Constructs a SID from a byte slice.
    /// The byte slice must follow the SID binary format.
    /// Returns an error if the byte slice is too short or invalid.
    pub fn from_bytes(bytes: &[u8]) -> Option<Sid> {
        // Check if the byte slice has a valid length for SID
        if bytes.len() < 8 {
            return None;
        }

        let revision = bytes[0];
        let sub_authority_count = bytes[1];
        let identifier_authority = &bytes[2..8];

        // Initialize SID string format with revision
        let mut value = format!("S-{}", revision);

        // Convert identifier authority bytes to a single u64 value
        let mut id_auth_value = 0u64;
        for &b in identifier_authority {
            id_auth_value = (id_auth_value << 8) + b as u64;
        }
        value += &format!("-{}", id_auth_value);

        // Calculate required length for sub-authorities and validate it
        if bytes.len() < 8 + (sub_authority_count as usize) * 4 {
            return None;
        }

        // Parse each sub-authority (32-bit values in little-endian format)
        for i in 0..sub_authority_count {
            let offset = 8 + (i as usize) * 4;
            let sub_auth_bytes = &bytes[offset..offset + 4];
            let sub_auth = u32::from_le_bytes([
                sub_auth_bytes[0],
                sub_auth_bytes[1],
                sub_auth_bytes[2],
                sub_auth_bytes[3],
            ]);
            value += &format!("-{}", sub_auth);
        }

        Some(Sid { value })
    }

    pub fn from_ptr(ptr: *mut c_void) -> Option<Sid> {
        if ptr.is_null() {
            return None;
        }

        unsafe {
            // Interpret the pointer as a byte slice
            let sid_bytes = core::slice::from_raw_parts(ptr as *const u8, 8);

            // Check the minimum SID length
            if sid_bytes.len() < 8 {
                return None;
            }

            // Retrieve the revision and sub-authority count
            // let revision = sid_bytes[0];
            let sub_authority_count = sid_bytes[1] as usize;

            // Calculate the total SID length based on sub-authority count
            let expected_length = 8 + (4 * sub_authority_count);
            let sid_data = core::slice::from_raw_parts(ptr as *const u8, expected_length);

            // Call your existing SID parsing function with the byte slice
            Sid::from_bytes(sid_data)
        }
    }
}

/// Represents a handle to a registry key, along with an optional value associated with it.
pub struct RegKeyHandle {
    pub handle: *mut c_void, // Raw pointer to the registry key handle
    pub value: Option<u32>,  // Optional 32-bit value associated with the key
}

impl RegKeyHandle {
    /// Creates a new `RegKeyHandle` instance.
    pub fn new(handle: *mut c_void, value: Option<u32>) -> Self {
        RegKeyHandle { handle, value }
    }
}
