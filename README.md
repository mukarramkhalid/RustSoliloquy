# RustSoliloquy

RustSoliloquy is a Rust implementation of the [Internal-Monologue](https://github.com/eladshamir/Internal-Monologue), designed to capture NetNTLM hashes by interacting locally with the NTLM authentication package without touching LSASS. This project combines the use of native APIs for most operations with the Security Support Provider Interface (SSPI) specifically for handling NTLM negotiation.

At its core, RustSoliloquy is a personal learning project aimed at deepening the understanding of NTLM authentication using the SSPI (Security Support Provider Interface) API.

## Key Features

- **Indirect Syscalls**: Leverages native API calls via indirect syscalls for registry modifications, process management, and token handling.
- **SSPI NTLM Negotiation**: Handles NTLM challenge/response using SSPI API.
- **No-Std**: Designed without Rust's standard library.
- **Cross-Compilation**: Supports both GNU and MSVC toolchains.

## Internal Monologue Overview

Internal Monologue is a technique for capturing NetNTLM hashes by leveraging the NTLM authentication package. It operates through four key steps: configuring registry settings to allow NetNTLMv1, impersonating logged-on users to gain their security context, simulating the NTLM authentication process to obtain NetNTLM hashes.

### 1. Extended NTLM Downgrade

This step modifies specific registry keys using native APIs such as `NtOpenKey`, `NtSetValueKey`, and `NtQueryValueKey`. The adjustments allow NetNTLMv1 authentication by changing:

- **LMCompatibilityLevel**: Set to `2` (Send NTLM response only) to enable NetNTLMv1 authentication.
- **NTLMMinClientSec**: Set to `0x20000000` (128-bit encryption) to remove the enforcement of specific session security features such as NTLMv2 session security.
- **RestrictSendingNTLMTraffic**: Set to `0` (Allow all) to permit NTLM traffic, overriding settings like _"Deny all"_, which block all NetNTLM authentication attempts.

### 2. Logged-on Users Impersonation

- **Extract tokens from non-network logon sessions of running processes**: The function first captures a snapshot of the running processes using `NtQuerySystemInformation`. For each process, it opens a handle using `NtOpenProcess` and retrieves the associated token with `NtOpenProcessToken`. This token allows access to the user's security context, which is required for impersonation.

- **Duplicate these tokens to impersonate users and create a new security context**: The token is first checked with `NtQueryInformationToken` to determine its type (primary or impersonation). If it is a primary token, it is duplicated into an impersonation token using `NtDuplicateToken`. After duplication, the impersonation token is applied to the current thread using `NtSetInformationThread`, allowing the program to operate in the security context of the impersonated user. If the token is already an impersonation token, it is directly applied without duplication.

### 3. NTLM Challenge/Response

- **Acquire Credentials**: The process begins by acquiring a handle to the NTLM credentials using `AcquireCredentialsHandle`. This function sets up the authentication package (`NTLM`) for the current user.

- **Type-1 Message (NtLmNegotiate)**: The client generates a Type-1 message by calling `InitializeSecurityContext`. This message advertises the client's capabilities and requests NTLM authentication from the server.

- **Type-2 Message (NtLmChallenge)**: The server simulates a response by invoking `AcceptSecurityContext` to craft a Type-2 message, which includes a challenge and flags indicating the supported authentication options.

- **Challenge Modification**: The crafted Type-2 message is intercepted and modified before being sent back to the client. A custom challenge replaces the default one, and optionally, the ESS (Extended Session Security) flag is disabled to simplify the client's response.

- **Type-3 Message (NtLmAuthenticate)**: The client processes the modified Type-2 message using `InitializeSecurityContext` and generates a Type-3 message containing its response to the challenge, including the NetNTLM hashes.

- **NetNTLM Hash Extraction**: The Type-3 message is parsed to extract the NetNTLM hashes, which can then be used for offline cracking or relay attacks.

### 4. Revert NTLM Downgrade

The restoration process ensures all modified registry keys are returned to their original values. Using `NtOpenKey` and `NtSetValueKey`, previous configurations are reapplied where applicable. If a value was originally absent, `NtDeleteValueKey` is used to remove the newly added entries, ensuring the system remains consistent with its initial state.

## Usage

RustSoliloquy offers several configurable options to tailor its functionality. The following features are available:

- **`impersonate`** _(default)_: Enables the extraction, duplication, and impersonation of user tokens to create new security contexts. Without this feature, only the NTLM hashes of the current user are retrieved.
- **`downgrade`** _(default)_: Adjusts registry settings to allow NTLMv1 authentication by lowering security constraints. If disabled, NTLMv2 hashes are captured where applicable.
- **`restore`** _(default)_: Includes the `downgrade` feature and restores all modified registry settings to their original values after execution.
- **`threads`**: Extends `impersonate` to support token impersonation at the thread level.
- **`verbose`**: Activates detailed logging for debugging and monitoring execution flow.

### Build Options

To build RustSoliloquy use the following commands:

- **Basic build** (impersonation, downgrade, restore):

  ```bash
  cargo build --release
  ```

- **Build with additional features**
  ```bash
  cargo build --release --features="verbose"
  ```

## Disclaimer

This project is intended **for educational and research purposes only**. RustSoliloquy is a personal learning project designed to explore NTLM authentication mechanisms and the Security Support Provider Interface (SSPI). Use it responsibly, and keep in mind that any misuse is solely your responsibility.

Always adhere to ethical guidelines and legal frameworks when conducting security research (and, seriously, in everything you do).

## Credits

- Thanks to [Elad Shamir](https://github.com/eladshamir) for his work on [Internal-Monologue](https://github.com/eladshamir/Internal-Monologue), which inspired this project.

## Contributing

Contributions are welcome! If you have suggestions for improvement or encounter issues, please open an issue or submit a pull request.
