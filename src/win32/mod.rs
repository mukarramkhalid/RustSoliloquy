pub mod advapi32;
pub mod allocator;
pub mod def;
pub mod gate;
pub mod k32;
pub mod ldrapi;
pub mod nocrt;
pub mod ntdll;
pub mod psapi;
pub mod sspicli;

#[cfg(feature = "downgrade")]
pub mod winreg;
