// Only go no_std when building for SBF.
#![cfg_attr(feature = "sbf", no_std)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "no-entrypoint"))]
pub mod entrypoint;

pub mod error;
pub mod helpers;
pub mod instruction;
pub mod state;

pinocchio_pubkey::declare_id!("Stake11111111111111111111111111111111111111");

// ---- SBF-only runtime shims (no_std builds) ----
#[cfg(feature = "sbf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // On-chain panic: emit a marker, then spin (abort semantics)
    pinocchio::msg!("panic:handler");
    loop {}
}

#[cfg(feature = "sbf")]
pinocchio::no_allocator!();
