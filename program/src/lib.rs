#![no_std]
#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod helpers;
pub mod instruction;
pub mod state;

pinocchio_pubkey::declare_id!("Stake11111111111111111111111111111111111111");


// #[cfg(not(feature = "no-entrypoint"))]
// #[panic_handler]
// fn panic(_info: &core::panic::PanicInfo) -> ! {
//     loop {}
// }

