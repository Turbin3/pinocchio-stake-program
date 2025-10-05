#![cfg(feature = "enforce-stake-config")]

// Optional StakeConfig identity for strict account-shape parity.
// When the feature `enforce-stake-config` is enabled, handlers may verify
// the 5th account matches this pubkey. The ID matches Solana's native
// stake-config program id for shape parity purposes.

use pinocchio_pubkey::declare_id;

// This constant mirrors the Solana stake-config program id. If this value
// diverges from your environment, disable the feature or adjust as needed.
declare_id!("StakeConfig11111111111111111111111111111111");

