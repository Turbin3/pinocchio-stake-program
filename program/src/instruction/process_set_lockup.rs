use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{self, Pubkey},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};

use crate::helpers::bytes_to_u64;
use pinocchio_system::instructions::CreateAccount;

use crate::state::accounts::{Authorized, SetLockupData};
use crate::state::state::{Lockup, Meta};

/// Processes the SetLockup instruction, which either creates a new lockup account or updates the existing lockup account

pub fn process_set_lockup(accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    let [stake_account, lockup_account, authority, _system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if instruction_data.len() < SetLockupData::LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    if stake_account.data_is_empty() {
        return Err(ProgramError::InvalidAccountData);
    }

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let (expected_lockup_pda, _bump) =
        pubkey::find_program_address(&[b"lockup", stake_account.key().as_ref()], &crate::ID);

    if lockup_account.key() != &expected_lockup_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    let stake_meta = Meta::get_account_info_mut(stake_account)?;

    let lockup_params = SetLockupData::instruction_data(instruction_data);

    // Validate at least one lockup parameter is provided
    if lockup_params.unix_timestamp.is_none()
        && lockup_params.epoch.is_none()
        && lockup_params.custodian.is_none()
    {
        return Err(ProgramError::InvalidInstructionData);
    }

    let clock = Clock::get().map_err(|_| ProgramError::InvalidAccountData)?;
    let current_timestamp = clock.unix_timestamp;
    let current_epoch = clock.epoch;

    let lockup_size = Lockup::size();

    // Determine if we need to create or update the lockup account
    let needs_creation = *lockup_account.owner() != crate::ID;

    if needs_creation {
        // Case 1: Create new lockup account
        create_lockup_account(lockup_account, authority, lockup_params, lockup_size)?;
    } else {
        // Case 2: Update existing lockup account
        update_existing_lockup(
            lockup_account,
            authority,
            lockup_params,
            current_timestamp,
            current_epoch,
        )?;
    }
    // stake_meta.lockup = *lockup_account.key();

    Ok(())
}

/// Creates a new lockup account with the provided parameters
fn create_lockup_account(
    lockup_account: &AccountInfo,
    authority: &AccountInfo,
    lockup_params: &SetLockupData,
    lockup_size: usize,
) -> ProgramResult {
    validate_lockup_authority(authority)?;

    let rent = Rent::get()?;
    let lamports_required = rent.minimum_balance(lockup_size);

    // Create lockup account via cross-program invocation to system program
    CreateAccount {
        from: authority,
        to: lockup_account,
        lamports: lamports_required,
        space: lockup_size as u64,
        owner: &crate::ID,
    }
    .invoke()?;

    let lockup_data = Lockup::get_account_info_mut(lockup_account)?;

    lockup_data.unix_timestamp = lockup_params.unix_timestamp.unwrap_or(0).to_le_bytes();
    lockup_data.epoch = lockup_params.epoch.unwrap_or(0).to_le_bytes();
    lockup_data.custodian = lockup_params.custodian.unwrap_or(Pubkey::default());

    Ok(())
}

/// Updates an existing lockup account with new parameters
fn update_existing_lockup(
    lockup_account: &AccountInfo,
    authority: &AccountInfo,
    lockup_params: &SetLockupData,
    current_timestamp: i64,
    current_epoch: u64,
) -> ProgramResult {
    let existing_lockup = Lockup::get_account_info_mut(lockup_account)?;

    let lockup_is_active = existing_lockup.is_active(current_timestamp, current_epoch);
    let authority_is_custodian = authority.key() == &existing_lockup.custodian;

    // Can modify if: lockup expired OR authority is the designated custodian
    let modification_allowed = !lockup_is_active || authority_is_custodian;

    if !modification_allowed {
        validate_lockup_authority(authority)?;
        return Err(ProgramError::InvalidAccountData);
    }

    if let Some(new_timestamp) = lockup_params.unix_timestamp {
        if new_timestamp >= i64::from_le_bytes(existing_lockup.unix_timestamp) {
            existing_lockup.unix_timestamp = new_timestamp.to_le_bytes();
        }
    }

    if let Some(new_epoch) = lockup_params.epoch {
        let existing_epoch = bytes_to_u64(existing_lockup.epoch);
        if new_epoch >= existing_epoch {
            existing_lockup.epoch = new_epoch.to_le_bytes();
        }
    }

    if let Some(new_custodian) = lockup_params.custodian {
        existing_lockup.custodian = new_custodian;
    }

    Ok(())
}

/// Validates that the provided authority has permission to modify lockup settings
fn validate_lockup_authority(authority: &AccountInfo) -> ProgramResult {
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let authorized_data = Authorized::get_account_info(authority)?;

    let is_authorized = authorized_data.is_staker(authority.key())
        || authorized_data.is_withdrawer(authority.key());

    if !is_authorized {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

// ============================ TESTING process_set_lockup ============================

// #[cfg(test)]
// pub mod testing {
//     use super::*;
//     use mollusk_svm::{program, result::Check, Mollusk};
//     use solana_sdk::{
//         account::Account,
//         instruction::{AccountMeta, Instruction},
//         native_token::LAMPORTS_PER_SOL,
//         pubkey::Pubkey,
//         pubkey
//     };

//     const PROGRAM_ID: Pubkey = pubkey!("Stake11111111111111111111111111111111111111");
//     const AUTHORITY: Pubkey = Pubkey::new_from_array([0x01; 32]);
//     const STAKE_ACCOUNT: Pubkey = Pubkey::new_from_array([0x02; 32]);

//     #[test]
//     fn test_process_set_lockup() {
//         let mollusk = Mollusk::new(&PROGRAM_ID, "target/deploy/pinocchio_stake");

//         let (expected_lockup_pda, _bump) = Pubkey::find_program_address(
//             &[b"lockup", STAKE_ACCOUNT.as_ref()],
//             &PROGRAM_ID,
//         );

//         let (system_program_id, system_account) = program::keyed_account_for_system_program();

//         // Construct instruction data
//         let mut instruction_data = [0u8; 49];
//         instruction_data[0] = 6; // Instruction discriminator

//         let timestamp: i64 = 1000000;
//         let epoch: u64 = 100;

//         instruction_data[1..9].copy_from_slice(&timestamp.to_le_bytes());
//         instruction_data[9..17].copy_from_slice(&epoch.to_le_bytes());
//         instruction_data[17..49].copy_from_slice(AUTHORITY.as_ref());

//         // Create AccountMeta array and convert to Vec only for the function call
//         let ix_accounts = [
//             AccountMeta::new(STAKE_ACCOUNT, true),
//             AccountMeta::new(expected_lockup_pda, false),
//             AccountMeta::new(AUTHORITY, true),
//             AccountMeta::new_readonly(system_program_id, false),
//         ];

//         // Create accounts with proper initialization
//         let stake_account_data = [0u8; 200]; // Fixed size array
//         let stake_account = Account {
//             lamports: 1 * LAMPORTS_PER_SOL,
//             data: stake_account_data.to_vec(), // Convert to Vec only for Account
//             owner: PROGRAM_ID,
//             executable: false,
//             rent_epoch: 0,
//         };

//         let lockup_account = Account::new(0, 0, &system_program_id);

//         let authority_account_data = [0u8; 64]; // Fixed size for Authorized struct
//         let authority_account = Account {
//             lamports: 1 * LAMPORTS_PER_SOL,
//             data: authority_account_data.to_vec(), // Convert to Vec only for Account
//             owner: PROGRAM_ID,
//             executable: false,
//             rent_epoch: 0,
//         };

//         let instruction = Instruction::new_with_bytes(
//             PROGRAM_ID,
//             &instruction_data,
//             ix_accounts.to_vec() // Convert to Vec only for function call
//         );

//         // Create account array and convert to Vec only for function call
//         let tx_accounts = [
//             (STAKE_ACCOUNT, stake_account),
//             (expected_lockup_pda, lockup_account),
//             (AUTHORITY, authority_account),
//             (system_program_id, system_account),
//         ];

//         // Debug: Try without validation first
//         mollusk.process_and_validate_instruction(
//             &instruction,
//             &tx_accounts.to_vec(), // Convert to Vec only for function call
//             &[Check::success()], // No checks first
//         );
//     }

//     // Minimal test to isolate compute unit issue
//     #[test]
//     fn test_process_set_lockup_minimal() {
//         let mollusk = Mollusk::new(&PROGRAM_ID, "target/deploy/pinocchio_stake");

//         // Minimal instruction - just discriminator
//         let instruction_data = [6u8; 1];
//         let dummy_pubkey = Pubkey::new_from_array([0x03; 32]);

//         let ix_accounts = [
//             AccountMeta::new(STAKE_ACCOUNT, true),
//             AccountMeta::new(dummy_pubkey, false),
//             AccountMeta::new(AUTHORITY, true),
//             AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
//         ];

//         let instruction = Instruction::new_with_bytes(
//             PROGRAM_ID,
//             &instruction_data,
//             ix_accounts.to_vec()
//         );

//         let tx_accounts = [
//             (STAKE_ACCOUNT, Account::new(1 * LAMPORTS_PER_SOL, 200, &PROGRAM_ID)),
//             (dummy_pubkey, Account::new(0, 0, &solana_sdk::system_program::ID)),
//             (AUTHORITY, Account::new(1 * LAMPORTS_PER_SOL, 64, &PROGRAM_ID)),
//             (solana_sdk::system_program::ID, Account::new(0, 0, &solana_sdk::system_program::ID)),
//         ];

//         mollusk.process_and_validate_instruction(
//             &instruction,
//             &tx_accounts.to_vec(),
//             &[Check::success()],
//         );

//     }

//     // Test with early return to isolate compute usage
//     #[test]
//     fn test_early_return() {
//         // First, modify your process_set_lockup function temporarily:
//         // Add `return Ok(());` as the first line to see if basic invocation works

//         let mollusk = Mollusk::new(&PROGRAM_ID, "target/deploy/pinocchio_stake");
//         let instruction_data = [6u8; 1];

//         let ix_accounts = [AccountMeta::new(STAKE_ACCOUNT, true)];
//         let instruction = Instruction::new_with_bytes(
//             PROGRAM_ID,
//             &instruction_data,
//             ix_accounts.to_vec()
//         );

//         let tx_accounts = [
//             (STAKE_ACCOUNT, Account::new(1 * LAMPORTS_PER_SOL, 0, &PROGRAM_ID))
//         ];

//         mollusk.process_and_validate_instruction(
//             &instruction,
//             &tx_accounts.to_vec(),
//             &[Check::success()],
//         );
//     }
// }
