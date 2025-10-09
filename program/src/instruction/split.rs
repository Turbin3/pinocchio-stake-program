extern crate alloc;
use crate::{
    error::*, helpers::*, state::accounts::StakeAuthorize, state::stake_state_v2::StakeStateV2,
    state::StakeHistorySysvar,
};
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

pub fn process_split(accounts: &[AccountInfo], split_lamports: u64) -> ProgramResult {
    pinocchio::msg!("split:enter");
    let mut arr_of_signers = [Pubkey::default(); MAXIMUM_SIGNERS];
    let _ = collect_signers(accounts, &mut arr_of_signers)?;

    // Canonical SDK order: [source_stake, destination_stake, stake_authority]
    if accounts.len() < 3 { return Err(ProgramError::NotEnoughAccountKeys); }
    let source_stake_account_info = &accounts[0];
    let destination_stake_account_info = &accounts[1];
    let authority_account_info = &accounts[2];

    // Basic account validation and parity checks
    if !source_stake_account_info.is_writable() || !destination_stake_account_info.is_writable() {
        return Err(ProgramError::InvalidInstructionData);
    }
    if !authority_account_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *source_stake_account_info.owner() != crate::ID {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if *destination_stake_account_info.owner() != crate::ID {
        return Err(ProgramError::InvalidAccountOwner);
    }

    let clock = Clock::get()?;
    let stake_history = &StakeHistorySysvar(clock.epoch);

    let source_lamport_balance = source_stake_account_info.lamports();

    // Global preflight: fail fast for oversplit before touching destination
    pinocchio::msg!("split:preflight_enter");
    if split_lamports > source_lamport_balance {
        pinocchio::msg!("split:preflight_over_balance");
        return Err(ProgramError::InsufficientFunds);
    }
    // Rent-reserve preflight applies to Initialized/Stake; Uninitialized is handled below.
    pinocchio::msg!("split:preflight_ok");

    let destination_lamport_balance = destination_stake_account_info.lamports();

    // Skip rent-reserve preflight for Uninitialized; handled in match arm.

    // note: over-balance already checked in preflight above

    // Validate destination after basic over-balance check so initial errors map to InsufficientFunds
    let destination_data_len = destination_stake_account_info.data_len();
    // Native requires exact account data size
    if destination_data_len != StakeStateV2::size_of() {
        pinocchio::msg!("split:dest_size_mismatch");
        return Err(ProgramError::InvalidAccountData);
    }
    // Destination must be Uninitialized
    match get_stake_state(destination_stake_account_info)? {
        StakeStateV2::Uninitialized => {}
        _ => {
            pinocchio::msg!("split:dest_not_uninit");
            return Err(ProgramError::InvalidAccountData)
        }
    }

    match get_stake_state(source_stake_account_info)? {
        StakeStateV2::Stake(source_meta, mut source_stake, stake_flags) => {
            if source_stake_account_info.key() == destination_stake_account_info.key() {
                return Err(ProgramError::InvalidArgument);
            }
            // Enforce index-2 is the staker and has signed
            if source_meta.authorized.staker != *authority_account_info.key() {
                return Err(ProgramError::MissingRequiredSignature);
            }

            let minimum_delegation = get_minimum_delegation();

            let status = source_stake.delegation.stake_activating_and_deactivating(
                clock.epoch.to_le_bytes(),
                stake_history,
                PERPETUAL_NEW_WARMUP_COOLDOWN_RATE_EPOCH,
            );

            let is_active = bytes_to_u64(status.effective) > 0;

            // NOTE this function also internally summons Rent via syscall
            let validated_split_info = validate_split_amount(
                source_lamport_balance,
                destination_lamport_balance,
                split_lamports,
                &source_meta,
                destination_data_len,
                minimum_delegation,
                is_active,
            )?;

            // split the stake, subtract rent_exempt_balance unless
            // the destination account already has those lamports
            // in place.
            // this means that the new stake account will have a stake equivalent to
            // lamports minus rent_exempt_reserve if it starts out with a zero balance
            let (remaining_stake_delta, split_stake_amount) =
                if validated_split_info.source_remaining_balance == 0 {
                    // If split amount equals the full source stake (as implied by 0
                    // source_remaining_balance), the new split stake must equal the same
                    // amount, regardless of any current lamport balance in the split account.
                    // Since split accounts retain the state of their source account, this
                    // prevents any magic activation of stake by prefunding the split account.
                    //
                    // The new split stake also needs to ignore any positive delta between the
                    // original rent_exempt_reserve and the split_rent_exempt_reserve, in order
                    // to prevent magic activation of stake by splitting between accounts of
                    // different sizes.
                    let remaining_stake_delta = split_lamports
                        .saturating_sub(bytes_to_u64(source_meta.rent_exempt_reserve));
                    (remaining_stake_delta, remaining_stake_delta)
                } else {
                    // Otherwise, the new split stake should reflect the entire split
                    // requested, less any lamports needed to cover the
                    // split_rent_exempt_reserve.
                    let split_stake_amount = split_lamports.saturating_sub(
                        validated_split_info
                            .destination_rent_exempt_reserve
                            .saturating_sub(destination_lamport_balance),
                    );

                    // Source must retain at least minimum delegation after removing only the stake portion
                    if bytes_to_u64(source_stake.delegation.stake)
                        .saturating_sub(split_stake_amount)
                        < minimum_delegation
                    {
                        return Err(to_program_error(StakeError::InsufficientDelegation.into()));
                    }

                    (split_stake_amount, split_stake_amount)
                };

            if split_stake_amount < minimum_delegation {
                return Err(to_program_error(StakeError::InsufficientDelegation.into()));
            }

            let destination_stake = source_stake
                .split(remaining_stake_delta, split_stake_amount)
                .map_err(to_program_error)?;

            let mut destination_meta = source_meta;
            destination_meta.rent_exempt_reserve = validated_split_info
                .destination_rent_exempt_reserve
                .to_le_bytes();

            set_stake_state(
                source_stake_account_info,
                &StakeStateV2::Stake(source_meta, source_stake, stake_flags),
            )?;

            set_stake_state(
                destination_stake_account_info,
                &StakeStateV2::Stake(destination_meta, destination_stake, stake_flags),
            )?;
        }
        StakeStateV2::Initialized(source_meta) => {
            if source_stake_account_info.key() == destination_stake_account_info.key() {
                return Err(ProgramError::InvalidArgument);
            }
            // Enforce index-2 is the staker and has signed
            if source_meta.authorized.staker != *authority_account_info.key() {
                return Err(ProgramError::MissingRequiredSignature);
            }

            // NOTE this function also internally summons Rent via syscall
            let validated_split_info = validate_split_amount(
                source_lamport_balance,
                destination_lamport_balance,
                split_lamports,
                &source_meta,
                destination_data_len,
                0,     // additional_required_lamports
                false, // is_active
            )?;

            let mut destination_meta = source_meta;
            destination_meta.rent_exempt_reserve = validated_split_info
                .destination_rent_exempt_reserve
                .to_le_bytes();

            set_stake_state(
                destination_stake_account_info,
                &StakeStateV2::Initialized(destination_meta),
            )?;
        }
        StakeStateV2::Uninitialized => {
            // Allow moving lamports from an Uninitialized source when the source account itself has signed.
            // Destination must still be a valid stake account (Uninitialized, correct size, owned by the program).
            if !source_stake_account_info.is_signer() {
                return Err(ProgramError::MissingRequiredSignature);
            }
            // No state changes; relocation happens after the match.
        }
        _ => { return Err(ProgramError::InvalidAccountData) },
    }

    // Deinitialize state upon zero balance
    if split_lamports == source_lamport_balance {
        set_stake_state(source_stake_account_info, &StakeStateV2::Uninitialized)?;
    }

    relocate_lamports(
        source_stake_account_info,
        destination_stake_account_info,
        split_lamports,
    )?;
    Ok(())
}
