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
    pinocchio::msg!("split:begin");
    let mut arr_of_signers = [Pubkey::default(); MAXIMUM_SIGNERS];
    let _ = collect_signers(accounts, &mut arr_of_signers)?;

    // Canonical SDK order: [source_stake, destination_stake, authority]
    if accounts.len() < 2 { pinocchio::msg!("split:acclt2"); return Err(ProgramError::NotEnoughAccountKeys); }
    pinocchio::msg!("split:acclenok");
    let source_stake_account_info = &accounts[0];
    let destination_stake_account_info = &accounts[1];
    pinocchio::msg!("split:accs_ok");
    if *source_stake_account_info.owner() != crate::ID {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if *destination_stake_account_info.owner() != crate::ID {
        return Err(ProgramError::InvalidAccountOwner);
    }
    #[cfg(feature = "cu-trace")] msg!("Split: destructured accounts");
    // Trace key account flags
    #[cfg(feature = "cu-trace")] if source_stake_account_info.is_signer() { msg!("Split: src signer=1"); } else { msg!("Split: src signer=0"); }
    #[cfg(feature = "cu-trace")] if source_stake_account_info.is_writable() { msg!("Split: src writable=1"); } else { msg!("Split: src writable=0"); }
    #[cfg(feature = "cu-trace")] if destination_stake_account_info.is_signer() { msg!("Split: dst signer=1"); } else { msg!("Split: dst signer=0"); }
    #[cfg(feature = "cu-trace")] if destination_stake_account_info.is_writable() { msg!("Split: dst writable=1"); } else { msg!("Split: dst writable=0"); }
    if *source_stake_account_info.owner() != crate::ID { return Err(ProgramError::InvalidAccountOwner); }
    if *destination_stake_account_info.owner() != crate::ID { return Err(ProgramError::InvalidAccountOwner); }


    let clock = Clock::get()?;
    pinocchio::msg!("split:clock");
    #[cfg(feature = "cu-trace")] msg!("Split: got Clock");
    let stake_history = &StakeHistorySysvar(clock.epoch);

    let _source_data_len = source_stake_account_info.data_len();
    let destination_data_len = destination_stake_account_info.data_len();
    #[cfg(feature = "cu-trace")] if source_data_len == 0 { msg!("Split: src len=0"); }
    #[cfg(feature = "cu-trace")] if destination_data_len == 0 { msg!("Split: dest len=0"); }
    let _min = StakeStateV2::size_of();
    #[cfg(feature = "cu-trace")] {
        if destination_data_len == 0 { msg!("Split: dest len=0"); }
        else if destination_data_len < min { msg!("Split: dest len<min"); }
        else { msg!("Split: dest len>=min"); }
    }
    if destination_data_len < StakeStateV2::size_of() {
        pinocchio::msg!("split:dest_too_small");
        return Err(ProgramError::InvalidAccountData);
    }
    pinocchio::msg!("split:len_ok");

    // Be tolerant of account data alignment for destination Uninitialized check.
    // Only require that the destination deserializes to Uninitialized.
    {
        let data = unsafe { destination_stake_account_info.borrow_data_unchecked() };
        pinocchio::msg!("split:dest_deser");
        match StakeStateV2::deserialize(&data) {
            Ok(StakeStateV2::Uninitialized) => { pinocchio::msg!("split:dest_uninit"); }
            Ok(_) => { pinocchio::msg!("split:dest_not_uninit"); return Err(ProgramError::InvalidAccountData); }
            Err(_) => { pinocchio::msg!("split:dest_deser_err"); return Err(ProgramError::InvalidAccountData); }
        }
    }

    let source_lamport_balance = source_stake_account_info.lamports();
    let destination_lamport_balance = destination_stake_account_info.lamports();

    if split_lamports > source_lamport_balance {
        return Err(ProgramError::InsufficientFunds);
    }

    pinocchio::msg!("split:state");
    match get_stake_state(source_stake_account_info)? {
        StakeStateV2::Stake(source_meta, mut source_stake, stake_flags) => {
            pinocchio::msg!("split:src=Stake");
            source_meta
                .authorized
                .check(&arr_of_signers, StakeAuthorize::Staker)
                .map_err(to_program_error)?;

            let minimum_delegation = get_minimum_delegation();

            let status = source_stake.delegation.stake_activating_and_deactivating(
                clock.epoch.to_le_bytes(),
                stake_history,
                PERPETUAL_NEW_WARMUP_COOLDOWN_RATE_EPOCH,
            );

            let is_active = bytes_to_u64(status.effective) > 0;

            // NOTE this function also internally summons Rent via syscall
            pinocchio::msg!("split:before_validate");
            let validated_split_info = validate_split_amount(
                source_lamport_balance,
                destination_lamport_balance,
                split_lamports,
                &source_meta,
                destination_data_len,
                minimum_delegation,
                is_active,
            )?;
            pinocchio::msg!("split:validated");

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
                    if bytes_to_u64(source_stake.delegation.stake).saturating_sub(split_lamports)
                        < minimum_delegation
                    {
                        return Err(to_program_error(StakeError::InsufficientDelegation.into()));
                    }

                    (
                        split_lamports,
                        split_lamports.saturating_sub(
                            validated_split_info
                                .destination_rent_exempt_reserve
                                .saturating_sub(destination_lamport_balance),
                        ),
                    )
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
            pinocchio::msg!("split:src=Init");
            source_meta
                .authorized
                .check(&arr_of_signers, StakeAuthorize::Staker)
                .map_err(to_program_error)?;

            // NOTE this function also internally summons Rent via syscall
            pinocchio::msg!("split:before_validate");
            let validated_split_info = validate_split_amount(
                source_lamport_balance,
                destination_lamport_balance,
                split_lamports,
                &source_meta,
                destination_data_len,
                0,     // additional_required_lamports
                false, // is_active
            )?;
            pinocchio::msg!("split:validated");

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
            pinocchio::msg!("split:src=Uninit");
            if !source_stake_account_info.is_signer() {
                return Err(ProgramError::MissingRequiredSignature);
            }
        }
        _ => { pinocchio::msg!("split:src=Other"); return Err(ProgramError::InvalidAccountData) },
    }

    // Deinitialize state upon zero balance
    if split_lamports == source_lamport_balance {
        set_stake_state(source_stake_account_info, &StakeStateV2::Uninitialized)?;
    }

    pinocchio::msg!("split:relocate");
    relocate_lamports(
        source_stake_account_info,
        destination_stake_account_info,
        split_lamports,
    )?;

    pinocchio::msg!("split:done");
    Ok(())
}
