use crate::helpers::constant::*;
use crate::state::stake_history::StakeHistorySysvar;
use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::{to_program_error, StakeError};
use crate::state::stake_state_v2::StakeStateV2;
use crate::state::vote_state::VoteState;
use crate::state::{
    delegation::{Delegation, Stake},
    Meta,
};
use crate::ID;

const FEATURE_STAKE_RAISE_MINIMUM_DELEGATION_TO_1_SOL: bool = false;
const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

// helper for stake amount validation
pub struct ValidatedDelegatedInfo {
    pub stake_amount: u64,
}

// wrapper for epoch to pass around
// pub struct StakeHistorySysvar(pub u64);

pub enum ErrorCode {
    TOOMANYSIGNERS = 0x1,
}

// almost all native stake program processors accumulate every account signer
// they then defer all signer validation to functions on Meta or Authorized
// this results in an instruction interface that is much looser than the one documented
// to avoid breaking backwards compatibility, we do the same here
// in the future, we may decide to tighten the interface and break badly formed transactions
pub fn collect_signers(
    accounts: &[AccountInfo],
    array_of_signers: &mut [Pubkey; MAXIMUM_SIGNERS],
) -> Result<usize, ProgramError> {
    let mut len_of_signers = 0;

    for account in accounts {
        if account.is_signer() {
            if len_of_signers < MAXIMUM_SIGNERS {
                array_of_signers[len_of_signers] = *account.key();
                len_of_signers += 1;
            } else {
                return Err(ProgramError::Custom(ErrorCode::TOOMANYSIGNERS as u32));
            }
        }
    }

    Ok(len_of_signers)
}

pub fn next_account_info<'a, I: Iterator<Item = &'a AccountInfo>>(
    iter: &mut I,
) -> Result<&'a AccountInfo, ProgramError> {
    iter.next().ok_or(ProgramError::NotEnoughAccountKeys)
}

/// The minimum stake amount that can be delegated, in lamports.
/// NOTE: This is also used to calculate the minimum balance of a delegated
/// stake account, which is the rent exempt reserve _plus_ the minimum stake
/// delegation.
#[inline(always)]
pub fn get_minimum_delegation() -> u64 {
    if FEATURE_STAKE_RAISE_MINIMUM_DELEGATION_TO_1_SOL {
        const MINIMUM_DELEGATION_SOL: u64 = 1;
        MINIMUM_DELEGATION_SOL * LAMPORTS_PER_SOL
    } else {
        1
    }
}
pub fn warmup_cooldown_rate(
    current_epoch: [u8; 8],
    new_rate_activation_epoch: Option<[u8; 8]>,
) -> f64 {
    if current_epoch < new_rate_activation_epoch.unwrap_or(u64::MAX.to_le_bytes()) {
        DEFAULT_WARMUP_COOLDOWN_RATE
    } else {
        NEW_WARMUP_COOLDOWN_RATE
    }
}

pub type Epoch = [u8; 8];

pub fn bytes_to_u64(bytes: [u8; 8]) -> u64 {
    u64::from_le_bytes(bytes)
}

/// After calling `validate_split_amount()`, this struct contains calculated
/// values that are used by the caller.
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct ValidatedSplitInfo {
    pub source_remaining_balance: u64,
    pub destination_rent_exempt_reserve: u64,
}

/// Ensure the split amount is valid.  This checks the source and destination
/// accounts meet the minimum balance requirements, which is the rent exempt
/// reserve plus the minimum stake delegation, and that the source account has
/// enough lamports for the request split amount.  If not, return an error.
pub(crate) fn validate_split_amount(
    source_lamports: u64,
    destination_lamports: u64,
    split_lamports: u64,
    source_meta: &Meta,
    destination_data_len: usize,
    additional_required_lamports: u64,
    source_is_active: bool,
) -> Result<ValidatedSplitInfo, ProgramError> {
    // Split amount has to be something
    if split_lamports == 0 {
        return Err(ProgramError::InsufficientFunds);
    }

    // Obviously cannot split more than what the source account has
    if split_lamports > source_lamports {
        return Err(ProgramError::InsufficientFunds);
    }

    // Verify that the source account still has enough lamports left after
    // splitting: EITHER at least the minimum balance, OR zero (in this case the
    // source account is transferring all lamports to new destination account,
    // and the source account will be closed)
    let source_minimum_balance =
        bytes_to_u64(source_meta.rent_exempt_reserve).saturating_add(additional_required_lamports);
    let source_remaining_balance = source_lamports.saturating_sub(split_lamports);
    if source_remaining_balance == 0 {
        // full amount is a withdrawal
        // nothing to do here
    } else if source_remaining_balance < source_minimum_balance {
        // the remaining balance is too low to do the split
        return Err(ProgramError::InsufficientFunds);
    } else {
        // all clear!
        // nothing to do here
    }

    let rent = Rent::get()?;
    let destination_rent_exempt_reserve = rent.minimum_balance(destination_data_len);

    // If the source is active stake, one of these criteria must be met:
    // 1. the destination account must be prefunded with at least the rent-exempt
    //    reserve, or
    // 2. the split must consume 100% of the source
    if source_is_active
        && source_remaining_balance != 0
        && destination_lamports < destination_rent_exempt_reserve
    {
        return Err(ProgramError::InsufficientFunds);
    }

    // Verify the destination account meets the minimum balance requirements
    // This must handle:
    // 1. The destination account having a different rent exempt reserve due to data
    //    size changes
    // 2. The destination account being prefunded, which would lower the minimum
    //    split amount
    let destination_minimum_balance =
        destination_rent_exempt_reserve.saturating_add(additional_required_lamports);
    let destination_balance_deficit =
        destination_minimum_balance.saturating_sub(destination_lamports);
    if split_lamports < destination_balance_deficit {
        return Err(ProgramError::InsufficientFunds);
    }

    Ok(ValidatedSplitInfo {
        source_remaining_balance,
        destination_rent_exempt_reserve,
    })
}

// fn get_stake_state(stake_account_info: &AccountInfo) -> Result<StakeStateV2, ProgramError> {
//     if *stake_account_info.owner() != ID {
//         return Err(ProgramError::InvalidAccountOwner);
//     }
// }

// returns a deserialized vote state from raw account data
pub fn get_vote_state(vote_account_info: &AccountInfo) -> Result<VoteState, ProgramError> {
    // enforce account is large enough
    let data = unsafe { vote_account_info.borrow_data_unchecked() };
    if data.len() < core::mem::size_of::<VoteState>() {
        return Err(ProgramError::InvalidAccountData);
    }

    let vote_state = unsafe { &*(data.as_ptr() as *const VoteState) };
    Ok(vote_state.clone())
}

// load stake state from account
pub fn get_stake_state(stake_account_info: &AccountInfo) -> Result<StakeStateV2, ProgramError> {
    if *stake_account_info.owner() != ID {
        return Err(ProgramError::InvalidAccountOwner);
    }

    let data = unsafe { stake_account_info.borrow_data_unchecked() };
    StakeStateV2::deserialize(&data)
}

// write stake state back into account
pub fn set_stake_state(
    stake_account_info: &AccountInfo,
    stake_state: &StakeStateV2,
) -> Result<(), ProgramError> {
    let mut data = unsafe { stake_account_info.borrow_mut_data_unchecked() };
    stake_state.serialize(&mut data)?;
    Ok(())
}

// compute stake amount = lamports - rent exempt reserve
pub fn validate_delegated_amount(
    stake_account_info: &AccountInfo,
    meta: &Meta,
) -> Result<ValidatedDelegatedInfo, ProgramError> {
    let rent_exempt_reserve = u64::from_le_bytes(meta.rent_exempt_reserve);
    let stake_amount = stake_account_info
        .lamports()
        .checked_sub(bytes_to_u64(meta.rent_exempt_reserve))
        .ok_or(StakeError::InsufficientFunds)
        .map_err(to_program_error)?;

    Ok(ValidatedDelegatedInfo { stake_amount })
}

// create new stake object from inputs
pub fn new_stake(
    stake_amount: u64,
    vote_pubkey: &Pubkey,
    vote_state: &VoteState,
    activation_epoch: u64,
) -> Stake {
    let mut stake = Stake::default();
    stake.delegation = Delegation::new(vote_pubkey, stake_amount, activation_epoch.to_le_bytes());
    stake.set_credits_observed(vote_state.credits());
    stake
}

// modify existing stake object with updated delegation
pub fn redelegate_stake(
    stake: &mut Stake,
    stake_amount: u64,
    vote_pubkey: &Pubkey,
    vote_state: &VoteState,
    clock_epoch: u64,
    _stake_history: &StakeHistorySysvar,
) -> Result<(), ProgramError> {
    stake.delegation.voter_pubkey = *vote_pubkey;
    stake.delegation.set_stake_amount(stake_amount);
    stake.delegation.activation_epoch = clock_epoch.to_le_bytes();
    stake.set_credits_observed(vote_state.credits());
    Ok(())
}

// dont call this "move" because we have an instruction MoveLamports
pub fn relocate_lamports(
    source_account_info: &AccountInfo,
    destination_account_info: &AccountInfo,
    lamports: u64,
) -> ProgramResult {
    {
        let mut source_lamports = source_account_info.try_borrow_mut_lamports()?;
        *source_lamports = source_lamports
            .checked_sub(lamports)
            .ok_or(ProgramError::InsufficientFunds)?;
    }

    {
        let mut destination_lamports = destination_account_info.try_borrow_mut_lamports()?;
        *destination_lamports = destination_lamports
            .checked_add(lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    Ok(())
}

const SUCCESS: u64 = 0;

pub fn get_sysvar(
    dst: &mut [u8],
    sysvar_id: &Pubkey,
    offset: u64,
    length: u64,
) -> Result<(), ProgramError> {
    // Check that the provided destination buffer is large enough to hold the
    // requested data.
    if dst.len() < length as usize {
        return Err(ProgramError::InvalidArgument);
    }

    let sysvar_id = sysvar_id as *const _ as *const u8;
    let var_addr = dst as *mut _ as *mut u8;

    #[cfg(feature = "solana")]
    let result =
        unsafe { pinocchio::syscalls::sol_get_sysvar(sysvar_id, var_addr, offset, length) };

    #[cfg(not(feature = "solana"))]
    let result =
        unsafe { pinocchio::syscalls::sol_get_sysvar(sysvar_id, var_addr, offset, length) };

    match result {
        SUCCESS => Ok(()),
        e => Err(e.into()),
    }
}

pub(crate) fn checked_add(a: u64, b: u64) -> Result<u64, ProgramError> {
    a.checked_add(b).ok_or(ProgramError::InsufficientFunds)
}
