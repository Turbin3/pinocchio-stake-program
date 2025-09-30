#![allow(clippy::result_large_err)]
extern crate alloc;

use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::{
    error::{to_program_error, StakeError},
    helpers::{get_stake_state, set_stake_state},
    state::{
        stake_state_v2::StakeStateV2,
        vote_state::vote_program_id,
    },
};
use crate::helpers::constant::MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION;

pub fn process_deactivate_delinquent(accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Instruction: DeactivateDelinquent");

    // --- Discover accounts by role ---
    let vote_pid = vote_program_id();
    let mut stake_ai: Option<&AccountInfo> = None;
    let mut delinquent_vote_ai: Option<&AccountInfo> = None;
    let mut reference_vote_ai: Option<&AccountInfo> = None;
    for ai in accounts.iter() {
        if stake_ai.is_none() && *ai.owner() == crate::ID && ai.is_writable() {
            stake_ai = Some(ai);
            continue;
        }
        if vote_pid != Pubkey::default() && *ai.owner() == vote_pid {
            if delinquent_vote_ai.is_none() { delinquent_vote_ai = Some(ai); continue; }
            if reference_vote_ai.is_none() { reference_vote_ai = Some(ai); continue; }
        }
    }
    let stake_ai = stake_ai.ok_or(ProgramError::NotEnoughAccountKeys)?;
    let delinquent_vote_ai = delinquent_vote_ai.ok_or(ProgramError::NotEnoughAccountKeys)?;
    let reference_vote_ai = reference_vote_ai.ok_or(ProgramError::NotEnoughAccountKeys)?;

    // --- Clock (use current epoch) ---
    let clock = Clock::get()?;

    // --- Optional owner check for vote accounts ---
    if vote_pid != Pubkey::default() {
        if *reference_vote_ai.owner() != vote_pid || *delinquent_vote_ai.owner() != vote_pid {
            return Err(ProgramError::IncorrectProgramId);
        }
    }

    // --- 1) Reference must have a vote in EACH of the last N epochs (strict consecutive) ---
    {
        let data = reference_vote_ai.try_borrow_data()?;
        let ok = acceptable_reference_epoch_credits_bytes(
            &data,
            clock.epoch,
            MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION,
        )?;
        if !ok {
            return Err(to_program_error(StakeError::InsufficientReferenceVotes));
        }
    }

    // --- 2) Delinquent last vote epoch <= current_epoch - N  ---
    let delinquent_is_eligible = {
        let data = delinquent_vote_ai.try_borrow_data()?;
        match last_vote_epoch_bytes(&data)? {
            None => true, // never voted => eligible
            Some(last_epoch) => match clock.epoch.checked_sub(MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION) {
                Some(min_epoch) => last_epoch <= min_epoch,
                None => false,
            }
        }
    };

    // --- 3) Load stake state, verify delegation target, deactivate if eligible ---
    match get_stake_state(stake_ai)? {
        StakeStateV2::Stake(meta, mut stake, flags) => {
            if stake.delegation.voter_pubkey != *delinquent_vote_ai.key() {
                return Err(to_program_error(StakeError::VoteAddressMismatch));
            }

            if delinquent_is_eligible {
                // Set deactivation_epoch = current epoch
                stake.deactivate(clock.epoch.to_le_bytes())
                    .map_err(to_program_error)?;
                set_stake_state(stake_ai, &StakeStateV2::Stake(meta, stake, flags))
            } else {
                Err(to_program_error(
                    StakeError::MinimumDelinquentEpochsForDeactivationNotMet,
                ))
            }
        }
        _ => Err(ProgramError::InvalidAccountData),
    }
}


fn acceptable_reference_epoch_credits_bytes(
    data: &[u8],
    current_epoch: u64,
    n: u64,
) -> Result<bool, ProgramError> {
    // Layout assumed by tests:
    // [0..4] u32 count, then `count` * (epoch:u64, credits:u64, prev:u64)
    if data.len() < 4 {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut n_bytes = [0u8; 4];
    n_bytes.copy_from_slice(&data[0..4]);
    let count = u32::from_le_bytes(n_bytes) as usize;

    if count < n as usize {
        return Ok(false);
    }

    // Start at the first of the last N entries and walk them in reverse
    // to compare: last => current_epoch, previous => current_epoch - 1, ...
    for i in 0..(n as usize) {
        // index of the (count - 1 - i)-th entry
        let entry_index = count - 1 - i;
        let off = 4 + entry_index * 24;
        if off + 8 > data.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut e = [0u8; 8];
        e.copy_from_slice(&data[off..off + 8]);
        let vote_epoch = u64::from_le_bytes(e);

        let expected = current_epoch.saturating_sub(i as u64);
        if vote_epoch != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn last_vote_epoch_bytes(data: &[u8]) -> Result<Option<u64>, ProgramError> {
    if data.len() < 4 {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut n_bytes = [0u8; 4];
    n_bytes.copy_from_slice(&data[0..4]);
    let count = u32::from_le_bytes(n_bytes) as usize;
    if count == 0 {
        return Ok(None);
    }
    let off = 4 + (count - 1) * 24;
    if off + 8 > data.len() {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut e = [0u8; 8];
    e.copy_from_slice(&data[off..off + 8]);
    Ok(Some(u64::from_le_bytes(e)))
}
#[cfg(test)]
mod tests {
    use super::*;

    fn build_epoch_credits_bytes(list: &[(u64, u64, u64)]) -> alloc::vec::Vec<u8> {
        use alloc::vec::Vec;
        let mut out = Vec::with_capacity(4 + list.len() * 24);
        out.extend_from_slice(&(list.len() as u32).to_le_bytes());
        for &(e, c, p) in list {
            out.extend_from_slice(&e.to_le_bytes());
            out.extend_from_slice(&c.to_le_bytes());
            out.extend_from_slice(&p.to_le_bytes());
        }
        out
    }

   #[test]
fn reference_has_all_last_n_epochs() {
    // current = 100, need epochs 100..=96 present
    let current = 100;
    let bytes = build_epoch_credits_bytes(&[
        (96, 1, 0),
        (97, 2, 1),
        (98, 3, 2),
        (99, 4, 3),
        (100, 5, 4),
    ]);
    assert!(acceptable_reference_epoch_credits_bytes(&bytes, current, 5).unwrap());
}

#[test]
fn reference_missing_one_epoch_fails() {
    // Missing 98 in the last 5 => should fail
    let current = 100;
    let bytes = build_epoch_credits_bytes(&[
        (96, 1, 0),
        (97, 2, 1),
        //(98 missing)
        (99, 4, 3),
        (100, 5, 4),
    ]);
    assert!(!acceptable_reference_epoch_credits_bytes(&bytes, current, 5).unwrap());
}

#[test]
fn delinquent_if_last_vote_older_than_n() {
    // current=100, N=5 => min_epoch = 95
    // last=94 => 94 <= 95 => eligible (delinquent)
    let current = 100;
    let bytes = build_epoch_credits_bytes(&[(94, 5, 0)]);
    let last = last_vote_epoch_bytes(&bytes).unwrap();
    assert_eq!(last, Some(94));
    let min_epoch = current - 5;
    assert!(last.unwrap() <= min_epoch);
}

#[test]
fn not_delinquent_if_last_vote_within_n() {
    // current=100, N=5 => min_epoch=95
    // last=97 => 97 > 95 => NOT delinquent
    let current = 100;
    let bytes = build_epoch_credits_bytes(&[(97, 5, 0)]);
    let last = last_vote_epoch_bytes(&bytes).unwrap();
    assert_eq!(last, Some(97));
    let min_epoch = current - 5;
    assert!(!(last.unwrap() <= min_epoch));
}
}
