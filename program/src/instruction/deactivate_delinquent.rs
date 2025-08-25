#![allow(clippy::result_large_err)]
extern crate alloc;
use pinocchio::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
};

use crate::{
    error::{to_program_error, StakeError},
    id,
    state::stake_state_v2::StakeStateV2,
};

pub fn process_deactivate_delinquent(accounts: &[AccountInfo]) -> Result<(), ProgramError> {
    msg!("Instruction: DeactivateDelinquent");

    let mut iter = accounts.iter();
    let stake_ai           = iter.next().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let delinquent_vote_ai = iter.next().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let reference_vote_ai  = iter.next().ok_or(ProgramError::NotEnoughAccountKeys)?;

    let clock = Clock::get()?;

    // 1) Reference validator must have at least one vote within the last 1 epoch
    {
        let data = reference_vote_ai.try_borrow_data()?;
        let has_recent = has_vote_within_epochs(&data, clock.epoch, 1)?;
        if !has_recent {
            return Err(to_program_error(StakeError::InsufficientReferenceVotes));
        }
    } 

    // 2) Delinquent validator: NO votes within the last 4 epochs
    let delinquent_is_eligible = {
        let data = delinquent_vote_ai.try_borrow_data()?;
        let has_recent = has_vote_within_epochs(&data, clock.epoch, 4)?;
        !has_recent
    }; 

    match stake_state(stake_ai)? {
        StakeStateV2::Stake(meta, mut stake, flags) => {
            // Must be the same vote account this stake is delegated to
            if stake.delegation.voter_pubkey != *delinquent_vote_ai.key() {
                return Err(to_program_error(StakeError::VoteAddressMismatch));
            }

            if delinquent_is_eligible {
                stake.delegation.deactivation_epoch = clock.epoch.to_le_bytes();
                overwrite_stake_state(stake_ai, &StakeStateV2::Stake(meta, stake, flags))
            } else {
                Err(to_program_error(
                    StakeError::MinimumDelinquentEpochsForDeactivationNotMet,
                ))
            }
        }
        _ => Err(ProgramError::InvalidAccountData),
    }
}


fn stake_state(ai: &AccountInfo) -> Result<StakeStateV2, ProgramError> {
    if ai.owner() != &id() {
        return Err(ProgramError::InvalidAccountOwner);
    }
    let data = ai.try_borrow_data()?;
    StakeStateV2::deserialize(&data)
}

fn overwrite_stake_state(ai: &AccountInfo, s: &StakeStateV2) -> Result<(), ProgramError> {
    if ai.owner() != &id() || !ai.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut data = ai.try_borrow_mut_data()?;
    s.serialize(&mut data)
}


fn has_vote_within_epochs(data: &[u8], current_epoch: u64, window: u64) -> Result<bool, ProgramError> {
    
    if data.len() < 4 {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut n_bytes = [0u8; 4];
    n_bytes.copy_from_slice(&data[0..4]);
    let n = u32::from_le_bytes(n_bytes) as usize;

    let mut off = 4usize;
    for _ in 0..n {
        // Need 24 bytes per triple
        if off + 24 > data.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        // read epoch (first 8 bytes)
        let mut e = [0u8; 8];
        e.copy_from_slice(&data[off..off + 8]);
        let epoch = u64::from_le_bytes(e);

        // skip credits + prev_credits (we don't need them here)
        off += 24;

        if current_epoch.saturating_sub(epoch) <= window {
            return Ok(true);
        }
    }
    Ok(false)
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
    fn reference_recent_votes_are_acceptable() {
        let current = 100;
        let bytes = build_epoch_credits_bytes(&[(100, 10, 0)]); // voted in current epoch
        assert!(has_vote_within_epochs(&bytes, current, 1).unwrap());
    }

    #[test]
    fn reference_old_votes_are_not_acceptable() {
        let current = 100;
        let bytes = build_epoch_credits_bytes(&[(98, 10, 0)]); // >1 epoch old
        assert!(!has_vote_within_epochs(&bytes, current, 1).unwrap());
    }

    #[test]
    fn delinquent_if_no_votes_within_last_4_epochs() {
        let current = 100;
        let bytes = build_epoch_credits_bytes(&[(94, 5, 0)]); // 6 epochs ago
        assert!(!has_vote_within_epochs(&bytes, current, 4).unwrap()); // "no recent" => eligible
    }

    #[test]
    fn not_delinquent_if_any_vote_within_last_4_epochs() {
        let current = 100;
        let bytes = build_epoch_credits_bytes(&[(97, 5, 0)]); // 3 epochs ago
        assert!(has_vote_within_epochs(&bytes, current, 4).unwrap()); // "has recent" => not eligible
    }
}
