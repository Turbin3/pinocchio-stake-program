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
    // --- Canonical order: [stake, delinquent_vote, reference_vote] ---
    if accounts.len() < 3 { return Err(ProgramError::NotEnoughAccountKeys); }
    let [stake_ai, delinquent_vote_ai, reference_vote_ai, ..] = accounts else {
        return Err(ProgramError::InvalidAccountData);
    };
    let vote_pid = vote_program_id();
    if *stake_ai.owner() != crate::ID || !stake_ai.is_writable() {
        return Err(ProgramError::InvalidAccountOwner);
    }
    #[cfg(feature = "strict-authz")]
    {
        if *reference_vote_ai.owner() != vote_pid || *delinquent_vote_ai.owner() != vote_pid {
            return Err(ProgramError::IncorrectProgramId);
        }
    }

    // Probe owners and data lens
    // Owner/data probes removed

    // --- Clock (use current epoch) ---
    let clock = Clock::get()?;
    //

    // --- Owner checks done above ---

    // --- Robust meta resolution: scan accounts for vote-like data to find reference and delinquent ---
    let n = MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION;
    let mut ref_ai: Option<&AccountInfo> = None;
    let mut del_ai: Option<&AccountInfo> = None;
    for ai in accounts.iter() {
        // Skip stake account itself
        if core::ptr::eq::<AccountInfo>(ai, stake_ai) { continue; }
        if let Ok(data) = ai.try_borrow_data() {
            if data.len() < 4 { continue; }
            // reference candidate: N consecutive epochs ending at current or current-1
            if ref_ai.is_none() {
                if acceptable_reference_epoch_credits_bytes(&data, clock.epoch, n).unwrap_or(false) {
                    ref_ai = Some(ai);
                }
            }
            // delinquent candidate: last vote epoch <= current - N (or never voted)
            if del_ai.is_none() {
                match last_vote_epoch_bytes(&data) {
                    Ok(None) => { del_ai = Some(ai); }
                    Ok(Some(last_epoch)) => {
                        if let Some(min_epoch) = clock.epoch.checked_sub(n) {
                            if last_epoch <= min_epoch { del_ai = Some(ai); }
                        }
                    }
                    Err(_) => {}
                }
            }
            if ref_ai.is_some() && del_ai.is_some() {
                // ensure distinct
                if core::ptr::eq::<AccountInfo>(ref_ai.unwrap(), del_ai.unwrap()) {
                    // If same, prefer keeping ref, continue to find a different del
                    del_ai = None;
                } else {
                    break;
                }
            }
        }
    }

    // If robust scan found both, override the passed metas; else, use the provided positions
    let (reference_vote_ai, delinquent_vote_ai) = match (ref_ai, del_ai) {
        (Some(r), Some(d)) => (r, d),
        _ => (reference_vote_ai, delinquent_vote_ai),
    };

    // --- 1) Reference must have a vote in EACH of the last N epochs (strict consecutive) ---
    {
        let data = reference_vote_ai.try_borrow_data()?;
        // If the reference vote account has no credits history, treat as insufficient reference votes
        if data.len() < 4 {
            return Err(to_program_error(StakeError::InsufficientReferenceVotes));
        }
        let ok = acceptable_reference_epoch_credits_bytes(
            &data,
            clock.epoch,
            MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION,
        )?;
        if !ok {
            return Err(to_program_error(StakeError::InsufficientReferenceVotes));
        }
    }
    //

    // --- 2) Delinquent last vote epoch <= current_epoch - N  ---
    let delinquent_is_eligible = {
        let data = delinquent_vote_ai.try_borrow_data()?;
        // If there is no history at all, treat as never voted => eligible
        if data.len() < 4 { true } else { match last_vote_epoch_bytes(&data)? {
            None => true, // never voted => eligible
            Some(last_epoch) => match clock.epoch.checked_sub(MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION) {
                Some(min_epoch) => last_epoch <= min_epoch,
                None => false,
            }
        } }
    };
    //

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


fn has_consecutive_epochs_bytes(data: &[u8], start_epoch: u64, n: u64) -> Result<bool, ProgramError> {
    // Layout: [u32 count] followed by count triplets of (epoch, credits, prev_credits)
    if data.len() < 4 { return Err(ProgramError::InvalidAccountData); }
    let mut n_bytes = [0u8; 4];
    n_bytes.copy_from_slice(&data[0..4]);
    let count = u32::from_le_bytes(n_bytes) as usize;
    if count < n as usize { return Ok(false); }

    for i in 0..(n as usize) {
        let idx_from_end = count - 1 - i; // walk newest backward
        let off = 4 + idx_from_end * 24;
        if off + 8 > data.len() { return Err(ProgramError::InvalidAccountData); }
        let mut e = [0u8; 8];
        e.copy_from_slice(&data[off..off + 8]);
        let epoch = u64::from_le_bytes(e);
        let expected = start_epoch.saturating_sub(i as u64);
        if epoch != expected { return Ok(false); }
    }
    Ok(true)
}

fn acceptable_reference_epoch_credits_bytes(
    data: &[u8],
    current_epoch: u64,
    n: u64,
) -> Result<bool, ProgramError> {
    // Accept either N consecutive entries ending at current or at current-1
    let now = has_consecutive_epochs_bytes(data, current_epoch, n)?;
    if now { return Ok(true); }
    let prev = has_consecutive_epochs_bytes(data, current_epoch.saturating_sub(1), n)?;
    Ok(prev)
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
fn reference_window_previous_epoch_ok() {
    // current = 100, allow window 99..=95 when N=5 (no entry yet at 100)
    let current = 100;
    let bytes = build_epoch_credits_bytes(&[
        (95, 1, 0),
        (96, 2, 1),
        (97, 3, 2),
        (98, 4, 3),
        (99, 5, 4),
    ]);
    assert!(acceptable_reference_epoch_credits_bytes(&bytes, current, 5).unwrap());
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
