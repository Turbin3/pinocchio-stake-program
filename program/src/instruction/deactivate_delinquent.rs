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
    if accounts.len() < 3 { return Err(ProgramError::NotEnoughAccountKeys); }

    // Prefer canonical wire order: [stake, delinquent_vote, reference_vote]
    let [stake_ai, delinquent_cand, reference_cand, ..] = accounts else {
        return Err(ProgramError::InvalidAccountData);
    };

    let vote_pid = vote_program_id();
    if *stake_ai.owner() != crate::ID || !stake_ai.is_writable() {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Current epoch (Pinocchio-safe)
    let clock = Clock::get()?;
    let n = MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION;

    // Helper: validate a candidate pair according to native vote semantics
    let validate_pair = |del_ai: &AccountInfo, ref_ai: &AccountInfo| -> Result<(bool, bool), ProgramError> {
        // reference_ok
        let ref_ok = {
            let data = ref_ai.try_borrow_data()?;
            data.len() >= 4
                && acceptable_reference_epoch_credits_bytes(&data, clock.epoch, n)?
        };
        // delinquent_ok
        let del_ok = {
            let data = del_ai.try_borrow_data()?;
            if data.len() < 4 { true } else { match last_vote_epoch_bytes(&data)? {
                None => true,
                Some(last) => match clock.epoch.checked_sub(n) {
                    Some(min_epoch) => last <= min_epoch,
                    None => false,
                }
            } }
        };
        Ok((ref_ok, del_ok))
    };

    // 1) Try canonical ordering first
    let mut reference_vote_ai = reference_cand;
    let mut delinquent_vote_ai = delinquent_cand;
    let (ref_ok, del_ok) = validate_pair(delinquent_vote_ai, reference_vote_ai)?;

    // 2) If canonical invalid or ambiguous (same account), scan to resolve
    if !(ref_ok && del_ok) || core::ptr::eq::<AccountInfo>(reference_vote_ai, delinquent_vote_ai) {
        let mut found_ref: Option<&AccountInfo> = None;
        let mut found_del: Option<&AccountInfo> = None;
        for ai in accounts.iter() {
            if core::ptr::eq::<AccountInfo>(ai, stake_ai) { continue; }
            if let Ok(bytes) = ai.try_borrow_data() {
                if bytes.len() >= 4 && found_ref.is_none() {
                    if acceptable_reference_epoch_credits_bytes(&bytes, clock.epoch, n).unwrap_or(false) {
                        found_ref = Some(ai);
                    }
                }
                if found_del.is_none() {
                    if bytes.len() < 4 {
                        found_del = Some(ai);
                    } else if let Ok(Some(last)) = last_vote_epoch_bytes(&bytes) {
                        if let Some(min_epoch) = clock.epoch.checked_sub(n) {
                            if last <= min_epoch { found_del = Some(ai); }
                        }
                    } else if let Ok(None) = last_vote_epoch_bytes(&bytes) {
                        found_del = Some(ai);
                    }
                }
                if let (Some(rf), Some(dl)) = (found_ref, found_del) {
                    if !core::ptr::eq::<AccountInfo>(rf, dl) { break; }
                    // same account cannot be both; keep ref, continue searching del
                    found_del = None;
                }
            }
        }
        reference_vote_ai = found_ref.unwrap_or(reference_cand);
        delinquent_vote_ai = found_del.unwrap_or(delinquent_cand);
    }

    // Enforce vote program ownership for both vote accounts
    if *reference_vote_ai.owner() != vote_pid || *delinquent_vote_ai.owner() != vote_pid {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Authoritative validation and branching by native error codes
    let (ref_ok2, del_ok2) = validate_pair(delinquent_vote_ai, reference_vote_ai)?;
    if !ref_ok2 {
        return Err(to_program_error(StakeError::InsufficientReferenceVotes));
    }
    if !del_ok2 {
        return Err(to_program_error(StakeError::MinimumDelinquentEpochsForDeactivationNotMet));
    }

    // Load stake and deactivate if matching delegation
    match get_stake_state(stake_ai)? {
        StakeStateV2::Stake(meta, mut stake, flags) => {
            if stake.delegation.voter_pubkey != *delinquent_vote_ai.key() {
                return Err(to_program_error(StakeError::VoteAddressMismatch));
            }
            // Set deactivation_epoch = current epoch (Epoch is [u8;8])
            stake.deactivate(clock.epoch.to_le_bytes()).map_err(to_program_error)?;
            set_stake_state(stake_ai, &StakeStateV2::Stake(meta, stake, flags))
        }
        _ => Err(ProgramError::InvalidAccountData),
    }
}


fn has_consecutive_epochs_bytes(data: &[u8], end_epoch: u64, n: u64) -> Result<bool, ProgramError> {
    // Layout: [u32 count] followed by count triplets of (epoch, credits, prev_credits)
    if data.len() < 4 { return Err(ProgramError::InvalidAccountData); }
    let mut n_bytes = [0u8; 4];
    n_bytes.copy_from_slice(&data[0..4]);
    let count = u32::from_le_bytes(n_bytes) as usize;
    if count < n as usize { return Ok(false); }

    for i in 0..(n as usize) {
        let idx_from_end = count - 1 - i; // walk newest backward
        let off = 4 + idx_from_end * 24;
        if off + 24 > data.len() { return Err(ProgramError::InvalidAccountData); }
        let mut e = [0u8; 8];
        let mut c = [0u8; 8];
        let mut p = [0u8; 8];
        e.copy_from_slice(&data[off..off + 8]);
        c.copy_from_slice(&data[off + 8..off + 16]);
        p.copy_from_slice(&data[off + 16..off + 24]);
        let epoch = u64::from_le_bytes(e);
        let credits = u64::from_le_bytes(c);
        let prev = u64::from_le_bytes(p);
        // Expect a consecutive run ending at `end_epoch` and a positive vote (credits > prev)
        let expected = end_epoch.saturating_sub(i as u64);
        if epoch != expected || credits <= prev {
            #[cfg(feature = "cu-trace")]
            { pinocchio::msg!("dd:ref_mismatch"); }
            return Ok(false);
        }
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
    // Walk newest to oldest; return newest epoch with a positive vote (credits > prev)
    for i in (0..count).rev() {
        let off = 4 + i * 24;
        if off + 24 > data.len() { return Err(ProgramError::InvalidAccountData); }
        let mut e = [0u8; 8];
        let mut c = [0u8; 8];
        let mut p = [0u8; 8];
        e.copy_from_slice(&data[off..off + 8]);
        c.copy_from_slice(&data[off + 8..off + 16]);
        p.copy_from_slice(&data[off + 16..off + 24]);
        if u64::from_le_bytes(c) > u64::from_le_bytes(p) {
            return Ok(Some(u64::from_le_bytes(e)));
        }
    }
    Ok(None)
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
