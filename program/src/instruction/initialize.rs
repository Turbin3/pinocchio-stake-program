use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::rent::Rent,
    ProgramResult,
};

use crate::{helpers::*, state::state::Lockup};
use crate::state::*;

// compute-unit tracing helpers (feature-gated)
#[cfg(feature = "cu-trace")]
#[inline(always)]
fn cu(label: &str) {
    use pinocchio::log::sol_log_compute_units;
    pinocchio::msg!(label);
    unsafe { sol_log_compute_units(); }
}
#[cfg(not(feature = "cu-trace"))]
#[inline(always)]
fn cu(_label: &str) {}

pub fn initialize(
    accounts: &[AccountInfo], 
    authorized: Authorized, 
    lockup: Lockup
) -> ProgramResult {
    
    // Expected accounts: 2 (1 sysvar)
        let [stake_account_info, rent_info, _rest @ ..] = accounts else{
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    cu("initialize: before rent");
    let rent = &Rent::from_account_info(rent_info)?;
    cu("initialize: after rent");

    // `get_stake_state()` is called unconditionally, which checks owner
        cu("initialize: before do_initialize");
        do_initialize(stake_account_info, authorized, lockup, rent)?;
        cu("initialize: after do_initialize");

    Ok(())
}

pub fn do_initialize(
    stake_account_info: &AccountInfo,
    authorized: Authorized,
    lockup: Lockup,
    rent: &Rent,
) -> ProgramResult{
    cu("do_initialize: enter");
    if stake_account_info.data_len() != StakeStateV2::size_of() {
        return Err(ProgramError::InvalidAccountData);
    }

    if let StakeStateV2::Uninitialized = get_stake_state(stake_account_info)? {
        cu("do_initialize: after state check");
        let rent_exempt_reserve = rent.minimum_balance(stake_account_info.data_len());
        cu("do_initialize: after rent calc");
        if stake_account_info.lamports() >= rent_exempt_reserve {
            let stake_state = StakeStateV2::Initialized(Meta {
                rent_exempt_reserve: rent_exempt_reserve.to_le_bytes(),
                authorized,
                lockup,
            });

            cu("do_initialize: before write");
            let res = set_stake_state(stake_account_info, &stake_state);
            cu("do_initialize: after write");
            res
        } else {
            Err(ProgramError::InsufficientFunds)
        }
    } else {
        Err(ProgramError::InvalidAccountData)
    }
}
