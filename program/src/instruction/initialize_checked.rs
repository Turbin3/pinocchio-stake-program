#![allow(clippy::result_large_err)]

  
  use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::rent::Rent,
    ProgramResult,
};

use crate::{ state::state::Lockup};
use crate::instruction::initialize::do_initialize;
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

pub fn process_initialize_checked(accounts: &[AccountInfo]) -> ProgramResult {
        cu("init_checked: enter");

        // native asserts: 4 accounts (1 sysvar)

    let [stake_account_info, rent_info,stake_authority_info,withdraw_authority_info, _rest @ ..] = accounts else{
        return Err(ProgramError::NotEnoughAccountKeys);
    };


        cu("init_checked: before rent");
        let rent = &Rent::from_account_info(rent_info)?;
        cu("init_checked: after rent");

        if !withdraw_authority_info.is_signer(){
            return Err(ProgramError::MissingRequiredSignature);
        }
        cu("init_checked: signer ok");

        let authorized = Authorized {
            staker: *stake_authority_info.key(),
            withdrawer: *withdraw_authority_info.key(),
        };

        // `get_stake_state()` is called unconditionally, which checks owner
        cu("init_checked: before do_initialize");
        do_initialize(stake_account_info, authorized, Lockup::default(), rent)?;
        cu("init_checked: after do_initialize");

        Ok(())
    }
    
