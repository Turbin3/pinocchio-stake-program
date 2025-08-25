use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    sysvars::rent::Rent,
    ProgramResult,
};

use crate::{helpers::*, state::state::Lockup};
use crate::state::*;

pub fn initialize(
    accounts: &[AccountInfo], 
    authorized: Authorized, 
    lockup: Lockup
) -> ProgramResult {
    
    // native asserts: 2 accounts (1 sysvar)}
        let [stake_account_info, rent_info, _rest @ ..] = accounts else{
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    let rent = &Rent::from_account_info(rent_info)?;

    // `get_stake_state()` is called unconditionally, which checks owner
        do_initialize(stake_account_info, authorized, lockup, rent)?;

    Ok(())
}

pub fn do_initialize(
    stake_account_info: &AccountInfo,
    authorized: Authorized,
    lockup: Lockup,
    rent: &Rent,
) -> ProgramResult{
    if stake_account_info.data_len() != StakeStateV2::size_of() {
        return Err(ProgramError::InvalidAccountData);
    }

    if let StakeStateV2::Uninitialized = get_stake_state(stake_account_info)? {
        let rent_exempt_reserve = rent.minimum_balance(stake_account_info.data_len());
        if stake_account_info.lamports() >= rent_exempt_reserve {
            let stake_state = StakeStateV2::Initialized(Meta {
                rent_exempt_reserve: rent_exempt_reserve.to_le_bytes(),
                authorized,
                lockup,
            });

            set_stake_state(stake_account_info, &stake_state)
        } else {
            Err(ProgramError::InsufficientFunds)
        }
    } else {
        Err(ProgramError::InvalidAccountData)
    }
}
