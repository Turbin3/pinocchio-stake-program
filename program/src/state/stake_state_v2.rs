use crate::state::delegation::Stake;
use crate::state::stake_flag::StakeFlags;
use crate::state::state::Meta;

use crate::ID;
use pinocchio::{account_info::{AccountInfo, RefMut as AiRefMut}, program_error::ProgramError};

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]

pub enum StakeStateV2 {
    Uninitialized,
    Initialized(Meta),
    Stake(Meta, Stake, StakeFlags),
    RewardsPool,
}

impl StakeStateV2 {
    // Native-compatible on-account size
    pub const ACCOUNT_SIZE: usize = 200;

    /// The fixed number of bytes used to serialize each stake account
    pub const fn size_of() -> usize { Self::ACCOUNT_SIZE }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProgramError> {
        if data.is_empty() {
            return Err(ProgramError::InvalidAccountData);
        }

        let discriminant = data[0];

        match discriminant {
            0 => Ok(StakeStateV2::Uninitialized),
            1 => {
                let meta = Self::deserialize_meta(&data[1..])?;
                Ok(StakeStateV2::Initialized(meta))
            }
            2 => {
                let meta = Self::deserialize_meta(&data[1..])?;
                let stake = Self::deserialize_stake(&data[1 + core::mem::size_of::<Meta>()..])?;

                let flags_offset = 1 + core::mem::size_of::<Meta>() + core::mem::size_of::<Stake>();
                let stake_flags = if data.len() > flags_offset && data[flags_offset] != 0 {
                    StakeFlags {
                        bits: data[flags_offset],
                    }
                } else {
                    StakeFlags::empty()
                };

                Ok(StakeStateV2::Stake(meta, stake, stake_flags))
            }
            3 => Ok(StakeStateV2::RewardsPool),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }

    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < Self::ACCOUNT_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data.iter_mut().for_each(|byte| *byte = 0);

        match self {
            StakeStateV2::Uninitialized => {
                data[0] = 0;
            }
            StakeStateV2::Initialized(meta) => {
                data[0] = 1;
                Self::serialize_meta(meta, &mut data[1..])?;
            }
            StakeStateV2::Stake(meta, stake, stake_flags) => {
                data[0] = 2;
                Self::serialize_meta(meta, &mut data[1..])?;
                Self::serialize_stake(stake, &mut data[1 + core::mem::size_of::<Meta>()..])?;

                let flags_offset = 1 + core::mem::size_of::<Meta>() + core::mem::size_of::<Stake>();
                data[flags_offset] = stake_flags.bits;
            }
            StakeStateV2::RewardsPool => {
                data[0] = 3;
            }
        }

        Ok(())
    }

    fn deserialize_meta(data: &[u8]) -> Result<Meta, ProgramError> {
        if data.len() < core::mem::size_of::<Meta>() {
            return Err(ProgramError::InvalidAccountData);
        }
        let meta = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Meta) };

        Ok(meta)
    }

    fn serialize_meta(meta: &Meta, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < core::mem::size_of::<Meta>() {
            return Err(ProgramError::AccountDataTooSmall);
        }
        unsafe { core::ptr::write_unaligned(data.as_mut_ptr() as *mut Meta, meta.clone()) };

        Ok(())
    }

    fn deserialize_stake(data: &[u8]) -> Result<Stake, ProgramError> {
        if data.len() < core::mem::size_of::<Stake>() {
            return Err(ProgramError::InvalidAccountData);
        }
        let stake = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Stake) };

        Ok(stake)
    }

    fn serialize_stake(stake: &Stake, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < core::mem::size_of::<Stake>() {
            return Err(ProgramError::AccountDataTooSmall);
        }
        unsafe {
            core::ptr::write_unaligned(data.as_mut_ptr() as *mut Stake, stake.clone());
        }

        Ok(())
    }
    // Avoid exposing raw &mut casting over account data at a fixed size. Use
    // helpers::get_stake_state()/set_stake_state() for safe (de)serialization.
}

#[cfg(test)]
mod tests {
    // use pinocchio::msg;
    use pinocchio_log::log;

    use super::*;
    #[test]
    fn test_size_of() {
        // Ensure reported on-account size matches native expectation
        assert_eq!(StakeStateV2::size_of(), 200);
    }

    #[test]
    fn test_internal_layout_fits() {
        let m = core::mem::size_of::<Meta>();
        let s = core::mem::size_of::<Stake>();
        let flags_offset = 1 + m + s;
        log!("Meta size: {} Stake size: {} flags_off: {}", m, s, flags_offset);
        assert!(flags_offset < StakeStateV2::ACCOUNT_SIZE);
    }
}
