use crate::state::delegation::Stake;
use crate::state::stake_flag::StakeFlags;
use crate::state::state::Meta;

use crate::ID;
use pinocchio::{account_info::AccountInfo, program_error::ProgramError};

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]

pub enum StakeStateV2 {
    Uninitialized,
    Initialized(Meta),
    Stake(Meta, Stake, StakeFlags),
    RewardsPool,
}

impl StakeStateV2 {
    pub const ACCOUNT_SIZE: usize = core::mem::size_of::<Self>();

    /// The fixed number of bytes used to serialize each stake account
    pub const fn size_of() -> usize {
        Self::ACCOUNT_SIZE
    }

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
    #[inline]
    pub fn try_from_account_info_mut_raw(
        account_info: &AccountInfo,
    ) -> Result<&mut Self, ProgramError> {
        let expected_size = Self::size_of();
        let data = account_info.try_borrow_mut_data()?; //  returns RefMut<[u8]>

        if data.len() != expected_size {
            return Err(ProgramError::InvalidAccountData);
        }

        let ptr = data.as_ptr() as usize;
        if ptr % core::mem::align_of::<Self>() != 0 {
            return Err(ProgramError::InvalidAccountData); // misaligned
        }

        let ptr = data.as_ptr() as *mut Self;
        // SAFETY:
        // - `data` is mutable and of correct length
        // - Alignment has been checked
        // - Memory is assumed to contain a valid StakeStateV2
        Ok(unsafe { &mut *ptr })
    }

    pub fn get_stake_state(
        stake_account_info: &AccountInfo,
    ) -> Result<&mut StakeStateV2, ProgramError> {
        if *stake_account_info.owner() != ID {
            return Err(ProgramError::InvalidAccountOwner);
        }
        Self::try_from_account_info_mut_raw(stake_account_info)
    }
}

#[cfg(test)]
mod tests {
    // use pinocchio::msg;
    use pinocchio_log::log;

    use super::*;
    #[test]
    fn test_size_of() {
        // log all the data size of the StakeStateV2
        log!("StakeStateV2 size: {}", StakeStateV2::size_of());
        log!("StakeStateV2 account size: {}", StakeStateV2::ACCOUNT_SIZE);
        log!("Meta size: {}", Meta::size());
        log!("Stake size: {}", core::mem::size_of::<Stake>());
        log!("StakeFlags size: {}", core::mem::size_of::<StakeFlags>());
        assert_eq!(
            StakeStateV2::size_of(),
            core::mem::size_of::<StakeStateV2>()
        );
    }

    // test Check alignment
    #[test]
    fn test_alignment() {
        use core::mem;

        // Allocate a buffer with the correct size for StakeStateV2
        const SIZE: usize = 208; //StakeStateV2::size_of();
        let data = [0u8; SIZE];

        // Get the raw pointer and check alignment
        let ptr = data.as_ptr() as usize;
        let alignment = mem::align_of::<StakeStateV2>();

        // Log for debug info
        // log!(" Alignment required: {}", alignment);
        // log!(" Pointer address: {}", ptr);
        // log!(" Pointer address % alignment: {}", ptr % alignment);

        // Assert that the pointer is correctly aligned
        assert_eq!(
            ptr % alignment,
            0,
            "Memory is not properly aligned for StakeStateV2"
        );
    }
}
