use crate::helpers::get_sysvar;
use crate::ID;
use core::mem::size_of;
use pinocchio::sysvars::clock::Epoch;

// we do not provide Default because this requires the real current epoch
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct StakeHistorySysvar(pub Epoch);
pub const MAX_STAKE_HISTORY_ENTRIES: usize = 512;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct StakeHistoryEntry {
    pub effective: [u8; 8],    // effective stake at this epoch
    pub activating: [u8; 8],   // sum of portion of stakes not fully warmed up
    pub deactivating: [u8; 8], // requested to be cooled down, not fully deactivated yet
}

pub trait StakeHistoryGetEntry {
    fn get_entry(&self, epoch: Epoch) -> Option<StakeHistoryEntry>;
}

#[macro_export]
macro_rules! impl_sysvar_id {
    ($type:ty) => {
        impl $crate::state::stake_history::SysvarId for $type {
            fn id() -> Pubkey {
                id()
            }

            fn check_id(pubkey: &Pubkey) -> bool {
                check_id(pubkey)
            }
        }
    };
}

#[macro_export]
macro_rules! declare_sysvar_id {
    ($name:expr, $type:ty) => {
        pinocchio_pubkey::declare_id!($name);
        $crate::impl_sysvar_id!($type);
    };
}

impl StakeHistoryEntry {
    pub const fn size() -> usize {
        size_of::<StakeHistoryEntry>()
    }
    pub fn with_effective(effective: u64) -> Self {
        Self {
            effective: effective.to_le_bytes(),
            ..Self::default()
        }
    }

    pub fn with_effective_and_activating(effective: u64, activating: u64) -> Self {
        Self {
            effective: effective.to_le_bytes(),
            activating: activating.to_le_bytes(),
            ..Self::default()
        }
    }

    pub fn with_deactivating(deactivating: u64) -> Self {
        Self {
            effective: deactivating.to_le_bytes(),
            deactivating: deactivating.to_le_bytes(),
            ..Self::default()
        }
    }
}

/// Complete stake history with fixed-size array
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct StakeHistory {
    /// Fixed-size array of stake history entries
    pub entries: [StakeHistoryEntry; MAX_STAKE_HISTORY_ENTRIES],
    /// Number of valid entries in the array
    pub len: usize,
}

impl StakeHistory {
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| StakeHistoryEntry {
                effective: [0u8; 8],
                activating: [0u8; 8],
                deactivating: [0u8; 8],
            }),
            len: 0,
        }
    }

    pub fn push(&mut self, entry: StakeHistoryEntry) -> Result<(), &'static str> {
        if self.len >= MAX_STAKE_HISTORY_ENTRIES {
            return Err("StakeHistory is full");
        }
        self.entries[self.len] = entry;
        self.len += 1;
        Ok(())
    }

    pub fn get(&self, index: usize) -> Option<&StakeHistoryEntry> {
        if index < self.len {
            Some(&self.entries[index])
        } else {
            None
        }
    }
}
const EPOCH_AND_ENTRY_SERIALIZED_SIZE: u64 = 32;

impl StakeHistoryGetEntry for StakeHistorySysvar {
    fn get_entry(&self, target_epoch: Epoch) -> Option<StakeHistoryEntry> {
        let current_epoch = self.0;

        // if current epoch is zero this returns None because there is no history yet
        let newest_historical_epoch = current_epoch.checked_sub(1)?;
        let oldest_historical_epoch =
            current_epoch.saturating_sub(MAX_STAKE_HISTORY_ENTRIES as u64);

        // target epoch is old enough to have fallen off history; presume fully active/deactive
        if target_epoch < oldest_historical_epoch {
            return None;
        }

        // epoch delta is how many epoch-entries we offset in the stake history vector, which may be zero
        // None means target epoch is current or in the future; this is a user error
        let epoch_delta = newest_historical_epoch.checked_sub(target_epoch)?;

        // offset is the number of bytes to our desired entry, including eight for vector length
        let offset = epoch_delta
            .checked_mul(EPOCH_AND_ENTRY_SERIALIZED_SIZE)?
            .checked_add(core::mem::size_of::<u64>() as u64)?;

        let mut entry_buf = [0; EPOCH_AND_ENTRY_SERIALIZED_SIZE as usize];
        let result = get_sysvar(&mut entry_buf, &ID, offset, EPOCH_AND_ENTRY_SERIALIZED_SIZE);

        match result {
            Ok(()) => {
                // All safe because `entry_buf` is a 32-length array
                let entry_epoch = u64::from_le_bytes(entry_buf[0..8].try_into().unwrap());
                let effective = u64::from_le_bytes(entry_buf[8..16].try_into().unwrap());
                let activating = u64::from_le_bytes(entry_buf[16..24].try_into().unwrap());
                let deactivating = u64::from_le_bytes(entry_buf[24..32].try_into().unwrap());

                // this would only fail if stake history skipped an epoch or the binary format of the sysvar changed
                assert_eq!(entry_epoch, target_epoch);

                Some(StakeHistoryEntry {
                    effective: effective.to_le_bytes(),
                    activating: activating.to_le_bytes(),
                    deactivating: deactivating.to_le_bytes(),
                })
            }
            _ => None,
        }
    }
}
