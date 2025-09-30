use crate::helpers::get_sysvar;
use core::mem::size_of;
use pinocchio::sysvars::clock::Epoch;

// Stake History sysvar id on Solana
pinocchio_pubkey::declare_id!("SysvarStakeHistory1111111111111111111111111");

// Default is not provided because it would require the real current epoch
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
    #[inline]
    pub fn from_account_data(data: &[u8], _current_epoch: u64) -> Self {
        // Native layout: bincode Vec<(u64, StakeHistoryEntry)>
        // [0..8) => len (u64, LE)
        // then len elements of 32 bytes each: epoch (u64 LE), then 3x u64 LE
        let mut sh = Self::new();
        if data.len() < core::mem::size_of::<u64>() {
            return sh;
        }
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&data[..8]);
        let len = u64::from_le_bytes(len_bytes) as usize;
        let want = len.saturating_mul(EPOCH_AND_ENTRY_SERIALIZED_SIZE as usize)
            .saturating_add(core::mem::size_of::<u64>());
        if data.len() < want { return sh; }

        let mut off = 8usize; // skip len
        let take = core::cmp::min(len, MAX_STAKE_HISTORY_ENTRIES);
        for _ in 0..take {
            let epoch = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            let effective = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
            let activating = u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap());
            let deactivating = u64::from_le_bytes(data[off + 24..off + 32].try_into().unwrap());
            let _ = epoch; // epoch not stored in this fixed array representation
            let _ = sh.push(StakeHistoryEntry {
                effective: effective.to_le_bytes(),
                activating: activating.to_le_bytes(),
                deactivating: deactivating.to_le_bytes(),
            });
            off += EPOCH_AND_ENTRY_SERIALIZED_SIZE as usize;
        }
        sh
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

        // Cannot query current or future epoch
        let newest_historical_epoch = current_epoch.checked_sub(1)?;
        if target_epoch > newest_historical_epoch { return None; }

        // Read vector length
        let mut len_buf = [0u8; 8];
        if get_sysvar(&mut len_buf, &ID, 0, 8).is_err() { return None; }
        let len = u64::from_le_bytes(len_buf);
        if len == 0 { return None; }

        // Oldest epoch present in the sysvar buffer
        // Oldest = current_epoch - len (saturating)
        let oldest_historical_epoch = current_epoch.saturating_sub(len);
        if target_epoch < oldest_historical_epoch { return None; }

        // Index of target within the vector (0-based from start of entries)
        // newest index = len-1 corresponds to epoch = current_epoch-1
        // idx = (target_epoch - oldest_historical_epoch)
        let distance_from_oldest = target_epoch.checked_sub(oldest_historical_epoch)?;
        if distance_from_oldest >= len { return None; }
        let idx = distance_from_oldest;

        // Compute byte offset: skip len (8) + idx * entry_size
        let offset = 8u64
            .checked_add(idx.checked_mul(EPOCH_AND_ENTRY_SERIALIZED_SIZE)?)?;

        let mut entry_buf = [0u8; EPOCH_AND_ENTRY_SERIALIZED_SIZE as usize];
        if get_sysvar(&mut entry_buf, &ID, offset, EPOCH_AND_ENTRY_SERIALIZED_SIZE).is_err() {
            return None;
        }

        let entry_epoch = u64::from_le_bytes(entry_buf[0..8].try_into().unwrap());
        let effective = u64::from_le_bytes(entry_buf[8..16].try_into().unwrap());
        let activating = u64::from_le_bytes(entry_buf[16..24].try_into().unwrap());
        let deactivating = u64::from_le_bytes(entry_buf[24..32].try_into().unwrap());

        // Verify epoch matches target; if not, return None (layout mismatch or gap)
        if entry_epoch != target_epoch { return None; }

        Some(StakeHistoryEntry {
            effective: effective.to_le_bytes(),
            activating: activating.to_le_bytes(),
            deactivating: deactivating.to_le_bytes(),
        })
    }
}
