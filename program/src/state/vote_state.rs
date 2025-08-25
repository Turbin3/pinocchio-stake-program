
use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

/// (epoch, credits, prev_credits)
pub type EpochCredits = (u64, u64, u64);

pub const MAX_EPOCH_CREDITS: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub struct EpochCreditsList {
    len: usize,
    items: [EpochCredits; MAX_EPOCH_CREDITS],
}

impl EpochCreditsList {
    #[inline]
    pub const fn new() -> Self {
       
        Self { len: 0, items: [(0, 0, 0); MAX_EPOCH_CREDITS] }
    }

    #[inline]
    pub fn push(&mut self, ec: EpochCredits) -> bool {
        if self.len == MAX_EPOCH_CREDITS {
            return false;
        }
        self.items[self.len] = ec;
        self.len += 1;
        true
    }

    #[inline]
    pub fn as_slice(&self) -> &[EpochCredits] {
        &self.items[..self.len]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VoteState {
    pub epoch_credits: EpochCreditsList,
    
}

impl VoteState {
      #[inline]
    pub fn credits(&self) -> u64 {
        match self.epoch_credits.as_slice().last() {
            Some((_, credits, _prev)) => *credits,
            None => 0,
        }
    }
       #[inline]
    pub fn credits_for_epoch(&self, epoch: u64) -> Option<u64> {
        self.epoch_credits
            .as_slice()
            .iter()
            .find(|(e, _, _)| *e == epoch)
            .map(|(_, credits, _)| *credits)
    }
    #[inline]
    pub fn epoch_credits_as_slice(&self) -> &[EpochCredits] {
        self.epoch_credits.as_slice()
    }

    #[inline]
    pub fn from_account_info(ai: &AccountInfo) -> Result<Self, ProgramError> {
        let data = ai.try_borrow_data()?;
        Self::from_bytes(&data)
    }

    #[inline]
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        let list = parse_epoch_credits(data).ok_or(ProgramError::InvalidAccountData)?;
        Ok(Self { epoch_credits: list })
    }
}

#[inline]
pub fn parse_epoch_credits(data: &[u8]) -> Option<EpochCreditsList> {
    if data.len() < 4 {
        return None;
    }
    let mut n_bytes = [0u8; 4];
    n_bytes.copy_from_slice(&data[0..4]);
    let n = u32::from_le_bytes(n_bytes) as usize;

    let need = 4 + n * (8 * 3);
    if data.len() < need {
        return None;
    }

    let mut list = EpochCreditsList::new();
    let mut off = 4;
    for _ in 0..n {
        let mut e = [0u8; 8];
        let mut c = [0u8; 8];
        let mut p = [0u8; 8];
        e.copy_from_slice(&data[off..off + 8]); off += 8;
        c.copy_from_slice(&data[off..off + 8]); off += 8;
        p.copy_from_slice(&data[off..off + 8]); off += 8;
        let _ = list.push((u64::from_le_bytes(e), u64::from_le_bytes(c), u64::from_le_bytes(p)));
    }
    Some(list)
}

#[inline]
pub fn parse_epoch_credits_slice(data: &[u8]) -> Option<EpochCreditsList> {
    parse_epoch_credits(data)
}

#[inline]
pub fn vote_program_id() -> Pubkey {

    Pubkey::default()
}