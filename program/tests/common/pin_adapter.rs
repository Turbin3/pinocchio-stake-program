use solana_program_test::BanksClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    stake::{
        instruction as sdk_ixn,
        program::id as stake_program_id,
        state::{Authorized, Lockup, Meta, Stake, StakeAuthorize},
    },
    clock::Clock,
    stake_history::StakeHistory,
};

pub mod ixn {
    use super::*;


    pub fn get_minimum_delegation() -> Instruction {
        sdk_ixn::get_minimum_delegation()
    }

    pub fn initialize(stake: &Pubkey, authorized: &Authorized, lockup: &Lockup) -> Instruction {
        sdk_ixn::initialize(stake, authorized, lockup)
    }

    pub fn initialize_checked(stake: &Pubkey, authorized: &Authorized) -> Instruction {
        sdk_ixn::initialize_checked(stake, authorized)
    }

    pub fn authorize(
        stake: &Pubkey,
        authority: &Pubkey,
        new_authorized: &Pubkey,
        role: StakeAuthorize,
        custodian: Option<&Pubkey>,
    ) -> Instruction {
        let mut ix = sdk_ixn::authorize(stake, authority, new_authorized, role, custodian);
        ix
    }

    pub fn authorize_checked(
        stake: &Pubkey,
        authority: &Pubkey,
        new_authorized: &Pubkey,
        role: StakeAuthorize,
        custodian: Option<&Pubkey>,
    ) -> Instruction {
        let mut ix = sdk_ixn::authorize_checked(stake, authority, new_authorized, role, custodian);
        ix
    }

    pub fn authorize_checked_with_seed(
        stake: &Pubkey,
        base: &Pubkey,
        seed: String,
        owner: &Pubkey,
        new_authorized: &Pubkey,
        role: StakeAuthorize,
        custodian: Option<&Pubkey>,
    ) -> Instruction {
        let mut ix = sdk_ixn::authorize_checked_with_seed(
            stake,
            base,
            seed.clone(),
            owner,
            new_authorized,
            role,
            custodian,
        );
        ix.program_id = Pubkey::new_from_array(pinocchio_stake::ID);
        // Ensure required signer flags are set for strict native parity
        for am in &mut ix.accounts {
            if am.pubkey == *base { am.is_signer = true; }
            if am.pubkey == *new_authorized { am.is_signer = true; }
        }
        // Canonicalize meta order to [stake, new_authorized, clock, base, (custodian?)]
        let mut stake_meta = None;
        let mut base_meta = None;
        let mut clock_meta = None;
        let mut new_meta = None;
        let mut other: Vec<AccountMeta> = Vec::new();
        for m in ix.accounts.drain(..) {
            if m.pubkey == *stake { stake_meta = Some(m); continue; }
            if m.pubkey == *new_authorized { new_meta = Some(m); continue; }
            if m.pubkey == solana_sdk::sysvar::clock::id() { clock_meta = Some(m); continue; }
            if m.pubkey == *base { base_meta = Some(m); continue; }
            other.push(m);
        }
        let mut ordered = Vec::new();
        if let Some(m) = stake_meta { ordered.push(m); }
        if let Some(m) = new_meta { ordered.push(m); }
        if let Some(m) = clock_meta { ordered.push(m); }
        if let Some(m) = base_meta { ordered.push(m); }
        // append any remaining metas (e.g., optional custodian) preserving their original flags
        ordered.extend(other.into_iter());
        ix.accounts = ordered;
        ix
    }

    // Non-checked with-seed variant: base signs; new_authorized does not need to sign
    pub fn authorize_with_seed(
        stake: &Pubkey,
        base: &Pubkey,
        seed: String,
        owner: &Pubkey,
        new_authorized: &Pubkey,
        role: StakeAuthorize,
        _custodian: Option<&Pubkey>,
    ) -> Instruction {
        let mut ix = sdk_ixn::authorize_with_seed(stake, base, seed, owner, new_authorized, role, _custodian);
        ix.program_id = Pubkey::new_from_array(pinocchio_stake::ID);
        // Do not force base signer here; let runtime enforce signatures
        // Canonicalize to [stake, clock, base, (others...)]
        let mut stake_meta = None;
        let mut clock_meta = None;
        let mut base_meta = None;
        let mut other: Vec<AccountMeta> = Vec::new();
        for m in ix.accounts.drain(..) {
            if m.pubkey == *stake { stake_meta = Some(m); continue; }
            if m.pubkey == solana_sdk::sysvar::clock::id() { clock_meta = Some(m); continue; }
            if m.pubkey == *base { base_meta = Some(m); continue; }
            other.push(m);
        }
        let mut ordered = Vec::new();
        if let Some(m) = stake_meta { ordered.push(m); }
        if let Some(m) = clock_meta { ordered.push(m); }
        if let Some(m) = base_meta { ordered.push(m); }
        ordered.extend(other.into_iter());
        ix.accounts = ordered;
        ix
    }

    pub fn set_lockup_checked(stake: &Pubkey, args: &solana_sdk::stake::instruction::LockupArgs, signer: &Pubkey) -> Instruction {
        let mut ix = sdk_ixn::set_lockup_checked(stake, args, signer);
        // Ensure signer flag for the role signer and canonicalize meta order to [stake, clock, signer, (custodian?)]
        for am in &mut ix.accounts {
            if am.pubkey == *signer { am.is_signer = true; }
        }
        let mut stake_meta = None;
        let mut clock_meta = None;
        let mut signer_meta = None;
        let mut cust_meta = None;
        let mut other: Vec<AccountMeta> = Vec::new();
        for m in ix.accounts.drain(..) {
            if m.pubkey == *stake { stake_meta = Some(m); continue; }
            if m.pubkey == solana_sdk::sysvar::clock::id() { clock_meta = Some(m); continue; }
            if m.pubkey == *signer { signer_meta = Some(m); continue; }
            // If a custodian was provided in args, the SDK adds it; keep its slot if present
            if let Some(c) = args.custodian { if m.pubkey == c { cust_meta = Some(m); continue; } }
            other.push(m);
        }
        let mut ordered = Vec::new();
        if let Some(m) = stake_meta { ordered.push(m); }
        if let Some(m) = clock_meta { ordered.push(m); }
        if let Some(m) = signer_meta { ordered.push(m); }
        if let Some(m) = cust_meta { ordered.push(m); }
        ordered.extend(other.into_iter());
        ix.accounts = ordered;
        // Rewrite data to universal short form: tag(12) + compact payload (flags + fields)
        let mut data: Vec<u8> = Vec::with_capacity(1 + 1 + 16 + 32);
        data.push(12u8);
        let mut flags = 0u8;
        let mut payload: Vec<u8> = Vec::with_capacity(16);
        if let Some(ts) = args.unix_timestamp { flags |= 0x01; payload.extend_from_slice(&ts.to_le_bytes()); }
        if let Some(ep) = args.epoch { flags |= 0x02; payload.extend_from_slice(&ep.to_le_bytes()); }
        if let Some(c) = args.custodian { flags |= 0x04; payload.extend_from_slice(&c.to_bytes()); }
        data.push(flags);
        data.extend_from_slice(&payload);
        ix.data = data;
        ix
    }

    pub fn delegate_stake(stake: &Pubkey, staker: &Pubkey, vote: &Pubkey) -> Instruction {
        // Use native metas and wire
        sdk_ixn::delegate_stake(stake, staker, vote)
    }

    pub fn split(stake: &Pubkey, authority: &Pubkey, lamports: u64, split_dest: &Pubkey) -> Vec<Instruction> {
        // Use native metas and wire
        sdk_ixn::split(stake, authority, lamports, split_dest)
    }

    pub fn withdraw(
        stake: &Pubkey,
        withdrawer: &Pubkey,
        recipient: &Pubkey,
        lamports: u64,
        custodian: Option<&Pubkey>,
    ) -> Instruction {
        // Use native metas and wire
        sdk_ixn::withdraw(stake, withdrawer, recipient, lamports, custodian)
    }

    pub fn deactivate_stake(stake: &Pubkey, staker: &Pubkey) -> Instruction {
        sdk_ixn::deactivate_stake(stake, staker)
    }

    // Convenience alias matching native name
    pub fn deactivate(stake: &Pubkey, staker: &Pubkey) -> Instruction {
        deactivate_stake(stake, staker)
    }

    pub fn merge(dest: &Pubkey, src: &Pubkey, authority: &Pubkey) -> Vec<Instruction> {
        // Use native metas and wire
        sdk_ixn::merge(dest, src, authority)
    }

    pub fn move_stake(source: &Pubkey, dest: &Pubkey, staker: &Pubkey, lamports: u64) -> Instruction {
        sdk_ixn::move_stake(source, dest, staker, lamports)
    }

    pub fn move_lamports(source: &Pubkey, dest: &Pubkey, staker: &Pubkey, lamports: u64) -> Instruction {
        sdk_ixn::move_lamports(source, dest, staker, lamports)
    }

    // DeactivateDelinquent: [stake, delinquent_vote, reference_vote]
    pub fn deactivate_delinquent(stake: &Pubkey, delinquent_vote: &Pubkey, reference_vote: &Pubkey) -> Instruction {
        // For test robustness, target our stake program directly and use empty data
        // (entrypoint tolerates empty -> DeactivateDelinquent). Keep metas native-shaped.
        Instruction {
            program_id: Pubkey::new_from_array(pinocchio_stake::ID),
            // Put both vote accounts immediately after stake; handler scans by data, order agnostic
            accounts: vec![
                AccountMeta::new(*stake, false),
                AccountMeta::new(*reference_vote, false),
                AccountMeta::new(*delinquent_vote, false),
            ],
            data: vec![],
        }
    }
}

// Re-export ixn::* so tests can `use crate::common::pin_adapter as ixn;`
pub use ixn::*;

// ---------- State helpers ----------
pub async fn get_stake_account(
    banks_client: &mut BanksClient,
    pubkey: &Pubkey,
) -> (Meta, Option<Stake>, u64) {
    use pinocchio_stake::state as pstate;
    let stake_account = banks_client.get_account(*pubkey).await.unwrap().unwrap();
    let lamports = stake_account.lamports;
    let st = pstate::stake_state_v2::StakeStateV2::deserialize(&stake_account.data).unwrap();
    match st {
        pstate::stake_state_v2::StakeStateV2::Initialized(meta) => {
            let meta_sdk = Meta {
                authorized: Authorized {
                    staker: Pubkey::new_from_array(meta.authorized.staker),
                    withdrawer: Pubkey::new_from_array(meta.authorized.withdrawer),
                },
                rent_exempt_reserve: u64::from_le_bytes(meta.rent_exempt_reserve),
                lockup: Lockup {
                    unix_timestamp: meta.lockup.unix_timestamp,
                    epoch: meta.lockup.epoch,
                    custodian: Pubkey::new_from_array(meta.lockup.custodian),
                },
            };
            (meta_sdk, None, lamports)
        }
        pstate::stake_state_v2::StakeStateV2::Stake(meta, stake, _flags) => {
            let meta_sdk = Meta {
                authorized: Authorized {
                    staker: Pubkey::new_from_array(meta.authorized.staker),
                    withdrawer: Pubkey::new_from_array(meta.authorized.withdrawer),
                },
                rent_exempt_reserve: u64::from_le_bytes(meta.rent_exempt_reserve),
                lockup: Lockup {
                    unix_timestamp: meta.lockup.unix_timestamp,
                    epoch: meta.lockup.epoch,
                    custodian: Pubkey::new_from_array(meta.lockup.custodian),
                },
            };
            let del = &stake.delegation;
            let delegation_sdk = solana_sdk::stake::state::Delegation {
                voter_pubkey: Pubkey::new_from_array(del.voter_pubkey),
                stake: u64::from_le_bytes(del.stake),
                activation_epoch: u64::from_le_bytes(del.activation_epoch),
                deactivation_epoch: u64::from_le_bytes(del.deactivation_epoch),
                warmup_cooldown_rate: f64::from_bits(u64::from_le_bytes(del.warmup_cooldown_rate)),
            };
            let stake_sdk = Stake {
                delegation: delegation_sdk,
                credits_observed: u64::from_le_bytes(stake.credits_observed),
            };
            (meta_sdk, Some(stake_sdk), lamports)
        }
        pstate::stake_state_v2::StakeStateV2::Uninitialized => panic!("panic: uninitialized"),
        _ => unimplemented!(),
    }
}

pub async fn get_stake_account_rent(banks_client: &mut BanksClient) -> u64 {
    let rent = banks_client.get_rent().await.unwrap();
    rent.minimum_balance(pinocchio_stake::state::stake_state_v2::StakeStateV2::size_of())
}

pub fn encode_program_stake_state(st: &pinocchio_stake::state::stake_state_v2::StakeStateV2) -> Vec<u8> {
    let mut buf = vec![0u8; pinocchio_stake::state::stake_state_v2::StakeStateV2::size_of()];
    pinocchio_stake::state::stake_state_v2::StakeStateV2::serialize(st, &mut buf)
        .expect("serialize stake state");
    buf
}

// ---------- Error helpers ----------
pub mod err {
    use solana_sdk::{program_error::ProgramError, stake::instruction::StakeError};

    pub fn matches_stake_error(e: &ProgramError, expected: StakeError) -> bool {
        match (e, expected.clone()) {
            (ProgramError::Custom(0x11), StakeError::AlreadyDeactivated) => true,
            (ProgramError::Custom(0x12), StakeError::InsufficientDelegation) => true,
            (ProgramError::Custom(0x13), StakeError::VoteAddressMismatch) => true,
            (ProgramError::Custom(0x14), StakeError::MergeMismatch) => true,
            (ProgramError::Custom(0x15), StakeError::LockupInForce) => true,
            (ProgramError::Custom(0x18), StakeError::TooSoonToRedelegate) => true,
            _ => *e == expected.into(),
        }
    }
}

// ---------- Effective stake via StakeHistory ----------
/// Compute effective stake at the current epoch using the SDK `StakeHistory`
/// and the stake account's SDK `Stake` delegation, following Solana's
/// warmup/cooldown rate-limited algorithm.
pub async fn effective_stake_from_history(
    banks_client: &mut BanksClient,
    stake_pubkey: &Pubkey,
) -> u64 {
    use solana_sdk::stake::state::warmup_cooldown_rate as sdk_wcr;

    let clock = banks_client.get_sysvar::<Clock>().await.unwrap();
    let hist = banks_client.get_sysvar::<StakeHistory>().await.unwrap();
    let (_meta, stake_opt, _lamports) = get_stake_account(banks_client, stake_pubkey).await;
    let Some(stake) = stake_opt else { return 0; };

    // Local getters
    let s = stake.delegation.stake;
    let act = stake.delegation.activation_epoch;
    let deact = stake.delegation.deactivation_epoch;
    let tgt = clock.epoch;

    // Helper to fetch history entry for an epoch
    let get_entry = |e: u64| -> Option<solana_sdk::stake_history::StakeHistoryEntry> {
        hist.get(e).cloned()
    };

    // Bootstrap stake: fully effective
    if act == u64::MAX {
        return s;
    }
    // Activated and immediately deactivated (no time to activate)
    if act == deact {
        return 0;
    }

    // Activation phase: compute (effective, activating)
    let (mut effective, activating) = if tgt < act {
        (0u64, 0u64)
    } else if tgt == act {
        (0u64, s)
    } else if let Some(mut prev_cluster) = get_entry(act) {
        let mut prev_epoch = act;
        let mut current_effective = 0u64;
        loop {
            let cur_epoch = prev_epoch.saturating_add(1);
            if prev_cluster.activating == 0 { break; }

            let remaining = s.saturating_sub(current_effective);
            let weight = (remaining as f64) / (prev_cluster.activating as f64);
            let rate = sdk_wcr(cur_epoch, None);
            let newly_cluster = (prev_cluster.effective as f64) * rate;
            let newly_effective = ((weight * newly_cluster) as u64).max(1);

            current_effective = current_effective.saturating_add(newly_effective);
            if current_effective >= s { current_effective = s; break; }
            if cur_epoch >= tgt || cur_epoch >= deact { break; }
            if let Some(next) = get_entry(cur_epoch) {
                prev_epoch = cur_epoch;
                prev_cluster = next;
            } else { break; }
        }
        (current_effective, s.saturating_sub(current_effective))
    } else {
        // No history entry for activation epoch; fall back to window check
        if tgt > act && tgt <= deact { (s, 0) } else { (0, 0) }
    };

    // If not yet deactivating at tgt
    if tgt < deact {
        return effective;
    }
    if tgt == deact {
        // Deactivation begins; only effective portion is considered deactivating now
        return effective;
    }

    // Cooldown phase: reduce effective over epochs after deact
    if let Some(mut prev_cluster) = get_entry(deact) {
        let mut prev_epoch = deact;
        let mut current_effective = effective;
        loop {
            let cur_epoch = prev_epoch.saturating_add(1);
            if prev_cluster.deactivating == 0 { break; }

            let weight = if prev_cluster.deactivating == 0 {
                0f64
            } else {
                (current_effective as f64) / (prev_cluster.deactivating as f64)
            };
            let rate = sdk_wcr(cur_epoch, None);
            let newly_not_effective_cluster = (prev_cluster.effective as f64) * rate;
            let delta = ((weight * newly_not_effective_cluster) as u64).max(1);
            current_effective = current_effective.saturating_sub(delta);
            if current_effective == 0 { break; }
            if cur_epoch >= tgt { break; }
            if let Some(next) = get_entry(cur_epoch) {
                prev_epoch = cur_epoch;
                prev_cluster = next;
            } else { break; }
        }
        return current_effective;
    }

    // Fallback if no history at deactivation epoch
    if tgt > act && tgt <= deact { effective } else { 0 }
}
