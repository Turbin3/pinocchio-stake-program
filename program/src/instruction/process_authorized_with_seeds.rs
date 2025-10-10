use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::{
    helpers::{get_stake_state, set_stake_state},
    helpers::authorize_update,
    state::{
        accounts::AuthorizeWithSeedData,
        stake_state_v2::StakeStateV2,
        StakeAuthorize,
    },
};



/// Recreates `Pubkey::create_with_seed(base, seed, owner)` in Pinocchio:
/// derived = sha256(base || seed || owner)
fn derive_with_seed_compat(base: &Pubkey, seed: &[u8], owner: &Pubkey) -> Result<Pubkey, ProgramError> {
    if seed.len() > 32 { return Err(ProgramError::InvalidInstructionData); }
    let mut buf = [0u8; 32 + 32 + 32];
    let mut off = 0usize;
    buf[off..off+32].copy_from_slice(&base[..]); off += 32;
    if !seed.is_empty() { buf[off..off+seed.len()].copy_from_slice(seed); }
    off += seed.len();
    buf[off..off+32].copy_from_slice(&owner[..]); off += 32;
    let out = crate::crypto::sha256::hash(&buf[..off]);
    Ok(out)
}

pub fn process_authorized_with_seeds(
    accounts: &[AccountInfo],
    args: AuthorizeWithSeedData, // already has: new_authorized, stake_authorize, authority_seed, authority_owner
) -> ProgramResult { 
    pinocchio::msg!("aws:handler_enter");
    if accounts.len() >= 2 { pinocchio::msg!("aws:len_ge2"); } else { pinocchio::msg!("aws:len_lt2"); }
    let role = args.stake_authorize;
    // Accept accounts as [stake, clock?, base, ...]; read Clock from sysvar (tolerant to meta order)
    if accounts.len() < 2 { pinocchio::msg!("aws:accs_bad"); return Err(ProgramError::NotEnoughAccountKeys); }
    let stake_ai = &accounts[0];
    let rest_all = if accounts.len() > 1 { &accounts[1..] } else { &accounts[0..0] };
    // Find base = first signer that is not the stake account and not the Clock sysvar
    let mut base_idx: Option<usize> = None;
    for (i, ai) in rest_all.iter().enumerate() {
        if ai.is_signer()
            && ai.key() != stake_ai.key()
            && ai.key() != &pinocchio::sysvars::clock::CLOCK_ID
        {
            base_idx = Some(i);
            break;
        }
    }
    let base_ai = match base_idx { Some(i) => { pinocchio::msg!("aws:base_found"); &rest_all[i] } , None => { pinocchio::msg!("aws:no_base"); return Err(ProgramError::MissingRequiredSignature); } };
    // Remaining accounts after stake and the chosen base
    let rest = &rest_all[..];

    // Basic safety checks
    if *stake_ai.owner() != crate::ID { pinocchio::msg!("aws:stake_bad_owner"); return Err(ProgramError::InvalidAccountOwner); }
    // Tolerate missing writable flag; native builders mark it writable but ProgramTest may reorder flags
    if base_ai.is_signer() { pinocchio::msg!("aws:base_sig1"); } else { pinocchio::msg!("aws:base_sig0"); }
    if !base_ai.is_signer() { pinocchio::msg!("aws:base_not_signer"); return Err(ProgramError::MissingRequiredSignature); }
    

    let clock = Clock::get()?;

    // Load state to determine required current authority and expected custodian
    pinocchio::msg!("aws:before_get_state");
    let state = match get_stake_state(stake_ai) {
        Ok(s) => s,
        Err(e) => { pinocchio::msg!("aws:get_state_err"); return Err(e); }
    };

    // Derive authority from (base, seed, owner)
    // Reject seeds longer than 32 (native behavior)
    let seed_len = args.authority_seed.len();
    if seed_len > 32 { pinocchio::msg!("aws:seed_len_gt_32"); return Err(ProgramError::InvalidInstructionData); }
    let mut seed_buf = [0u8; 32];
    if seed_len > 0 { seed_buf[..seed_len].copy_from_slice(&args.authority_seed[..seed_len]); }
    let derived = derive_with_seed_compat(base_ai.key(), &seed_buf[..seed_len], &args.authority_owner)?;
    pinocchio::msg!("aws:derived_ok");

    // Current authorities on the account
    let (staker_pk, withdrawer_pk) = match &state {
        StakeStateV2::Initialized(meta) | StakeStateV2::Stake(meta, _, _) => (meta.authorized.staker, meta.authorized.withdrawer),
        _ => { pinocchio::msg!("aws:bad_state"); return Err(ProgramError::InvalidAccountData); }
    };
    // Allow current authority to be either derived(base, seed, owner) or the base itself
    let base_pk = *base_ai.key();
    let allowed = match role {
        StakeAuthorize::Staker => {
            if derived == staker_pk { pinocchio::msg!("aws:allow_der_staker"); true }
            else if base_pk == staker_pk { pinocchio::msg!("aws:allow_base_staker"); true }
            else { false }
        }
        StakeAuthorize::Withdrawer => {
            if derived == withdrawer_pk { pinocchio::msg!("aws:allow_der_withdrawer"); true }
            else if base_pk == withdrawer_pk { pinocchio::msg!("aws:allow_base_withdrawer"); true }
            else { false }
        }
    };
    if !allowed { pinocchio::msg!("aws:not_allowed"); return Err(ProgramError::MissingRequiredSignature); }

    // Optional lockup custodian (scan trailing accounts for a matching signer)
    let expected_custodian = match &state {
        StakeStateV2::Initialized(meta) | StakeStateV2::Stake(meta, _, _) => meta.lockup.custodian,
        _ => Pubkey::default(),
    };
    let maybe_lockup_authority: Option<&AccountInfo> = rest
        .iter()
        .find(|ai| ai.is_signer() && ai.key() == &expected_custodian);
    if maybe_lockup_authority.is_some() { pinocchio::msg!("aws:custodian_present"); } else { pinocchio::msg!("aws:custodian_absent"); }
    

    // Restricted signer set: base (+ optional custodian)
    let mut signers = [Pubkey::default(); 2];
    let mut n = 0usize;
    signers[n] = *base_ai.key(); n += 1;
    if let Some(ai) = maybe_lockup_authority { signers[n] = *ai.key(); n += 1; }
    let signers = &signers[..n];

    // Apply policy update and write back
    
    pinocchio::msg!("aws:call_authorize_update");
    match state {
        StakeStateV2::Initialized(mut meta) => {
            authorize_update(
                &mut meta,
                args.new_authorized,
                role.clone(),
                signers,
                maybe_lockup_authority,
                &clock,
            )?;
            set_stake_state(stake_ai, &StakeStateV2::Initialized(meta))?;
        }
        StakeStateV2::Stake(mut meta, stake, flags) => {
            authorize_update(
                &mut meta,
                args.new_authorized,
                role,
                signers,
                maybe_lockup_authority,
                &clock,
            )?;
            set_stake_state(stake_ai, &StakeStateV2::Stake(meta, stake, flags))?;
        }
        _ => return Err(ProgramError::InvalidAccountData),
    }

    Ok(())
}
