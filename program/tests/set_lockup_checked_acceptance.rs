#![cfg(feature = "e2e")]
mod common;
use common::*;
use solana_program_test::ProgramTest;
use solana_sdk::{instruction::{AccountMeta, Instruction}, message::Message};

#[derive(Clone, Copy)]
enum BenchKind { Native, Pin }

async fn bench(kind: BenchKind) -> ProgramTestContext {
    let pt = match kind { BenchKind::Native => common::program_test_native(), BenchKind::Pin => common::program_test() };
    pt.start_with_context().await
}

async fn create_initialized_stake(
    ctx: &mut ProgramTestContext,
    program_owner: &Pubkey,
    staker: &Keypair,
    withdrawer: &Keypair,
) -> Pubkey {
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let stake = Keypair::new();
    let create = system_instruction::create_account(&ctx.payer.pubkey(), &stake.pubkey(), reserve, space, program_owner);
    let tx = Transaction::new_signed_with_payer(&[create], Some(&ctx.payer.pubkey()), &[&ctx.payer, &stake], ctx.last_blockhash);
    ctx.banks_client.process_transaction(tx).await.unwrap();
    let init_ix = solana_sdk::stake::instruction::initialize_checked(
        &stake.pubkey(),
        &solana_sdk::stake::state::Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() },
    );
    let tx = Transaction::new_signed_with_payer(&[init_ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, withdrawer], ctx.last_blockhash);
    ctx.banks_client.process_transaction(tx).await.unwrap();
    stake.pubkey()
}

fn build_slc_ix(
    stake: &Pubkey,
    args: solana_sdk::stake::instruction::LockupArgs,
    role_signer: &Pubkey,
    extras: &[AccountMeta],
) -> Instruction {
    // Start from the SDK builder (canonical)
    let mut ix = solana_sdk::stake::instruction::set_lockup_checked(stake, &args, role_signer);
    ix.accounts.extend_from_slice(extras);
    ix
}

fn want_missing_sig(err: &solana_sdk::transaction::TransactionError) -> bool {
    use solana_sdk::transaction::TransactionError as TE;
    use solana_sdk::instruction::InstructionError as IE;
    matches!(err, TE::InstructionError(0, IE::MissingRequiredSignature))
}

async fn run_case(
    kind: BenchKind,
    in_force: bool,
    role_is_withdrawer: bool,
    with_new_cust: bool,
    extras_count: usize,
    expect_ok: bool,
    new_cust_after_extras: bool,
) {
    let mut ctx = bench(kind).await;
    let program_owner = match kind { BenchKind::Native => solana_sdk::stake::program::id(), BenchKind::Pin => Pubkey::new_from_array(pinocchio_stake::ID) };
    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let custodian = Keypair::new();
    let stake = create_initialized_stake(&mut ctx, &program_owner, &staker, &withdrawer).await;

    if in_force {
        let clock = ctx.banks_client.get_sysvar::<solana_sdk::clock::Clock>().await.unwrap();
        let args = solana_sdk::stake::instruction::LockupArgs { unix_timestamp: None, epoch: Some(clock.epoch + 10), custodian: Some(custodian.pubkey()) };
        let ix = solana_sdk::stake::instruction::set_lockup(&stake, &args, &withdrawer.pubkey());
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &[&ctx.payer, &withdrawer], ctx.last_blockhash);
        ctx.banks_client.process_transaction(tx).await.unwrap();
    }

    let args = solana_sdk::stake::instruction::LockupArgs { unix_timestamp: None, epoch: Some(3), custodian: None };
    let role = if role_is_withdrawer { withdrawer.pubkey() } else { custodian.pubkey() };
    let mut extras = Vec::new();
    let mut maybe_new_cust_kp: Option<Keypair> = None;
    if with_new_cust && !new_cust_after_extras {
        let new_cust = Keypair::new();
        extras.push(AccountMeta::new_readonly(new_cust.pubkey(), true));
        maybe_new_cust_kp = Some(new_cust);
    }
    for _ in 0..extras_count { extras.push(AccountMeta::new_readonly(Pubkey::new_unique(), false)); }
    if with_new_cust && new_cust_after_extras {
        let new_cust = Keypair::new();
        extras.push(AccountMeta::new_readonly(new_cust.pubkey(), true));
        maybe_new_cust_kp = Some(new_cust);
    }
    let ix = build_slc_ix(&stake, args, &role, &extras);
    println!(
        "kind={:?} in_force={} role_is_withdrawer={} with_new_cust={} extras_count={} new_cust_after_extras={}",
        kind as u8, in_force, role_is_withdrawer, with_new_cust, extras_count, new_cust_after_extras
    );
    for (i, am) in ix.accounts.iter().enumerate() {
        println!("  acct[{i}]: {} signer={} writable={}", am.pubkey, am.is_signer, am.is_writable);
    }
    let msg = Message::new(&[ix.clone()], Some(&ctx.payer.pubkey()));
    let mut signers: Vec<&Keypair> = vec![&ctx.payer];
    if role == withdrawer.pubkey() { signers.push(&withdrawer); }
    if role == custodian.pubkey() { signers.push(&custodian); }
    if let Some(ref kp) = maybe_new_cust_kp { signers.push(kp); }
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&ctx.payer.pubkey()), &signers, ctx.last_blockhash);
    let res = ctx.banks_client.process_transaction(tx).await;
    match (expect_ok, res) {
        (true, Ok(())) => {}
        (false, Err(e)) => {
            if let solana_program_test::BanksClientError::TransactionError(te) = e { assert!(want_missing_sig(&te), "unexpected error: {:?}", te); }
            else { panic!("unexpected transport error: {:?}", e); }
        }
        (true, Err(e)) => panic!("expected Ok, got {:?}", e),
        (false, Ok(())) => panic!("expected error, got Ok"),
    }
}

#[tokio::test]
async fn set_lockup_checked_acceptance_matrix() {
    // Not in force: withdrawer must sign; extras ignored; optional new custodian as signer allowed
    // If any account exists at index 2, it must be a signer (native rule)
    run_case(BenchKind::Native, false, true, false, 1, false, false).await;
    run_case(BenchKind::Pin,    false, true, false, 1, false, false).await;

    // New custodian immediately after role signer (index 2)
    run_case(BenchKind::Native, false, true, true, 2, true, false).await;
    run_case(BenchKind::Pin,    false, true, true, 2, true, false).await;
    // New custodian after extras (not at index 2) — assert native vs pin agree
    run_case(BenchKind::Native, false, true, true, 2, false, true).await;
    run_case(BenchKind::Pin,    false, true, true, 2, false, true).await;

    run_case(BenchKind::Native, false, false, false, 0, false, false).await;
    run_case(BenchKind::Pin,    false, false, false, 0, false, false).await;

    // In force: custodian must sign; if index 2 is present and not signer -> error
    run_case(BenchKind::Native, true, false, false, 1, false, false).await;
    run_case(BenchKind::Pin,    true, false, false, 1, false, false).await;

    run_case(BenchKind::Native, true, true, false, 0, false, false).await;
    run_case(BenchKind::Pin,    true, true, false, 0, false, false).await;
}
