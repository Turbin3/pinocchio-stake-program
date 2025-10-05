mod common;
use common::*;
use common::pin_adapter as ixn;
use solana_sdk::{pubkey::Pubkey, system_instruction, message::Message, stake::state::Authorized};
use std::str::FromStr;

#[tokio::test]
async fn withdraw_uninitialized_partial() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    // Create stake account owned by our program (Uninitialized path)
    let stake_acc = Keypair::new();
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);

    let create = system_instruction::create_account(&ctx.payer.pubkey(), &stake_acc.pubkey(), reserve, space, &program_id);
    let msg = Message::new(&[create], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &stake_acc], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Prefund with reserve + small extra to allow partial withdraw
    let extra = reserve + 1_000_000; // small extra on top of reserve
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&ctx.payer.pubkey(), &stake_acc.pubkey(), extra)],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(fund_tx).await.unwrap();

    // Withdraw some lamports to payer using Uninitialized fast path
    let withdraw_lamports: u64 = 500_000;
    let w_ix = ixn::withdraw(&stake_acc.pubkey(), &stake_acc.pubkey(), &ctx.payer.pubkey(), withdraw_lamports, None);
    let msg = Message::new(&[w_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &stake_acc], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_ok(), "Withdraw should succeed: {:?}", res);
}

#[tokio::test]
async fn withdraw_initialized_partial_respects_reserve() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    // Create Initialized stake with authorities
    let stake_acc = Keypair::new();
    let staker = Keypair::new();
    let withdrawer = Keypair::new();

    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);

    // Create + InitializeChecked
    let create = system_instruction::create_account(&ctx.payer.pubkey(), &stake_acc.pubkey(), reserve, space, &program_id);
    let msg = Message::new(&[create], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &stake_acc], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let init_ix = ixn::initialize_checked(&stake_acc.pubkey(), &Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() });
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Prefund above reserve
    let extra: u64 = 1_500_000;
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&ctx.payer.pubkey(), &stake_acc.pubkey(), extra)],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(fund_tx).await.unwrap();

    // Withdraw less than extra, ensure reserve stays
    let withdraw_lamports: u64 = extra / 2;
    let ix = ixn::withdraw(&stake_acc.pubkey(), &withdrawer.pubkey(), &ctx.payer.pubkey(), withdraw_lamports, None);
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_ok(), "Withdraw(partial) should succeed: {:?}", res);

    // Verify remaining >= reserve
    let acct = ctx.banks_client.get_account(stake_acc.pubkey()).await.unwrap().unwrap();
    assert!(acct.lamports >= reserve, "stake must retain at least reserve");
    // And state remains Initialized
    let state = pinocchio_stake::state::stake_state_v2::StakeStateV2::deserialize(&acct.data).unwrap();
    matches!(state, pinocchio_stake::state::stake_state_v2::StakeStateV2::Initialized(_));
}

#[tokio::test]
async fn withdraw_initialized_full_closes_account() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let stake_acc = Keypair::new();
    let staker = Keypair::new();
    let withdrawer = Keypair::new();

    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);

    // Create + InitializeChecked
    let create = system_instruction::create_account(&ctx.payer.pubkey(), &stake_acc.pubkey(), reserve, space, &program_id);
    let msg = Message::new(&[create], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &stake_acc], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let init_ix = ixn::initialize_checked(
        &stake_acc.pubkey(),
        &Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() },
    );
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Full withdraw: exactly current lamports
    let acct_before = ctx.banks_client.get_account(stake_acc.pubkey()).await.unwrap().unwrap();
    let full = acct_before.lamports;
    let ix = ixn::withdraw(&stake_acc.pubkey(), &withdrawer.pubkey(), &ctx.payer.pubkey(), full, None);
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_ok(), "Full withdraw should succeed on Initialized");

    // Account may be purged by runtime when lamports reach zero. Accept either case.
    let acct_after_opt = ctx.banks_client.get_account(stake_acc.pubkey()).await.unwrap();
    if let Some(acct_after) = acct_after_opt {
        assert_eq!(acct_after.lamports, 0);
        let state = pinocchio_stake::state::stake_state_v2::StakeStateV2::deserialize(&acct_after.data).unwrap();
        assert!(matches!(state, pinocchio_stake::state::stake_state_v2::StakeStateV2::Uninitialized));
    }
}

#[tokio::test]
async fn withdraw_stake_active_fails_partial() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    // Authorities and stake
    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let stake = Keypair::new();

    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);

    // Create + InitializeChecked
    let create = system_instruction::create_account(&ctx.payer.pubkey(), &stake.pubkey(), reserve, space, &program_id);
    let msg = Message::new(&[create], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &stake], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let init_ix = ixn::initialize_checked(
        &stake.pubkey(),
        &Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() },
    );
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Fund extra (at least minimum delegation) and delegate to dummy vote account
    let extra: u64 = common::get_minimum_delegation_lamports(&mut ctx).await;
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&ctx.payer.pubkey(), &stake.pubkey(), extra)],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(fund_tx).await.unwrap();

    let vote = Keypair::new();
    // create a minimal vote account with byte layout expected by get_vote_state
    let vote_space = std::mem::size_of::<pinocchio_stake::state::vote_state::VoteState>() as u64;
    let vote_lamports = rent.minimum_balance(vote_space as usize);
    let vote_program_id = Pubkey::from_str("Vote111111111111111111111111111111111111111").unwrap();
    let create_vote = system_instruction::create_account(&ctx.payer.pubkey(), &vote.pubkey(), vote_lamports, vote_space, &vote_program_id);
    let msg = Message::new(&[create_vote], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &vote], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Delegate
    let del_ix = ixn::delegate_stake(&stake.pubkey(), &staker.pubkey(), &vote.pubkey());
    let msg = Message::new(&[del_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &staker], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Attempt partial withdraw while still active -> should fail
    let attempt: u64 = 1_000; // any positive amount should fail under active constraints
    let ix = ixn::withdraw(&stake.pubkey(), &withdrawer.pubkey(), &ctx.payer.pubkey(), attempt, None);
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_err(), "Withdraw should fail while stake is active");
}

#[tokio::test]
async fn withdraw_stake_after_deactivate_full_succeeds() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    // Authorities and stake
    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let stake = Keypair::new();

    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);

    // Create + InitializeChecked
    let create = system_instruction::create_account(&ctx.payer.pubkey(), &stake.pubkey(), reserve, space, &program_id);
    let msg = Message::new(&[create], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &stake], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let init_ix = ixn::initialize_checked(
        &stake.pubkey(),
        &Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() },
    );
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Fund and delegate with at least the minimum delegation
    let extra: u64 = common::get_minimum_delegation_lamports(&mut ctx).await;
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&ctx.payer.pubkey(), &stake.pubkey(), extra)],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(fund_tx).await.unwrap();

    let vote = Keypair::new();
    let vote_space = std::mem::size_of::<pinocchio_stake::state::vote_state::VoteState>() as u64;
    let vote_lamports = rent.minimum_balance(vote_space as usize);
    let vote_program_id = Pubkey::from_str("Vote111111111111111111111111111111111111111").unwrap();
    let create_vote = system_instruction::create_account(&ctx.payer.pubkey(), &vote.pubkey(), vote_lamports, vote_space, &vote_program_id);
    let msg = Message::new(&[create_vote], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &vote], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let del_ix = ixn::delegate_stake(&stake.pubkey(), &staker.pubkey(), &vote.pubkey());
    let msg = Message::new(&[del_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &staker], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Deactivate
    let deact_ix = ixn::deactivate_stake(&stake.pubkey(), &staker.pubkey());
    let msg = Message::new(&[deact_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &staker], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Advance one epoch so effective stake becomes zero (in our model)
    let root_slot = ctx.banks_client.get_root_slot().await.unwrap();
    let slots_per_epoch = ctx.genesis_config().epoch_schedule.slots_per_epoch;
    ctx.warp_to_slot(root_slot + slots_per_epoch).unwrap();

    // Full withdraw now succeeds
    let current = ctx.banks_client.get_account(stake.pubkey()).await.unwrap().unwrap();
    let full = current.lamports;
    let ix = ixn::withdraw(&stake.pubkey(), &withdrawer.pubkey(), &ctx.payer.pubkey(), full, None);
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_ok(), "Full withdraw after deactivation should succeed: {:?}", res);

    // Account may be purged by runtime when lamports reach zero. Accept either case.
    let after_opt = ctx.banks_client.get_account(stake.pubkey()).await.unwrap();
    if let Some(after) = after_opt {
        assert_eq!(after.lamports, 0);
        let state = pinocchio_stake::state::stake_state_v2::StakeStateV2::deserialize(&after.data).unwrap();
        assert!(matches!(state, pinocchio_stake::state::stake_state_v2::StakeStateV2::Uninitialized));
    }
}
