
mod common;
use common::*;
use common::pin_adapter as ixn;
use solana_sdk::{
    account::Account as SolanaAccount,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    system_instruction,
};

fn build_epoch_credits_bytes(list: &[(u64, u64, u64)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + list.len() * 24);
    out.extend_from_slice(&(list.len() as u32).to_le_bytes());
    for &(e, c, p) in list {
        out.extend_from_slice(&e.to_le_bytes());
        out.extend_from_slice(&c.to_le_bytes());
        out.extend_from_slice(&p.to_le_bytes());
    }
    out
}

#[tokio::test]
async fn deactivate_delinquent_happy_path() {
    // Prepare vote accounts at genesis with fixed epoch credits
    let mut pt = common::program_test();

    // Choose target current epoch = 5 to satisfy N=5 requirements
    // Reference vote must have last 5 epochs exactly [5,4,3,2,1]
    let reference_votes = build_epoch_credits_bytes(&[(1, 1, 0), (2, 1, 0), (3, 1, 0), (4, 1, 0), (5, 1, 0)]);
    // Delinquent vote last vote epoch = 0 (older than current-5 => eligible)
    let delinquent_votes = build_epoch_credits_bytes(&[(0, 1, 0)]);

    let reference_vote = Pubkey::new_unique();
    let delinquent_vote = Pubkey::new_unique();

    // Add accounts to test genesis (owner doesn't matter; program only reads bytes)
    pt.add_account(
        reference_vote,
        SolanaAccount {
            lamports: 1_000_000,
            data: reference_votes,
            owner: solana_sdk::vote::program::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        delinquent_vote,
        SolanaAccount {
            lamports: 1_000_000,
            data: delinquent_votes,
            owner: solana_sdk::vote::program::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    // Warp to epoch 5 so that reference sequence [1..5] matches and min_epoch = 0
    let slots_per_epoch = ctx.genesis_config().epoch_schedule.slots_per_epoch;
    let first_normal = ctx.genesis_config().epoch_schedule.first_normal_slot;
    let target_slot = first_normal + slots_per_epoch * 5 + 1;
    ctx.warp_to_slot(target_slot).unwrap();

    // Rewrite vote accounts' data to align with the actual current epoch
    let clock = ctx.banks_client.get_sysvar::<solana_sdk::clock::Clock>().await.unwrap();
    let n = pinocchio_stake::helpers::constant::MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION;
    let start = clock.epoch.saturating_sub(n - 1);
    let mut seq = Vec::with_capacity(n as usize);
    for e in start..=clock.epoch { seq.push((e, 1, 0)); }
    let updated_ref = build_epoch_credits_bytes(&seq);
    let updated_del = build_epoch_credits_bytes(&[(clock.epoch.saturating_sub(n), 1, 0)]);

    // Update accounts in banks
    let mut acc = ctx.banks_client.get_account(reference_vote).await.unwrap().unwrap();
    acc.data = updated_ref;
    ctx.set_account(&reference_vote, &acc.into());
    let mut acc2 = ctx.banks_client.get_account(delinquent_vote).await.unwrap().unwrap();
    acc2.data = updated_del;
    ctx.set_account(&delinquent_vote, &acc2.into());

    // Create stake account and initialize authorities
    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let stake = Keypair::new();
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let create_stake = system_instruction::create_account(
        &ctx.payer.pubkey(),
        &stake.pubkey(),
        reserve,
        space,
        &program_id,
    );
    let msg = Message::new(&[create_stake], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &stake], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let init_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(stake.pubkey(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            AccountMeta::new_readonly(staker.pubkey(), false),
            AccountMeta::new_readonly(withdrawer.pubkey(), true),
        ],
        data: vec![9u8],
    };
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Prefund above reserve with at least the minimum delegation to delegate non-zero stake
    let extra: u64 = common::get_minimum_delegation_lamports(&mut ctx).await;
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&ctx.payer.pubkey(), &stake.pubkey(), extra)],
        Some(&ctx.payer.pubkey()),
        &[&ctx.payer],
        ctx.last_blockhash,
    );
    ctx.banks_client.process_transaction(fund_tx).await.unwrap();

    // Delegate to the delinquent vote account (staker signs)
    let del_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(stake.pubkey(), false),
            AccountMeta::new_readonly(delinquent_vote, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::stake_history::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::stake_history::id(), false),
            AccountMeta::new_readonly(staker.pubkey(), true),
        ],
        data: vec![2u8],
    };
    let msg = Message::new(&[del_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &staker], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Now call DeactivateDelinquent via adapter
    let dd_ix = ixn::deactivate_delinquent(&stake.pubkey(), &delinquent_vote, &reference_vote);
    assert!(dd_ix.accounts.len() >= 3, "dd_ix should have at least 3 metas, got {}", dd_ix.accounts.len());
    let msg = Message::new(&[dd_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    // No signer required by this instruction
    tx.try_sign(&[&ctx.payer], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_ok(), "DeactivateDelinquent should succeed: {:?}", res);

    // Verify stake got deactivated at current epoch
    let clock = ctx.banks_client.get_sysvar::<solana_sdk::clock::Clock>().await.unwrap();
    let acct = ctx.banks_client.get_account(stake.pubkey()).await.unwrap().unwrap();
    let state = pinocchio_stake::state::stake_state_v2::StakeStateV2::deserialize(&acct.data).unwrap();
    match state {
        pinocchio_stake::state::stake_state_v2::StakeStateV2::Stake(_meta, stake_data, _flags) => {
            let deact = u64::from_le_bytes(stake_data.delegation.deactivation_epoch);
            assert_eq!(deact, clock.epoch);
        }
        other => panic!("expected Stake state, got {:?}", other),
    }
}

// Reference vote does not have N consecutive epochs => should fail
#[tokio::test]
async fn deactivate_delinquent_reference_not_consecutive_fails() {
    let mut pt = common::program_test();
    // Create placeholder vote accounts, real bytes will be written after starting context
    let reference_vote = Pubkey::new_unique();
    let delinquent_vote = Pubkey::new_unique();
    pt.add_account(
        reference_vote,
        SolanaAccount { lamports: 1_000_000, data: vec![], owner: solana_sdk::vote::program::id(), executable: false, rent_epoch: 0 }
    );
    pt.add_account(
        delinquent_vote,
        SolanaAccount { lamports: 1_000_000, data: vec![], owner: solana_sdk::vote::program::id(), executable: false, rent_epoch: 0 }
    );

    let mut ctx = pt.start_with_context().await;
    // Build reference sequence with a gap at current epoch window and write into accounts
    let clock = ctx.banks_client.get_sysvar::<solana_sdk::clock::Clock>().await.unwrap();
    let n = pinocchio_stake::helpers::constant::MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION;
    let start = clock.epoch.saturating_sub(n - 1);
    let mut seq = Vec::new();
    for e in start..=clock.epoch {
        if e != clock.epoch.saturating_sub(2) { // inject a gap
            seq.push((e, 1, 0));
        }
    }
    let reference_votes = build_epoch_credits_bytes(&seq);
    let delinquent_votes = build_epoch_credits_bytes(&[(start.saturating_sub(1), 1, 0)]);
    let mut acc = ctx.banks_client.get_account(reference_vote).await.unwrap().unwrap();
    acc.data = reference_votes;
    ctx.set_account(&reference_vote, &acc.into());
    let chk_ref = ctx.banks_client.get_account(reference_vote).await.unwrap().unwrap();
    eprintln!("host2:ref_len={}", chk_ref.data.len());
    let mut acc2 = ctx.banks_client.get_account(delinquent_vote).await.unwrap().unwrap();
    acc2.data = delinquent_votes;
    ctx.set_account(&delinquent_vote, &acc2.into());
    let chk_del = ctx.banks_client.get_account(delinquent_vote).await.unwrap().unwrap();
    eprintln!("host2:del_len={}", chk_del.data.len());
    // Create a minimal initialized stake account
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);
    let stake = Keypair::new();
    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let create = system_instruction::create_account(
        &ctx.payer.pubkey(), &stake.pubkey(), reserve, space, &program_id,
    );
    let msg = Message::new(&[create], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &stake], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();
    let init_ix = Instruction { program_id, accounts: vec![
        AccountMeta::new(stake.pubkey(), false),
        AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        AccountMeta::new_readonly(staker.pubkey(), false),
        AccountMeta::new_readonly(withdrawer.pubkey(), true),
    ], data: vec![9u8] };
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Attempt DeactivateDelinquent
    let dd_ix = ixn::deactivate_delinquent(&stake.pubkey(), &delinquent_vote, &reference_vote);
    assert!(dd_ix.accounts.len() >= 3, "dd_ix should have at least 3 metas, got {}", dd_ix.accounts.len());
    let msg = Message::new(&[dd_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_err(), "expected failure due to non-consecutive reference votes");
}

// Delinquent vote is not old enough => should fail
#[tokio::test]
async fn deactivate_delinquent_not_delinquent_enough_fails() {
    let mut pt = common::program_test();
    let reference_vote = Pubkey::new_unique();
    let delinquent_vote = Pubkey::new_unique();
    pt.add_account(
        reference_vote,
        SolanaAccount { lamports: 1_000_000, data: vec![], owner: solana_sdk::vote::program::id(), executable: false, rent_epoch: 0 }
    );
    pt.add_account(
        delinquent_vote,
        SolanaAccount { lamports: 1_000_000, data: vec![], owner: solana_sdk::vote::program::id(), executable: false, rent_epoch: 0 }
    );

    let mut ctx = pt.start_with_context().await;
    let clock = ctx.banks_client.get_sysvar::<solana_sdk::clock::Clock>().await.unwrap();
    let n = pinocchio_stake::helpers::constant::MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION;
    let start = clock.epoch.saturating_sub(n - 1);
    let mut seq = Vec::new();
    for e in start..=clock.epoch { seq.push((e, 1, 0)); }
    let reference_votes = build_epoch_credits_bytes(&seq);
    let delinquent_votes = build_epoch_credits_bytes(&[(clock.epoch.saturating_sub(2), 1, 0)]);
    let mut acc = ctx.banks_client.get_account(reference_vote).await.unwrap().unwrap();
    acc.data = reference_votes;
    ctx.set_account(&reference_vote, &acc.into());
    let mut acc2 = ctx.banks_client.get_account(delinquent_vote).await.unwrap().unwrap();
    acc2.data = delinquent_votes;
    ctx.set_account(&delinquent_vote, &acc2.into());
    // Create a minimal initialized stake account
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);
    let stake = Keypair::new();
    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let create = system_instruction::create_account(
        &ctx.payer.pubkey(), &stake.pubkey(), reserve, space, &program_id,
    );
    let msg = Message::new(&[create], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &stake], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();
    let init_ix = Instruction { program_id, accounts: vec![
        AccountMeta::new(stake.pubkey(), false),
        AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        AccountMeta::new_readonly(staker.pubkey(), false),
        AccountMeta::new_readonly(withdrawer.pubkey(), true),
    ], data: vec![9u8] };
    let msg = Message::new(&[init_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Attempt DeactivateDelinquent
    let dd_ix = ixn::deactivate_delinquent(&stake.pubkey(), &delinquent_vote, &reference_vote);
    let msg = Message::new(&[dd_ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_err(), "expected failure due to insufficient delinquency");
}
// Only run these when strict-authz is explicitly enabled
#[cfg(not(feature = "strict-authz"))]
fn main() {}
