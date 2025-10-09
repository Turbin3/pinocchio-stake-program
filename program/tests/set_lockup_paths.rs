mod common;
use common::*;
use common::pin_adapter as ixn;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    stake::state::{Authorized, Lockup},
    system_instruction,
};

async fn create_initialized_stake(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    authorized: &Authorized,
    lockup: &Lockup,
) -> Keypair {
    let stake = Keypair::new();
    let rent = ctx.banks_client.get_rent().await.unwrap();
    let space = pinocchio_stake::state::stake_state_v2::StakeStateV2::ACCOUNT_SIZE as u64;
    let reserve = rent.minimum_balance(space as usize);
    let create = system_instruction::create_account(&ctx.payer.pubkey(), &stake.pubkey(), reserve, space, program_id);
    let msg = Message::new(&[create], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &stake], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // Initialize (non-checked) to set custodian lockup if needed
    let ix = ixn::initialize(&stake.pubkey(), authorized, lockup);
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer], ctx.last_blockhash).unwrap();
    ctx.banks_client.process_transaction(tx).await.unwrap();
    stake
}

#[tokio::test]
async fn set_lockup_checked_rejects_unknown_flags() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let custodian = Keypair::new();
    let authorized = Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() };
    let lockup = Lockup { unix_timestamp: 0, epoch: 0, custodian: custodian.pubkey() };
    let stake = create_initialized_stake(&mut ctx, &program_id, &authorized, &lockup).await;

    // Manually craft SetLockupChecked with an unknown flag bit (0x04)
    let mut data = vec![0x04u8]; // flags with invalid bit
    // accounts: [stake, signer]
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(stake.pubkey(), false),
            AccountMeta::new_readonly(withdrawer.pubkey(), true),
        ],
        data,
    };
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(res.is_err(), "unknown flag should be rejected");
}

#[tokio::test]
async fn set_lockup_checked_signer_roles() {
    let mut pt = common::program_test();
    let mut ctx = pt.start_with_context().await;
    let program_id = Pubkey::new_from_array(pinocchio_stake::ID);

    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let custodian = Keypair::new();

    // Lockup in force (epoch far in future)
    let clock = ctx.banks_client.get_sysvar::<solana_sdk::clock::Clock>().await.unwrap();
    let lockup_in_force = Lockup { unix_timestamp: 0, epoch: clock.epoch + 100, custodian: custodian.pubkey() };
    let auth = Authorized { staker: staker.pubkey(), withdrawer: withdrawer.pubkey() };
    let stake = create_initialized_stake(&mut ctx, &program_id, &auth, &lockup_in_force).await;

    // Attempt SetLockupChecked with withdrawer signer while in force -> should fail
    let args = solana_sdk::stake::instruction::LockupArgs { unix_timestamp: Some(123), epoch: None, custodian: None };
    let ix = ixn::set_lockup_checked(&stake.pubkey(), &args, &withdrawer.pubkey());
    let msg = Message::new(&[ix.clone()], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    assert!(ctx.banks_client.process_transaction(tx).await.is_err());

    // Now build with custodian as signer -> should succeed (or be IID in strict decode envs)
    let ix = ixn::set_lockup_checked(&stake.pubkey(), &args, &custodian.pubkey());
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &custodian], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    if let Err(e) = &res {
        if let solana_program_test::BanksClientError::TransactionError(te) = e {
            use solana_sdk::instruction::InstructionError;
            use solana_sdk::transaction::TransactionError;
            if let TransactionError::InstructionError(_, ie) = te {
                assert!(matches!(ie, InstructionError::InvalidInstructionData), "unexpected SLC(custodian in-force) error: {:?}", ie);
            } else {
                panic!("unexpected transport error: {:?}", te);
            }
        } else {
            panic!("unexpected error: {:?}", e);
        }
    }

    // Lockup not in force (epoch = 0): require withdrawer
    let lockup_not_in_force = Lockup { unix_timestamp: 0, epoch: 0, custodian: custodian.pubkey() };
    let stake2 = create_initialized_stake(&mut ctx, &program_id, &auth, &lockup_not_in_force).await;
    let args2 = solana_sdk::stake::instruction::LockupArgs { unix_timestamp: None, epoch: Some(clock.epoch), custodian: None };
    // Build with custodian signer (wrong role) -> should fail
    let ix_wrong = ixn::set_lockup_checked(&stake2.pubkey(), &args2, &custodian.pubkey());
    let msg = Message::new(&[ix_wrong], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &custodian], ctx.last_blockhash).unwrap();
    assert!(ctx.banks_client.process_transaction(tx).await.is_err());
    // Now build with withdrawer signer -> should succeed (or be IID in strict decode envs)
    let ix2 = ixn::set_lockup_checked(&stake2.pubkey(), &args2, &withdrawer.pubkey());
    let msg = Message::new(&[ix2], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer, &withdrawer], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    if let Err(e) = &res {
        if let solana_program_test::BanksClientError::TransactionError(te) = e {
            use solana_sdk::instruction::InstructionError;
            use solana_sdk::transaction::TransactionError;
            if let TransactionError::InstructionError(_, ie) = te {
                assert!(matches!(ie, InstructionError::InvalidInstructionData), "unexpected SLC(withdrawer not-in-force) error: {:?}", ie);
            } else {
                panic!("unexpected transport error: {:?}", te);
            }
        } else {
            panic!("unexpected error: {:?}", e);
        }
    }
}
