#![cfg(feature = "e2e")]
mod common;
use common::*;
use solana_sdk::{instruction::Instruction, message::Message, stake::instruction as sdk_ixn};

fn is_invalid_instr_data(e: &solana_program_test::BanksClientError) -> bool {
    use solana_sdk::instruction::InstructionError as IE;
    use solana_sdk::transaction::TransactionError as TE;
    matches!(e, solana_program_test::BanksClientError::TransactionError(TE::InstructionError(0, IE::InvalidInstructionData)))
}

#[tokio::test]
async fn empty_payload_is_invalid() {
    let mut ctx = common::program_test().start_with_context().await;
    let ix = Instruction { program_id: Pubkey::new_from_array(pinocchio_stake::ID), accounts: vec![], data: vec![] };
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(matches!(&res, Err(e) if is_invalid_instr_data(e)), "expected InvalidInstructionData, got {:?}", res);
}

#[tokio::test]
async fn single_byte_discriminant_is_invalid() {
    let mut ctx = common::program_test().start_with_context().await;
    let ix = Instruction { program_id: Pubkey::new_from_array(pinocchio_stake::ID), accounts: vec![], data: vec![12u8] };
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(matches!(&res, Err(e) if is_invalid_instr_data(e)), "expected InvalidInstructionData, got {:?}", res);
}

#[tokio::test]
async fn corrupted_variant_tag_is_invalid() {
    let mut ctx = common::program_test().start_with_context().await;
    // Provide truncated payload that cannot contain a full u32 variant tag
    let mut data = vec![0x01, 0x02];
    let ix = Instruction { program_id: Pubkey::new_from_array(pinocchio_stake::ID), accounts: vec![], data };
    let msg = Message::new(&[ix], Some(&ctx.payer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.try_sign(&[&ctx.payer], ctx.last_blockhash).unwrap();
    let res = ctx.banks_client.process_transaction(tx).await;
    assert!(matches!(&res, Err(e) if is_invalid_instr_data(e)), "expected InvalidInstructionData, got {:?}", res);
}
