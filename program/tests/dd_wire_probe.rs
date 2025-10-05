use bincode;
use solana_sdk::stake::instruction::StakeInstruction as SdkStakeInstruction;

#[test]
fn print_dd_bincode_len() {
    let v = bincode::serialize(&SdkStakeInstruction::DeactivateDelinquent)
        .expect("serialize dd");
    eprintln!("host:dd_bincode_len={}", v.len());
    assert!(v.len() > 0, "expected non-empty bincode for dd");
}

