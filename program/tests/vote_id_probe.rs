#[test]
fn compare_vote_ids() {
    let ours = pinocchio_stake::state::vote_state::ID;
    let sdk = solana_sdk::vote::program::id();
    eprintln!("host:ours={:?}, sdk={:?}", ours, sdk);
    assert_eq!(ours, *sdk.as_ref(), "vote program IDs differ");
}
