use pinocchio::program_error::ProgramError;

// simple internal error enum
#[derive(Debug)]
pub enum StakeError {
    InvalidAuthorization,
    InsufficientFunds,
    InsufficientStake,
    AlreadyDeactivated,
    InsufficientDelegation,
    VoteAddressMismatch,
    MergeMismatch,
    LockupInForce,
    InsufficientReferenceVotes,
    MinimumDelinquentEpochsForDeactivationNotMet
}

// map internal errors to standard program error
pub fn to_program_error(err: StakeError) -> ProgramError {
    match err {
        StakeError::InvalidAuthorization => ProgramError::MissingRequiredSignature,
        StakeError::InsufficientFunds => ProgramError::InsufficientFunds,
        StakeError::InsufficientStake => ProgramError::Custom(0x10),
        StakeError::AlreadyDeactivated => ProgramError::Custom(0x11),
        StakeError::InsufficientDelegation => ProgramError::Custom(0x12),
        StakeError::VoteAddressMismatch => ProgramError::Custom(0x13),
        StakeError::MergeMismatch => ProgramError::Custom(0x14),
        StakeError::LockupInForce => ProgramError::Custom(0x15),
        StakeError::InsufficientReferenceVotes=> ProgramError::Custom(0x16),
        StakeError::MinimumDelinquentEpochsForDeactivationNotMet=> ProgramError::Custom(0x17),
    }
}
