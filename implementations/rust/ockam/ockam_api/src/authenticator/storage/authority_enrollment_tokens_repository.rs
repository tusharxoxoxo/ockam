use crate::authenticator::one_time_code::OneTimeCode;
use crate::authenticator::Token;
use ockam::identity::TimestampInSeconds;
use ockam_core::async_trait;
use ockam_core::compat::boxed::Box;
use ockam_core::Result;

/// This repository stores identity change histories
#[async_trait]
pub trait AuthorityEnrollmentTokensRepository: Send + Sync + 'static {
    async fn use_token(
        &self,
        one_time_code: OneTimeCode,
        now: TimestampInSeconds,
    ) -> Result<Option<Token>>;

    async fn issue_token(&self, token: Token) -> Result<()>;
}
