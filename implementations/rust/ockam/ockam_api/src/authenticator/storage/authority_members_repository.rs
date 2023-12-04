use crate::authenticator::{AuthorityMember, PreTrustedIdentities};
use ockam::identity::Identifier;
use ockam_core::async_trait;
use ockam_core::compat::boxed::Box;
use ockam_core::compat::vec::Vec;
use ockam_core::Result;

/// This repository stores identity change histories
#[async_trait]
pub trait AuthorityMembersRepository: Send + Sync + 'static {
    async fn get_member(&self, identifier: &Identifier) -> Result<Option<AuthorityMember>>;

    async fn get_members(&self) -> Result<Vec<AuthorityMember>>;

    async fn delete_member(&self, identifier: &Identifier) -> Result<()>;

    async fn add_member(&self, member: AuthorityMember) -> Result<()>;

    async fn bootstrap_pre_trusted_members(
        &self,
        pre_trusted_identities: &PreTrustedIdentities,
    ) -> Result<()>;
}
