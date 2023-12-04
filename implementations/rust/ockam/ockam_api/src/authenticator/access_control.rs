use crate::authenticator::AuthorityMembersRepository;
use ockam::identity::IdentitySecureChannelLocalInfo;
use ockam_core::access_control::IncomingAccessControl;
use ockam_core::compat::sync::Arc;
use ockam_core::{async_trait, compat::boxed::Box, RelayMessage, Result};
use std::fmt::{Debug, Formatter};

pub struct EnrollersOnlyAccessControl {
    members: Arc<dyn AuthorityMembersRepository>,
}

impl Debug for EnrollersOnlyAccessControl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnrollersOnlyAccessControl")
    }
}

impl EnrollersOnlyAccessControl {
    /// Constructor
    pub fn new(members: Arc<dyn AuthorityMembersRepository>) -> Self {
        Self { members }
    }
}

#[async_trait]
impl IncomingAccessControl for EnrollersOnlyAccessControl {
    async fn is_authorized(&self, relay_msg: &RelayMessage) -> Result<bool> {
        // Get identity identifier from message metadata:
        let id = if let Ok(info) =
            IdentitySecureChannelLocalInfo::find_info(relay_msg.local_message())
        {
            info.their_identity_id()
        } else {
            warn! {
                "identity identifier not found; access denied"
            }
            return Ok(false);
        };

        let member = if let Some(member) = self.members.get_member(&id).await? {
            member
        } else {
            warn! {
                "member not found; access denied"
            }
            return Ok(false);
        };

        // TODO: Move to consts
        return if let Some(val) = member.attributes().get("ockam-role".as_bytes()) {
            if val == b"enroller" {
                Ok(true)
            } else {
                warn! {
                    "member not enroller; access denied"
                }
                Ok(false)
            }
        } else {
            warn! {
                "member doesn't have role; access denied"
            }
            Ok(false)
        };
    }
}
