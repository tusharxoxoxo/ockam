use std::collections::HashMap;

use minicbor::Decoder;
use tracing::trace;

use ockam::identity::utils::now;
use ockam::identity::{AttributesEntry, TimestampInSeconds};
use ockam::identity::{Identifier, IdentitySecureChannelLocalInfo};
use ockam_core::api::{Method, RequestHeader, Response};
use ockam_core::compat::sync::Arc;
use ockam_core::{CowStr, Result, Routed, Worker};
use ockam_node::Context;

use crate::authenticator::direct::types::AddMember;
use crate::authenticator::{secure_channel_required, AuthorityMember, AuthorityMembersRepository};

pub struct DirectAuthenticator {
    members: Arc<dyn AuthorityMembersRepository>,
}

impl DirectAuthenticator {
    pub async fn new(members: Arc<dyn AuthorityMembersRepository>) -> Result<Self> {
        Ok(Self { members })
    }

    async fn add_member<'a>(
        &self,
        enroller: &Identifier,
        id: &Identifier,
        attrs: &HashMap<CowStr<'a>, CowStr<'a>>,
        expires_at: Option<TimestampInSeconds>,
    ) -> Result<()> {
        let auth_attrs = attrs
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        let member = AuthorityMember::new(
            id.clone(),
            auth_attrs,
            Some(enroller.clone()),
            now()?,
            expires_at,
            false,
        );
        self.members.add_member(member).await
    }

    async fn list_members(&self) -> Result<HashMap<Identifier, AttributesEntry>> {
        let all_members = self.members.get_members().await?;

        let mut res = HashMap::<Identifier, AttributesEntry>::default();
        for member in all_members {
            let entry = AttributesEntry::new(
                member.attributes().clone(),
                member.added_at(),
                None,
                member.added_by().clone(),
            );
            res.insert(member.identifier().clone(), entry);
        }

        Ok(res)
    }
}

#[ockam_core::worker]
impl Worker for DirectAuthenticator {
    type Context = Context;
    type Message = Vec<u8>;

    async fn handle_message(&mut self, c: &mut Context, m: Routed<Self::Message>) -> Result<()> {
        if let Ok(i) = IdentitySecureChannelLocalInfo::find_info(m.local_message()) {
            let from = i.their_identity_id();
            let mut dec = Decoder::new(m.as_body());
            let req: RequestHeader = dec.decode()?;
            trace! {
                target: "ockam_api::authenticator::direct::direct_authenticator",
                from   = %from,
                id     = %req.id(),
                method = ?req.method(),
                path   = %req.path(),
                body   = %req.has_body(),
                "request"
            }
            let path_segments = req.path_segments::<5>();
            let res = match (req.method(), path_segments.as_slice()) {
                (Some(Method::Post), [""]) | (Some(Method::Post), ["members"]) => {
                    let add: AddMember = dec.decode()?;
                    self.add_member(&from, add.member(), add.attributes(), add.expires_at())
                        .await?;
                    Response::ok().with_headers(&req).to_vec()?
                }
                (Some(Method::Get), ["member_ids"]) => {
                    let entries = self.list_members().await?;
                    let ids: Vec<Identifier> = entries.into_keys().collect();
                    Response::ok().with_headers(&req).body(ids).to_vec()?
                }
                (Some(Method::Get), [""]) | (Some(Method::Get), ["members"]) => {
                    let entries = self.list_members().await?;

                    Response::ok().with_headers(&req).body(entries).to_vec()?
                }
                (Some(Method::Delete), [id]) | (Some(Method::Delete), ["members", id]) => {
                    let identifier = Identifier::try_from(id.to_string())?;
                    self.members.delete_member(&identifier).await?;

                    Response::ok().with_headers(&req).to_vec()?
                }

                _ => Response::unknown_path(&req).to_vec()?,
            };
            c.send(m.return_route(), res).await
        } else {
            secure_channel_required(c, m).await
        }
    }
}
