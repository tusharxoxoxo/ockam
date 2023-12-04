use minicbor::Decoder;
use ockam::identity::utils::now;
use ockam::identity::{Identifier, IdentitySecureChannelLocalInfo};
use ockam_core::api::{Method, RequestHeader, Response};
use ockam_core::compat::sync::Arc;
use ockam_core::{Result, Routed, Worker};
use ockam_node::Context;
use tracing::trace;

use crate::authenticator::one_time_code::OneTimeCode;
use crate::authenticator::{
    secure_channel_required, AuthorityEnrollmentTokensRepository, AuthorityMember,
    AuthorityMembersRepository,
};

pub struct EnrollmentTokenAcceptor {
    pub(super) tokens: Arc<dyn AuthorityEnrollmentTokensRepository>,
    pub(super) members: Arc<dyn AuthorityMembersRepository>,
}

impl EnrollmentTokenAcceptor {
    pub fn new(
        tokens: Arc<dyn AuthorityEnrollmentTokensRepository>,
        members: Arc<dyn AuthorityMembersRepository>,
    ) -> Self {
        Self { tokens, members }
    }

    async fn accept_token(
        &mut self,
        req: &RequestHeader,
        otc: OneTimeCode,
        from: &Identifier,
    ) -> Result<Vec<u8>> {
        let token = match self.tokens.use_token(otc, now()?).await {
            Ok(Some(token)) => token,
            Ok(None) => {
                return Ok(Response::forbidden(req, "unknown token").to_vec()?);
            }
            Err(_) => {
                return Ok(Response::forbidden(req, "unknown token").to_vec()?);
            }
        };

        //TODO: fixme:  unify use of hashmap vs btreemap
        let attrs = token
            .attrs
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();

        let member = AuthorityMember::new(
            from.clone(),
            attrs,
            Some(token.issued_by),
            now()?,
            None,
            false,
        );

        if let Err(_err) = self.members.add_member(member).await {
            return Ok(Response::internal_error(req, "attributes storage error").to_vec()?);
        }

        Ok(Response::ok().with_headers(req).to_vec()?)
    }
}

#[ockam_core::worker]
impl Worker for EnrollmentTokenAcceptor {
    type Context = Context;
    type Message = Vec<u8>;

    async fn handle_message(&mut self, c: &mut Context, m: Routed<Self::Message>) -> Result<()> {
        if let Ok(i) = IdentitySecureChannelLocalInfo::find_info(m.local_message()) {
            let from = i.their_identity_id();
            let mut dec = Decoder::new(m.as_body());
            let req: RequestHeader = dec.decode()?;
            trace! {
                target: "ockam_api::authenticator::direct::enrollment_token_acceptor",
                from   = %from,
                id     = %req.id(),
                method = ?req.method(),
                path   = %req.path(),
                body   = %req.has_body(),
                "request"
            }
            let res = match (req.method(), req.path()) {
                (Some(Method::Post), "/") | (Some(Method::Post), "/credential") => {
                    let otc: OneTimeCode = dec.decode()?;
                    self.accept_token(&req, otc, &from).await?
                }
                _ => Response::unknown_path(&req).to_vec()?,
            };
            c.send(m.return_route(), res).await
        } else {
            secure_channel_required(c, m).await
        }
    }
}
