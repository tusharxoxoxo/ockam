use clap::{Args, Subcommand};
use miette::IntoDiagnostic;

pub use create::CreateCommand;
pub use list::ListCommand;
use ockam_api::cloud::project::Projects;
use ockam_api::cloud::ProjectNode;
use ockam_api::nodes::InMemoryNode;
pub use show::ShowCommand;

use crate::util::api::{CloudOpts, TrustOpts};
use crate::CommandGlobalOpts;

use self::revoke::RevokeCommand;

mod create;
mod list;
mod revoke;
mod show;

#[derive(Clone, Debug, Args)]
#[command(arg_required_else_help = true, subcommand_required = true)]
pub struct LeaseCommand {
    #[command(subcommand)]
    subcommand: LeaseSubcommand,

    #[command(flatten)]
    cloud_opts: CloudOpts,

    #[command(flatten)]
    trust_opts: TrustOpts,
}

#[derive(Clone, Debug, Subcommand)]
pub enum LeaseSubcommand {
    Create(CreateCommand),
    List(ListCommand),
    Show(ShowCommand),
    Revoke(RevokeCommand),
}

impl LeaseCommand {
    pub fn run(self, options: CommandGlobalOpts) {
        match self.subcommand {
            LeaseSubcommand::Create(c) => c.run(options, self.cloud_opts, self.trust_opts),
            LeaseSubcommand::List(c) => c.run(options, self.cloud_opts, self.trust_opts),
            LeaseSubcommand::Show(c) => c.run(options, self.cloud_opts, self.trust_opts),
            LeaseSubcommand::Revoke(c) => c.run(options, self.cloud_opts, self.trust_opts),
        }
    }
}

async fn authenticate(
    ctx: &ockam_node::Context,
    opts: &CommandGlobalOpts,
    cloud_opts: &CloudOpts,
    trust_opts: &TrustOpts,
) -> miette::Result<ProjectNode> {
    let node =
        InMemoryNode::start_with_trust_context(ctx, &opts.state, trust_opts.project_name()).await?;
    let identity = opts
        .state
        .get_identity_name_or_default(&cloud_opts.identity)
        .await?;
    let project = node
        .get_project_by_name_or_default(ctx, &trust_opts.project_name())
        .await?;

    let authority_identity = project.authority_identity().await.into_diagnostic()?;

    let _authority_node = node
        .create_authority_client(
            authority_identity.identifier(),
            &project.authority_access_route().into_diagnostic()?,
            Some(identity.clone()),
        )
        .await?;

    // FIXME
    // authority_node
    //     .authenticate(ctx, Some(identity.clone()))
    //     .await?;
    node.create_project_client(
        &project.identifier().into_diagnostic()?,
        &project.access_route().into_diagnostic()?,
        Some(identity.clone()),
    )
    .await
}
