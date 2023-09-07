use clap::builder::NonEmptyStringValueParser;
use clap::Args;
use colorful::Colorful;

use ockam::Context;
use ockam_api::cloud::addon::{Addons, KafkaConfig};
use ockam_api::nodes::InMemoryNode;

use crate::project::addon::{check_configuration_completion, get_project_id};
use crate::util::node_rpc;
use crate::{docs, fmt_ok, CommandGlobalOpts};

const LONG_ABOUT: &str = include_str!("./static/configure_kafka/long_about.txt");
const AFTER_LONG_HELP: &str = include_str!("./static/configure_kafka/after_long_help.txt");
const REDPANDA_LONG_ABOUT: &str = include_str!("./static/configure_redpanda/long_about.txt");
const REDPANDA_AFTER_LONG_HELP: &str =
    include_str!("./static/configure_redpanda/after_long_help.txt");
const INSTACLUSTR_LONG_ABOUT: &str = include_str!("./static/configure_instaclustr/long_about.txt");
const INSTACLUSTR_AFTER_LONG_HELP: &str =
    include_str!("./static/configure_instaclustr/after_long_help.txt");
const AIVEN_LONG_ABOUT: &str = include_str!("./static/configure_aiven/long_about.txt");
const AIVEN_AFTER_LONG_HELP: &str = include_str!("./static/configure_aiven/after_long_help.txt");
const CONFLUENT_LONG_ABOUT: &str = include_str!("./static/configure_confluent/long_about.txt");
const CONFLUENT_AFTER_LONG_HELP: &str =
    include_str!("./static/configure_confluent/after_long_help.txt");

/// Configure the Apache Kafka addon for a project
#[derive(Clone, Debug, Args)]
pub struct KafkaCommandConfig {
    /// Ockam project name
    #[arg(
        long = "project",
        id = "project",
        value_name = "PROJECT_NAME",
        default_value = "default",
        value_parser(NonEmptyStringValueParser::new())
    )]
    project_name: String,

    /// Bootstrap server address
    #[arg(
        long,
        id = "bootstrap_server",
        value_name = "BOOTSTRAP_SERVER",
        value_parser(NonEmptyStringValueParser::new())
    )]
    bootstrap_server: String,
}

#[derive(Clone, Debug, Args)]
#[command(
long_about = docs::about(LONG_ABOUT),
after_long_help = docs::after_help(AFTER_LONG_HELP),
)]
pub struct AddonConfigureKafkaSubcommand {
    #[command(flatten)]
    inner: KafkaCommandConfig,
}

impl AddonConfigureKafkaSubcommand {
    pub fn run(self, opts: CommandGlobalOpts) {
        node_rpc(run_impl, (opts, "Apache Kafka", self.inner));
    }
}

/// Configure the Redpanda addon for a project
#[derive(Clone, Debug, Args)]
#[command(
long_about = docs::about(REDPANDA_LONG_ABOUT),
after_long_help = docs::after_help(REDPANDA_AFTER_LONG_HELP),
)]
pub struct AddonConfigureRedpandaSubcommand {
    #[command(flatten)]
    inner: KafkaCommandConfig,
}

impl AddonConfigureRedpandaSubcommand {
    pub fn run(self, opts: CommandGlobalOpts) {
        node_rpc(run_impl, (opts, "Redpanda", self.inner));
    }
}

/// Configure the Instaclustr (Kafka) addon for a project
#[derive(Clone, Debug, Args)]
#[command(
long_about = docs::about(INSTACLUSTR_LONG_ABOUT),
after_long_help = docs::after_help(INSTACLUSTR_AFTER_LONG_HELP),
)]
pub struct AddonConfigureInstaclustrSubcommand {
    #[command(flatten)]
    inner: KafkaCommandConfig,
}

impl AddonConfigureInstaclustrSubcommand {
    pub fn run(self, opts: CommandGlobalOpts) {
        node_rpc(run_impl, (opts, "Instaclustr (Kafka)", self.inner));
    }
}

/// Configure the Aiven (Kafka) addon for a project
#[derive(Clone, Debug, Args)]
#[command(
long_about = docs::about(AIVEN_LONG_ABOUT),
after_long_help = docs::after_help(AIVEN_AFTER_LONG_HELP),
)]
pub struct AddonConfigureAivenSubcommand {
    #[command(flatten)]
    inner: KafkaCommandConfig,
}

impl AddonConfigureAivenSubcommand {
    pub fn run(self, opts: CommandGlobalOpts) {
        node_rpc(run_impl, (opts, "Aiven (Kafka)", self.inner));
    }
}

/// Configure the Confluent addon for a project
#[derive(Clone, Debug, Args)]
#[command(
long_about = docs::about(CONFLUENT_LONG_ABOUT),
after_long_help = docs::after_help(CONFLUENT_AFTER_LONG_HELP),
)]
pub struct AddonConfigureConfluentSubcommand {
    #[command(flatten)]
    inner: KafkaCommandConfig,
}

impl AddonConfigureConfluentSubcommand {
    pub fn run(self, opts: CommandGlobalOpts) {
        node_rpc(run_impl, (opts, "Confluent", self.inner));
    }
}

async fn run_impl(
    ctx: Context,
    (opts, addon_name, cmd): (CommandGlobalOpts, &str, KafkaCommandConfig),
) -> miette::Result<()> {
    let KafkaCommandConfig {
        project_name,
        bootstrap_server,
    } = cmd;
    let project_id = get_project_id(&opts.state, project_name.as_str())?;
    let config = KafkaConfig::new(bootstrap_server);

    let node = InMemoryNode::start(&ctx, &opts.state).await?;
    let controller = node.create_controller().await?;

    let response = controller
        .configure_confluent_addon(&ctx, project_id.clone(), config)
        .await?;
    check_configuration_completion(&opts, &ctx, &node, project_id, response.operation_id).await?;

    opts.terminal
        .write_line(&fmt_ok!("{} addon configured successfully", addon_name))?;

    Ok(())
}
