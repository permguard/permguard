// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The command line, as clap parses it: the globals every command shares,
//! the command tree, and the sub-actions of each family.
//!
//! Shape only — no behaviour. What a command *does* lives in `commands/`,
//! which is what keeps this file readable as the CLI's contract with the
//! people who type into it.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::output::OutputFormat;

#[derive(Debug, Parser)]
#[command(
    name = "permguard",
    about = "Permguard command-line interface",
    before_help = crate::banner::banner(),
    before_long_help = crate::banner::banner()
)]
pub struct Cli {
    #[command(flatten)]
    pub globals: Globals,

    #[command(subcommand)]
    pub command: Command,
}

/// What applies to every command.
///
/// The endpoints and the TLS material are here rather than on `inspect` because they describe *which
/// Permguard* is being talked to, which every command that talks to one needs, and because an
/// operator should not have to learn where a flag lives per command.
#[derive(Debug, Args)]
pub struct Globals {
    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal, global = true)]
    pub output: OutputFormat,

    /// Narrate what is being done, on stderr.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Directory relative paths are resolved against.
    #[arg(short, long, global = true, default_value = ".", value_name = "DIR")]
    pub workdir: PathBuf,

    /// Configuration file to read and write, instead of ~/.permguard/config.yml.
    #[arg(long, global = true, env = "PERMGUARD_CONFIG", value_name = "FILE")]
    pub config: Option<String>,

    /// Where the control plane is reached.
    #[arg(long, global = true, alias = "endpoint", value_name = "URL")]
    pub control_endpoint: Option<String>,

    /// Where the data plane is reached.
    #[arg(long, global = true, value_name = "URL")]
    pub data_endpoint: Option<String>,

    /// Certificate authority the endpoint's certificate is checked against (PEM).
    #[arg(
        long,
        global = true,
        env = "PERMGUARD_TLS_CA_FILE",
        value_name = "FILE"
    )]
    pub tls_ca_file: Option<PathBuf>,

    /// Our own certificate, for an endpoint that asks for one — mutual TLS (PEM).
    #[arg(
        long,
        global = true,
        env = "PERMGUARD_TLS_CERT_FILE",
        value_name = "FILE"
    )]
    pub tls_cert_file: Option<PathBuf>,

    /// The private key belonging to that certificate (PEM).
    #[arg(
        long,
        global = true,
        env = "PERMGUARD_TLS_KEY_FILE",
        value_name = "FILE"
    )]
    pub tls_key_file: Option<PathBuf>,

    /// Name to check the endpoint's certificate against, when it is not the endpoint's host.
    #[arg(
        long,
        global = true,
        env = "PERMGUARD_TLS_SERVER_NAME",
        value_name = "NAME"
    )]
    pub tls_server_name: Option<String>,

    /// Accept any server certificate. Insecure, and for development only.
    #[arg(long, global = true, env = "PERMGUARD_TLS_SKIP_VERIFY")]
    pub tls_skip_verify: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Report this CLI's version and the build it came from.
    Version,
    /// Manage zones — the isolation boundary everything else lives inside.
    Zones {
        #[command(subcommand)]
        action: ZonesAction,
    },
    /// Manage ledgers — the named containers inside a zone.
    Ledgers {
        #[command(subcommand)]
        action: LedgersAction,
    },
    /// Read and write the CLI's own configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Print shell completions. Add to your shell's config to complete commands and flags.
    #[command(
        after_help = "Examples:\n  permguard completion zsh > \"${fpath[1]}/_permguard\"\n  permguard completion bash >> ~/.bashrc"
    )]
    Completion {
        /// The shell to generate for.
        shell: clap_complete::Shell,
    },
    /// Initialize a permguard workspace in the working directory.
    Init {
        /// The workspace name, written into the manifest.
        #[arg(default_value = "permguard-workspace")]
        name: String,
        /// The languages to author in (comma-separated). Cedar by default.
        #[arg(long, value_delimiter = ',', default_value = "cedar")]
        language: Vec<String>,
    },
    /// Manage the named remote servers of this workspace.
    Remote {
        #[command(subcommand)]
        action: RemoteAction,
    },
    /// Clone a remote ledger into a fresh workspace directory.
    Clone {
        /// https://host[:port][/prefix]/<zone>/<ledger>
        url: String,
        /// Where to clone; defaults to the ledger name.
        directory: Option<std::path::PathBuf>,
    },
    /// Bind this workspace to a remote ledger and materialize it.
    Checkout {
        /// <remote>/<zone>/<ledger>[@<ref>]
        reference: String,
    },
    /// Fetch the latest changes, verify them, and materialize what is missing.
    Pull,
    /// Scan the sources and build the local snapshot.
    Refresh,
    /// Refresh plus every local check: manifest, identities, duplicates.
    Validate,
    /// Show what apply would change on the remote ledger.
    Plan,
    /// Plan, then push the changes to the remote ledger.
    Apply {
        /// The commit message.
        #[arg(short, long, default_value = "apply")]
        message: String,
    },
    /// Show the commit history of the tracked ref.
    History,
    /// Show what this workspace tracks and where it stands — offline.
    Status,
    /// Inspect the local object store.
    Objects {
        #[command(subcommand)]
        action: ObjectsAction,
    },
    /// Verify the remote head statement and the local closure.
    Verify,
    /// Ask a data plane for an authorization decision.
    #[command(
        after_help = "Examples:\n  permguard check -f request.json\n  cat request.json | permguard check -f -\n  permguard check --subject user:alice --action read --resource document:budget\n  permguard check -f request.json --zone acme --ledger main-ledger -o json"
    )]
    Check(CheckArgs),
    /// Read the decisions a data plane recorded.
    ///
    /// Every subcommand reads from an offset that belongs to the consumer, and the control plane
    /// keeps no cursor: two people running `permguard decisions tail` at once do not interfere,
    /// and neither can back-pressure the plane that is deciding.
    #[command(
        after_help = "Examples:\n  permguard decisions list --zone acme --ledger main-ledger\n  permguard decisions tail --follow\n  permguard decisions get 0198f3f2-7c1a-7e2b-9f4c-1d2e3a4b5c6d\n  permguard decisions export --from <offset> -o json\n  permguard decisions list --verify --keys data-plane-keys.json"
    )]
    Decisions {
        #[command(subcommand)]
        action: DecisionsAction,
    },
    /// Report what each Permguard plane is, and whether it is willing to be sent work.
    ///
    /// Every plane is probed and reported, whether it answers or not: a plane that is down is a
    /// line in the report, not a failure of the command. A plane that answers is asked for its
    /// health too, so `ready`, `degraded` and `unhealthy` are told apart rather than all reported
    /// as reachable.
    Inspect {
        /// How long to wait for one request, in seconds.
        #[arg(long, default_value = "5", value_name = "SECONDS")]
        timeout: u64,
    },
}

/// What to read, and how far.
#[derive(Debug, Subcommand)]
pub enum DecisionsAction {
    /// List a page of decisions, oldest first.
    List(DecisionsQuery),
    /// Follow the decisions as they arrive.
    Tail {
        #[command(flatten)]
        query: DecisionsQuery,
        /// Keep reading instead of stopping at the end of what is held.
        #[arg(long)]
        follow: bool,
    },
    /// Show one decision, by the identifier the caller was given back.
    Get {
        /// The decision's own identifier, as it appeared in `context.id`.
        id: String,
        #[command(flatten)]
        query: DecisionsQuery,
    },
    /// Read in bulk, resumably: every page, from an offset, to standard output.
    Export(DecisionsQuery),
}

/// Which decisions, and how they are checked.
#[derive(Debug, clap::Args)]
pub struct DecisionsQuery {
    /// The zone whose decisions to read, overriding the workspace.
    #[arg(long, value_name = "ZONE")]
    pub zone: Option<String>,

    /// The ledger whose decisions to read, overriding the workspace.
    #[arg(long, value_name = "LEDGER")]
    pub ledger: Option<String>,

    /// Read one producer's whole stream instead of one tenant's records.
    ///
    /// The most powerful read in the system — every tenant's decisions, which is who accessed
    /// what — and the only one from which a producer chain can be verified end to end.
    #[arg(long, value_name = "PDP_ID", requires = "instance")]
    pub pdp: Option<String>,

    /// Which incarnation of that producer.
    #[arg(long, value_name = "INSTANCE", requires = "pdp")]
    pub instance: Option<String>,

    /// Where to resume from: the opaque offset a previous page returned.
    #[arg(long, value_name = "OFFSET")]
    pub from: Option<String>,

    /// How many records to read at once.
    #[arg(long, default_value = "100", value_name = "N")]
    pub limit: usize,

    /// Only decisions at or after this RFC 3339 timestamp.
    #[arg(long, value_name = "TIMESTAMP")]
    pub since: Option<String>,

    /// Only permits, or only denies.
    #[arg(long, value_name = "permit|deny")]
    pub decision: Option<String>,

    /// Re-compute the chain, and the signatures when a key set is given.
    ///
    /// Without `--keys` this checks that the records are a contiguous, unaltered chain — which is
    /// what the records alone can prove. With one, it also checks that the batches were signed by
    /// a key that set publishes, which is what makes the answer independent of the server that
    /// served it.
    #[arg(long)]
    pub verify: bool,

    /// The producer's published key set (a JWKS file), for `--verify`.
    #[arg(long, value_name = "FILE")]
    pub keys: Option<String>,

    /// Read the document exactly as asked, even inside a workspace.
    #[arg(long)]
    pub ignore_workspace: bool,
}

#[derive(Debug, Subcommand)]
pub enum RemoteAction {
    /// Add (or replace) a named remote.
    Add {
        name: String,
        /// https://host[:port][/prefix]
        url: String,
    },
    /// List the remotes.
    List,
    /// Remove a remote.
    Remove { name: String },
}

#[derive(Debug, Subcommand)]
pub enum ObjectsAction {
    /// List the local store: every object, its kind, and who reaches it.
    List {
        /// Only objects reachable from the tracked remote head.
        #[arg(long)]
        tracked: bool,
        /// Only objects reachable from the staged snapshot.
        #[arg(long)]
        staged: bool,
    },
    /// Remove objects nothing reaches: an interrupted pull, a snapshot nobody applied,
    /// a policy version the head has moved past.
    #[command(
        after_help = "Examples:\n  permguard objects prune --dry-run\n  permguard objects prune\n  permguard objects prune --dry-run -o json | jq '.bytes'"
    )]
    Prune {
        /// Report what would go, and remove nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print one object. Default view: a blob's content; otherwise `--human`.
    Cat {
        digest: String,
        /// The exact stored bytes (canonical CBOR), for piping.
        #[arg(long, conflicts_with_all = ["content", "inspect", "human"])]
        raw: bool,
        /// A blob's payload, nothing else.
        #[arg(long, conflicts_with_all = ["inspect", "human"])]
        content: bool,
        /// Every field, as a structured report (works with -o json/yaml).
        #[arg(long, conflicts_with = "human")]
        inspect: bool,
        /// A reading for people: commits like a log, trees as a listing.
        #[arg(long)]
        human: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Show every setting, its value, and which layer that value came from.
    Show,
    /// Print one setting's value, and nothing else.
    Get {
        /// The setting to read.
        key: String,
    },
    /// Write one setting into the configuration file.
    Set {
        /// The setting to write.
        key: String,
        /// The value to write.
        value: String,
    },
    /// Take settings back out of the configuration file.
    Reset {
        /// The setting to reset. Every setting, when left out.
        key: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ZonesAction {
    /// Create a zone. Names are lowercase a-z, 0-9, `-` and `_`, unique across the deployment.
    #[command(
        after_help = "Examples:\n  permguard zones create pharma\n  permguard zones create pharma -o json"
    )]
    Create { name: String },
    /// List zones — every one, or a page at a time.
    #[command(
        after_help = "Examples:\n  permguard zones list\n  permguard zones list --page 2 --size 50\n  permguard zones list -o json | jq '.zones[].name'"
    )]
    List {
        /// Which page of the listing, starting at 1. Absent: everything.
        #[arg(long, value_name = "N")]
        page: Option<u32>,
        /// How many entries per page (server-capped). Absent with --page: 100.
        #[arg(long, value_name = "N")]
        size: Option<u32>,
    },
    /// Show one zone, by name or id.
    #[command(
        after_help = "Examples:\n  permguard zones get pharma\n  permguard zones get 01a02b7b-e9e8-73c2-9aa9-a95039e7bdf6 -o json"
    )]
    Get { zone: String },
    /// Update a zone — today its name, with `--name`. The id never changes.
    #[command(
        after_help = "Examples:\n  permguard zones update pharma --name pharma-eu\n  permguard zones update 01a02b7b-e9e8-73c2-9aa9-a95039e7bdf6 --name pharma-eu -o json"
    )]
    Update {
        zone: String,
        /// The new name.
        #[arg(long)]
        name: String,
    },
    /// Delete a zone. Refused while it still holds ledgers.
    #[command(
        after_help = "Examples:\n  permguard zones delete pharma\n  permguard zones delete pharma -o json"
    )]
    Delete { zone: String },
}

#[derive(Debug, Subcommand)]
pub enum LedgersAction {
    /// Create a ledger inside a zone. Names are unique within their zone.
    #[command(
        after_help = "Examples:\n  permguard ledgers create --zone pharma policies\n  permguard ledgers create --zone pharma policies -o json"
    )]
    Create {
        /// The zone, by name or id.
        #[arg(long, alias = "zone-id")]
        zone: String,
        name: String,
    },
    /// List a zone's ledgers — every one, or a page at a time.
    #[command(
        after_help = "Examples:\n  permguard ledgers list --zone pharma\n  permguard ledgers list --zone pharma --page 2 --size 50\n  permguard ledgers list --zone pharma -o json | jq '.ledgers[].id'"
    )]
    List {
        #[arg(long, alias = "zone-id")]
        zone: String,
        /// Which page of the listing, starting at 1. Absent: everything.
        #[arg(long, value_name = "N")]
        page: Option<u32>,
        /// How many entries per page (server-capped). Absent with --page: 100.
        #[arg(long, value_name = "N")]
        size: Option<u32>,
    },
    /// Show one ledger, by name or id.
    #[command(
        after_help = "Examples:\n  permguard ledgers get --zone pharma policies\n  permguard ledgers get --zone pharma 01a02b87-818c-79d7-b171-e9f7d3645083 -o json"
    )]
    Get {
        #[arg(long, alias = "zone-id")]
        zone: String,
        ledger: String,
    },
    /// Update a ledger — today its name, with `--name`. The id never changes.
    #[command(
        after_help = "Examples:\n  permguard ledgers update --zone pharma policies --name policies-v2\n  permguard ledgers update --zone pharma policies --name policies-v2 -o json"
    )]
    Update {
        #[arg(long, alias = "zone-id")]
        zone: String,
        ledger: String,
        #[arg(long)]
        name: String,
    },
    /// Delete a ledger.
    #[command(after_help = "Examples:\n  permguard ledgers delete --zone pharma policies")]
    Delete {
        #[arg(long, alias = "zone-id")]
        zone: String,
        ledger: String,
    },
}

/// What `permguard check` was told.
///
/// A document or the flags that describe one, plus which store to ask about —
/// see [`crate::target`] for how that is resolved.
#[derive(Debug, Args)]
pub struct CheckArgs {
    /// The request document (the `permguard.pdp.v1` payload). `-` reads standard input.
    #[arg(short, long, value_name = "FILE")]
    pub file: Option<String>,

    /// The zone to ask about, overriding the workspace and the document.
    #[arg(long, value_name = "ZONE")]
    pub zone: Option<String>,

    /// The ledger to ask about, overriding the workspace and the document.
    #[arg(long, value_name = "LEDGER")]
    pub ledger: Option<String>,

    /// Which of the ledger's profiles to evaluate. `default` when absent.
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<String>,

    /// Whom the decision is about, as `type:id`.
    #[arg(long, value_name = "TYPE:ID")]
    pub subject: Option<String>,

    /// The operation, e.g. `read`.
    #[arg(long, value_name = "NAME")]
    pub action: Option<String>,

    /// What it targets, as `type:id`.
    #[arg(long, value_name = "TYPE:ID")]
    pub resource: Option<String>,

    /// Environmental attributes, as a JSON object.
    #[arg(long, value_name = "JSON")]
    pub context: Option<String>,

    /// Send the document exactly as written, even inside a workspace.
    #[arg(long)]
    pub ignore_workspace: bool,
}
