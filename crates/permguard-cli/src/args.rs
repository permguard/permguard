// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The command line, as clap parses it: the globals every command shares,
//! the command tree, and the sub-actions of each family.
//!
//! Shape only — no behaviour. What a command *does* lives in `commands/`,
//! which is what keeps this file readable as the CLI's contract with the
//! people who type into it.

use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand};

use crate::output::OutputFormat;

/// The heading the flags that apply to every command are listed under.
///
/// Their own block, rather than mixed into each command's: clap appends a global flag wherever it
/// is inherited, which interleaves `--tls-ca-file` with `--follow` in an order nobody chose and
/// which comes out different per command. The heading is what makes every help read the same way —
/// the command's own flags, then the ones that are the same everywhere.
const GLOBAL_HEADING: &str = "Global options";

/// A display order past anything the tree declares, so that `-h` closes every help.
const HELP_LAST: usize = 1000;

/// The command tree, with one help instead of two.
///
/// clap answers `-h` with a summary and `--help` with an expanded form, so the
/// same question asked two ways gets two different answers — and the short one
/// says "see more with '--help'", which tells a user that what they just read
/// was abridged. A CLI's help is a contract, and a contract with an abridged
/// edition is two contracts. Both spell the same help, on every command in the
/// tree, and the flag says so: "Print help".
pub fn command() -> clap::Command {
    one_help(Cli::command())
}

/// `-h` and `--help` print the same help — the compact one, with the banner
/// above it — here and in every subcommand below.
///
/// Compact rather than expanded because the expanded form puts every argument's
/// description on its own line below the flag, which turns one screenful into
/// several and buries the command list a reader is scanning. Nothing is lost:
/// the compact form still carries the defaults, the possible values and the
/// `[env: …]` names. Only the second paragraph of a doc comment is left out, and
/// that is rationale for whoever reads the source, not an answer somebody at a
/// terminal is looking for.
///
/// The banner is on every command rather than only the root because every help
/// is a place somebody arrives at cold, and `permguard init -h` is as likely to
/// be the first thing a person sees as `permguard --help` is. It costs nothing
/// elsewhere: help is the one output that carries no data, so unlike a report
/// there is no `-o json` for the decoration to corrupt.
///
/// The help flag is declared rather than mutated: clap generates its own only
/// while building, and reaching for it before that is a panic. Declaring it
/// means turning clap's off, which is what `disable_help_flag` is for.
///
/// The same goes for the `help` subcommand, the third spelling of the question:
/// clap's own answers it with the expanded form, and answers it from inside the
/// parser, where there is nothing left to intervene on. It is turned off and
/// replaced by a stand-in that parses but does nothing, so that `help_request`
/// can read it back out of the matches and `main` can print the one help.
fn one_help(command: clap::Command) -> clap::Command {
    let subcommands: Vec<String> = command
        .get_subcommands()
        .map(|subcommand| subcommand.get_name().to_owned())
        .collect();
    let has_subcommands = !subcommands.is_empty();

    let mut command = command
        .before_help(crate::banner::banner())
        .before_long_help(crate::banner::banner())
        .disable_help_flag(true)
        .disable_help_subcommand(true)
        .arg(
            clap::Arg::new("help")
                .short('h')
                .long("help")
                .action(clap::ArgAction::HelpShort)
                .help("Print help")
                .help_heading(GLOBAL_HEADING)
                // Last, always. Without an order of its own it takes the one its insertion index
                // gives it, which is a count of the command's own arguments — so it lands in a
                // different place in every command's help, which is the thing being fixed.
                .display_order(HELP_LAST),
        )
        // One dialect for the environment, everywhere: `[env: NAME]`. clap's own rendering appends
        // the variable's current value, which the two endpoints — read by `settings` rather than by
        // clap, so that `config show` can still say where a value came from — cannot produce, and
        // which would put a machine's TLS paths into the output of `--help`.
        .mut_args(|arg| arg.hide_env_values(true));

    // clap builds a help flag per command, so the whole tree has to be walked:
    // consistency that stops at the first level is the inconsistency again.
    for name in subcommands {
        command = command.mut_subcommand(name, one_help);
    }

    // Only where clap would have put one, so that `permguard version help` stays
    // the usage error it always was.
    if has_subcommands {
        command = command.subcommand(one_help(help_subcommand()));
    }

    command
}

/// The stand-in for clap's `help` subcommand: the same name, the same summary,
/// the same trailing list of command names, and no behaviour of its own.
fn help_subcommand() -> clap::Command {
    clap::Command::new("help")
        .about("Print this message or the help of the given subcommand(s)")
        .arg(
            clap::Arg::new("command")
                .value_name("COMMAND")
                .num_args(0..)
                .help("The command to describe, and its own subcommand"),
        )
}

/// The path of command names a `help` invocation asks about, when the invocation
/// is one — empty for a bare `permguard help`.
///
/// Read off the matches rather than off the derived `Command`, because the
/// stand-in lives in the clap tree and has no variant there: reaching it means
/// the question was help, and it is answered before anything is derived.
pub fn help_request(matches: &clap::ArgMatches) -> Option<Vec<String>> {
    let mut path = Vec::new();
    let mut current = matches;

    loop {
        let (name, inner) = current.subcommand()?;

        if name == "help" {
            path.extend(
                inner
                    .get_many::<String>("command")
                    .into_iter()
                    .flatten()
                    .cloned(),
            );

            return Some(path);
        }

        path.push(name.to_owned());
        current = inner;
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "permguard",
    // The banner is not here: `one_help` puts it on this command and on every one below it,
    // from a single place, so the root cannot end up wearing a different one.
    about = "Permguard command-line interface",
    // Spelled out because clap hands a flattened struct's doc comment to whichever of the two the
    // command has not set, and `Globals` explains itself to a reader of the source, not to somebody
    // asking what `permguard` is.
    long_about = "Permguard command-line interface"
)]
pub struct Cli {
    #[command(flatten)]
    pub globals: Globals,

    /// Report this CLI's version and the build it came from.
    ///
    /// The same answer `permguard version` gives, in whichever format was asked for — one
    /// question, one answer, however it is spelled. `-V` rather than `-v`, which is `--verbose`.
    #[arg(short = 'V', long, help_heading = GLOBAL_HEADING)]
    pub version: bool,

    /// Optional so that `--version` can be asked without naming a command — and so that a bare
    /// `permguard` is a question rather than a mistake: it is answered with the help, on stdout,
    /// and a zero status. Nothing was typed wrong.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// What applies to every command.
///
/// The endpoints and the TLS material are here rather than on `inspect` because they describe *which
/// Permguard* is being talked to, which every command that talks to one needs, and because an
/// operator should not have to learn where a flag lives per command.
#[derive(Debug, Args)]
#[command(next_help_heading = GLOBAL_HEADING)]
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

    // Not clap's `env`: `config show` reports which of flag, environment and file a value came
    // from, and a value clap resolved would arrive indistinguishable from a flag. `settings` reads
    // the variable itself — so the help has to say so by hand, in the same `[env: NAME]` that
    // `one_help` makes clap render for the variables clap does read.
    /// Where the control plane is reached [env: PERMGUARD_CONTROL_PLANE_ENDPOINT]
    #[arg(long, global = true, alias = "endpoint", value_name = "URL")]
    pub control_endpoint: Option<String>,

    /// Where the data plane is reached [env: PERMGUARD_DATA_PLANE_ENDPOINT]
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
    #[command(after_help = "Examples:\n  permguard version\n  permguard version -o json")]
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
    #[command(
        after_help = "Examples:\n  permguard init\n  permguard init release-pipeline --language cedar,rego"
    )]
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
    #[command(
        after_help = "Examples:\n  permguard clone https://permguard.internal:7556/delivery/release-pipeline\n  permguard clone https://permguard.internal:7556/delivery/release-pipeline ./release-pipeline"
    )]
    Clone {
        /// The ledger to clone, as `https://host[:port][/prefix]/<zone>/<ledger>`.
        url: String,
        /// Where to clone; defaults to the ledger name.
        directory: Option<std::path::PathBuf>,
    },
    /// Bind this workspace to a remote ledger and materialize it.
    #[command(
        after_help = "Examples:\n  permguard checkout origin/delivery/release-pipeline\n  permguard checkout origin/delivery/release-pipeline@main"
    )]
    Checkout {
        /// The ledger to bind to, as `<remote>/<zone>/<ledger>[@<ref>]`.
        reference: String,
    },
    /// Fetch the latest changes, verify them, and materialize what is missing.
    #[command(after_help = "Examples:\n  permguard pull\n  permguard pull -v")]
    Pull,
    /// Scan the sources and build the local snapshot.
    #[command(
        after_help = "Examples:\n  permguard refresh\n  permguard refresh -o json | jq '.root'"
    )]
    Refresh,
    /// Refresh plus every local check: manifest, identities, duplicates.
    #[command(after_help = "Examples:\n  permguard validate\n  permguard validate -o json")]
    Validate,
    /// Check that the policies decide what the cases say they decide — offline.
    ///
    /// The step between `validate` and `plan`: `validate` answers whether the workspace is well
    /// formed, this answers whether it is *right*, against the same engines a data plane uses and
    /// before anything is pushed.
    #[command(
        after_help = "Examples:\n  permguard test\n  permguard -w examples/release-pipeline test\n  permguard test tests/release.yml\n  permguard test --name separation -v\n  permguard test --remote\n  permguard test -o json | jq '.failed'"
    )]
    Test {
        /// The case files or folders to run. The workspace's `tests` folder when left out.
        #[arg(value_name = "PATH")]
        path: Vec<String>,

        /// Only cases whose name contains this text.
        #[arg(long, value_name = "PATTERN")]
        name: Option<String>,

        /// Ask every case under this profile, whatever its request names.
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,

        /// List the cases and what they expect, and decide nothing.
        #[arg(long)]
        list: bool,

        /// Ask the tracked data plane instead of deciding here.
        ///
        /// A different question, and the one worth asking after `apply`: not *do my sources decide
        /// this*, but *does the ledger that is deployed still decide this*. It is what catches a
        /// mirror that has not caught up, a commit a plane refuses to serve, and a ledger somebody
        /// else applied to.
        ///
        /// A Permguard plane records every decision — one that cannot record refuses to decide
        /// rather than decide unrecorded — so a suite run this way writes its cases into the
        /// decision log as real decisions. Point it at a plane whose log you are willing to have
        /// them in.
        #[arg(long)]
        remote: bool,

        /// The zone to ask, overriding the workspace.
        #[arg(long, alias = "zone-id", value_name = "ZONE", requires = "remote")]
        zone: Option<String>,

        /// The ledger to ask, overriding the workspace.
        #[arg(long, value_name = "LEDGER", requires = "remote")]
        ledger: Option<String>,
    },
    /// Show what apply would change on the remote ledger.
    #[command(after_help = "Examples:\n  permguard plan\n  permguard plan -o json")]
    Plan,
    /// Plan, then push the changes to the remote ledger.
    #[command(
        after_help = "Examples:\n  permguard apply\n  permguard apply -m \"require a signed artifact before approval\""
    )]
    Apply {
        /// The commit message.
        #[arg(short, long, default_value = "apply")]
        message: String,
    },
    /// Show the commit history of the tracked ref.
    #[command(
        after_help = "Examples:\n  permguard history\n  permguard history -o json | jq '.commits[].commit'"
    )]
    History,
    /// Show what this workspace tracks and where it stands — offline.
    #[command(after_help = "Examples:\n  permguard status\n  permguard status -o json")]
    Status,
    /// Inspect the local object store.
    Objects {
        #[command(subcommand)]
        action: ObjectsAction,
    },
    /// Verify the remote head statement and the local closure.
    #[command(after_help = "Examples:\n  permguard verify\n  permguard verify -o json")]
    Verify,
    /// Ask a data plane for an authorization decision.
    #[command(
        after_help = "Examples:\n  permguard check -f request.json\n  cat request.json | permguard check -f -\n  permguard check -f request.json --zone delivery --ledger release-pipeline -o json\n  permguard check --profile pipeline --subject Workload:ci-pipeline --action artifact:upload --resource Release:v2.4.0"
    )]
    Check(CheckArgs),
    /// Read the decisions a data plane recorded.
    ///
    /// Every subcommand reads from an offset that belongs to the consumer, and the control plane
    /// keeps no cursor: two people running `permguard decisions tail` at once do not interfere,
    /// and neither can back-pressure the plane that is deciding.
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
    #[command(
        after_help = "Examples:\n  permguard inspect\n  permguard inspect --timeout 2 -o json"
    )]
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
    #[command(
        after_help = "Examples:\n  permguard decisions list --zone delivery --ledger release-pipeline\n  permguard decisions list --decision deny --since 2026-08-01T00:00:00Z"
    )]
    List(DecisionsQuery),
    /// Follow the decisions as they arrive.
    #[command(
        after_help = "Examples:\n  permguard decisions tail --follow\n  permguard decisions tail --decision deny --follow"
    )]
    Tail {
        #[command(flatten)]
        query: DecisionsQuery,
        /// Keep reading instead of stopping at the end of what is held.
        #[arg(long)]
        follow: bool,
    },
    /// Show one decision, by the identifier the caller was given back.
    #[command(
        after_help = "Examples:\n  permguard decisions get 0198f3f2-7c1a-7e2b-9f4c-1d2e3a4b5c6d\n  permguard decisions get 0198f3f2-7c1a-7e2b-9f4c-1d2e3a4b5c6d -o json"
    )]
    Get {
        /// The decision's own identifier, as it appeared in `context.id`.
        id: String,
        #[command(flatten)]
        query: DecisionsQuery,
    },
    /// Read in bulk, resumably: every page, from an offset, to standard output.
    #[command(
        after_help = "Examples:\n  permguard decisions export -o json > decisions.json\n  permguard decisions export --pdp pdp-eu-1 --instance 7f3c --verify --keys data-plane-keys.json"
    )]
    Export(DecisionsQuery),
}

/// Which way a decision went, as `--decision` spells it.
///
/// An enumeration rather than a free string, so that a misspelling is refused at the command line
/// instead of quietly filtering to the other answer, and so that the help lists the two values the
/// way `--output` lists its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Decision {
    /// Only the requests that were allowed.
    Permit,
    /// Only the requests that were refused.
    Deny,
}

/// Which decisions, and how they are checked.
#[derive(Debug, clap::Args)]
pub struct DecisionsQuery {
    /// The zone whose decisions to read, overriding the workspace.
    #[arg(long, alias = "zone-id", value_name = "ZONE")]
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
    #[arg(long, value_enum, value_name = "DECISION")]
    pub decision: Option<Decision>,

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
    #[command(
        after_help = "Examples:\n  permguard remote add origin https://permguard.internal:7556\n  permguard remote add origin https://permguard.internal:7556 -o json"
    )]
    Add {
        /// The name this remote is known by.
        name: String,
        /// Where it is reached, as `https://host[:port][/prefix]`.
        url: String,
    },
    /// List the remotes.
    #[command(
        after_help = "Examples:\n  permguard remote list\n  permguard remote list -o json | jq '.remotes[].name'"
    )]
    List,
    /// Remove a remote.
    #[command(
        after_help = "Examples:\n  permguard remote remove origin\n  permguard remote remove origin -o json"
    )]
    Remove {
        /// The remote to remove, by name.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ObjectsAction {
    /// List the local store: every object, its kind, and who reaches it.
    #[command(
        after_help = "Examples:\n  permguard objects list\n  permguard objects list --tracked -o json | jq '.objects[].digest'"
    )]
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
    #[command(
        after_help = "Examples:\n  permguard objects cat sha256:0d757bf6828225c716b7b49cda3bde7f5087ca49ed582b85d7ae38ad38e9ee26 --human\n  permguard objects cat sha256:0d757bf6828225c716b7b49cda3bde7f5087ca49ed582b85d7ae38ad38e9ee26 --raw > object.cbor"
    )]
    Cat {
        /// The object, by the digest `objects list` reports.
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
    #[command(
        after_help = "Examples:\n  permguard config show\n  permguard config show -o json | jq '.settings[].origin'"
    )]
    Show,
    /// Print one setting's value, and nothing else.
    #[command(
        after_help = "Examples:\n  permguard config get control-plane.endpoint\n  permguard config get data-plane.endpoint -o json"
    )]
    Get {
        /// The setting to read.
        key: String,
    },
    /// Write one setting into the configuration file.
    #[command(
        after_help = "Examples:\n  permguard config set control-plane.endpoint https://permguard.internal:7556\n  permguard config set data-plane.endpoint https://permguard.internal:7557"
    )]
    Set {
        /// The setting to write.
        key: String,
        /// The value to write.
        value: String,
    },
    /// Take settings back out of the configuration file.
    #[command(
        after_help = "Examples:\n  permguard config reset control-plane.endpoint\n  permguard config reset"
    )]
    Reset {
        /// The setting to reset. Every setting, when left out.
        key: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ZonesAction {
    /// Create a zone. Names are lowercase a-z, 0-9, `-` and `_`, unique across the deployment.
    #[command(
        after_help = "Examples:\n  permguard zones create delivery\n  permguard zones create delivery -o json"
    )]
    Create {
        /// The zone's name.
        name: String,
    },
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
        after_help = "Examples:\n  permguard zones get delivery\n  permguard zones get 01a02b7b-e9e8-73c2-9aa9-a95039e7bdf6 -o json"
    )]
    Get {
        /// The zone, by name or id.
        zone: String,
    },
    /// Update a zone — today its name, with `--name`. The id never changes.
    #[command(
        after_help = "Examples:\n  permguard zones update delivery --name delivery-eu\n  permguard zones update 01a02b7b-e9e8-73c2-9aa9-a95039e7bdf6 --name delivery-eu -o json"
    )]
    Update {
        /// The zone, by name or id.
        zone: String,
        /// The new name.
        #[arg(long)]
        name: String,
    },
    /// Delete a zone. Refused while it still holds ledgers.
    #[command(
        after_help = "Examples:\n  permguard zones delete delivery\n  permguard zones delete delivery -o json"
    )]
    Delete {
        /// The zone, by name or id.
        zone: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum LedgersAction {
    /// Create a ledger inside a zone. Names are unique within their zone.
    #[command(
        after_help = "Examples:\n  permguard ledgers create --zone delivery release-pipeline\n  permguard ledgers create --zone delivery release-pipeline -o json"
    )]
    Create {
        /// The zone, by name or id.
        #[arg(long, alias = "zone-id")]
        zone: String,
        /// The ledger's name.
        name: String,
    },
    /// List a zone's ledgers — every one, or a page at a time.
    #[command(
        after_help = "Examples:\n  permguard ledgers list --zone delivery\n  permguard ledgers list --zone delivery --page 2 --size 50\n  permguard ledgers list --zone delivery -o json | jq '.ledgers[].id'"
    )]
    List {
        /// The zone, by name or id.
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
        after_help = "Examples:\n  permguard ledgers get --zone delivery release-pipeline\n  permguard ledgers get --zone delivery 01a02b87-818c-79d7-b171-e9f7d3645083 -o json"
    )]
    Get {
        /// The zone, by name or id.
        #[arg(long, alias = "zone-id")]
        zone: String,
        /// The ledger, by name or id.
        ledger: String,
    },
    /// Update a ledger — today its name, with `--name`. The id never changes.
    #[command(
        after_help = "Examples:\n  permguard ledgers update --zone delivery release-pipeline --name release-pipeline-v2\n  permguard ledgers update --zone delivery release-pipeline --name release-pipeline-v2 -o json"
    )]
    Update {
        /// The zone, by name or id.
        #[arg(long, alias = "zone-id")]
        zone: String,
        /// The ledger, by name or id.
        ledger: String,
        /// The new name.
        #[arg(long)]
        name: String,
    },
    /// Delete a ledger.
    #[command(
        after_help = "Examples:\n  permguard ledgers delete --zone delivery release-pipeline\n  permguard ledgers delete --zone delivery release-pipeline -o json"
    )]
    Delete {
        /// The zone, by name or id.
        #[arg(long, alias = "zone-id")]
        zone: String,
        /// The ledger, by name or id.
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
    #[arg(long, alias = "zone-id", value_name = "ZONE")]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The tree as a command line actually sees it: `global = true` arguments reach the commands
    /// that inherit them only once clap has built it, and it is the built tree that answers `-h`.
    fn built() -> clap::Command {
        let mut command = command();
        command.build();

        command
    }

    /// Every command in the tree, the root included.
    fn walk(command: &clap::Command, visit: &mut dyn FnMut(&clap::Command)) {
        visit(command);
        for subcommand in command.get_subcommands() {
            walk(subcommand, visit);
        }
    }

    #[test]
    fn test_every_command_answers_h_and_help_the_same_way() {
        let mut checked = 0;

        walk(&command(), &mut |command| {
            let help = command
                .get_arguments()
                .find(|arg| arg.get_id() == "help")
                .unwrap_or_else(|| panic!("{} has no help flag", command.get_name()));

            assert_eq!(help.get_short(), Some('h'), "{}", command.get_name());
            assert_eq!(help.get_long(), Some("help"), "{}", command.get_name());
            assert!(
                matches!(help.get_action(), clap::ArgAction::HelpShort),
                "{} answers -h with something other than the compact help",
                command.get_name()
            );
            checked += 1;
        });

        // A tree that stopped being walked would pass every assertion above.
        assert!(checked > 20, "only {checked} commands were checked");
    }

    #[test]
    fn test_every_help_in_the_tree_carries_the_banner() {
        let banner = crate::banner::banner();
        let mut checked = 0;

        walk(&command(), &mut |command| {
            for before in [command.get_before_help(), command.get_before_long_help()] {
                let rendered = before.map(ToString::to_string).unwrap_or_else(|| {
                    format!("{} has no banner above its help", command.get_name())
                });

                assert_eq!(rendered, banner, "{}", command.get_name());
            }
            checked += 1;
        });

        assert!(checked > 20, "only {checked} commands were checked");
    }

    /// The `help` subcommand is the third way of asking, and it has to be there to be answered.
    #[test]
    fn test_help_is_a_subcommand_of_every_command_that_has_subcommands() {
        let mut checked = 0;

        walk(&command(), &mut |command| {
            let others = command
                .get_subcommands()
                .filter(|subcommand| subcommand.get_name() != "help")
                .count();
            let stand_in = command
                .get_subcommands()
                .any(|subcommand| subcommand.get_name() == "help");

            assert_eq!(
                stand_in,
                others > 0,
                "{} has {others} subcommands and {} a help subcommand",
                command.get_name(),
                if stand_in { "does have" } else { "has no" }
            );
            checked += 1;
        });

        assert!(checked > 20, "only {checked} commands were checked");
    }

    /// The flags that are the same everywhere are listed together, in the same order, and `-h`
    /// closes the block — in every command, or the help stops reading the same way twice.
    #[test]
    fn test_the_global_flags_are_one_block_ending_in_help_everywhere() {
        let mut expected: Option<Vec<String>> = None;
        let mut checked = 0;

        walk(&built(), &mut |command| {
            let mut global: Vec<&clap::Arg> = command
                .get_arguments()
                .filter(|arg| arg.get_help_heading() == Some(GLOBAL_HEADING))
                .collect();
            global.sort_by_key(|arg| arg.get_display_order());

            let names: Vec<String> = global
                .iter()
                .filter_map(|arg| arg.get_long())
                // Only the root can be asked its version without naming a command.
                .filter(|long| *long != "version")
                .map(ToOwned::to_owned)
                .collect();

            assert_eq!(
                names.last().map(String::as_str),
                Some("help"),
                "{} does not close its global block with --help",
                command.get_name()
            );

            match &expected {
                None => expected = Some(names),
                Some(first) => assert_eq!(first, &names, "{}", command.get_name()),
            }

            checked += 1;
        });

        assert!(checked > 20, "only {checked} commands were checked");
    }

    /// A flag or an argument with nothing beside it in the help is one the reader has to guess at.
    #[test]
    fn test_every_argument_in_the_tree_says_what_it_is() {
        let mut checked = 0;

        walk(&built(), &mut |command| {
            for arg in command.get_arguments() {
                assert!(
                    arg.get_help().is_some(),
                    "{} {} carries no description",
                    command.get_name(),
                    arg.get_id()
                );
                checked += 1;
            }
        });

        assert!(checked > 100, "only {checked} arguments were checked");
    }

    /// One dialect for the environment: `[env: NAME]`, never `[env: NAME=whatever is set]`.
    #[test]
    fn test_no_help_in_the_tree_prints_the_value_of_an_environment_variable() {
        let mut checked = 0;

        walk(&built(), &mut |command| {
            for arg in command.get_arguments() {
                assert!(
                    arg.is_hide_env_values_set(),
                    "{} {} would print what its variable is set to",
                    command.get_name(),
                    arg.get_id()
                );
                checked += 1;
            }
        });

        assert!(checked > 100, "only {checked} arguments were checked");
    }

    /// The `permguard …` part of an example: the stage of the pipeline that runs this CLI, up to a
    /// redirection, split the way a shell would split it.
    fn invocation(example: &str) -> Option<Vec<String>> {
        let stage = example
            .split('|')
            .map(str::trim)
            .find(|stage| stage.starts_with("permguard"))?;
        let stage = stage.split('>').next().unwrap_or(stage).trim();

        let mut argv = Vec::new();
        let mut word = String::new();
        let mut quoted = false;

        for character in stage.chars() {
            match character {
                '"' => quoted = !quoted,
                character if character.is_whitespace() && !quoted => {
                    if !word.is_empty() {
                        argv.push(std::mem::take(&mut word));
                    }
                }
                character => word.push(character),
            }
        }

        if !word.is_empty() {
            argv.push(word);
        }

        Some(argv)
    }

    /// Examples belong to the commands that do something, and to those only: a group's help is
    /// already the list of its subcommands, and examples put there duplicate the leaves and go
    /// stale on their own.
    #[test]
    fn test_every_command_that_does_something_shows_examples() {
        let mut leaves = 0;

        walk(&command(), &mut |command| {
            // The stand-in is a command of clap's tree, not of the CLI's vocabulary.
            if command.get_name() == "help" {
                return;
            }

            let does_something = command
                .get_subcommands()
                .all(|subcommand| subcommand.get_name() == "help");
            let examples = command.get_after_help().map(ToString::to_string);

            match (does_something, examples) {
                (true, Some(text)) => {
                    assert!(
                        text.starts_with("Examples:\n"),
                        "{} puts something other than examples after its help",
                        command.get_name()
                    );
                    assert!(
                        text.lines().skip(1).count() >= 2,
                        "{} shows fewer than two examples",
                        command.get_name()
                    );
                    leaves += 1;
                }
                (true, None) => panic!("{} shows no examples", command.get_name()),
                (false, Some(_)) => panic!(
                    "{} lists subcommands and carries examples of its own",
                    command.get_name()
                ),
                (false, None) => {}
            }
        });

        assert!(leaves > 30, "only {leaves} commands were checked");
    }

    /// Every example is a command line this CLI accepts. Without this, a renamed flag leaves the
    /// examples that used it wrong, and wrong at a pace nobody notices.
    #[test]
    fn test_every_example_is_a_command_line_that_parses() {
        let mut checked = 0;

        walk(&command(), &mut |command| {
            let Some(after) = command.get_after_help() else {
                return;
            };

            for line in after.to_string().lines().skip(1) {
                let Some(argv) = invocation(line) else {
                    panic!(
                        "{}: `{}` runs no permguard",
                        command.get_name(),
                        line.trim()
                    )
                };

                assert!(
                    super::command().try_get_matches_from(&argv).is_ok(),
                    "{}: `{}` is not a command line this CLI accepts",
                    command.get_name(),
                    line.trim()
                );
                checked += 1;
            }
        });

        assert!(checked > 60, "only {checked} examples were checked");
    }

    #[test]
    fn test_zone_answers_to_the_same_two_spellings_everywhere() {
        let mut checked = 0;

        walk(&command(), &mut |command| {
            for arg in command.get_arguments() {
                // Positionals cannot carry an alias, and do not need one.
                if arg.get_id() != "zone" || arg.get_long().is_none() {
                    continue;
                }

                let aliases = arg.get_all_aliases().unwrap_or_default();
                assert!(
                    aliases.contains(&"zone-id"),
                    "{} takes --zone but not --zone-id",
                    command.get_name()
                );
                checked += 1;
            }
        });

        assert!(checked > 5, "only {checked} --zone flags were checked");
    }

    #[test]
    fn test_no_option_is_reachable_by_a_short_name_alone() {
        walk(&command(), &mut |command| {
            for arg in command.get_arguments() {
                if arg.get_short().is_some() {
                    assert!(
                        arg.get_long().is_some(),
                        "{} has -{} with no long spelling",
                        command.get_name(),
                        arg.get_short().unwrap_or('?')
                    );
                }
            }
        });
    }
}
