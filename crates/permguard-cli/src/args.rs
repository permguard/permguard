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
                .help("Print help"),
        );

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
    about = "Permguard command-line interface"
)]
pub struct Cli {
    #[command(flatten)]
    pub globals: Globals,

    /// Report this CLI's version and the build it came from.
    ///
    /// The same answer `permguard version` gives, in whichever format was asked for — one
    /// question, one answer, however it is spelled. `-V` rather than `-v`, which is `--verbose`.
    #[arg(short = 'V', long)]
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
    // the variable itself — so the help has to say so, rather than showing clap's `[env: …]`.
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
