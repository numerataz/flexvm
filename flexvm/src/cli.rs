//! Command-line definition and parsing, backed by `clap`.

use clap::{Arg, ArgAction, Args as ClapArgs, Command, CommandFactory, FromArgMatches, Parser, Subcommand};

use crate::util::{self, Result};

/// Global options accepted before or after any subcommand.
///
/// Short `-v` and `-h` are attached to the root command and every subcommand except `run`,
/// where Docker's `-v` (volumes) and `-h` (hostname) are explicitly refused instead of
/// silently becoming verbose output or help.
#[derive(Clone, Debug, Default, ClapArgs)]
pub struct GlobalArgs {
    #[arg(long, global = true, value_name = "DIR")]
    pub state: Option<String>,
    #[arg(long, global = true, value_name = "DIR")]
    pub run: Option<String>,
    #[arg(long, global = true)]
    pub verbose: bool,
    #[arg(long, global = true)]
    pub help: bool,
    #[arg(long, global = true)]
    pub version: bool,
}

impl GlobalArgs {
    /// Global flags to forward to a child `flexvm` invocation, followed by `words`.
    pub fn child_args(&self, words: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(state) = &self.state {
            out.extend(["--state".into(), state.clone()]);
        }
        if let Some(run) = &self.run {
            out.extend(["--run".into(), run.clone()]);
        }
        if self.verbose {
            out.push("--verbose".into());
        }
        out.extend(words.iter().map(|w| (*w).to_string()));
        out
    }
}

/// Top-level `flexvm` CLI.
#[derive(Clone, Debug, Parser)]
#[command(name = "flexvm", disable_help_flag = true, disable_version_flag = true, disable_help_subcommand = true, args_override_self = true)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,
    #[command(subcommand)]
    pub command: Option<Cmd>,
}

/// All `flexvm` subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum Cmd {
    Run(Box<RunArgs>),
    Software(Box<SoftwareArgs>),
    #[command(name = "standby-refill", hide = true)]
    StandbyRefill(SingleArg),
    #[command(name = "restart-due", hide = true)]
    RestartDue(SingleArg),
    Ps(PsArgs),
    Exec(ExecArgs),
    Attach(SingleArg),
    Cp(TwoArgs),
    Logs(LogsArgs),
    Inspect(NamesArgs),
    Wait(NamesArgs),
    Restart(RestartArgs),
    Rename(TwoArgs),
    Stop(NamesArgs),
    Start(StartArgs),
    Pause(NamesArgs),
    Unpause(NamesArgs),
    Kill(KillArgs),
    Rm(RmArgs),
    Volume(VolumeArgs),
    Checkpoint(CheckpointArgs),
    #[command(name = "software-transfer")]
    SoftwareTransfer(SoftwareTransferArgs),
    Migrate(TwoArgs),
    Reclaim(ReclaimArgs),
    Listen(OptionalArg),
    Api(OptionalArg),
    Info,
    Pull(Box<PullArgs>),
    Images(ImagesArgs),
    Tag(TwoArgs),
    Image(ImageArgs),
    System(SystemArgs),
    Version,
    Login(LoginArgs),
    Logout(OptionalArg),
    Rmi(SingleArg),
    Bench(BenchArgs),
    #[command(hide = true)]
    Debug(DebugArgs),
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct SingleArg {
    pub value: Option<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct OptionalArg {
    pub value: Option<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct TwoArgs {
    pub first: Option<String>,
    pub second: Option<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct NamesArgs {
    pub names: Vec<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct RunArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(short = 'd', long)]
    pub detach: bool,
    #[arg(short = 'i', long)]
    pub interactive: bool,
    #[arg(short = 't', long)]
    pub tty: bool,
    #[arg(long)]
    pub ip: Option<String>,
    #[arg(long)]
    pub cpus: Option<String>,
    #[arg(short = 'm', long)]
    pub memory: Option<String>,
    #[arg(short = 'e', long = "env", action = ArgAction::Append)]
    pub env: Vec<String>,
    #[arg(long = "env-file", action = ArgAction::Append)]
    pub env_file: Vec<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub entrypoint: Option<String>,
    #[arg(long)]
    pub keep: bool,
    #[arg(long)]
    pub rm: bool,
    #[arg(long)]
    pub checkpoint: Option<String>,
    #[arg(long)]
    pub paused: bool,
    #[arg(long, hide = true)]
    pub standby: bool,
    #[arg(long, hide = true)]
    pub incoming: bool,
    #[arg(short = 'p', long = "publish", action = ArgAction::Append)]
    pub publish: Vec<String>,
    #[arg(long)]
    pub restart: Option<String>,
    /// Docker's `-h` (hostname): refused rather than silently treated as `--help`.
    #[arg(short = 'h', hide = true)]
    pub hostname_unsupported: bool,
    /// Docker's `-v` (volumes): refused rather than silently treated as `--verbose`.
    #[arg(short = 'v', hide = true)]
    pub volume_unsupported: bool,
    /// `IMAGE [CMD...]` (captured together so flags after `IMAGE` are never parsed as flexvm options).
    #[arg(trailing_var_arg = true)]
    pub raw: Vec<String>,
    /// Populated by `normalize_trailing`: true when `--` preceded `raw`.
    #[arg(skip)]
    pub saw_separator: bool,
    #[arg(skip)]
    pub image: Option<String>,
    #[arg(skip)]
    pub cmd: Vec<String>,
}

impl RunArgs {
    /// Reconstructs argv for a detached child VM process (omitting `-d`/`--detach`).
    pub fn child_args(&self, global: &GlobalArgs, name_override: Option<&str>) -> Vec<String> {
        let mut out = global.child_args(&["run"]);
        if let Some(name) = name_override.or(self.name.as_deref()) {
            out.extend(["--name".into(), name.into()]);
        }
        if self.interactive {
            out.push("--interactive".into());
        }
        if self.tty {
            out.push("--tty".into());
        }
        if let Some(ip) = &self.ip {
            out.extend(["--ip".into(), ip.clone()]);
        }
        if let Some(cpus) = &self.cpus {
            out.extend(["--cpus".into(), cpus.clone()]);
        }
        if let Some(memory) = &self.memory {
            out.extend(["--memory".into(), memory.clone()]);
        }
        for env in &self.env {
            out.extend(["--env".into(), env.clone()]);
        }
        for file in &self.env_file {
            out.extend(["--env-file".into(), file.clone()]);
        }
        if let Some(ep) = &self.entrypoint {
            out.extend(["--entrypoint".into(), ep.clone()]);
        }
        if self.keep {
            out.push("--keep".into());
        }
        if self.rm {
            out.push("--rm".into());
        }
        if let Some(ck) = &self.checkpoint {
            out.extend(["--checkpoint".into(), ck.clone()]);
        }
        if self.paused {
            out.push("--paused".into());
        }
        if self.standby {
            out.push("--standby".into());
        }
        if self.incoming {
            out.push("--incoming".into());
        }
        for p in &self.publish {
            out.extend(["--publish".into(), p.clone()]);
        }
        if let Some(r) = &self.restart {
            out.extend(["--restart".into(), r.clone()]);
        }
        if let Some(image) = &self.image {
            if image.starts_with('-') {
                out.push("--".into());
            }
            out.push(image.clone());
            if !self.cmd.is_empty() {
                if self.cmd[0] == "--" {
                    out.push("--".into());
                }
                out.extend(self.cmd.iter().cloned());
            }
        }
        out
    }
}

/// Shared image-preparation options for `pull` and `software`.
#[derive(Clone, Debug, Default, ClapArgs)]
pub struct ImageFlags {
    #[arg(long)]
    pub boot: Option<String>,
    #[arg(long = "kernel-modules")]
    pub kernel_modules: Option<String>,
    #[arg(long = "kernel-sdk")]
    pub kernel_sdk: bool,
    #[arg(long)]
    pub init: Option<String>,
    #[arg(long, allow_hyphen_values = true, value_parser = non_flag_value)]
    pub entrypoint: Option<String>,
    #[arg(long, allow_hyphen_values = true, value_parser = non_flag_value)]
    pub cmd: Option<String>,
    #[arg(long = "env", action = ArgAction::Append)]
    pub env: Vec<String>,
    #[arg(long)]
    pub workdir: Option<String>,
    #[arg(long)]
    pub user: Option<String>,
    #[arg(long)]
    pub warm: bool,
    #[arg(long = "ready-port", allow_negative_numbers = true)]
    pub ready_port: Option<String>,
    #[arg(long = "ready-cmd", allow_hyphen_values = true, value_parser = non_flag_value)]
    pub ready_cmd: Option<String>,
    #[arg(long = "ready-timeout")]
    pub ready_timeout: Option<String>,
    #[arg(long = "max-download-mib")]
    pub max_download_mib: Option<String>,
    #[arg(long = "max-unpacked-mib")]
    pub max_unpacked_mib: Option<String>,
    #[arg(long = "max-file-mib")]
    pub max_file_mib: Option<String>,
    #[arg(long = "max-entries")]
    pub max_entries: Option<String>,
}

impl ImageFlags {
    pub fn any_set(&self) -> bool {
        self.boot.is_some()
            || self.kernel_modules.is_some()
            || self.kernel_sdk
            || self.init.is_some()
            || self.entrypoint.is_some()
            || self.cmd.is_some()
            || !self.env.is_empty()
            || self.workdir.is_some()
            || self.user.is_some()
            || self.warm
            || self.ready_port.is_some()
            || self.ready_cmd.is_some()
            || self.ready_timeout.is_some()
            || self.max_download_mib.is_some()
            || self.max_unpacked_mib.is_some()
            || self.max_file_mib.is_some()
            || self.max_entries.is_some()
    }
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct PullArgs {
    #[command(flatten)]
    pub image_flags: ImageFlags,
    #[arg(long)]
    pub tag: Option<String>,
    #[arg(long)]
    pub vcpus: Option<String>,
    #[arg(long)]
    pub mem: Option<String>,
    #[arg(long)]
    pub plug: Option<String>,
    #[arg(long)]
    pub standby: Option<String>,
    pub image: Option<String>,
}

impl PullArgs {
    /// Whether this pull only adjusts the standby count (with optional `--tag`), leaving template options intact.
    pub fn only_standby(&self) -> bool {
        !self.image_flags.any_set() && self.vcpus.is_none() && self.mem.is_none() && self.plug.is_none()
    }
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct SoftwareArgs {
    #[command(flatten)]
    pub image_flags: ImageFlags,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub kernel: Option<String>,
    #[arg(long)]
    pub qemu: Option<String>,
    #[arg(long)]
    pub control: Option<String>,
    #[arg(long = "vsock-backend")]
    pub vsock_backend: Option<String>,
    #[arg(long)]
    pub mem: Option<String>,
    #[arg(long)]
    pub vcpus: Option<String>,
    #[arg(long)]
    pub timeout: Option<String>,
    #[arg(long = "disk", action = ArgAction::Append)]
    pub disk: Vec<String>,
    #[arg(long = "parent-kvm-bundle")]
    pub parent_kvm_bundle: Option<String>,
    #[arg(long = "parent-kvm-engine")]
    pub parent_kvm_engine: Option<String>,
    #[arg(long = "parent-kvm-mem")]
    pub parent_kvm_mem: Option<String>,
    #[arg(trailing_var_arg = true)]
    pub raw: Vec<String>,
    #[arg(skip)]
    pub image: Option<String>,
    #[arg(skip)]
    pub cmd: Vec<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct PsArgs {
    #[arg(short = 'a', long)]
    pub all: bool,
    #[arg(long)]
    pub json: bool,
    #[arg(short = 'q', long)]
    pub quiet: bool,
    #[arg(short = 'f', long = "filter", action = ArgAction::Append)]
    pub filter: Vec<String>,
    #[arg(long)]
    pub format: Option<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct ExecArgs {
    #[arg(short = 'd', long)]
    pub detach: bool,
    #[arg(short = 'i', long)]
    pub interactive: bool,
    #[arg(short = 't', long)]
    pub tty: bool,
    #[arg(short = 'e', long = "env", action = ArgAction::Append)]
    pub env: Vec<String>,
    #[arg(short = 'w', long)]
    pub workdir: Option<String>,
    #[arg(short = 'u', long)]
    pub user: Option<String>,
    #[arg(trailing_var_arg = true)]
    pub raw: Vec<String>,
    #[arg(skip)]
    pub name: Option<String>,
    #[arg(skip)]
    pub cmd: Vec<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct LogsArgs {
    #[arg(short = 'f', long)]
    pub follow: bool,
    #[arg(short = 'n', long)]
    pub tail: Option<String>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct StartArgs {
    #[arg(short = 'a', long)]
    pub attach: bool,
    #[arg(long = "parent-kvm-bundle")]
    pub parent_kvm_bundle: Option<String>,
    pub names: Vec<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct RestartArgs {
    #[arg(long = "parent-kvm-bundle")]
    pub parent_kvm_bundle: Option<String>,
    pub names: Vec<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct KillArgs {
    #[arg(short = 's', long)]
    pub signal: Option<String>,
    pub names: Vec<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct RmArgs {
    #[arg(short = 'f', long)]
    pub force: bool,
    pub names: Vec<String>,
}

#[derive(Clone, Debug, ClapArgs)]
pub struct VolumeArgs {
    #[command(subcommand)]
    pub cmd: Option<VolumeCmd>,
}

#[derive(Clone, Debug, Subcommand)]
pub enum VolumeCmd {
    Create {
        name: Option<String>,
        #[arg(long)]
        size: Option<String>,
    },
    Clone {
        source: Option<String>,
        name: Option<String>,
    },
    Ls,
    Inspect {
        target: Option<String>,
    },
    Rm {
        target: Option<String>,
    },
}

#[derive(Clone, Debug, ClapArgs)]
pub struct CheckpointArgs {
    #[command(subcommand)]
    pub cmd: Option<CheckpointCmd>,
}

#[derive(Clone, Debug, Subcommand)]
pub enum CheckpointCmd {
    Create {
        vm: Option<String>,
        name: Option<String>,
        #[arg(long)]
        stop: bool,
        #[arg(long)]
        incremental: bool,
    },
    Ls {
        #[arg(short = 'q', long)]
        quiet: bool,
        #[arg(long)]
        format: Option<String>,
        #[arg(long = "filter", action = ArgAction::Append)]
        filter: Vec<String>,
    },
    Rm {
        #[arg(short = 'f', long)]
        force: bool,
        names: Vec<String>,
    },
    Prune {
        #[arg(long = "older-than")]
        older_than: Option<String>,
        #[arg(short = 'f', long)]
        force: bool,
    },
    Save {
        target: Option<String>,
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    Load {
        #[arg(short = 'i', long)]
        input: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        sha256: Option<String>,
    },
}

#[derive(Clone, Debug, ClapArgs)]
pub struct SoftwareTransferArgs {
    #[command(subcommand)]
    pub cmd: Option<SoftwareTransferCmd>,
}

#[derive(Clone, Debug, Subcommand)]
pub enum SoftwareTransferCmd {
    Id,
    Offer {
        vm: String,
        destination: String,
    },
    Retire {
        vm: String,
        offer: String,
        #[arg(long = "signing-key")]
        signing_key: String,
        #[arg(long = "destination-key")]
        destination_key: String,
    },
    Prepare {
        offer: String,
        #[arg(long = "source-key")]
        source_key: String,
        #[arg(long = "handoff-chain")]
        handoff_chain: Option<String>,
    },
    Commit {
        receipt: String,
    },
    #[command(name = "acknowledge-commit")]
    AcknowledgeCommit {
        offer: String,
        #[arg(long = "signing-key")]
        signing_key: String,
    },
    Finalize {
        #[arg(value_name = "COMMIT-ACK")]
        commit_ack: String,
        #[arg(long = "signing-key")]
        signing_key: String,
    },
    Abort {
        offer: String,
    },
    #[command(name = "acknowledge-abort")]
    AcknowledgeAbort {
        offer: String,
        #[arg(long = "signing-key")]
        signing_key: String,
    },
    Recover {
        #[arg(value_name = "ABORT-RECEIPT")]
        abort_receipt: String,
    },
    Send {
        vm: String,
        offer: String,
    },
    Receive {
        offer: String,
        #[arg(long = "max-bundle-mib")]
        max_bundle_mib: Option<String>,
    },
    Activate {
        offer: String,
        vm: String,
        #[arg(long)]
        qemu: String,
    },
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct ReclaimArgs {
    #[arg(long, allow_negative_numbers = true)]
    pub force: Option<String>,
    pub ip: Option<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct ImagesArgs {
    #[arg(long)]
    pub json: bool,
    #[arg(short = 'q', long)]
    pub quiet: bool,
    #[arg(long = "filter", action = ArgAction::Append)]
    pub filter: Vec<String>,
}

#[derive(Clone, Debug, ClapArgs)]
pub struct ImageArgs {
    #[command(subcommand)]
    pub cmd: Option<ImageCmd>,
}

#[derive(Clone, Debug, Subcommand)]
pub enum ImageCmd {
    Prune {
        #[arg(short = 'f', long)]
        force: bool,
        #[arg(long = "force-shared")]
        force_shared: bool,
    },
}

#[derive(Clone, Debug, ClapArgs)]
pub struct SystemArgs {
    #[command(subcommand)]
    pub cmd: Option<SystemCmd>,
}

#[derive(Clone, Debug, Subcommand)]
pub enum SystemCmd {
    Prune {
        #[arg(short = 'f', long)]
        force: bool,
        #[arg(long = "force-shared")]
        force_shared: bool,
    },
    Df,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct LoginArgs {
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long = "password-stdin")]
    pub password_stdin: bool,
    pub registry: Option<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct BenchArgs {
    #[arg(long)]
    pub template: Option<String>,
    #[arg(long)]
    pub to: Option<String>,
    #[arg(long = "to-state")]
    pub to_state: Option<String>,
    #[arg(long = "to-run")]
    pub to_run: Option<String>,
    #[arg(long)]
    pub timeout: Option<String>,
    #[arg(long)]
    pub lifecycle: bool,
    #[arg(long)]
    pub iterations: Option<String>,
    #[arg(long)]
    pub warmup: Option<String>,
    #[arg(long = "dirty-mib")]
    pub dirty_mib: Option<String>,
    #[arg(long = "settle-ms")]
    pub settle_ms: Option<String>,
    #[arg(long = "ready-port")]
    pub ready_port: Option<String>,
    #[arg(long = "ready-http")]
    pub ready_http: Option<String>,
}

#[derive(Clone, Debug, Default, ClapArgs)]
pub struct DebugArgs {
    pub words: Vec<String>,
}

/// Rejects bare known flexvm flags accidentally passed as the value of an argv-style option
/// (e.g. `--cmd --run X`), while allowing arbitrary guest flags like `--cmd "--port 8080"`.
fn non_flag_value(v: &str) -> std::result::Result<String, String> {
    let bare = v.split_once('=').map_or(v, |(k, _)| k);
    if matches!(
        bare,
        "--" | "--state" | "--run" | "--verbose" | "--help" | "--version" | "--detach" | "--standby" | "--force" | "--warm" | "--name" | "--ip" | "--tag"
    ) {
        return Err(format!("missing value before {v}"));
    }
    Ok(v.to_string())
}

/// Parses a `T` from an optional flag string, using `default` if absent.
pub fn parse_or<T: std::str::FromStr>(value: Option<&str>, name: &str, default: T) -> Result<T> {
    value.map_or(Ok(default), |v| v.parse().map_err(|_| format!("bad --{name} {v:?}").into()))
}

const SHORT_VERBOSE_ID: &str = "_short_verbose";
const SHORT_HELP_ID: &str = "_short_help";

/// Attaches `-v` (verbose) and `-h` (help) to the root command and every subcommand
/// except `run` (where `-h` and `-v` are explicitly refused), and enables last-wins
/// overriding (`args_override_self`) on every command.
fn build_command() -> Command {
    fn decorate(mut cmd: Command, is_run: bool) -> Command {
        cmd = cmd.args_override_self(true).disable_help_flag(true).disable_version_flag(true).disable_help_subcommand(true);
        if !is_run {
            cmd = cmd
                .arg(Arg::new(SHORT_VERBOSE_ID).short('v').action(ArgAction::SetTrue).hide(true))
                .arg(Arg::new(SHORT_HELP_ID).short('h').action(ArgAction::SetTrue).hide(true));
        }
        cmd.mut_subcommands(|sub| {
            let sub_is_run = is_run || sub.get_name() == "run";
            decorate(sub, sub_is_run)
        })
    }
    decorate(Cli::command(), false)
}

fn any_flag_set(matches: &clap::ArgMatches, id: &str) -> bool {
    if matches.try_get_one::<bool>(id).ok().flatten().copied().unwrap_or(false) {
        return true;
    }
    matches.subcommand().is_some_and(|(_, sub)| any_flag_set(sub, id))
}

/// Splits `raw` (`[FIRST, CMD...]`) into `(first, cmd)`, dropping at most one leading `"--"`
/// between `FIRST` and `CMD`.
fn split_trailing(raw: &[String]) -> (Option<String>, Vec<String>) {
    let Some((first, rest)) = raw.split_first() else {
        return (None, Vec::new());
    };
    let rest = rest.strip_prefix(&["--".to_string()]).unwrap_or(rest);
    (Some(first.clone()), rest.to_vec())
}

/// Returns whether a raw argv slice (without argv[0]) targets a VM-execution command whose
/// flexvm failures exit with Docker-compatible code 125 (`run`, `start`, `exec`, `software`,
/// `software-transfer activate`). Works even when an invalid flag precedes the command.
pub fn is_vm_command(raw_args: &[String]) -> bool {
    let mut i = 0;
    let mut first_word: Option<&str> = None;
    let mut second_word: Option<&str> = None;
    while i < raw_args.len() {
        let arg = raw_args[i].as_str();
        if arg == "--" {
            break;
        }
        if matches!(arg, "--state" | "--run") {
            i += 2;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        if first_word.is_none() {
            first_word = Some(arg);
        } else {
            second_word = Some(arg);
            break;
        }
        i += 1;
    }
    matches!(first_word, Some("run" | "start" | "exec" | "software")) || (first_word == Some("software-transfer") && second_word == Some("activate"))
}

/// Checks whether a bare `--` appears before any subcommand in `raw_args`.
fn dashdash_before_command(raw_args: &[String]) -> bool {
    let mut i = 0;
    while i < raw_args.len() {
        let arg = raw_args[i].as_str();
        if arg == "--" {
            return true;
        }
        if matches!(arg, "--state" | "--run") {
            i += 2;
            continue;
        }
        if !arg.starts_with('-') {
            return false;
        }
        i += 1;
    }
    false
}

/// Checks whether `--` appeared before the positional arguments of `run`.
fn run_has_leading_separator(raw_args: &[String]) -> bool {
    let mut seen_run = false;
    let mut i = 0;
    while i < raw_args.len() {
        let arg = raw_args[i].as_str();
        if !seen_run {
            if matches!(arg, "--state" | "--run") {
                i += 2;
                continue;
            }
            if arg == "run" {
                seen_run = true;
            }
            i += 1;
            continue;
        }
        if arg == "--" {
            return true;
        }
        if matches!(
            arg,
            "--state"
                | "--run"
                | "--name"
                | "--ip"
                | "--cpus"
                | "-m"
                | "--memory"
                | "-e"
                | "--env"
                | "--env-file"
                | "--entrypoint"
                | "--checkpoint"
                | "-p"
                | "--publish"
                | "--restart"
        ) {
            i += 2;
            continue;
        }
        if !arg.starts_with('-') {
            return false;
        }
        i += 1;
    }
    false
}

/// Parses argv (without argv[0]) into a typed [`Cli`].
pub fn parse_from(raw_args: &[String]) -> Result<Cli> {
    if dashdash_before_command(raw_args) {
        return Err("-- must follow the command".into());
    }
    let mut full = Vec::with_capacity(raw_args.len() + 1);
    full.push("flexvm".to_string());
    full.extend(raw_args.iter().cloned());

    let cmd = build_command();
    let matches = cmd.try_get_matches_from(&full).map_err(|e| format_clap_error(e, raw_args))?;
    let short_v = any_flag_set(&matches, SHORT_VERBOSE_ID);
    let short_h = any_flag_set(&matches, SHORT_HELP_ID);
    let mut cli = Cli::from_arg_matches(&matches).map_err(|e| format_clap_error(e, raw_args))?;
    cli.global.verbose |= short_v;
    cli.global.help |= short_h;

    match &mut cli.command {
        Some(Cmd::Run(r)) => {
            if r.hostname_unsupported {
                return Err("hostname (-h) is not supported; the hostname is the VM's name (--name); use --help for help".into());
            }
            if r.volume_unsupported {
                return Err("volumes (-v) are not supported (#717); for verbose output, -v or --verbose goes before the command".into());
            }
            r.saw_separator = run_has_leading_separator(raw_args);
            if r.checkpoint.is_some() && r.saw_separator {
                // `run --checkpoint DIR -- CMD`: everything after `--` is a (refused) CMD, not IMAGE.
                r.cmd = r.raw.clone();
            } else {
                let (image, rest) = split_trailing(&r.raw);
                r.image = image;
                r.cmd = rest;
            }
        }
        Some(Cmd::Exec(e)) => {
            let (name, rest) = split_trailing(&e.raw);
            e.name = name;
            e.cmd = rest;
        }
        Some(Cmd::Software(s)) => {
            let (image, rest) = split_trailing(&s.raw);
            s.image = image;
            s.cmd = rest;
        }
        _ => {}
    }

    Ok(cli)
}

/// Translates clap parse errors into concise single-line `flexvm` errors, preserving
/// helpful legacy hints (e.g. `checkpoint VM DIR` before #775, `reclaim --force`).
fn format_clap_error(err: clap::Error, raw_args: &[String]) -> util::Error {
    // Preserve the legacy `checkpoint VM DIR` hint when an unknown checkpoint subcommand is given.
    if raw_args.iter().any(|a| a == "checkpoint") && matches!(err.kind(), clap::error::ErrorKind::InvalidSubcommand) {
        return "checkpoint needs create, ls, rm, prune, save or load: flexvm checkpoint create VM [NAME] keeps a VM's checkpoint in STATE/checkpoints (it took a DIR before), and run --checkpoint NAME restores it".into();
    }
    // Preserve `reclaim --force` missing-value hint.
    if raw_args.iter().any(|a| a == "reclaim") && raw_args.iter().any(|a| a == "--force") && matches!(err.kind(), clap::error::ErrorKind::InvalidValue) {
        return "--force needs a generation; run flexvm reclaim IP to see GEN".into();
    }
    // Strip clap's "error: " prefix and trailing usage/help boilerplate for clean `flexvm: ...` output.
    let rendered = err.render().to_string();
    let first_line = rendered.lines().next().unwrap_or("invalid arguments");
    first_line.strip_prefix("error: ").unwrap_or(first_line).to_string().into()
}
