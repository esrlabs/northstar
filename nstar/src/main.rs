// Copyright (c) 2019 - 2020 ESRLabs
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

use crate::communication::containers;
use crate::communication::shutdown;
use crate::communication::start;
use crate::communication::start_receiving_from_socket;
use crate::communication::stop;
use crate::communication::stream_update;
use ansi_term::Color;
use anyhow::{anyhow, Context, Result};
use log::{info, warn};
use north::api::Response;
use rustyline::{
    completion::{Completer, FilenameCompleter, Pair},
    config::OutputStreamType,
    error::ReadlineError,
    highlight::{Highlighter, MatchingBracketHighlighter},
    hint::{Hinter, HistoryHinter},
    Cmd, CompletionType, Config, EditMode, Editor, Helper, KeyPress,
};
use rustyline_derive::Validator;
use std::{
    borrow::Cow::{self, Owned},
    env, fs,
};
use structopt::StructOpt;
use tokio::{io::AsyncWriteExt, net::TcpStream, sync};

mod communication;

static PROMPT: &str = ">> ";

#[derive(Debug, StructOpt)]
#[structopt(name = "nstar", about = "Northstar CLI")]
struct Opt {
    /// File that contains the north configuration
    #[structopt(short, long, default_value = "localhost:4200")]
    pub host: String,

    /// Run in verbose mode
    #[structopt(short, long)]
    verbose: bool,

    /// Disable history
    #[structopt(short, long)]
    disable_history: bool,

    /// Run command and exit
    cmd: Vec<String>,
}

#[derive(Validator)]
struct NstarHelper {
    file_name: FilenameCompleter,
    brackets_highliter: MatchingBracketHighlighter,
    history_hinter: HistoryHinter,
}

impl Completer for NstarHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &rustyline::Context<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        self.file_name.complete(line, pos, ctx)
    }
}

impl Hinter for NstarHelper {
    fn hint(&self, line: &str, pos: usize, ctx: &rustyline::Context<'_>) -> Option<String> {
        let hint = command_hint(line, pos, ctx);
        if hint.is_some() {
            hint
        } else {
            self.history_hinter.hint(line, pos, ctx)
        }
    }
}

impl Highlighter for NstarHelper {
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> Cow<'b, str> {
        if prompt == PROMPT {
            Owned(Color::Green.bold().paint(PROMPT).to_string())
        } else {
            PROMPT.into()
        }
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Owned(Color::Fixed(240).paint(hint).to_string())
    }

    fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> {
        self.brackets_highliter.highlight(line, pos)
    }

    fn highlight_char(&self, line: &str, pos: usize) -> bool {
        self.brackets_highliter.highlight_char(line, pos)
    }
}

impl Helper for NstarHelper {}

fn command_hint(line: &str, pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
    did_you_mean(
        &line,
        &["containers", "shutdown", "start", "stop", "install"],
    )
    .and_then(|s| {
        if s.len() > pos {
            Some(s[pos..].into())
        } else {
            None
        }
    })
}

fn did_you_mean<'a, T: ?Sized, I>(v: &str, possible_values: I) -> Option<&'a str>
where
    T: AsRef<str> + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut candidate: Option<(f64, &str)> = None;
    for pv in possible_values {
        let confidence = strsim::jaro_winkler(v, pv.as_ref());
        if confidence > 0.8 && (candidate.is_none() || (candidate.as_ref().unwrap().0 < confidence))
        {
            candidate = Some((confidence, pv.as_ref()));
        }
    }
    match candidate {
        None => None,
        Some((_, candidate)) => Some(candidate),
    }
}

fn help() -> String {
    r"
containers:     List installed containers
shutdown:       Stop the northstar runtime
start <name>:   Start application
stop <name>:    Stop application
install <file>: Install/Update npk"
        .into()
}

async fn run_cmd<S: AsyncWriteExt + Unpin>(
    cmd: &str,
    stream: &mut S,
    response_receiver: sync::broadcast::Receiver<Response>,
) -> Result<()> {
    let mut cmd = cmd.trim().split_whitespace();
    let c = cmd.next().ok_or_else(|| anyhow!("Invalid command"))?;

    match c {
        "containers" => containers(stream, response_receiver).await?,
        "shutdown" => shutdown(stream, response_receiver).await?,
        "start" => start(cmd, stream, response_receiver).await?,
        "stop" => stop(cmd, stream, response_receiver).await?,
        "install" => stream_update(cmd.next(), stream, response_receiver).await?,
        _ => (),
    }
    Ok(())
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let opt = Opt::from_args();

    if opt.verbose {
        env::set_var("RUST_LOG", "nstar=debug");
        env_logger::init();
        info!("Verbose mode is enabled");
    } else {
        env::set_var("RUST_LOG", "nstar=warn");
        env_logger::init();
    }

    let stream = TcpStream::connect(&opt.host)
        .await
        .with_context(|| format!("Failed to connect to {}", opt.host))?;
    let (read_half, mut write_half) = stream.into_split();
    let response_sender = start_receiving_from_socket(read_half)?;

    if !opt.cmd.is_empty() {
        let cmd_str = opt.cmd.join(" ");
        run_cmd(cmd_str.trim(), &mut write_half, response_sender.subscribe()).await
    } else {
        let config = Config::builder()
            .auto_add_history(false)
            .completion_type(CompletionType::List)
            .edit_mode(EditMode::Vi)
            .history_ignore_space(true)
            .history_ignore_dups(true)
            .output_stream(OutputStreamType::Stdout)
            .max_history_size(1000)
            .build();
        let h = NstarHelper {
            file_name: FilenameCompleter::new(),
            brackets_highliter: MatchingBracketHighlighter::new(),
            history_hinter: HistoryHinter {},
        };
        let mut rl = Editor::with_config(config);
        rl.set_helper(Some(h));
        rl.bind_sequence(KeyPress::Tab, Cmd::CompleteHint);
        rl.bind_sequence(KeyPress::Ctrl('L'), Cmd::ClearScreen);

        let history = if !opt.disable_history {
            let history = directories::ProjectDirs::from("com", "esrlabs", "nstar")
                .map(|d| d.config_dir().join("history"))
                .ok_or_else(|| anyhow!("Failed to get config directory"))?;
            if history.exists() {
                info!("Loading history from {:?}", history);
                rl.load_history(&history)
                    .context("Failed to load history")?;
            }
            Some(history)
        } else {
            info!("History is disabled");
            None
        };

        // Prompt loop
        loop {
            match rl.readline(PROMPT) {
                Ok(line) => {
                    if line.trim().is_empty() {
                        continue;
                    } else if line.trim() == "help" {
                        println!("{}", help());
                    } else {
                        run_cmd(&line, &mut write_half, response_sender.subscribe()).await?;
                        rl.add_history_entry(line);
                        if !opt.disable_history {
                            if let Some(ref history) = history {
                                if let Some(parent) = history.parent() {
                                    if !parent.exists() {
                                        info!("Creating nstar config dir {:?}", parent);
                                        fs::create_dir_all(parent).with_context(|| {
                                            format!("Failed to create {}", parent.display())
                                        })?;
                                    }
                                    info!("Saving history to {:?}", history);
                                    rl.save_history(history)?;
                                }
                            }
                        }
                    }
                }
                Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
                Err(err) => {
                    warn!("Error: {}", err);
                    break;
                }
            }
        }
        Ok(())
    }
}
