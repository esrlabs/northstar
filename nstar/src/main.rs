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

use ansi_term::Color;
use anyhow::{anyhow, Context, Result};
use api::{
    InstallationResult, Message, Payload, Request, Response, ShutdownResult, StartResult,
    StopResult, UninstallResult,
};
use byteorder::{BigEndian, ByteOrder};
use itertools::Itertools;
use log::{info, warn};
use net::TcpStream;
use north_common::api;
use prettytable::{format, Attr, Cell, Row, Table};
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
    io::{Read, Write},
    net::{self},
    time::Duration,
};
use structopt::StructOpt;

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

    /// Print raw json payload
    #[structopt(short, long)]
    json: bool,

    /// Run command and exit
    cmd: Option<String>,
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
    did_you_mean(&line, &["containers", "shutdown", "start", "stop"]).and_then(|s| {
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

fn run<S: Read + Write>(mut stream: S, req: Request) -> Result<Response> {
    // Send request
    let request_msg = Message {
        id: uuid::Uuid::new_v4().to_string(),
        payload: Payload::Request(req),
    };
    let request = serde_json::to_string(&request_msg).context("Failed to serialize")?;
    let mut buf = [0u8; 4];
    BigEndian::write_u32(&mut buf, request.as_bytes().len() as u32);
    stream
        .write_all(&buf)
        .context("Failed to write to stream")?;
    stream
        .write_all(request.as_bytes())
        .context("Failed to write to stream")?;

    // Receive reply
    let mut buffer = [0u8; 4];
    stream
        .read_exact(&mut buffer)
        .context("Failed to read frame length")?;
    let frame_len = BigEndian::read_u32(&buffer) as usize;
    let mut buffer = vec![0; frame_len];
    stream
        .read_exact(&mut buffer)
        .context("Failed to read frame")?;

    // Deserialize message
    let message: Message = serde_json::from_slice(&buffer).context("Failed to parse reply")?;

    match message.payload {
        Payload::Request(_) => Err(anyhow!("Invalid response")),
        Payload::Response(r) => Ok(r),
        Payload::Notification(_) => Err(anyhow!("Invalid response")),
    }
}

fn help() -> String {
    r"
containers:     List installed containers
shutdown:       Stop the northstar runtime
start <name>:   Start application
stop <name>:    Stop application"
        .into()
}

fn run_cmd<S: Read + Write>(cmd: &str, stream: S) -> Result<Option<Response>> {
    let mut cmd = cmd.trim().split_whitespace();
    let c = cmd.next().ok_or_else(|| anyhow!("Invalid command"))?;

    let response = match c {
        "containers" => Some(run(stream, Request::Containers)?),
        "shutdown" => Some(run(stream, Request::Shutdown)?),
        "start" => {
            if let Some(name) = cmd.next() {
                Some(run(stream, Request::Start(name.into()))?)
            } else {
                None
            }
        }
        "stop" => {
            if let Some(name) = cmd.next() {
                Some(run(stream, Request::Stop(name.into()))?)
            } else {
                None
            }
        }
        _ => None,
    };
    Ok(response)
}

fn main() -> Result<()> {
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
        .with_context(|| format!("Failed to connect to {}", opt.host))?;

    if let Some(cmd) = opt.cmd {
        if let Some(response) = run_cmd(cmd.trim(), &stream)? {
            if opt.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                print_response(&response);
            }
        } else {
            eprintln!("Invalid cmd \"{}\"", cmd);
        }
        Ok(())
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
                    if line.trim() == "help" {
                        println!("{}", help());
                    } else if let Some(response) = run_cmd(&line, &stream)? {
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
                        print_response(&response);
                    } else {
                        println!("Invalid command: {}", line);
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

// TODO: This can be done smarter
fn print_response(response: &Response) {
    match response {
        Response::Containers(containers) => {
            let mut table = Table::new();
            table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
            table.set_titles(Row::new(vec![
                Cell::new("Name").with_style(Attr::Bold),
                Cell::new("Version").with_style(Attr::Bold),
                Cell::new("Type").with_style(Attr::Bold),
                Cell::new("PID").with_style(Attr::Bold),
                Cell::new("Uptime").with_style(Attr::Bold),
            ]));
            for container in containers
                .iter()
                .sorted_by_key(|c| &c.manifest.name) // Sort by name
                .sorted_by_key(|c| c.manifest.init.is_none())
            {
                table.add_row(Row::new(vec![
                    Cell::new(&container.manifest.name).with_style(Attr::Bold),
                    Cell::new(&container.manifest.version.to_string()),
                    Cell::new(
                        container
                            .manifest
                            .init
                            .as_ref()
                            .map(|_| "App")
                            .unwrap_or("Resource"),
                    ),
                    Cell::new(
                        &container
                            .process
                            .as_ref()
                            .map(|p| p.pid.to_string())
                            .unwrap_or_default(),
                    )
                    .with_style(Attr::ForegroundColor(prettytable::color::GREEN)),
                    Cell::new(
                        &container
                            .process
                            .as_ref()
                            .map(|p| format!("{:?}", Duration::from_nanos(p.uptime)))
                            .unwrap_or_default(),
                    ),
                ]));
            }
            table.printstd();
        }
        Response::Start { result } => match result {
            StartResult::Success => println!("Success"),
            StartResult::Error(e) => println!("Failed: {}", e),
        },
        Response::Stop { result } => match result {
            StopResult::Success => println!("Success"),
            StopResult::Error(e) => println!("Failed: {}", e),
        },
        Response::Uninstall { result } => match result {
            UninstallResult::Success => println!("Success"),
            UninstallResult::Error(e) => println!("Failed: {}", e),
        },
        Response::Install { result } => match result {
            InstallationResult::Success => println!("Success"),
            InstallationResult::Error(e) => println!("Failed: {}", e),
        },
        Response::Shutdown { result } => match result {
            ShutdownResult::Success => println!("Success"),
            ShutdownResult::Error(e) => println!("Failed: {}", e),
        },
    }
}
