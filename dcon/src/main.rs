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
use clap::{value_t, App, AppSettings, Arg};
use log::{info, warn};
use prettytable::{cell, format, row, Table};
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
    collections::HashSet,
    env, fs,
    io::{Read, Write},
    net::{self, ToSocketAddrs},
};

static PROMPT: &str = ">> ";
const BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug)]
struct Opt {
    host: String,
    verbose: bool,
    history: bool,
    cmd: Option<String>,
}

fn cli() -> Opt {
    let app = App::new("dcon")
        .about("Debug console client")
        .setting(AppSettings::AllowExternalSubcommands)
        .setting(AppSettings::ArgRequiredElseHelp)
        .setting(AppSettings::ColoredHelp)
        .setting(AppSettings::UnifiedHelpMessage)
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Verbose mode"),
        )
        .arg(
            Arg::with_name("disable-history")
                .short("d")
                .long("disable-history")
                .help("Disable history functionality"),
        )
        .arg(
            Arg::with_name("host")
                .short("h")
                .long("host")
                .takes_value(true)
                .default_value("127.0.0.1:4242")
                .help("Console host address"),
        );
    let matches = app.get_matches();
    let host = value_t!(matches.value_of("host"), String).unwrap();
    let verbose = matches.is_present("verbose");
    let history = !matches.is_present("disable-history");
    let cmd = match matches.subcommand() {
        (c, Some(matches)) => {
            let arg = vec![
                c.to_string(),
                matches
                    .values_of("")
                    .map(|v| v.collect::<Vec<&str>>().join(" "))
                    .unwrap_or_else(|| "".into()),
            ]
            .join(" ");
            Some(arg)
        }
        _ => None,
    };
    Opt {
        host,
        verbose,
        history,
        cmd,
    }
}

#[derive(Validator)]
struct DConHelper<'a> {
    file_name: FilenameCompleter,
    brackets_highliter: MatchingBracketHighlighter,
    history_hinter: HistoryHinter,
    command_hinter: CommandHinter<'a>,
}

impl<'a> Completer for DConHelper<'a> {
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

impl Hinter for DConHelper<'_> {
    fn hint(&self, line: &str, pos: usize, ctx: &rustyline::Context<'_>) -> Option<String> {
        let hint = self.command_hinter.hint(line, pos, ctx);
        if hint.is_some() {
            hint
        } else {
            self.history_hinter.hint(line, pos, ctx)
        }
    }
}

impl Highlighter for DConHelper<'_> {
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

impl Helper for DConHelper<'_> {}

struct CommandHinter<'a> {
    commands: Vec<&'a str>,
}

impl<'a> CommandHinter<'a> {
    fn new(commands: Vec<&str>) -> CommandHinter {
        CommandHinter { commands }
    }

    fn hint(&self, line: &str, pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        did_you_mean(&line, &self.commands).and_then(|s| {
            if s.len() > pos {
                Some(s[pos..].into())
            } else {
                None
            }
        })
    }
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

fn run(addr: &str, cmd: &str) -> Result<String> {
    if let Some(addr) = addr.to_socket_addrs()?.next() {
        let mut socket = net::TcpStream::connect(addr)
            .with_context(|| format!("Failed to connect to {}", addr))?;

        let mut cmd = cmd.to_string();
        cmd.push('\n');
        socket
            .write_all(cmd.as_bytes())
            .context("Failed to send command")?;

        let mut reply = String::new();
        let mut buffer = [0u8; BUFFER_SIZE];
        loop {
            let n = socket
                .read(&mut buffer)
                .context("Failed to read from connection")?;
            let s = String::from_utf8(buffer[..n].to_vec()).context("Received invalid reply")?;
            reply.push_str(&s);
            if !n < BUFFER_SIZE {
                continue;
            }
            break;
        }
        Ok(reply)
    } else {
        Err(anyhow!("Cannot resolve address {}", addr))
    }
}

fn run_help(opt: &Opt) -> Result<()> {
    let reply = run(&opt.host, "help")?;
    let mut table = Table::new();
    let format = format::FormatBuilder::new()
        .column_separator('|')
        .separators(&[], format::LineSeparator::new('-', '+', '+', '+'))
        .padding(1, 1)
        .build();
    table.set_format(format);
    table.set_titles(row!["Command", "Subcommands", "Help"]);

    let mut last_cmd = "";
    for l in reply.lines().filter(|n| !n.is_empty()) {
        let mut split = l.split_terminator(':').map(str::trim);
        if let Some(e) = split.next() {
            let mut cmd = e.split(' ').map(str::trim);
            let help = split.map(str::trim).collect::<Vec<&str>>().join(" ");
            if let Some(e) = cmd.next() {
                let args = cmd.collect::<Vec<&str>>().join(" ");
                let c = if last_cmd == e { "" } else { e };
                last_cmd = e;
                table.add_row(row![bFg->c, Fc->args, help]);
            }
        }
    }

    table.printstd();
    Ok(())
}

fn run_cmd(
    cmd: &str,
    opt: &Opt,
    commands: &[&str],
    editor: &mut Editor<DConHelper<'_>>,
    commands_entered: Option<&mut HashSet<String>>,
) -> Result<()> {
    let cmd = cmd.trim();
    let stripped_cmd = cmd.replace(" ", "");

    if cmd == "help" || cmd == "?" {
        run_help(opt)
    } else if stripped_cmd.is_empty() {
        Ok(())
    } else if !commands
        .iter()
        .map(|c| c.replace(" ", ""))
        .any(|c| stripped_cmd.starts_with(&c))
    {
        println!("Unknown command: \"{}\"", Color::Yellow.paint(cmd));
        if let Some(suggestion) = did_you_mean(cmd, commands) {
            println!("Did you mean: \"{}\"?", Color::Green.paint(suggestion));
        }
        Ok(())
    } else {
        let reply = run(&opt.host, cmd).map(|r| if r.is_empty() { "none".into() } else { r })?;
        if let Some(commands_entered) = commands_entered {
            if !commands_entered.contains(cmd) {
                editor.add_history_entry(cmd);
                commands_entered.insert(cmd.into());
            }
        }
        println!("{}", reply);
        Ok(())
    }
}

fn main() -> Result<()> {
    let opt = cli();

    if opt.verbose {
        env::set_var("RUST_LOG", "dcon=debug");
        env_logger::init();
        info!("Verbose mode is enabled");
    } else {
        env::set_var("RUST_LOG", "dcon=warn");
        env_logger::init();
    }

    // Run help once to populate hinter and suggestions
    let help = run(&opt.host, "help")?;
    // Get a list of all commands for hinter and suggestions
    let commands: Vec<&str> = help
        .lines()
        .filter(|n| !n.is_empty())
        .flat_map(|l| l.split_terminator(':').next())
        .collect();

    let config = Config::builder()
        .auto_add_history(false)
        .completion_type(CompletionType::List)
        .edit_mode(EditMode::Vi)
        .history_ignore_space(true)
        .history_ignore_dups(true)
        .output_stream(OutputStreamType::Stdout)
        .max_history_size(1000)
        .build();
    let h = DConHelper {
        file_name: FilenameCompleter::new(),
        brackets_highliter: MatchingBracketHighlighter::new(),
        history_hinter: HistoryHinter {},
        command_hinter: CommandHinter::new(commands.clone()),
    };
    let mut rl = Editor::with_config(config);
    rl.set_helper(Some(h));
    rl.bind_sequence(KeyPress::Tab, Cmd::CompleteHint);
    rl.bind_sequence(KeyPress::Ctrl('L'), Cmd::ClearScreen);

    // Single command mode
    if let Some(ref cmd) = opt.cmd {
        run_cmd(cmd, &opt, &commands, &mut rl, None)
    } else {
        let history = if opt.history {
            let history = directories::ProjectDirs::from("com", "esrlabs", "dcon")
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
        let mut commands_entered = HashSet::new();
        loop {
            match rl.readline(PROMPT) {
                Ok(line) => run_cmd(&line, &opt, &commands, &mut rl, Some(&mut commands_entered))?,
                Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
                Err(err) => {
                    warn!("Error: {}", err);
                    break;
                }
            }
        }

        // Maybe store history...
        if opt.history {
            if let Some(ref history) = history {
                if let Some(parent) = history.parent() {
                    if !parent.exists() {
                        info!("Creating dcon config dir {:?}", parent);
                        fs::create_dir_all(parent)
                            .with_context(|| format!("Failed to create {}", parent.display()))?;
                    }
                    info!("Saving history to {:?}", history);
                    rl.save_history(history)?;
                }
            }
        }
        Ok(())
    }
}
