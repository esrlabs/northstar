// Copyright (c) 2020 ESRLabs
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

use super::commands::parse_prompt;
use anyhow::{Context as _, Result};
use colored::Colorize;
use futures::Stream;
use pin::Pin;
use rustyline::{
    completion::{Completer, FilenameCompleter, Pair},
    config::OutputStreamType,
    error::ReadlineError,
    highlight::{Highlighter, MatchingBracketHighlighter},
    hint::{Hinter, HistoryHinter},
    validate::{self, Validator},
    Cmd, CompletionType, Config, Context, EditMode, ExternalPrinter, KeyEvent, Modifiers,
};
use rustyline_derive::Helper;
use std::{
    borrow::{
        Cow,
        Cow::{Borrowed, Owned},
    },
    io::Write,
    pin,
};
use structopt::clap;
use tokio::{sync::mpsc, task};

#[derive(Debug)]
pub enum UserInput {
    Line(String),
    Eof,
}

pub struct Terminal {
    rx: mpsc::Receiver<UserInput>,
}

impl Terminal {
    pub fn new() -> Result<(impl Write, Terminal)> {
        let config = Config::builder()
            .history_ignore_space(true)
            .auto_add_history(true)
            .completion_type(CompletionType::List)
            .edit_mode(EditMode::Vi)
            .output_stream(OutputStreamType::Stdout)
            .build();
        let h = NstarHelper {
            completer: FilenameCompleter::new(),
            highlighter: MatchingBracketHighlighter::new(),
            hinter: HistoryHinter {},
            colored_prompt: "".to_owned(),
        };
        let mut rl = rustyline::Editor::<NstarHelper>::with_config(config);
        rl.set_helper(Some(h));

        // rl.set_helper(Some(h));
        rl.bind_sequence(KeyEvent::new('\t', Modifiers::NONE), Cmd::CompleteHint);
        rl.bind_sequence(KeyEvent::alt('L'), Cmd::ClearScreen);

        let history = match directories::ProjectDirs::from("com", "esrlabs", "nstar")
            .map(|d| d.config_dir().join("history"))
        {
            Some(d) => d,
            None => return Err(anyhow::anyhow!("Failed to detect history dir")),
        };

        if history.exists() && rl.load_history(&history).is_err() {
            return Err(anyhow::anyhow!("Failed to load history"));
        }

        //let stdout: Box<dyn std::io::Write> = Box::new(stdout);
        let stdout = Stdout {
            inner: rl.create_external_printer()?,
            buffer: Vec::new(),
        };

        let prompt = "➜ ";
        rl.helper_mut().expect("No helper").colored_prompt = format!("\x1b[1;32m{}\x1b[0m", prompt);

        let (tx, rx) = mpsc::channel(10);

        task::spawn_blocking(move || {
            loop {
                let readline = rl.readline(&prompt);
                match readline {
                    Ok(line) => {
                        if tx.blocking_send(UserInput::Line(line)).is_err() {
                            break;
                        }
                    }
                    Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                        tx.blocking_send(UserInput::Eof).unwrap();
                        break;
                    }
                    Err(err) => {
                        eprintln!("Error: {:?}", err);
                        break;
                    }
                }
            }
            rl.save_history(&history)
                .context("Failed to write history")
                .ok();
        });

        Ok((stdout, Terminal { rx }))
    }
}

// Stream of input lines
impl<'a> Stream for Terminal {
    type Item = UserInput;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.rx).poll_recv(cx)
    }
}

#[derive(Helper)]
struct NstarHelper {
    completer: FilenameCompleter,
    highlighter: MatchingBracketHighlighter,
    hinter: HistoryHinter,
    colored_prompt: String,
}

impl Completer for NstarHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        self.completer.complete(line, pos, ctx)
    }
}

impl Hinter for NstarHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Option<String> {
        self.hinter.hint(line, pos, ctx)
    }
}

impl Highlighter for NstarHelper {
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        default: bool,
    ) -> Cow<'b, str> {
        if default {
            Borrowed(&self.colored_prompt)
        } else {
            Borrowed(prompt)
        }
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Owned(hint.to_owned())
    }

    fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> {
        self.highlighter.highlight(line, pos)
    }

    fn highlight_char(&self, line: &str, pos: usize) -> bool {
        self.highlighter.highlight_char(line, pos)
    }
}

impl Validator for NstarHelper {
    fn validate(
        &self,
        ctx: &mut validate::ValidationContext,
    ) -> rustyline::Result<validate::ValidationResult> {
        use validate::ValidationResult::*;

        match parse_prompt(ctx.input()) {
            Ok(_) => Ok(Valid(None)),
            Err(e) => {
                // Help requested
                if e.kind == clap::ErrorKind::HelpDisplayed {
                    return Ok(Valid(None));
                }

                let message = match e.kind {
                    clap::ErrorKind::InvalidSubcommand | clap::ErrorKind::UnknownArgument => {
                        format!("Invalid command, use {}", "help".blue())
                    }
                    clap::ErrorKind::MissingRequiredArgument => {
                        format!("Missing argument, use {} for help", "-h,--help".blue())
                    }
                    _ => format!("{:?} {}", e.kind, "Unknown".normal()),
                };

                Ok(Invalid(Some(format!("    <- ⚠️: {}", message))))
            }
        }
    }

    fn validate_while_typing(&self) -> bool {
        false
    }
}

struct Stdout<T: ExternalPrinter> {
    inner: T,
    buffer: Vec<u8>,
}

impl<T: ExternalPrinter> std::io::Write for Stdout<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for c in buf {
            if *c == b'\n' {
                let msg = String::from_utf8_lossy(&self.buffer).to_string();
                self.inner
                    .print(msg)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                self.buffer.clear();
            } else {
                self.buffer.push(*c);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
