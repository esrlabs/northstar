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

use anyhow::Result;
use colored::Colorize;
use rustyline::{
    completion::{Completer, FilenameCompleter, Pair},
    config::OutputStreamType,
    error::ReadlineError,
    highlight::{Highlighter, MatchingBracketHighlighter},
    hint::{Hinter, HistoryHinter},
    validate::Validator,
    Cmd, CompletionType, Config, Context, EditMode, ExternalPrinter, KeyEvent, Modifiers,
};
use rustyline_derive::Helper;
use std::borrow::{
    Cow,
    Cow::{Borrowed, Owned},
};

pub struct Terminal {
    stdout: Box<dyn ExternalPrinter>,
    buffer: Vec<u8>,
    line_rx: tokio::sync::mpsc::Receiver<rustyline::Result<String>>,
    next_line: tokio::sync::mpsc::Sender<bool>,
}

impl Terminal {
    pub fn new() -> Result<Terminal> {
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
        let ep = Box::new(rl.create_external_printer()?);
        let buffer = Vec::new();

        let green_arrow = "-> ".green().to_string();
        rl.helper_mut().expect("No helper").colored_prompt = green_arrow;

        let (line_tx, line_rx) = tokio::sync::mpsc::channel(1);
        let (ready_tx, mut ready_rx) = tokio::sync::mpsc::channel(1);
        tokio::task::spawn(async move {
            while let Some(true) = ready_rx.recv().await {
                line_tx
                    .send(tokio::task::block_in_place(|| rl.readline(&"-> ".green())))
                    .await
                    .ok();
            }
            rl.save_history(&history).ok();
        });

        Ok(Terminal {
            stdout: ep,
            buffer,
            line_rx,
            next_line: ready_tx,
        })
    }

    pub async fn readline(&mut self) -> rustyline::Result<String> {
        self.next_line.send(true).await.unwrap();
        self.line_rx.recv().await.unwrap()
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

// Skip the validation step, this is done with clap
impl Validator for NstarHelper {}

impl std::io::Write for Terminal {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for c in buf {
            self.buffer.push(*c);
            if *c == b'\n' {
                self.flush()?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let msg = String::from_utf8_lossy(&self.buffer).to_string();
        self.stdout
            .print(msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        self.buffer.clear();
        Ok(())
    }
}
