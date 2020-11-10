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

use std::{borrow::Cow, sync::Arc};

use anyhow::Context;
use log::{error, info, warn};
use rustyline::{
    completion::{Completer, FilenameCompleter, Pair},
    config::OutputStreamType,
    error::ReadlineError,
    highlight::{Highlighter, MatchingBracketHighlighter},
    hint::{Hinter, HistoryHinter},
    validate::{self, MatchingBracketValidator, Validator},
    Cmd, CompletionType, Config, EditMode, Editor, KeyPress,
};
use rustyline_derive::Helper;
use std::borrow::Cow::{Borrowed, Owned};
use tokio::{
    sync::{self, mpsc, oneshot},
    task,
};

#[derive(Helper)]
struct ReadlineHelper {
    completer: FilenameCompleter,
    highlighter: MatchingBracketHighlighter,
    validator: MatchingBracketValidator,
    hinter: HistoryHinter,
    colored_prompt: String,
}

impl Completer for ReadlineHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &rustyline::Context<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        self.completer.complete(line, pos, ctx)
    }
}

impl Hinter for ReadlineHelper {
    fn hint(&self, line: &str, pos: usize, ctx: &rustyline::Context<'_>) -> Option<String> {
        self.hinter.hint(line, pos, ctx)
    }
}

impl Highlighter for ReadlineHelper {
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
        Owned("\x1b[1m".to_owned() + hint + "\x1b[m")
    }

    fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> {
        self.highlighter.highlight(line, pos)
    }

    fn highlight_char(&self, line: &str, pos: usize) -> bool {
        self.highlighter.highlight_char(line, pos)
    }
}

impl Validator for ReadlineHelper {
    fn validate(
        &self,
        ctx: &mut validate::ValidationContext,
    ) -> rustyline::Result<validate::ValidationResult> {
        self.validator.validate(ctx)
    }

    fn validate_while_typing(&self) -> bool {
        self.validator.validate_while_typing()
    }
}

pub(crate) async fn readline(
    barrier: Arc<sync::Barrier>,
    tx: mpsc::Sender<(oneshot::Sender<()>, String)>,
) {
    let config = Config::builder()
        .history_ignore_space(true)
        .auto_add_history(true)
        .completion_type(CompletionType::List)
        .edit_mode(EditMode::Vi)
        .output_stream(OutputStreamType::Stdout)
        .build();
    let h = ReadlineHelper {
        completer: FilenameCompleter::new(),
        highlighter: MatchingBracketHighlighter::new(),
        hinter: HistoryHinter {},
        colored_prompt: "".to_owned(),
        validator: MatchingBracketValidator::new(),
    };
    let mut rl = Editor::with_config(config);
    rl.set_helper(Some(h));
    rl.bind_sequence(KeyPress::Tab, Cmd::CompleteHint);
    rl.bind_sequence(KeyPress::Ctrl('L'), Cmd::ClearScreen);
    rl.bind_sequence(KeyPress::Meta('N'), Cmd::HistorySearchForward);
    rl.bind_sequence(KeyPress::Meta('P'), Cmd::HistorySearchBackward);

    let history = match directories::ProjectDirs::from("com", "esrlabs", "nstar")
        .map(|d| d.config_dir().join("history"))
    {
        Some(d) => d,
        None => {
            warn!("Failed to detect history dir");
            return;
        }
    };

    if history.exists() {
        info!("Loading history from {}", history.display());
        if rl.load_history(&history).is_err() {
            warn!("Failed to load history");
            return;
        }
    }

    let prompt = ">> ";
    rl.helper_mut().expect("No helper").colored_prompt = format!("\x1b[1;32m{}\x1b[0m", prompt);

    // Wait until we have a connection to the runtime
    barrier.wait().await;

    loop {
        let readline = task::block_in_place(|| rl.readline(prompt));
        match readline {
            Ok(line) => {
                let (tx_wait, rx_wait) = oneshot::channel::<()>();
                tx.send((tx_wait, line)).await.ok();
                // Wait until this line is processed
                rx_wait.await.ok();
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(err) => {
                error!("Readline error: {:?}", err);
                break;
            }
        }
    }
    if task::block_in_place(|| rl.save_history(&history).context("Failed to write history"))
        .is_err()
    {
        warn!("Failed to write history");
    }
}
