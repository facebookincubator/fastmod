/**
 * Copyright 2018-present, Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::io;
use term::{self, StdoutTerminal};
use term::color::Color;
use term::terminfo::TermInfo;

pub struct Terminal {
    ti: Option<TermInfo>,
    term: Option<Box<StdoutTerminal>>,
}

impl Terminal {
    pub fn new() -> Terminal {
        Terminal {
            ti: TermInfo::from_env().ok(),
            term: term::stdout(),
        }
    }

    fn use_capability(&self, capability_name: &str) -> bool {
        match &self.ti {
            &None => false,
            &Some(ref ti) => ti.apply_cap(capability_name, &[], &mut io::stdout())
                .is_ok(),
        }
    }

    pub fn clear(&self) {
        if !self.use_capability("clear") {
            print!("{}", "\n".repeat(8));
        }
    }

    pub fn fg(&mut self, color: Color) {
        if let Some(ref mut term) = self.term {
            let _ = term.fg(color);
        }
    }

    pub fn reset(&mut self) {
        if let Some(ref mut term) = self.term {
            let _ = term.reset();
        }
    }
}
