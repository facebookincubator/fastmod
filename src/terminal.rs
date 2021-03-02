/*
 * Copyright (c) Facebook, Inc. and its affiliates.
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

use crossterm::style::SetForegroundColor;
use crossterm::terminal::{Clear, ClearType};
use crossterm::ExecutableCommand;
use std::io;

pub enum Color {
    Red,
    Green,
}

impl Color {
    pub fn to_crossterm_color(self) -> crossterm::style::Color {
        match self {
            Color::Red => crossterm::style::Color::DarkRed,
            Color::Green => crossterm::style::Color::DarkGreen,
        }
    }
}

pub fn clear() {
    if io::stdout().execute(Clear(ClearType::All)).is_err() {
        print!("{}", "\n".repeat(8));
    }
}

pub fn fg(color: Color) {
    let _ = io::stdout().execute(SetForegroundColor(color.to_crossterm_color()));
}

pub fn reset() {
    let _ = io::stdout().execute(SetForegroundColor(crossterm::style::Color::Reset));
}

pub fn size() -> Option<(usize, usize)> {
    crossterm::terminal::size()
        .ok()
        .map(|(w, h)| (w as usize, h as usize))
}
