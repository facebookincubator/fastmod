/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
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

use std::borrow::Cow;
use std::cmp::max;
use std::cmp::min;
use std::collections::HashSet;
use std::env;
use std::fmt;
use std::fs;
use std::fs::read_to_string;
use std::iter;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::process::Command;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

use anyhow::ensure;
use anyhow::Context;
use anyhow::Error;
use clap::Parser;
use diff::Result as DiffResult;
use grep::regex::RegexMatcher;
use grep::regex::RegexMatcherBuilder;
use grep::searcher::BinaryDetection;
use grep::searcher::Searcher;
use grep::searcher::SearcherBuilder;
use grep::searcher::Sink;
use grep::searcher::SinkMatch;
use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use ignore::WalkState;
use regex::Regex;
use regex::RegexBuilder;

mod terminal;

use rprompt::prompt_reply_from_bufread;

use crate::terminal::Color;

type Result<T> = ::std::result::Result<T, Error>;

enum FileSet {
    Extensions(Vec<String>),
    Glob {
        matches: Vec<String>,
        case_insensitive: bool,
    },
}

fn notify_fast_mode() {
    eprintln!("Fast mode activated. Sit back, relax, and enjoy the brief flight.");
}

fn run_editor(path: &Path, start_line: usize) -> Result<()> {
    let editor = env::var("EDITOR").unwrap_or_else(|_| String::from("vim"));
    let args: Vec<&str> = editor.split(' ').collect();
    let mut editor_cmd = {
        let mut cmd = Command::new(args[0])
            .args(&args[1..])
            .arg(format!("+{}", start_line))
            .arg(path)
            .spawn()
            .with_context(|| format!("Unable to launch editor {} on path {:?}", editor, path));
        if cfg!(target_os = "windows") && cmd.is_err() {
            // Windows-only fallback to notepad.exe.
            cmd = Command::new("notepad.exe")
                .arg(path)
                .spawn()
                .with_context(|| format!("Unable to launch editor notepad.exe on path {:?}", path));
        }
        cmd?
    };
    editor_cmd
        .wait()
        .context("Error waiting for editor to exit")?;
    Ok(())
}

fn looks_like_code(path: &Path) -> bool {
    let s = path.to_string_lossy();
    !s.ends_with('~') && !s.ends_with("tags") && !s.ends_with("TAGS")
}

fn prompt(prompt_text: &str, letters: &str, default: Option<char>) -> Result<char> {
    loop {
        let input = prompt_reply_from_bufread(
            &mut std::io::stdin().lock(),
            &mut std::io::stdout(),
            prompt_text,
        )
        .context("Unable to read user input")?;

        match (input.as_ref(), default) {
            ("", Some(default)) => return Ok(default),
            (input, _) if input.len() == 1 && letters.contains(input) => {
                return Ok(input.chars().next().unwrap())
            }
            _ => println!("Come again?"),
        }
    }
}

fn walk_builder_with_file_set<P>(dirs: &[P], file_set: &Option<FileSet>) -> Result<WalkBuilder>
where
    P: AsRef<Path>,
{
    ensure!(!dirs.is_empty(), "must provide at least one path to walk!");
    let mut builder = WalkBuilder::new(&dirs[0]);
    for dir in &dirs[1..] {
        builder.add(dir);
    }
    if let Some(file_set) = file_set {
        use crate::FileSet::*;
        match file_set {
            Extensions(e) => {
                let mut override_builder = OverrideBuilder::new(".");
                for ext in e {
                    override_builder
                        .add(&format!("*.{}", ext))
                        .context("Unable to register extension with directory walker")?;
                }
                builder.overrides(
                    override_builder
                        .build()
                        .context("Unable to register extensions with directory walker")?,
                );
            }
            Glob {
                matches,
                case_insensitive,
            } => {
                let mut override_builder = OverrideBuilder::new(".");
                // Case sensitivity needs to be added before the patterns are.
                if *case_insensitive {
                    override_builder
                        .case_insensitive(true)
                        .context("Unable to toggle case sensitivity")?;
                }
                for file in matches {
                    override_builder
                        .add(file)
                        .context("Unable to register glob with directory walker")?;
                }
                builder.overrides(
                    override_builder
                        .build()
                        .context("Unable to register glob with directory walker")?,
                );
            }
        }
    }
    Ok(builder)
}

/// Convert a 0-based character offset to 0-based line number and column.
fn index_to_row_col(s: &str, index: usize) -> (usize, usize) {
    let chunk = &s[..index];
    let line_num = chunk.chars().filter(|x| x == &'\n').count();
    let last_newline = if let Some(result) = chunk.rfind('\n') {
        result as isize
    } else {
        -1
    };
    let col = index as isize - last_newline - 1;
    (line_num, col as usize)
}

fn display_warning(error: &Error) -> DisplayWarning {
    DisplayWarning { inner: error }
}

fn make_searcher() -> Searcher {
    SearcherBuilder::new()
        .line_number(false)
        .multi_line(true)
        .binary_detection(BinaryDetection::quit(b'\x00'))
        .bom_sniffing(false)
        .build()
}

fn file_contents_if_matches(
    searcher: &mut Searcher,
    matcher: &RegexMatcher,
    path: &Path,
) -> Option<String> {
    let mut sink = FastmodSink::new();
    if let Err(e) = searcher.search_path(matcher, path, &mut sink) {
        eprintln!("{}", display_warning(&e.into()));
    };
    if sink.did_match {
        match read_to_string(path) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("{}", display_warning(&e.into()));
                None
            }
        }
    } else {
        None
    }
}

#[derive(Debug)]
struct DisplayWarning<'a> {
    inner: &'a Error,
}

impl<'a> fmt::Display for DisplayWarning<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        writeln!(fmt, "Warning: {:?}", self.inner)?;
        Ok(())
    }
}

struct FastmodSink {
    did_match: bool,
}

impl FastmodSink {
    fn new() -> Self {
        Self { did_match: false }
    }
}

struct Fastmod {
    yes_to_all: bool,
    hidden: bool,
    changed_files: Option<Vec<PathBuf>>,
}

impl Sink for FastmodSink {
    type Error = std::io::Error;

    fn matched(
        &mut self,
        _searcher: &Searcher,
        _mat: &SinkMatch,
    ) -> std::result::Result<bool, std::io::Error> {
        self.did_match = true;
        Ok(false)
    }
}

fn to_char_boundary(s: &str, mut index: usize) -> usize {
    while index < s.len() && !s.is_char_boundary(index) {
        index += 1;
    }
    debug_assert!(
        index > s.len() || s.is_char_boundary(index),
        "index: {}, len: {}",
        index,
        s.len()
    );
    index
}

fn backward_to_char_boundary(s: &str, mut index: usize) -> usize {
    while !s.is_char_boundary(index) {
        index -= 1;
    }
    index
}

impl Fastmod {
    fn new(accept_all: bool, hidden: bool, print_changed_files: bool) -> Fastmod {
        Fastmod {
            yes_to_all: accept_all,
            hidden,
            changed_files: if print_changed_files {
                Some(Vec::new())
            } else {
                None
            },
        }
    }

    fn save(&mut self, path: &Path, text: &str) -> Result<()> {
        fs::write(path, text).with_context(|| format!("Unable to write to {:?}", path))?;
        self.record_change(path.to_owned());
        Ok(())
    }

    fn record_change(&mut self, path: PathBuf) {
        if let Some(ref mut changed_files) = self.changed_files {
            changed_files.push(path);
        }
    }

    fn print_changed_files_if_needed(&mut self) {
        if let Some(ref mut changed_files) = self.changed_files {
            changed_files.sort();
            for file in changed_files {
                println!("{}", file.display());
            }
        }
    }

    // Returns true if the file was changed, false otherwise.
    fn fast_patch(
        &mut self,
        regex: &Regex,
        subst: &str,
        path: &Path,
        contents: &str,
    ) -> Result<bool> {
        let new_contents = regex.replace_all(contents, subst);
        match new_contents {
            Cow::Borrowed(_) => Ok(false),
            Cow::Owned(_) => {
                self.save(path, &new_contents)?;
                Ok(true)
            }
        }
    }

    fn present_and_apply_patches(
        &mut self,
        regex: &Regex,
        subst: &str,
        path: &Path,
        mut contents: String,
    ) -> Result<()> {
        // Overall flow:
        // 0) offset = 0.
        // 1) Find next patch from *current* contents of the file at
        //    given offset. If none, we are done.
        // 2) Set the offset to the start of the previous patch + 1.
        // 3) Ask the user to make a modification to the file.
        // 4) Re-read the file. (User may have made arbitrary edits!)
        let mut offset = 0;
        while offset < contents.len() {
            {
                let mat = regex.find(&contents[offset..]);
                match mat {
                    None => break,
                    Some(mat) => {
                        let mut new_contents = contents[..offset].to_string();
                        let new_trailing_contents = regex.replace(&contents[offset..], subst);
                        new_contents.push_str(&new_trailing_contents);
                        // Zero-length matches can happen with any
                        // regex that matches the empty string,
                        // such as `a?` or the empty regex.
                        let is_zero_length_match = mat.end() == mat.start();
                        let (start_line, _) = index_to_row_col(&contents, mat.start() + offset);
                        let (end_line, _) = index_to_row_col(
                            &contents,
                            // Avoid generating index of -1 when start
                            // == end == offset = 0 for a zero-length
                            // match.
                            backward_to_char_boundary(
                                &contents,
                                mat.end() + offset - if is_zero_length_match { 0 } else { 1 },
                            ),
                        );
                        let accepted = self.ask_about_patch(
                            path,
                            &contents,
                            start_line + 1,
                            end_line + 1,
                            &new_contents,
                        )?;
                        if accepted {
                            offset = to_char_boundary(
                                &contents,
                                offset
                                + mat.start()
                                + subst.len()
                                // Ensure forward progress when there
                                // is a zero-length match.
                                + if is_zero_length_match { 1 } else { 0 },
                            );
                        } else {
                            // Advance to the next character after the match.
                            offset = to_char_boundary(&contents, offset + mat.end() + 1);
                        }
                    }
                }
            }
            // re-open file in case contents changed.
            contents = read_to_string(path)?;
        }
        Ok(())
    }

    /// Returns true if the patch was accepted, false otherwise.
    fn ask_about_patch<'a>(
        &mut self,
        path: &Path,
        old: &'a str,
        start_line: usize,
        end_line: usize,
        new: &'a str,
    ) -> Result<bool> {
        terminal::clear();

        let diffs = self.diffs_to_print(old, new);
        if diffs.is_empty() {
            return Ok(false);
        }

        if start_line == end_line {
            println!("{}:{}", path.to_string_lossy(), start_line);
        } else {
            println!("{}:{}-{}", path.to_string_lossy(), start_line, end_line);
        }
        self.print_diff(&diffs);
        let mut user_input = if self.yes_to_all {
            'y'
        } else {
            prompt(
                "Accept change (y = yes [default], \
                 n = no, e = edit, A = yes to all, E = yes+edit, q = quit)?\n",
                "yneAEq",
                Some('y'),
            )?
        };
        if user_input == 'A' {
            self.yes_to_all = true;
            user_input = 'y';
        }
        match user_input {
            'y' => {
                self.save(path, new)?;
                Ok(true)
            }
            'E' => {
                self.save(path, new)?;
                run_editor(path, start_line)?;
                Ok(true)
            }
            'e' => {
                self.record_change(path.to_owned());
                run_editor(path, start_line)?;
                Ok(true)
            }
            'q' => exit(0),
            'n' => Ok(false),
            _ => unreachable!(),
        }
    }

    fn diffs_to_print<'a>(&self, orig: &'a str, edit: &'a str) -> Vec<DiffResult<&'a str>> {
        let mut diffs = diff::lines(orig, edit);
        fn is_same(x: &&DiffResult<&str>) -> bool {
            matches!(x, DiffResult::Both(..))
        }
        let lines_to_print = match terminal::size() {
            Some((_w, h)) => h,
            None => 25,
        } - 20;

        let num_prefix_lines = diffs.iter().take_while(is_same).count();
        let num_suffix_lines = diffs.iter().rev().take_while(is_same).count();

        // If the prefix is the length of the diff then the file matched <regex>
        // but applying <subst> didn't result in any changes, there are no diffs
        // to print so we return an empty Vec.
        if diffs.len() == num_prefix_lines {
            return vec![];
        }

        let size_of_diff = diffs.len() - num_prefix_lines - num_suffix_lines;
        let size_of_context = lines_to_print.saturating_sub(size_of_diff);
        let size_of_up_context = size_of_context / 2;
        let size_of_down_context = size_of_context / 2 + size_of_context % 2;

        let start_offset = num_prefix_lines.saturating_sub(size_of_up_context);
        let end_offset = min(
            diffs.len(),
            num_prefix_lines + size_of_diff + size_of_down_context,
        );

        diffs.truncate(end_offset);
        diffs.splice(..start_offset, iter::empty());

        assert!(
            diffs.len() <= max(lines_to_print, size_of_diff),
            "changeset too long: {} > max({}, {})",
            diffs.len(),
            lines_to_print,
            size_of_diff
        );

        diffs
    }

    fn print_diff(&mut self, diffs: &[DiffResult<&str>]) {
        for diff in diffs {
            match diff {
                DiffResult::Left(l) => {
                    terminal::fg(Color::Red);
                    println!("- {}", l);
                    terminal::reset();
                }
                DiffResult::Both(l, _) => println!("  {}", l),
                DiffResult::Right(r) => {
                    terminal::fg(Color::Green);
                    println!("+ {}", r);
                    terminal::reset();
                }
            }
        }
    }

    fn run_interactive<P>(
        &mut self,
        regex: &Regex,
        matcher: &RegexMatcher,
        subst: &str,
        dirs: &[P],
        file_set: &Option<FileSet>,
    ) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let walk = walk_builder_with_file_set(dirs, file_set)?
            .hidden(!self.hidden)
            .threads(min(12, num_cpus::get()))
            .build_parallel();
        let (tx, rx) = channel();
        let thread_matcher = matcher.clone();
        thread::spawn(|| {
            walk.run(move || {
                let mut searcher = make_searcher();
                let tx = tx.clone();
                let matcher = thread_matcher.clone();
                Box::new(move |result| {
                    let dirent = match result {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("Warning: {}", &e);
                            return WalkState::Continue;
                        }
                    };
                    if let Some(file_type) = dirent.file_type() {
                        if !file_type.is_file() {
                            return WalkState::Continue;
                        }
                        let path = dirent.path();
                        if !looks_like_code(path) {
                            return WalkState::Continue;
                        }
                        if let Some(contents) =
                            file_contents_if_matches(&mut searcher, &matcher, path)
                        {
                            if tx.send((path.to_path_buf(), contents)).is_err() {
                                return WalkState::Quit;
                            }
                        }
                    }
                    WalkState::Continue
                })
            })
        });

        // We have to keep track of which paths we've visited so that
        // if the user presses A to accept all changes and we kick
        // over into run_fast(), we don't apply the regex to files the
        // user has already addressed interactively. (The user may
        // have made manual edits or declined to replace some files.)
        // Since the user is doing this interactively and we don't
        // support bookmarks, this set presumably isn't going to grow so large
        // that the memory usage becomes a concern.
        let mut visited = HashSet::default();
        while let Ok((path, contents)) = rx.recv() {
            visited.insert(path.clone());
            self.present_and_apply_patches(regex, subst, &path, contents)?;
            if self.yes_to_all {
                // Kick over into fast mode. We restart the
                // search, but we have our visited set so that
                // we won't apply changes to files the user
                // has already addressed.
                terminal::clear();
                notify_fast_mode();
                return Fastmod::run_fast_impl(
                    regex,
                    matcher,
                    subst,
                    dirs,
                    file_set,
                    self.hidden,
                    self.changed_files.clone(),
                    Some(visited),
                );
            }
        }
        self.print_changed_files_if_needed();
        Ok(())
    }

    fn run_fast<P>(
        regex: &Regex,
        matcher: &RegexMatcher,
        subst: &str,
        dirs: &[P],
        file_set: &Option<FileSet>,
        hidden: bool,
        print_changed_files: bool,
    ) -> Result<()>
    where
        P: AsRef<Path>,
    {
        Fastmod::run_fast_impl(
            regex,
            matcher,
            subst,
            dirs,
            file_set,
            hidden,
            if print_changed_files {
                Some(Vec::new())
            } else {
                None
            },
            None,
        )
    }

    fn run_fast_impl<P>(
        regex: &Regex,
        matcher: &RegexMatcher,
        subst: &str,
        dirs: &[P],
        file_set: &Option<FileSet>,
        hidden: bool,
        changed_files: Option<Vec<PathBuf>>,
        visited: Option<HashSet<PathBuf>>,
    ) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let walk = walk_builder_with_file_set(dirs, file_set)?
            .hidden(!hidden)
            .threads(min(12, num_cpus::get()))
            .build_parallel();
        let matcher = matcher.clone();
        let visited = Arc::new(visited);
        let should_record_changed_files = changed_files.is_some();
        let changed_files = Arc::new(Mutex::new(changed_files.unwrap_or_default()));
        let changed_files_inner = changed_files.clone();
        walk.run(move || {
            // We have to do our own changed file tracking, so don't
            // enable it in our Fastmod instance.
            let mut fm = Fastmod::new(true, hidden, false);
            let regex = regex.clone();
            let matcher = matcher.clone();
            let subst = subst.to_string();
            let visited = visited.clone();
            let changed_files = changed_files_inner.clone();
            let mut searcher = make_searcher();
            Box::new(move |result| {
                let dirent = match result {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("Warning: {}", &e);
                        return WalkState::Continue;
                    }
                };
                if let Some(file_type) = dirent.file_type() {
                    if !file_type.is_file() {
                        return WalkState::Continue;
                    }
                    let path = dirent.path();
                    if let Some(ref visited) = *visited {
                        if visited.contains(path) {
                            return WalkState::Continue;
                        }
                    }
                    if !looks_like_code(path) {
                        return WalkState::Continue;
                    }
                    if let Some(contents) = file_contents_if_matches(&mut searcher, &matcher, path)
                    {
                        let patching_result = fm.fast_patch(&regex, &subst, path, &contents);
                        match patching_result {
                            Ok(changed_file) => {
                                if should_record_changed_files && changed_file {
                                    let mut changed_files = changed_files.lock().unwrap();
                                    changed_files.push(path.to_owned())
                                }
                            }
                            Err(error) => eprintln!("{}", display_warning(&error)),
                        }
                    }
                }
                WalkState::Continue
            })
        });
        if should_record_changed_files {
            let mut changed_files = changed_files.lock().unwrap();
            (*changed_files).sort();
            for file in &*changed_files {
                println!("{}", file.display());
            }
        }
        Ok(())
    }
}

/// fastmod is a tool to assist you with large-scale codebase refactors
/// that can be partially automated but still require human oversight and occasional
/// intervention.
///
/// Example: Let's say you're deprecating your use of the <font> tag. From the
/// command line, you might make progress by running:
///
///   fastmod -m -d www --extensions php,html \\
///       '<font *color=\"?(.*?)\"?>(.*?)</font>' \\
///       '<span style=\"color: ${1};\">${2}</span>'
///
/// For each match of the regex, you'll be shown a colored diff and asked if you
/// want to accept the change, reject it, or edit the line in question in your
/// $EDITOR of choice.
///
/// NOTE: Whereas codemod uses Python regexes, fastmod uses the Rust regex
/// crate, which supports a slightly different regex syntax and does not
/// support look around or backreferences. In particular, use ${1} instead
/// of \\1 to get the contents of the first capture group, and use $$ to
/// write a literal $ in the replacement string. See
/// https://docs.rs/regex#syntax for details.
///
/// A consequence of this syntax is that the use of single quotes instead
/// of double quotes around the replacment text is important, because the
/// bash shell itself cares about the $ character in double-quoted
/// strings. If you must double-quote your input text, be careful to
/// escape $ characters properly!
#[derive(Parser, Debug)]
#[command(
    version,
    about = "fastmod is a fast partial replacement for codemod.",
    verbatim_doc_comment
)]
struct Args {
    /// Automatically accept all changes (use with caution).
    #[arg(long)]
    accept_all: bool,

    /// Search hidden files.
    #[arg(long)]
    hidden: bool,

    /// Treat REGEX as a literal string. Avoids the need to escape regex metacharacters
    /// (compare to ripgrep's option of the same name).
    #[arg(short = 'F', long)]
    fixed_strings: bool,

    /// Perform case-insensitive search.
    #[arg(short, long)]
    ignore_case: bool,

    /// Have regex work over multiple lines (i.e., have dot match newlines).
    #[arg(short, long)]
    multiline: bool,

    /// Print the paths of changed files. (Recommended to be combined with --accept-all.)
    #[arg(long)]
    print_changed_files: bool,

    /// The path whose descendent files are to be explored.
    /// Included as a flag instead of a positional argument for
    /// compatibility with the original codemod.
    #[arg(
        short,
        long,
        help = "The path whose descendent files are to be explored."
    )]
    dir: Vec<PathBuf>,

    /// A comma-delimited list of file extensions to process.
    #[arg(short, long, value_name = "EXTENSION", value_delimiter = ',', conflicts_with_all = ["glob", "iglob"])]
    extensions: Vec<String>,

    /// A space-delimited list of globs to process.
    #[arg(short, long, conflicts_with = "iglob")]
    glob: Vec<String>,

    /// A space-delimited list of case-insensitive globs to process.
    #[arg(long)]
    iglob: Vec<String>,

    /// Regular expression to match.
    #[arg(value_name = "REGEX")]
    r#match: String,

    /// Substitution to replace with.
    #[arg()]
    // TODO: support empty substitution to mean "open my
    // editor at instances of this regex"?
    subst: String,

    /// Paths whose descendent files are to be explored.
    #[arg(value_name = "FILE OR DIR")]
    file_or_dir: Vec<PathBuf>,
}

fn fastmod() -> Result<()> {
    let args = Args::parse();

    let dirs = {
        let mut dirs: Vec<_> = args.dir.into_iter().chain(args.file_or_dir).collect();
        if dirs.is_empty() {
            dirs.push(PathBuf::from("."));
        }
        dirs
    };

    let file_set = {
        if !args.extensions.is_empty() {
            Some(FileSet::Extensions(args.extensions))
        } else if !args.glob.is_empty() {
            Some(FileSet::Glob {
                matches: args.glob,
                case_insensitive: false,
            })
        } else if !args.iglob.is_empty() {
            Some(FileSet::Glob {
                matches: args.iglob,
                case_insensitive: true,
            })
        } else {
            None
        }
    };

    let (maybe_escaped_regex, subst) = if args.fixed_strings {
        (regex::escape(&args.r#match), args.subst.replace('$', "$$"))
    } else {
        (args.r#match, args.subst)
    };

    let regex = RegexBuilder::new(&maybe_escaped_regex)
        .case_insensitive(args.ignore_case)
        .multi_line(true) // match codemod behavior for ^ and $.
        .dot_matches_new_line(args.multiline)
        .build()
        .with_context(|| format!("Unable to make regex from {}", maybe_escaped_regex))?;

    if regex.is_match("") {
        let _ = prompt_reply_from_bufread(
            &mut std::io::stdin().lock(),
            &mut std::io::stderr(),
            &format!(
                "Warning: your regex {:?} matches the empty string. This is probably
    not what you want. Press Enter to continue anyway or Ctrl-C to quit.",
                regex,
            ),
        )?;
    }

    let matcher = RegexMatcherBuilder::new()
        .case_insensitive(args.ignore_case)
        .multi_line(true)
        .dot_matches_new_line(args.multiline)
        .build(&maybe_escaped_regex)?;

    if args.accept_all {
        Fastmod::run_fast(
            &regex,
            &matcher,
            &subst,
            &dirs,
            &file_set,
            args.hidden,
            args.print_changed_files,
        )
    } else {
        Fastmod::new(args.accept_all, args.hidden, args.print_changed_files)
            .run_interactive(&regex, &matcher, &subst, &dirs, &file_set)
    }
}

fn main() {
    if let Err(e) = fastmod() {
        eprint!("{:?}", e);
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;

    use assert_cmd::Command;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_index_to_row_col() {
        assert_eq!(index_to_row_col("abc", 1), (0, 1));
        assert_eq!(index_to_row_col("abc\ndef", 2), (0, 2));
        assert_eq!(index_to_row_col("abc\ndef", 3), (0, 3));
        assert_eq!(index_to_row_col("abc\ndef", 4), (1, 0));
        assert_eq!(index_to_row_col("abc\ndef\nghi", 8), (2, 0));
    }

    fn create_test_files<'a>(
        names_and_contents: impl IntoIterator<Item = &'a (&'a str, &'a str)>,
    ) -> TempDir {
        let dir = TempDir::with_prefix("fastmodtest.").unwrap();
        for (name, contents) in names_and_contents {
            let path = dir.path().join(name);
            let mut file = File::create(path.clone()).unwrap();
            file.write_all(contents.as_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        dir
    }

    #[test]
    fn test_simple_replace_all() {
        let dir = create_test_files(&[("file1.c", "foo\nfoo blah foo")]);
        Command::cargo_bin("fastmod")
            .unwrap()
            .args([
                "foo",
                "bar",
                "--accept-all",
                "--dir",
                dir.path().to_str().unwrap(),
            ])
            .assert()
            .success();
        let contents = read_to_string(dir.path().join("file1.c")).unwrap();
        assert_eq!(contents, "bar\nbar blah bar");
    }

    #[test]
    fn test_glob_matches() {
        let dir = create_test_files(&[
            ("f1.txt", "some awesome text"),
            ("f2.TXT", "some more awesome text"),
            ("skip.rs", "i should be skipped but i am still awesome"),
        ]);

        Command::cargo_bin("fastmod")
            .unwrap()
            .args([
                "awesome",
                "great",
                "--accept-all",
                "--iglob",
                "*.txt",
                "--dir",
                dir.path().to_str().unwrap(),
            ])
            .assert()
            .success();

        let lower_translated = read_to_string(dir.path().join("f1.txt")).unwrap();
        let upper_translated = read_to_string(dir.path().join("f2.TXT")).unwrap();
        let skipped_translated = read_to_string(dir.path().join("skip.rs")).unwrap();
        assert_eq!(lower_translated, "some great text");
        assert_eq!(upper_translated, "some more great text");
        assert_eq!(
            skipped_translated,
            "i should be skipped but i am still awesome"
        );
    }

    #[test]
    fn test_fixed_strings() {
        let dir = create_test_files(&[("file1.txt", "foo+bar\nfoooobar")]);
        let file_path = dir.path().join("file1.txt");
        Command::cargo_bin("fastmod")
            .unwrap()
            .args([
                "foo+bar",
                "baz",
                "--accept-all",
                "--dir",
                dir.path().to_str().unwrap(),
                "--fixed-strings",
            ])
            .assert()
            .success();
        let contents = read_to_string(file_path).unwrap();
        assert_eq!(contents, "baz\nfoooobar");
    }

    #[test]
    fn test_diff_with_unchanged_line_in_middle() {
        let fm = Fastmod::new(false, false, false);
        let diffs = fm.diffs_to_print("foo\nbar\nbaz", "bat\nbar\nqux");
        assert_eq!(
            diffs,
            vec![
                DiffResult::Left("foo"),
                DiffResult::Right("bat"),
                DiffResult::Both("bar", "bar"),
                DiffResult::Left("baz"),
                DiffResult::Right("qux"),
            ]
        )
    }

    #[test]
    fn test_diff_no_changes() {
        let fm = Fastmod::new(false, false, false);
        let diffs = fm.diffs_to_print("foo", "foo");
        assert_eq!(diffs, vec![]);
    }

    #[test]
    fn test_print_changed_files() {
        let dir = TempDir::with_prefix("fastmodtest.").unwrap();
        let mut expected_changed_files = Vec::new();
        for file_num in 1..6 {
            let path = dir.path().join(format!("file{}.c", file_num));
            let mut file = File::create(path.clone()).unwrap();
            file.write_all(if file_num % 2 == 0 {
                b"foo\n"
            } else {
                b"bar\n"
            })
            .unwrap();
            file.sync_all().unwrap();
            if file_num % 2 == 0 {
                expected_changed_files.push(path.as_os_str().to_string_lossy().into_owned());
            }
        }
        Command::cargo_bin("fastmod")
            .unwrap()
            .args([
                "foo",
                "baz",
                "--accept-all",
                "--print-changed-files",
                "--dir",
                dir.path().to_str().unwrap(),
            ])
            .assert()
            .stdout(format!("{}\n", expected_changed_files.join("\n")));
    }

    #[test]
    fn test_zero_length_match() {
        let dir = create_test_files(&[("foo.txt", "foo")]);
        let file_path = dir.path().join("foo.txt");
        let regex = RegexBuilder::new("").multi_line(true).build().unwrap();
        let mut fm = Fastmod::new(true, false, false);
        fm.present_and_apply_patches(&regex, "x", &file_path, "foo".into())
            .unwrap();
        let contents = read_to_string(file_path).unwrap();
        assert_eq!(contents, "xfxoxo");
    }

    #[test]
    fn test_zero_length_replacement() {
        let dir = create_test_files(&[("foo.txt", "foofoo")]);
        let file_path = dir.path().join("foo.txt");
        let regex = RegexBuilder::new("foo").multi_line(true).build().unwrap();
        let mut fm = Fastmod::new(true, false, false);
        fm.present_and_apply_patches(&regex, "", &file_path, "foofoo".into())
            .unwrap();
        let contents = read_to_string(file_path).unwrap();
        assert_eq!(contents, "");
    }

    #[test]
    fn test_replacement_matches_search() {
        let dir = create_test_files(&[("foo.txt", "foo")]);
        let file_path = dir.path().join("foo.txt");
        let regex = RegexBuilder::new("foo").build().unwrap();
        let mut fm = Fastmod::new(true, false, false);
        fm.present_and_apply_patches(&regex, "foofoo", &file_path, "foo".into())
            .unwrap();
        let contents = read_to_string(file_path).unwrap();
        assert_eq!(contents, "foofoo");
    }

    #[test]
    fn test_empty_contents() {
        let dir = create_test_files(&[("foo.txt", "foo")]);
        Command::cargo_bin("fastmod")
            .unwrap()
            .args(["foo", "baz", "--dir", dir.path().to_str().unwrap()])
            .write_stdin("n\n")
            .assert()
            .success();
    }

    // Leading dot meaning hidden is a Unix thing.
    #[cfg(target_family = "unix")]
    #[test]
    fn test_hidden_files() {
        for &hidden in &[false, true] {
            let dir = create_test_files(&[(".hidden", "foo")]);
            let mut args = vec![
                "foo",
                "bar",
                "--dir",
                dir.path().to_str().unwrap(),
                "--accept-all",
            ];
            if hidden {
                args.push("--hidden");
            }

            Command::cargo_bin("fastmod")
                .unwrap()
                .args(&args)
                .assert()
                .success();
            let file_path = dir.path().join(".hidden");
            let contents = read_to_string(file_path).unwrap();
            if hidden {
                assert_eq!(contents, "bar");
            } else {
                assert_eq!(contents, "foo");
            }
        }
    }

    #[test]
    fn test_replace_next_to_unicode_character() {
        let contents = "I have “unicodequotes”";
        let dir = create_test_files(&[("foo.txt", contents)]);
        Command::cargo_bin("fastmod")
            .unwrap()
            .args([
                "quotes",
                "characters",
                "--dir",
                dir.path().to_str().unwrap(),
            ])
            .write_stdin("n\n")
            .assert()
            .success();
    }

    #[test]
    fn test_dollar_sign_in_replacement_string_with_fixed_strings() {
        let contents = "something";
        let dir = create_test_files(&[("foo.txt", contents)]);
        Command::cargo_bin("fastmod")
            .unwrap()
            .args([
                "-F",
                "something",
                "$foo.bar",
                "--dir",
                dir.path().to_str().unwrap(),
            ])
            .write_stdin("y\n")
            .assert()
            .success();
        let file_path = dir.path().join("foo.txt");
        let new_contents = read_to_string(file_path).unwrap();
        assert_eq!(new_contents, "$foo.bar");
    }
}
