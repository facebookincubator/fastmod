# fastmod
`fastmod` is a fast partial replacement for
[codemod](https://github.com/facebook/codemod). Like `codemod`, it is
a tool to assist you with large-scale codebase refactors, and it
supports most of `codemod`'s options. `fastmod`'s major philosophical
difference from `codemod` is that it is focused on improving the use
case "I want to use interactive mode to make sure my regex is correct,
and then I want to apply the regex everywhere". For this use case, it
offers much better performance than `codemod`. Accordingly, `fastmod`
does not support `codemod`'s `--start`, `--end`, or `--count` options,
nor does it support anything like `codemod`'s Python API.

## Examples

Let's say you're deprecating your use of the `<font>` tag. From the
command line, you might make progress by running:

```
fastmod -m -d /home/jrosenstein/www --extensions php,html \
    '<font *color="?(.*?)"?>(.*?)</font>' \
    '<span style="color: ${1};">${2}</span>'
```

For each match of the regex, you'll be shown a colored diff and asked
if you want to accept the change (the replacement of the `<font>` tag
with a `<span>` tag), reject it, or edit the line in question in your
`$EDITOR` of choice.

NOTE: Whereas `codemod` uses Python regexes, `fastmod` uses the Rust
[regex](https://github.com/rust-lang/regex) crate, which supports a
slightly different regex syntax and does not support look around or
backreferences. In particular, use `${1}` instead of `\1` to get the
contents of the first capture group, and use `$$` to write a literal
`$` in the replacement string. See the regex crate's
[documentation](https://docs.rs/regex/#syntax) for details.

A consequence of this syntax is that the use of single quotes instead
of double quotes around the replacement text is important, because the
`bash` shell itself cares about the `$` character in double-quoted
strings. If you must double-quote your input text, be careful to
escape `$` characters properly!

`fastmod` also offers a usability improvement over `codemod`: it
accepts files or directories to process as extra positional arguments
after the regex and substitution. For instance, the example above
could have been rewritten as

```
fastmod -m --extensions php,html \
    '<font *color="?(.*?)"?>(.*?)</font>' \
    '<span style="color: ${1};">${2}</span>' \
    /home/jrosenstein/www
```

This makes it possible to use `fastmod` to process a list of files
from somewhere else if needed. Note, however, that `fastmod` does its
own parallel directory traversal internally, so doing `find ... |
xargs fastmod ...` may be much slower than using `fastmod` by itself.

## Requirements

`fastmod` is primarily supported on macOS and Linux.

`fastmod` has also been reported to work reasonably well on
Windows. The major portability concerns are 1) the use of `$EDITOR`
with a fallback and 2) the console UI, which is descended from
`codemod`'s ncurses-based text coloring & screen clearing
code. Windows-specific issues and PRs will be considered as long as
they aren't too invasive. For example, if something doesn't work on
Windows because a Linux/Mac-specific API was used instead of
equivalent POSIX or Rust standard library calls, we would be happy to
fix that. On the other hand, we would like to avoid taking a direct
`winapi` dependency or substantially increasing the size of our
dependency graph for Windows-only enhancements.

## Building `fastmod`

`fastmod` is written in (stable) [Rust](https://www.rust-lang.org/)
and compiles with Rust's `cargo` build system. To build:

```
$ git clone https://github.com/facebookincubator/fastmod.git
$ cd fastmod
$ cargo build --release
$ ./target/release/fastmod --help
...
```

## Installing fastmod
The easiest way to install fastmod is simply `cargo install
fastmod`. If you have built `fastmod` from source following the
directions above, you can install your build with `cargo install`.

## How `fastmod` works
`fastmod` uses the
[ignore](https://github.com/BurntSushi/ripgrep/tree/master/ignore)
crate to walk the given directory hierarchy using multiple threads in
parallel while respecting `.gitignore`. It uses the
[grep](https://github.com/BurntSushi/ripgrep/tree/master/crates/grep)
crate to match each file, reads matching files into memory, applies
the given regex substitution one match at a time, and uses the
[diff](https://github.com/utkarshkukreti/diff.rs) crate to present the
resulting changes as patches for human review.

## Full documentation

See `fastmod --help`.

## License
`fastmod` is Apache-2.0-licensed.
