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
contents of the first capture group. See the regex crate's
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
`fastmod` is supported on macOS and Linux.

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
If you have built `fastmod` following the directions above, you can
install it with `cargo install`. You can also have cargo build it from
https://crates.io/ via `cargo install fastmod`.

## How `fastmod` works
`fastmod` uses the
[ignore](https://github.com/BurntSushi/ripgrep/tree/master/ignore)
crate to walk the given directory hierarchy while respecting
`.gitignore`. It reads each matching file into memory, applies the
given regex substitution one match at a time, and uses the
[diff](https://github.com/utkarshkukreti/diff.rs) crate to present the
resulting change as a patch for human review.
In `--accept-all` mode, it walks the directory hierarchy using multiple
threads in parallel and avoids calculating patches for efficiency.

## Full documentation

See `fastmod --help`.

## License
`fastmod` is Apache-2.0-licensed.
