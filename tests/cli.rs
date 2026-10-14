use std::fs::{File, read_to_string};
use std::io::Write;

use assert_cmd::Command;
use tempfile::TempDir;

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
fn test_no_ignore_files() {
    for &no_ignore in &[false, true] {
        let dir = create_test_files(&[
            (".ignore", "ignored.txt"),
            ("ignored.txt", "original text"),
            ("not-ignored.txt", "original text"),
        ]);
        let mut args = vec![
            "original",
            "replacement",
            "--dir",
            dir.path().to_str().unwrap(),
            "--accept-all",
        ];
        if no_ignore {
            args.push("--no-ignore");
        }

        Command::cargo_bin("fastmod")
            .unwrap()
            .args(&args)
            .assert()
            .success();

        let file_path_regular = dir.path().join("not-ignored.txt");
        let contents_regular = read_to_string(file_path_regular).unwrap();
        assert_eq!(contents_regular, "replacement text");

        let file_path_ignored = dir.path().join("ignored.txt");
        let contents_ignored = read_to_string(file_path_ignored).unwrap();
        if no_ignore {
            assert_eq!(contents_ignored, "replacement text");
        } else {
            assert_eq!(contents_ignored, "original text");
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
