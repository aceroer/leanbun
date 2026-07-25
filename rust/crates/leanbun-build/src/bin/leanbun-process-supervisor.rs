#![forbid(unsafe_code)]

use std::env;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("__leanbun-supervise")) {
        eprintln!("leanbun supervisor requires its private dispatch marker");
        return ExitCode::from(64);
    }
    let Some(executable) = arguments.next() else {
        eprintln!("leanbun supervisor requires an executable");
        return ExitCode::from(64);
    };
    if rustix::process::setsid().is_err() {
        eprintln!("leanbun supervisor could not create a process group");
        return ExitCode::from(70);
    }
    let error = Command::new(executable).args(arguments).exec();
    eprintln!("leanbun supervisor exec failed: {error}");
    ExitCode::from(71)
}
