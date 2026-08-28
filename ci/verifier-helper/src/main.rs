//! Small dependency-free verifier used by CI to exercise argv preservation,
//! bounded output, timeouts and process-tree cleanup without a shell.

use std::{
    env,
    io::{self, Write},
    process::Command,
    thread,
    time::Duration,
};

fn value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}

fn number(args: &[String], flag: &str) -> u64 {
    value(args, flag)
        .and_then(|value| value.parse().ok())
        .unwrap_or_default()
}

fn main() -> io::Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--version") {
        println!("rbx-heal-verifier-helper 0.9.0");
        return Ok(());
    }
    if args.iter().any(|arg| arg == "--echo-args") {
        println!(
            "{}",
            args.iter()
                .skip(1)
                .cloned()
                .collect::<Vec<_>>()
                .join("\u{1f}")
        );
    }
    let stdout_bytes = number(&args, "--stdout-bytes");
    if stdout_bytes > 0 {
        io::stdout().write_all(&vec![b'o'; stdout_bytes as usize])?;
        io::stdout().flush()?;
    }
    let stderr_bytes = number(&args, "--stderr-bytes");
    if stderr_bytes > 0 {
        io::stderr().write_all(&vec![b'e'; stderr_bytes as usize])?;
        io::stderr().flush()?;
    }
    if args.iter().any(|arg| arg == "--spawn-child") {
        let sleep_ms = number(&args, "--child-sleep-ms").max(1);
        let executable = env::current_exe()?;
        let mut child = Command::new(executable)
            .args(["--sleep-ms", &sleep_ms.to_string()])
            .spawn()?;
        let parent_ms = number(&args, "--sleep-ms").max(sleep_ms + 1);
        thread::sleep(Duration::from_millis(parent_ms));
        let _ = child.kill();
        let _ = child.wait();
    } else if let Some(milliseconds) = value(&args, "--sleep-ms") {
        thread::sleep(Duration::from_millis(milliseconds.parse().unwrap_or(1)));
    }
    let exit_code = value(&args, "--exit-code")
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(0);
    std::process::exit(exit_code);
}
