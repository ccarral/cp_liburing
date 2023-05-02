use anyhow::{self, bail};
use std::{self, path::PathBuf};

pub fn parse_args(args: &[String]) -> anyhow::Result<(PathBuf, PathBuf)> {
    // Check args length == 2
    let args = &args[1..];
    if args.len() != 2 {
        bail!("Unexpected number of arguments");
    }
    let in_path = &args[0];
    let out_path = &args[1];

    Ok((PathBuf::from(in_path), PathBuf::from(out_path)))
}
