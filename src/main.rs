extern crate serde;

use evtx::EvtxParser;
use rusty_blue::detections::configs;
use rusty_blue::detections::detection;
use rusty_blue::detections::print::MessageNotation;
use std::{fs, path::PathBuf, process};

fn main() {
    if let Some(filepath) = configs::singleton().args.value_of("filepath") {
        parse_file(&filepath.to_string());
    } else if let Some(dirpath) = configs::singleton().args.value_of("directory") {
        parse_dir(&dirpath.to_string());
    }

    if configs::singleton().args.is_present("credits") {
        print_credits();
    }
}

fn print_credits() {
    match fs::read_to_string("./credits.txt") {
        Ok(contents) => {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            MessageNotation::info_noheader(&mut stdout, format!("{}", contents)).ok();
        }
        Err(err) => {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            MessageNotation::alert(&mut stdout, format!("credits.txt not found , {}", err)).ok();
        }
    }
}

fn parse_file(filepath: &str) {
    let fp = PathBuf::from(filepath);
    let parser = match EvtxParser::from_path(fp) {
        Ok(pointer) => pointer,
        Err(e) => {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            MessageNotation::alert(&mut stdout, format!("{}", e)).ok();
            process::exit(1);
        }
    };

    let mut detection = detection::Detection::new();
    &detection.start(parser);
}

fn parse_dir(dirpath: &String) -> Vec<PathBuf> {
    let input_dir = fs::read_dir(dirpath);
    if input_dir.is_err() {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        MessageNotation::alert(&mut stdout, format!("{}", input_dir.unwrap_err())).ok();
        return vec![];
    }
    return vec![];
}
