extern crate serde;

use evtx::EvtxParser;
use quick_xml::de::DeError;
use std::{fs, path::PathBuf, process};
use rusty_blue::detections::configs;
use rusty_blue::detections::detection;
use rusty_blue::omikuji::Omikuji;

fn main() -> Result<(), DeError> {
    let filepath: String = configs::singleton()
        .args
        .value_of("filepath")
        .unwrap_or("")
        .to_string();
    if filepath != "" {
        parse_file(&filepath);
    }

    Ok(())
}

fn parse_file(filepath: &str) {
    let fp = PathBuf::from(filepath);
    let parser = match EvtxParser::from_path(fp) {
        Ok(pointer) => pointer,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    let mut detection = detection::Detection::new();
    &detection.start(parser);
}

fn output_with_omikuji(omikuji: Omikuji) {
    let fp = &format!("art/omikuji/{}", omikuji);
    let content = fs::read_to_string(fp).unwrap();
    println!("{}", content);
}
