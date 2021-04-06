extern crate serde;

use evtx::EvtxParser;
use rusty_blue::detections::configs;
use rusty_blue::detections::detection;
use rusty_blue::detections::print::MessageNotation;
use std::{fs, path::PathBuf, process};

fn main() {
    if let Some(filepath) = configs::singleton().args.value_of("filepath") {
        parse_file(&filepath.to_string());
    } else if let Some(dirpath) = configs::singleton().args.value_of("dirpath") {
        let target_paths = parse_dir(&dirpath.to_string());
        for target_path in target_paths {
            println!("---------------------");
            println!("{}", target_path.display().to_string());
            parse_file(&target_path.display().to_string());
            println!("---------------------");
        }
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

fn parse_dir(dirpath: &str) -> Vec<PathBuf> {
    let input_dir = fs::read_dir(dirpath);
    if input_dir.is_err() {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        MessageNotation::alert(&mut stdout, format!("{}", input_dir.unwrap_err())).ok();
        return vec![];
    }
    let mut ret = vec![];
    for f in input_dir.unwrap() {
        if f.is_err() {
            continue;
        }
        let path = f.unwrap().path();
        if path.is_dir() {
            path.to_str().and_then(|path_str| {
                let subdir_ret = parse_dir(path_str);
                ret.extend(subdir_ret);
                return Option::Some(());
            });
        } else {
            let path_str = path.to_str().unwrap_or("");
            if path_str.ends_with(".evtx") {
                ret.push(path);
            }
        }
    }
    return ret;
}

#[cfg(test)]
mod tests {
    use crate::parse_dir;

    #[test]
    fn test_parse_dir_not_exists() {
        let files = parse_dir("test_files/evtx/notfiles");
        assert_eq!(0, files.len());
    }

    #[test]
    fn test_parse_dir_exists() {
        let files = parse_dir("test_files/evtx");
        assert_eq!(3, files.len());
        files.iter().for_each(|file| {
            let is_contains = &vec!["test1.evtx", "test2.evtx", "testtest4.evtx"]
                .into_iter()
                .any(|filepath_str| {
                    return file.file_name().unwrap().to_str().unwrap_or("") == filepath_str;
                });
            assert_eq!(is_contains, &true);
        })
    }
}
