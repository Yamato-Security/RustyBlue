extern crate serde_derive;
extern crate yaml_rust;

use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::{fs, io};

use yaml_rust::YamlLoader;

use crate::detections::print::MessageNotation;

pub struct ParseYaml {
    pub files: Vec<yaml_rust::Yaml>,
}

impl ParseYaml {
    pub fn new() -> ParseYaml {
        ParseYaml { files: Vec::new() }
    }

    pub fn read_file(&self, path: PathBuf) -> Result<String, String> {
        let mut file_content = String::new();

        let mut fr = fs::File::open(path)
            .map(BufReader::new)
            .map_err(|e| e.to_string())?;

        fr.read_to_string(&mut file_content)
            .map_err(|e| e.to_string())?;

        Ok(file_content)
    }

    pub fn read_yaml_file(&mut self, path: PathBuf) -> Result<(), String> {
        let file = self.read_file(path)?;

        let load_result = YamlLoader::load_from_str(&file);
        if load_result.is_err() {
            return Result::Err(format!("fail to read file\n{} ", load_result.unwrap_err()));
        }

        let load_yamls = load_result.unwrap();
        load_yamls.into_iter().for_each(|loaded_yaml| {
            self.files.push(loaded_yaml);
        });

        Result::Ok(())
    }

    pub fn read_dir<P: AsRef<Path>>(&mut self, path: P) -> io::Result<String> {
        Ok(fs::read_dir(path)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                if entry.file_type().ok()?.is_file() {
                    let stdout = std::io::stdout();
                    let mut stdout = stdout.lock();
                    match self.read_file(entry.path()) {
                        Ok(s) => {
                            match YamlLoader::load_from_str(&s) {
                                Ok(docs) => {
                                    for i in docs {
                                        // If there is no "enabled" it does not load
                                        if i["enabled"].as_bool().unwrap_or(false) {
                                            self.files.push(i);
                                        }
                                    }
                                }
                                Err(e) => {
                                    MessageNotation::info_noheader(
                                        &mut stdout,
                                        format!("fail to read file\n{}\n{} ", s, e),
                                    )
                                    .ok();
                                }
                            }
                        }
                        Err(e) => {
                            MessageNotation::info_noheader(
                                &mut stdout,
                                format!("fail to read file: {}\n{} ", entry.path().display(), e),
                            )
                            .ok();
                        }
                    };
                }
                if entry.file_type().ok()?.is_dir() {
                    let _ = self.read_dir(entry.path());
                }
                Some("")
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {

    use crate::detections::yaml;
    use std::path::Path;
    use yaml_rust::YamlLoader;

    #[test]
    fn test_read_yaml() {
        let yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/yaml/1.yml");
        let ret = yaml.read_file(path.to_path_buf()).unwrap();
        let rule = YamlLoader::load_from_str(&ret).unwrap();
        for i in rule {
            if i["title"].as_str().unwrap() == "Sysmon Check command lines" {
                assert_eq!(
                    "*",
                    i["detection"]["selection"]["CommandLine"].as_str().unwrap()
                );
                assert_eq!(1, i["detection"]["selection"]["EventID"].as_i64().unwrap());
            }
        }
    }

    #[test]
    fn test_failed_read_yaml() {
        let yaml = yaml::ParseYaml::new();
        let path = Path::new("test_files/rules/yaml/error.yml");
        let ret = yaml.read_file(path.to_path_buf()).unwrap();
        let rule = YamlLoader::load_from_str(&ret);
        assert!(rule.is_err());
    }
}
