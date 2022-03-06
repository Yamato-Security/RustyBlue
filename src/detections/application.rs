extern crate regex;

use crate::detections::configs;
use crate::detections::print::MessageNotation;
use crate::models::event;
use std::collections::HashMap;

pub struct Application {}

impl Application {
    pub fn new() -> Application {
        Application {}
    }

    pub fn detection(
        &mut self,
        event_id: String,
        system: &event::System,
        _event_data: HashMap<String, String>,
    ) {
        self.emet(&event_id, system);
    }

    fn emet(&mut self, event_id: &str, system: &event::System) {
        if event_id != "2" {
            return;
        }

        match &system.provider.name {
            Some(name) => {
                if name != "EMET" {
                    return;
                }
            }
            None => return,
        }
        match &system.message {
            Some(message) => {
                let message_split: Vec<&str> = message.split('\n').collect();
                if !message_split.is_empty() && message_split.len() >= 5 {
                    let text = message_split[0];
                    let application = message_split[3];
                    let command = configs::CONFIG
                        .application_regex
                        .replace_all(application, "");
                    let username = message_split[4];
                    let stdout = std::io::stdout();
                    let mut stdout = stdout.lock();

                    MessageNotation::info_noheader(
                        &mut stdout,
                        format!("Date    : {}", system.time_created.system_time),
                    )
                    .ok();
                    MessageNotation::info_noheader(
                        &mut stdout,
                        "Message: Message EMET Block".to_string(),
                    )
                    .ok();
                    MessageNotation::info_noheader(&mut stdout, "EventID: 2".to_string()).ok();
                    MessageNotation::info_noheader(&mut stdout, format!("Command: {}", command))
                        .ok();
                    MessageNotation::info_noheader(&mut stdout, format!("Results: {}", text)).ok();
                    MessageNotation::info_noheader(&mut stdout, format!("Results: {}", username))
                        .ok();
                    if let Some(csvfilepath) = configs::CONFIG.args.value_of("outcsvpath") {
                        let mut file = OpenOptions::new()
                            .write(true)
                            .append(true)
                            .create(true)
                            .open(csvfilepath)
                            .unwrap();
                        // filepath指定のために関数への引き渡しが必要
                        match MessageNotation::output_csv(
                            &mut file,
                            CsvFormat {
                                filepath: &"test".to_owned(),
                                date: &system.time_created.system_time,
                                eventid: &"2".to_owned(),
                                message: &"Message EMET Block".to_owned(),
                                result: &format!("{}/Username:{}", text, username),
                                command: &command.to_owned(),
                            },
                        ) {
                            Ok(..) => {}
                            Err(e) => {
                                let stdout = std::io::stdout();
                                let mut stdout = stdout.lock();
                                MessageNotation::warn(
                                    &mut stdout,
                                    format!("csv output failed:{}", e),
                                )
                                .ok();
                            }
                        }
                    }
                }
            }
            None => {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::warn(&mut stdout, "EMET Message field is blank. Install EMET locally to see full details of this alert".to_string()).ok();
            }
        }
    }
}
