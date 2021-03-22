extern crate regex;

use crate::detections::print::MessageNotation;
use crate::models::event;
use regex::Regex;
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

    fn emet(&mut self, event_id: &String, system: &event::System) {
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
                let message_split: Vec<&str> = message.split("\n").collect();
                if !message_split.is_empty() && message_split.len() >= 5 {
                    let text = message_split[0];
                    let application = message_split[3];
                    let re = Regex::new(r"^Application: ").unwrap();
                    let command = re.replace_all(application, "");
                    let username = message_split[4];
                    let stdout = std::io::stdout();
                    let mut stdout = stdout.lock();

                    MessageNotation::info_noheader(
                        &mut stdout,
                        format!("Date    : {}", system.time_created.system_time),
                    )
                    .ok();
                    MessageNotation::info_noheader(&mut stdout, format!("Message EMET Block")).ok();
                    MessageNotation::info_noheader(&mut stdout, format!("Command : {}", command))
                        .ok();
                    MessageNotation::info_noheader(&mut stdout, format!("Results : {}", text)).ok();
                    MessageNotation::info_noheader(&mut stdout, format!("Results : {}", username))
                        .ok();
                }
            }
            None => {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::warn(&mut stdout, format!("EMET Message field is blank. Install EMET locally to see full details of this alert")).ok();
            }
        }
    }
}
