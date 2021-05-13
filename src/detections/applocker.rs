extern crate regex;

use crate::detections::configs;
use crate::detections::print::MessageNotation;
use crate::models::event;
use std::collections::HashMap;

pub struct AppLocker {}

impl AppLocker {
    pub fn new() -> AppLocker {
        AppLocker {}
    }

    pub fn detection(
        &mut self,
        event_id: String,
        _system: &event::System,
        _event_data: HashMap<String, String>,
    ) {
        self.applocker_log_warning(&event_id, &_system);
        self.applocker_log_block(&event_id, &_system);
    }

    fn applocker_log_warning(&mut self, event_id: &String, system: &event::System) {
        if event_id != "8003" {
            return;
        }

        let default = "".to_string();
        let message = &system.message.as_ref().unwrap_or(&default);
        let command = configs::CONFIG.applocker_regex.replace_all(&message, "");

        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        MessageNotation::info_noheader(&mut stdout, format!("Message Applocker Warning")).ok();
        MessageNotation::info_noheader(&mut stdout, format!("Command : {}", command)).ok();
        MessageNotation::info_noheader(&mut stdout, format!("Results : {}", message)).ok();
    }

    fn applocker_log_block(&mut self, event_id: &String, system: &event::System) {
        if event_id != "8004" {
            return;
        }

        let default = "".to_string();
        let message = &system.message.as_ref().unwrap_or(&default);
        let command = configs::CONFIG.applocker_regex.replace_all(&message, "");

        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();

        MessageNotation::info_noheader(&mut stdout, format!("Message Applocker Block")).ok();
        MessageNotation::info_noheader(&mut stdout, format!("Command : {}", command)).ok();
        MessageNotation::info_noheader(&mut stdout, format!("Results : {}", message)).ok();
    }
}
