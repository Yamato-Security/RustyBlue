extern crate regex;

use crate::models::event;
use crate::detections::configs;
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

        println!("Message Applocker Warning");
        println!("Command : {}", command);
        println!("Results : {}", message);
    }

    fn applocker_log_block(&mut self, event_id: &String, system: &event::System) {
        if event_id != "8004" {
            return;
        }

        let default = "".to_string();
        let message = &system.message.as_ref().unwrap_or(&default);
        let command = configs::CONFIG.applocker_regex.replace_all(&message, "");

        println!("Message Applocker Block");
        println!("Command : {}", command);
        println!("Results : {}", message);
    }
}
