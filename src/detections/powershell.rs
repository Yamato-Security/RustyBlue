use crate::detections::configs;
use crate::detections::utils;
use crate::models::event;
use std::collections::HashMap;
use std::usize;

pub struct PowerShell {}

impl PowerShell {
    pub fn new() -> PowerShell {
        PowerShell {}
    }

    pub fn detection(
        &mut self,
        event_id: String,
        system: &event::System,
        event_data: HashMap<String, String>,
    ) {
        self.execute_pipeline(&event_id, &event_data, &system.time_created.system_time);
        self.execute_remote_command(&event_id, &event_data, &system.time_created.system_time);
    }

    fn execute_pipeline(
        &mut self,
        event_id: &str,
        event_data: &HashMap<String, String>,
        system_time: &str,
    ) {
        if event_id != "4103" {
            return;
        }

        let default = String::from("");
        let commandline = event_data.get("ContextInfo").unwrap_or(&default);

        if commandline.contains("Host Application")
            || commandline.contains("ホスト アプリケーション")
        {
            let temp_command_with_extra = configs::CONFIG
                .powershell_hostapplication_regex
                .replace_all(commandline, "");
            let command = configs::CONFIG
                .powershell_line_feed_regex
                .replace_all(&temp_command_with_extra, "");

            if command != "" {
                let configs: &yaml_rust::Yaml = &configs::CONFIG.configs;
                let value = configs["minlength"].as_i64().unwrap_or(1000);
                utils::check_command(
                    4103,
                    &command,
                    value as usize,
                    0,
                    &default,
                    &default,
                    system_time,
                );
            }
        }
    }

    fn execute_remote_command(
        &mut self,
        event_id: &str,
        event_data: &HashMap<String, String>,
        system_time: &str,
    ) {
        if event_id != "4104" {
            return;
        }

        let default = String::from("");
        let path = event_data.get("Path").unwrap().to_string();
        if path.is_empty() {
            let commandline = event_data.get("ScriptBlockText").unwrap_or(&default);
            if commandline != &default {
                let configs: &yaml_rust::Yaml = &configs::CONFIG.configs;
                let value = configs["minlength"].as_i64().unwrap_or(1000);

                utils::check_command(
                    4104,
                    commandline,
                    value as usize,
                    0,
                    &default,
                    &default,
                    system_time,
                );
            }
        }
    }
}
