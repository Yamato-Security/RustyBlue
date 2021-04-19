extern crate csv;
extern crate quick_xml;

use crate::detections::application;
use crate::detections::applocker;
use crate::detections::common;
use crate::detections::powershell;
use crate::detections::print::MessageNotation;
use crate::detections::security;
use crate::detections::sysmon;
use crate::detections::system;
use crate::models::event;
use evtx::EvtxParser;
use quick_xml::de::DeError;
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct Detection {
    timeline_list: BTreeMap<String, String>,
}

impl Detection {
    pub fn new() -> Detection {
        Detection {
            timeline_list: BTreeMap::new(),
        }
    }

    pub fn start(&mut self, mut parser: EvtxParser<std::fs::File>) -> Result<(), DeError> {
        let mut common: common::Common = common::Common::new();
        let mut security = security::Security::new();
        let mut system = system::System::new();
        let mut application = application::Application::new();
        let mut applocker = applocker::AppLocker::new();
        let mut sysmon = sysmon::Sysmon::new();
        let mut powershell = powershell::PowerShell::new();

        for record in parser.records() {
            match record {
                Ok(r) => {
                    match quick_xml::de::from_str(&r.data) {
                        Ok(event) => {
                            let event: event::Evtx = event;

                            let event_id = event.system.event_id.to_string();
                            let channel = event.system.channel.to_string();
                            let event_data = event.parse_event_data();

                            &common.detection(&event.system, &event_data);
                            if channel == "Security" {
                                &security.detection(
                                    event_id,
                                    &event.system,
                                    &event.user_data,
                                    event_data,
                                );
                                match &*event_id {
                                    "7030" | "7036" | "7045" | "7040" | "104" => {
                                        println!("Detected Events : Security id {}", event_id)
                                    }
                                    _ => println!("Not Found Events_id {}", event_id),
                                }
                            } else if channel == "System" {
                                &system.detection(event_id, &event.system, event_data);
                                match &*event_id {
                                    "4688" | "4672" | "4720" | "4728" | "4732" | "4756"
                                    | "4625" | "4673" | "4674" | "4648" | "1102" => {
                                        println!("Detected Events : System id {}", event_id)
                                    }
                                    _ => println!("Not Found Events_id {}", event_id),
                                }
                            } else if channel == "Application" {
                                &application.detection(event_id, &event.system, event_data);
                                match &*event_id {
                                    "2" => {
                                        println!("Detected Events : Application id {}", event_id)
                                    }
                                    _ => println!("Not Found Events_id {}", event_id),
                                }
                            } else if channel == "Microsoft-Windows-PowerShell/Operational" {
                                &powershell.detection(event_id, &event.system, event_data);
                                match &*event_id {
                                    "8003" | "8004" | "8006" | "8007" => {
                                        println!("Detected Events : AppLocker id {}", event_id)
                                    }
                                    _ => println!("Not Found Events_id {}", event_id),
                                }
                            } else if channel == "Microsoft-Windows-Sysmon/Operational" {
                                &sysmon.detection(event_id, &event.system, event_data);
                                match &*event_id {
                                    "4103" | "4104" => {
                                        println!("Detected Events : PowerShell id {}", event_id)
                                    }
                                    _ => println!("Not Found Events_id {}", event_id),
                                }
                            } else if channel == "Microsoft-Windows-AppLocker/EXE and DLL" {
                                &applocker.detection(event_id, &event.system, event_data);
                                match &*event_id {
                                    "1" | "7" => {
                                        println!("Detected Events : Sysmon id {}", event_id)
                                    }
                                    _ => println!("Not Found Events_id {}", event_id),
                                }
                            } else {
                                //&other.detection();
                            }
                        }
                        Err(err) => {
                            let stdout = std::io::stdout();
                            let mut stdout = stdout.lock();
                            MessageNotation::alert(&mut stdout, format!("{}", err)).ok();
                        }
                    }
                }
                Err(e) => {
                    let stdout = std::io::stdout();
                    let mut stdout = stdout.lock();
                    MessageNotation::alert(&mut stdout, format!("{}", e)).ok();
                }
            }
        }

        ////////////////////////////
        // 表示
        ////////////////////////////
        common.disp();
        security.disp();

        return Ok(());
    }
}
