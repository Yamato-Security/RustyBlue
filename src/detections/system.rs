use crate::detections::print::MessageNotation;
use crate::detections::utils;
use crate::models::event;
use std::collections::HashMap;

#[derive(Debug)]
pub struct System {}

impl System {
    pub fn new() -> System {
        System {}
    }

    pub fn detection(
        &mut self,
        event_id: String,
        system: &event::System,
        event_data: HashMap<String, String>,
    ) {
        self.system_log_clear(&event_id, &system.time_created.system_time)
            .and_then(System::print_console);
        self.windows_event_log(&event_id, &event_data, &system.time_created.system_time);
        self.new_service_created(&event_id, &event_data, &system.time_created.system_time)
            .and_then(System::print_console);
        self.interactive_service_warning(&event_id, &event_data, &system.time_created.system_time)
            .and_then(System::print_console);
        self.suspicious_service_name(&event_id, &event_data, &system.time_created.system_time)
            .and_then(System::print_console);
    }

    fn print_console(v: Vec<String>) -> Option<Vec<String>> {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        v.iter().for_each(|s| {
            MessageNotation::info_noheader(&mut stdout, format!("{}", s)).ok();
        });
        MessageNotation::info_noheader(&mut stdout, format!("\n")).ok();
        return Option::Some(v);
    }

    fn new_service_created(
        &mut self,
        event_id: &String,
        event_data: &HashMap<String, String>,
        system_time: &String,
    ) -> Option<Vec<String>> {
        if event_id != "7045" {
            return Option::None;
        }

        let default = String::from("");
        let servicename = &event_data.get("ServiceName").unwrap_or(&default);
        let commandline = &event_data.get("ImagePath").unwrap_or(&default);
        let text = utils::check_regex(&servicename, 1);
        let mut msges: Vec<String> = Vec::new();
        if !text.is_empty() {
            msges.push(format!("Date : {}", system_time));
            msges.push("Message : New Service Created".to_string());
            msges.push(format!("Command : {}", commandline));
            msges.push(format!("Results : Service name: {}", servicename));
            msges.push(format!("Results : {}", text));
        }
        if !commandline.is_empty() {
            utils::check_command(7045, &commandline, 1000, 0, &servicename, &"", &system_time);
        }
        return Option::Some(msges);
    }

    fn interactive_service_warning(
        &mut self,
        event_id: &String,
        event_data: &HashMap<String, String>,
        system_time: &String,
    ) -> Option<Vec<String>> {
        if event_id != "7030" {
            return Option::None;
        }

        let default = String::from("");
        let servicename = &event_data.get("param1").unwrap_or(&default);
        let mut msges: Vec<String> = Vec::new();
        msges.push(format!("Date    : {}", system_time));
        msges.push("Message : Interactive service warning".to_string());
        msges.push(format!("Results : Service name: {}", servicename));
        msges.push(
            "Results : Malware (and some third party software) trigger this warning".to_string(),
        );
        msges.push(format!("{}", utils::check_regex(&servicename, 1)));
        return Option::Some(msges);
    }

    fn suspicious_service_name(
        &mut self,
        event_id: &String,
        event_data: &HashMap<String, String>,
        system_time: &String,
    ) -> Option<Vec<String>> {
        if event_id != "7036" {
            return Option::None;
        }

        let default = String::from("");
        let servicename = &event_data.get("param1").unwrap_or(&default);
        let text = utils::check_regex(&servicename, 1);
        let mut msges: Vec<String> = Vec::new();
        if !text.is_empty() {
            msges.push(format!("Date    : {}", system_time));
            msges.push("Message : Suspicious Service Name".to_string());
            msges.push(format!("Results : Service name: {}", servicename));
            msges.push(format!("Results : {}", text));
        }
        return Option::Some(msges);
    }

    fn system_log_clear(&mut self, event_id: &String, system_time: &String) -> Option<Vec<String>> {
        if event_id != "104" {
            return Option::None;
        }
        let mut msges: Vec<String> = Vec::new();

        msges.push(format!("Date : {}", system_time));
        msges.push("Message : System Log Clear".to_string());
        msges.push("Results : The System log was cleared.".to_string());
        return Option::Some(msges);
    }

    fn windows_event_log(
        &mut self,
        event_id: &String,
        event_data: &HashMap<String, String>,
        system_time: &String,
    ) -> Option<Vec<String>> {
        if event_id != "7040" {
            return Option::None;
        }
        let mut msges: Vec<String> = Vec::new();
        if let Some(_param1) = event_data.get("param1") {
            if _param1 == "Windows Event Log" {
                msges.push(format!("Date    : {}", system_time));
                msges.push(format!("Service name : {}", _param1));
                if let Some(_param2) = event_data.get("param2") {
                    if _param2 == "disabled" {
                        msges.push("Message : Event Log Service Stopped".to_string());
                        msges.push(
                            "Results : Selective event log manipulation may follow this event."
                                .to_string(),
                        );
                    } else if _param2 == "auto start" {
                        msges.push("Message : Event Log Service Started".to_string());
                        msges.push(
                            "Results : Selective event log manipulation may precede this event."
                                .to_string(),
                        );
                    }
                }
            }
        }
        return Option::Some(msges);
    }
}

#[cfg(test)]
mod tests {
    extern crate quick_xml;

    use crate::detections::system;
    use crate::detections::system::MessageNotation;
    use crate::models::event;

    // 正しくヒットするパターン
    #[test]
    fn test_system_log_clear() {
        let xml_str = get_system_log_clear_xml();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::alert(&mut stdout, format!("{}", e.to_string())).ok();
            })
            .unwrap();

        let mut sys = system::System::new();
        let option_v = sys.system_log_clear(
            &event.system.event_id.to_string(),
            &event.system.time_created.system_time,
        );

        let v = option_v.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"Date : 2019-04-27 21:04:25.733401 UTC".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Message : System Log Clear".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Results : The System log was cleared.".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(Option::None, ite.next());
    }

    // eventidが異なりヒットしないパターン
    #[test]
    fn test_system_log_clear_noteq_eventid() {
        let xml_str = get_system_log_clear_xml()
            .replace(r"<EventID>104</EventID>", r"<EventID>105</EventID>");
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::alert(&mut stdout, format!("{}", e.to_string())).ok();
            })
            .unwrap();

        let mut sys = system::System::new();
        let option_v = sys.system_log_clear(
            &event.system.event_id.to_string(),
            &event.system.time_created.system_time,
        );
        assert_eq!(Option::None, option_v);
    }

    #[test]
    fn test_new_service_created() {
        let xml_str = get_system_service_created_xml();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::alert(&mut stdout, format!("{}", e.to_string())).ok();
            })
            .unwrap();

        let mut sys = system::System::new();
        let option_v = sys.new_service_created(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
            &event.system.time_created.system_time,
        );
        let v = option_v.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"Date : 2017-07-12 17:16:29.401630 UTC".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Message : New Service Created".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Command : \\SystemRoot\\System32\\drivers\\WUDFRd.sys".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Results : Service name: ijklmnopIJKLMNOP".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Results : Metasploit-style service name: 16 characters\n".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(Option::None, ite.next());
    }

    // eventidが異なりヒットしないパターン
    #[test]
    fn test_new_service_created_noteq_eventid() {
        let xml_str = get_system_service_created_xml()
            .replace(r"<EventID>7045</EventID>", r"<EventID>7046</EventID>");
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::alert(&mut stdout, format!("{}", e.to_string())).ok();
            })
            .unwrap();

        let mut sys = system::System::new();
        let option_v = sys.new_service_created(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
            &event.system.time_created.system_time,
        );
        assert_eq!(Option::None, option_v);
    }

    // cmdlineがセットされていないパターン
    #[test]
    fn test_new_service_created_cmdline_notset() {
        let xml_str = r#"
        <?xml version="1.0" encoding="utf-8"?>
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager">
            </Provider>
            <EventID>7045</EventID>
            <Version>0</Version>
            <Level>4</Level>
            <Task>0</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8080000000000000</Keywords>
            <TimeCreated SystemTime="2017-07-12 17:16:29.401630 UTC">
            </TimeCreated>
            <EventRecordID>45</EventRecordID>
            <Correlation>
            </Correlation>
            <Execution ProcessID="620" ThreadID="1796">
            </Execution>
            <Channel>System</Channel>
            <Computer>WIN-P4SIAA0SQCO</Computer>
            <Security UserID="S-1-5-18">
            </Security>
          </System>
          <EventData>
            <Data Name="ServiceName">ijklmnopIJKLMNOP</Data>
            <Data Name="ServiceType">kernel mode driver</Data>
            <Data Name="StartType">demand start</Data>
            <Data Name="AccountName"></Data>
          </EventData>
        </Event>""#;

        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::alert(&mut stdout, format!("{}", e.to_string())).ok();
            })
            .unwrap();

        let mut sys = system::System::new();
        let option_v = sys.new_service_created(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
            &event.system.time_created.system_time,
        );
        let v = option_v.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"Date : 2017-07-12 17:16:29.401630 UTC".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Message : New Service Created".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Command : ".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Results : Service name: ijklmnopIJKLMNOP".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Results : Metasploit-style service name: 16 characters\n".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(Option::None, ite.next());
    }

    #[test]
    fn test_interactive_service_warning() {
        let xml_str = get_interactive_service_warning();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::alert(&mut stdout, format!("{}", e.to_string())).ok();
            })
            .unwrap();
        let mut sys = system::System::new();
        let option_v = sys.interactive_service_warning(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
            &event.system.time_created.system_time,
        );
        let v = option_v.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"Date    : 2017-07-12 07:19:24.066431 UTC".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Message : Interactive service warning".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Results : Service name: Printer Extensions and Notifications".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Results : Malware (and some third party software) trigger this warning".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(&"".to_string(), ite.next().unwrap_or(&"".to_string()));
        assert_eq!(Option::None, ite.next());
    }

    // eventidが異なりヒットしないパターン
    #[test]
    fn test_interactive_service_warning_noteq_eventid() {
        let xml_str = get_interactive_service_warning()
            .replace(r"<EventID>7030</EventID>", r"<EventID>7031</EventID>");
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::alert(&mut stdout, format!("{}", e.to_string())).ok();
            })
            .unwrap();

        let mut sys = system::System::new();
        let option_v = sys.interactive_service_warning(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
            &event.system.time_created.system_time,
        );
        assert_eq!(Option::None, option_v);
    }

    #[test]
    fn test_suspicious_service_name() {
        let xml_str = get_suspicious_service_name();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::alert(&mut stdout, format!("{}", e.to_string())).ok();
            })
            .unwrap();
        let mut sys = system::System::new();
        let option_v = sys.suspicious_service_name(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
            &event.system.time_created.system_time,
        );
        let v = option_v.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"Date    : 2017-07-12 07:19:24.066431 UTC".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Message : Suspicious Service Name".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Results : Service name: abcdefghABCDEFGH".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Results : Metasploit-style service name: 16 characters\n".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(Option::None, ite.next());
    }

    // eventidが異なりヒットしないパターン
    #[test]
    fn test_suspicious_service_name_noteq_eventid() {
        let xml_str = get_suspicious_service_name()
            .replace(r"<EventID>7036</EventID>", r"<EventID>7037</EventID>");
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::alert(&mut stdout, format!("{}", e.to_string())).ok();
            })
            .unwrap();

        let mut sys = system::System::new();
        let option_v = sys.suspicious_service_name(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
            &event.system.time_created.system_time,
        );
        assert_eq!(Option::None, option_v);
    }

    #[test]
    fn test_windows_event_log() {
        let xml_str = get_windows_event_log();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::alert(&mut stdout, format!("{}", e.to_string())).ok();
            })
            .unwrap();
        let mut sys = system::System::new();
        let option_v = sys.windows_event_log(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
            &event.system.time_created.system_time,
        );
        let v = option_v.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"Date    : 2017-07-12 07:20:03.875567 UTC".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Service name : Windows Event Log".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Message : Event Log Service Stopped".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Results : Selective event log manipulation may follow this event.".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(Option::None, ite.next());
    }

    #[test]
    fn test_windows_event_log_auto_start() {
        let xml_str = r#"
        <?xml version="1.0" encoding="utf-8"?>
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager">
            </Provider>
            <EventID>7040</EventID>
            <Version>0</Version>
            <Level>4</Level>
            <Task>0</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8080000000000000</Keywords>
            <TimeCreated SystemTime="2017-07-12 07:20:03.875567 UTC">
            </TimeCreated>
            <EventRecordID>242</EventRecordID>
            <Correlation>
            </Correlation>
            <Execution ProcessID="616" ThreadID="1608">
            </Execution>
            <Channel>System</Channel>
            <Computer>DESKTOP-2KGM189</Computer>
            <Security UserID="S-1-5-18">
            </Security>
          </System>
          <EventData>
            <Data Name="param1">Windows Event Log</Data>
            <Data Name="param2">auto start</Data>
            <Data Name="param3">auto start</Data>
            <Data Name="param4">BITS</Data>
          </EventData>
        </Event>"#.to_string();
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::alert(&mut stdout, format!("{}", e.to_string())).ok();
            })
            .unwrap();
        let mut sys = system::System::new();
        let option_v = sys.windows_event_log(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
            &event.system.time_created.system_time,
        );
        let v = option_v.unwrap();
        let mut ite = v.iter();
        assert_eq!(
            &"Date    : 2017-07-12 07:20:03.875567 UTC".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Service name : Windows Event Log".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Message : Event Log Service Started".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(
            &"Results : Selective event log manipulation may precede this event.".to_string(),
            ite.next().unwrap_or(&"".to_string())
        );
        assert_eq!(Option::None, ite.next());
    }

    // eventidが異なりヒットしないパターン
    #[test]
    fn test_windows_event_log_noteq_eventid() {
        let xml_str =
            get_windows_event_log().replace(r"<EventID>7040</EventID>", r"<EventID>7041</EventID>");
        let event: event::Evtx = quick_xml::de::from_str(&xml_str)
            .map_err(|e| {
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                MessageNotation::alert(&mut stdout, format!("{}", e.to_string())).ok();
            })
            .unwrap();

        let mut sys = system::System::new();
        let option_v = sys.windows_event_log(
            &event.system.event_id.to_string(),
            &event.parse_event_data(),
            &event.system.time_created.system_time,
        );
        assert_eq!(Option::None, option_v);
    }

    fn get_system_log_clear_xml() -> String {
        return r#"
        <?xml version="1.0" encoding="utf-8"?>
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}">
            </Provider>
            <EventID>104</EventID>
            <Version>0</Version>
            <Level>4</Level>
            <Task>104</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8000000000000000</Keywords>
            <TimeCreated SystemTime="2019-04-27 21:04:25.733401 UTC">
            </TimeCreated>
            <EventRecordID>9252</EventRecordID>
            <Correlation>
            </Correlation>
            <Execution ProcessID="7464" ThreadID="5848">
            </Execution>
            <Channel>System</Channel>
            <Computer>DESKTOP-JR78RLP</Computer>
            <Security UserID="S-1-5-21-979008924-657238111-836329461-1002">
            </Security>
          </System>
          <UserData>
            <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
              <SubjectUserName>jwrig</SubjectUserName>
              <SubjectDomainName>DESKTOP-JR78RLP</SubjectDomainName>
              <Channel>System</Channel>
              <BackupPath></BackupPath>
            </LogFileCleared>
          </UserData>
        </Event>"#.to_string();
    }

    fn get_system_service_created_xml() -> String {
        return r#"
        <?xml version="1.0" encoding="utf-8"?>
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager">
            </Provider>
            <EventID>7045</EventID>
            <Version>0</Version>
            <Level>4</Level>
            <Task>0</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8080000000000000</Keywords>
            <TimeCreated SystemTime="2017-07-12 17:16:29.401630 UTC">
            </TimeCreated>
            <EventRecordID>45</EventRecordID>
            <Correlation>
            </Correlation>
            <Execution ProcessID="620" ThreadID="1796">
            </Execution>
            <Channel>System</Channel>
            <Computer>WIN-P4SIAA0SQCO</Computer>
            <Security UserID="S-1-5-18">
            </Security>
          </System>
          <EventData>
            <Data Name="ServiceName">ijklmnopIJKLMNOP</Data>
            <Data Name="ImagePath">\SystemRoot\System32\drivers\WUDFRd.sys</Data>
            <Data Name="ServiceType">kernel mode driver</Data>
            <Data Name="StartType">demand start</Data>
            <Data Name="AccountName"></Data>
          </EventData>
        </Event>"#.to_string();
    }
    fn get_interactive_service_warning() -> String {
        return r#"
        <?xml version="1.0" encoding="utf-8"?>
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager">
            </Provider>
            <EventID>7030</EventID>
            <Version>0</Version>
            <Level>2</Level>
            <Task>0</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8080000000000000</Keywords>
            <TimeCreated SystemTime="2017-07-12 07:19:24.066431 UTC">
            </TimeCreated>
            <EventRecordID>241</EventRecordID>
            <Correlation>
            </Correlation>
            <Execution ProcessID="616" ThreadID="1712">
            </Execution>
            <Channel>System</Channel>
            <Computer>DESKTOP-2KGM189</Computer>
            <Security>
            </Security>
          </System>
          <EventData>
            <Data Name="param1">Printer Extensions and Notifications</Data>
          </EventData>
        </Event>"#.to_string();
    }
    fn get_suspicious_service_name() -> String {
        return r#"
        <?xml version="1.0" encoding="utf-8"?>
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager">
            </Provider>
            <EventID>7036</EventID>
            <Version>0</Version>
            <Level>2</Level>
            <Task>0</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8080000000000000</Keywords>
            <TimeCreated SystemTime="2017-07-12 07:19:24.066431 UTC">
            </TimeCreated>
            <EventRecordID>241</EventRecordID>
            <Correlation>
            </Correlation>
            <Execution ProcessID="616" ThreadID="1712">
            </Execution>
            <Channel>System</Channel>
            <Computer>DESKTOP-2KGM189</Computer>
            <Security>
            </Security>
          </System>
          <EventData>
            <Data Name="param1">abcdefghABCDEFGH</Data>
          </EventData>
        </Event>"#.to_string();
    }

    fn get_windows_event_log() -> String {
        return r#"
        <?xml version="1.0" encoding="utf-8"?>
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager">
            </Provider>
            <EventID>7040</EventID>
            <Version>0</Version>
            <Level>4</Level>
            <Task>0</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8080000000000000</Keywords>
            <TimeCreated SystemTime="2017-07-12 07:20:03.875567 UTC">
            </TimeCreated>
            <EventRecordID>242</EventRecordID>
            <Correlation>
            </Correlation>
            <Execution ProcessID="616" ThreadID="1608">
            </Execution>
            <Channel>System</Channel>
            <Computer>DESKTOP-2KGM189</Computer>
            <Security UserID="S-1-5-18">
            </Security>
          </System>
          <EventData>
            <Data Name="param1">Windows Event Log</Data>
            <Data Name="param2">disabled</Data>
            <Data Name="param3">auto start</Data>
            <Data Name="param4">BITS</Data>
          </EventData>
        </Event>"#.to_string();
    }
}
