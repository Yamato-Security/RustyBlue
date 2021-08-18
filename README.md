# RustyBlue


![RustyBlueLogo](https://user-images.githubusercontent.com/2350416/129946711-2b146040-335b-4b28-8283-0f6c8bc0bd5d.png)


RustyBlue is a Rust implementation of Eric Conrad's DeepBlueCLI, a DFIR tool that detects various Windows attacks by analyzing event logs. It cannot take advantage of some of the PowerShell features to do remote investigations or use a GUI but it is very lightweight and fast so its main purpose is to be used on large event log files and to be a reference for writing more Windows event log analysis tools in Rust.

DeepBlueCLI: https://github.com/sans-blue-team/DeepBlueCLI

RustyBlueはDeepBlueCLIをRust言語で移植されたソフトです。私たちは、DeepBlueCLIを称賛しています。

## Usage

`````````````````````
Analyze one event log file:
-f or --filepath=<FilePath>

Analyze event log files in a directory:
-d or --dirpath=<DirectoryPath>

Print credits:
-c or --credits
`````````````````````

## Usage Examples

### Analyzing one event log:

コンパイルされたバイナリを使用する場合、下記のようなコマンドで実行することができます:

``````````
rusty_blue.exe --filepath=C:\Users\user\Downloads\security.evtx
``````````

### Analyzing recusively all event logs in specified directory:

コンパイルされたバイナリを使用する場合、下記のようなコマンドで実行することができます:

``````````
rusty_blue.exe --dirpath=C:\WindowsEventLogs
``````````

### Building from source code:

You can compile the cloned source code with the following command.

以下コマンドでcloneしたソースコードからコンパイルすることができます。Rustのコンパイル環境をローカル環境に導入していることが条件です:

``````````
cargo build --release
``````````

### RustyBlue Binaries

You can download the compiled binaries for Windows, Linux and MacOS here: https://github.com/Yamato-Security/RustyBlue/releases/
