# RustyBlue 
RustyBlue is a software ported from DeepBlueCLI in Rust language. We admire the DeepBlueCLI.

RustyBlueはDeepBlueCLIをRust言語で移植されたソフトです。私たちは、DeepBlueCLIを称賛しています。

# Usage
`````````````````````
-f --filepath=[FILEPATH] 'analyze event file'
-d --dirpath=[DIRECTORYPATH] 'analyze event log files in directory'
-c --credits 'print credits infomation'
`````````````````````

# Usage Example
### Analysis one event log for specified path.
コンパイルされたバイナリを使用する場合、下記のようなコマンドで実行することができます。
``````````
rusty_blue.exe --filepath=C:\Users\user\Downloads\security.evtx
``````````

このレポジトリをクローンし、下記のコマンドに実行する方法もあります。
ただし、ローカルPCにRustをインストールしている必要があります。
``````````
cargo run -- --filepath=C:\Users\user\Downloads\security.evtx
``````````

### Analysis recusively all event logs in specified directory.
コンパイルされたバイナリを使用する場合、下記のようなコマンドで実行することができます。
``````````
rusty_blue.exe --dirpath=C:\Users\user\Downloads
``````````

Rustのcargoコマンドを用いて、実行することもできます。
``````````
cargo run -- --dirpath=C:\Users\user\Downloads\security.evtx
``````````