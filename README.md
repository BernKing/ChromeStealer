<div align="center">
  <h1>ChromeStealer</h1>
  <br/>

  <p><i>ChromeStealer is a tool for educational purposes to demonstrate how to extract and decrypt stored passwords from Google Chrome on a Windows system using C/C++. <br/>Created by <a href="https://x.com/bernKing20">@bernKing20</a>.</i></p>
  <br />
</div>

## Overview

ChromeStealer was created because existing write-ups and C/C++ versions either didn't work or didn't satisfy me enough. I hope that the write-up helps other people who were in the same position as me.

## Dependencies

This project uses the following libraries:

1. [libsodium](https://libsodium.gitbook.io/doc/)
2. [nlohmann/json](https://github.com/nlohmann/json)
3. [sqlite3](https://www.sqlite.org/index.html)

## Installation

This project uses [vcpkg](https://vcpkg.io/) to manage dependencies. Ensure you have vcpkg installed and integrated with Visual Studio 2022.

1. Clone the repository:

    ```sh
    git clone https://github.com/yourusername/ChromeStealer.git
    cd ChromeStealer
    ```

2. Install the dependencies using vcpkg:

    ```sh
    vcpkg install libsodium jsoncpp sqlite3
    ```

3. Open the project in Visual Studio 2022.

## Usage

1. Build the project in Visual Studio 2022.
2. Run the executable. Follow the on-screen instructions to extract and decrypt stored passwords from Google Chrome.

## Full Write-Up

For a detailed explanation of the project, visit the full write-up at [bernking.com](https://bernking.com).

## Disclaimer

This tool is intended for educational purposes only. Misuse of this tool can lead to legal consequences. Always ensure you have permission before using it on any system. The author is not responsible for any misuse of this tool.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [libsodium](https://libsodium.gitbook.io/doc/)
- [nlohmann/json](https://github.com/nlohmann/json)
- [sqlite3](https://www.sqlite.org/index.html)
- [How to Hack Chrome Password with Python](https://ohyicong.medium.com/how-to-hack-chrome-password-with-python-1bedc167be3d)
