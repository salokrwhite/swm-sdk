# SWM SDK

This repository contains the standalone Software Web Manager client SDK.

Supported SDK implementations:

- `CSharp/`: pure managed .NET 10 on Windows x86/x64.
- `Cpp/`: pure C++20 static library on Windows x86/x64.
- `Java/`: Java 17 Windows desktop SDK using JNA for system CNG/DPAPI APIs.
- `Go/`: Go 1.26 Windows desktop SDK using CNG, DPAPI, and pure Go Win32 bindings.
- `Rust/`: Rust 1.85+ async Windows desktop SDK using CNG, DPAPI, and Win32 APIs.
- `Python/`: Python 3.10+ synchronous Windows desktop SDK using CNG, DPAPI, and Win32 APIs.

See each SDK directory's `README.md` for usage and build instructions.
