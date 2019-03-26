# TlsDecorator

This is a library which can be used to decorate objects implementing the `SystemAbstractions::INetworkConnection` interface in order to add a layer of Transport Layer Security (TLS) to the underlying connections.

## Usage

The `TlsDecorator` class takes another object implementing the `SystemAbstractions::INetworkConnection` interface, and decorates it, passing all data through a TLS layer.

## Supported platforms / recommended toolchains

This is a portable C++11 library which depends only on the C++11 compiler and standard library, so it should be supported on almost any platform.  The following are recommended toolchains for popular platforms.

* Windows -- [Visual Studio](https://www.visualstudio.com/) (Microsoft Visual C++)
* Linux -- clang or gcc
* MacOS -- Xcode (clang)

## Building

This library is not intended to stand alone.  It is intended to be included in a larger solution which uses [CMake](https://cmake.org/) to generate the build system and build applications which will link with the library.

There are two distinct steps in the build process:

1. Generation of the build system, using CMake
2. Compiling, linking, etc., using CMake-compatible toolchain

### Prerequisites

* [CMake](https://cmake.org/) version 3.8 or newer
* C++11 toolchain compatible with CMake for your development platform (e.g. [Visual Studio](https://www.visualstudio.com/) on Windows)
* [googletest](https://github.com/google/googletest.git) - The Google C++ Test
  framework
* [SystemAbstractions](https://github.com/rhymu8354/SystemAbstractions.git) - a
  cross-platform adapter library for system services whose APIs vary from one
  operating system to another
* `libtls`, `libssl`, and `libcrypto`, as provided by packages such as
  [LibreSSL](https://github.com/rhymu8354/LibreSSL.git)

### Build system generation

Generate the build system using [CMake](https://cmake.org/) from the solution root.  For example:

```bash
mkdir build
cd build
cmake -G "Visual Studio 15 2017" -A "x64" ..
```

### Compiling, linking, et cetera

Either use [CMake](https://cmake.org/) or your toolchain's IDE to build.
For [CMake](https://cmake.org/):

```bash
cd build
cmake --build . --config Release
```
