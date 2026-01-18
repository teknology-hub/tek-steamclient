# TEK Steam Client
[![Discord](https://img.shields.io/discord/937821572285206659?style=flat-square&label=Discord&logo=discord&logoColor=white&color=7289DA)](https://discord.gg/JBUgcwvpfc)

**Disclaimer**: This project is not affiliated with Valve Corporation and their official Steam client

tek-steamclient is an open-source C library that implements some parts of a Steam client, most notably the application manager, that allows downloading, verifying and updating Steam applications. It is written in C and C++ and can be built for Windows, Linux and MacOS.

This repository also provides tek-sc-cli, simple command-line interface on top of tek-steamclient, somewhat similar to steamcmd in functionality.

## Features

- Cross-platform, has been tested on x86_64 and AArch64 CPU architectures, might be able to be compiled for others
- Does *not* require Steam application to be installed, and in fact offers alternative to some of its functionality
- Can utilize [tek-s3](https://github.com/teknology-hub/tek-s3) servers to work with applications owned by other people, without logging into their accounts locally
- Efficiently utilizes modern OS features to achieve best I/O performance
- Uses homemade update algorithms that allow utilizing much less disk space for patching than official Steam client does

## Installing

### Windows

There are statically linked binaries for libtek-steamclient-X.dll and tek-sc-cli.exe in [releases](https://github.com/teknology-hub/tek-steamclient/releases), in archives marked as win-x86_64-static. They do not have any external dependencies other than Windows system DLLs, and are recommended for regular use. These binaries are built in MSYS2 [TEK-X86_64 environment](https://github.com/teknology-hub/MinGW-env) and signed by Nuclearist's code signing certificate, which in turn is signed by [TEK CA](https://teknology-hub.com/public-keys/ca.crt), so they will be trusted by OS if TEK CA certificate is.

### Linux

There is `tek-sc-cli-x86_64.AppImage` in [releases](https://github.com/teknology-hub/tek-steamclient/releases), which is built in a Debian Stable container and signed by Nuclearist's [GPG key](https://teknology-hub.com/public-keys/gpg/nuclearist.asc). It can be run with `TEK_SC_USE_SYSTEM_LIBS=1` environment variable to prefer system libraries over bundled ones.

To use the library, you have to install a package for your distro listed below, or [build from source](https://github.com/teknology-hub/tek-steamclient/blob/main/BUILD.md) if it's not there.

|Distro|Package|
|-|-|
|Gentoo|`games-util/tek-steamclient` from [tek-overlay](https://github.com/teknology-hub/tek-overlay)|

## Using

tek-steamclient consists of several APIs:
- Application manager (app_manager, am) - Higher level API, uses all the other ones under the hood. Manages Steam item installations in a directory, provides functions for installing, updating, verifying, uninstalling them. Recommended to use unless there is a good reason not to.
- SteamPipe API (steampipe, sp) - Focused on downloading and decoding data from SteamPipe content servers (manifests, patches, chunks).
- Content API (content, [dm, dp, vc, dd]) - provides structures and functions for parsing/creating, serializing and deserializing Steam content files in tek-steamclient's own formats: depot manifests, depot patches, verification caches, and depot deltas.
- tek-s3 client API (s3_client, s3c) - provides integration with tek-s3 servers, allowing to fetch manifest request codes, depot decryption keys and PICS access tokens from them. Application manager uses it with servers synchronized via `tek_sc_s3c_sync_manifest`
- CM client API (cm) - provides client for Steam CM servers that manage account-related functionality. Application manager implicitly uses it with an anonymous account to fetch some of the data it needs.

For end users, tek-sc-cli program provides thin command-line interface for application manager and tek-s3 client APIs. Use its `--help` argument or `help` command to list available commands.

For developers, libtek-steamclient interfaces are provided via header files:
- [base.h](https://github.com/teknology-hub/tek-steamclient/blob/main/include/tek-steamclient/base.h) - Basic declarations used by all APIs and library context functions.
- [error.h](https://github.com/teknology-hub/tek-steamclient/blob/main/include/tek-steamclient/error.h) - Declarations of types and functions for error handling, used by all APIs.
- [os.h](https://github.com/teknology-hub/tek-steamclient/blob/main/include/tek-steamclient/os.h) - OS-specific type declarations used by some of the APIs.
- [cm.h](https://github.com/teknology-hub/tek-steamclient/blob/main/include/tek-steamclient/cm.h) - CM client API.
- [s3c.h](https://github.com/teknology-hub/tek-steamclient/blob/main/include/tek-steamclient/s3c.h) - tek-s3 client API.
- [content.h](https://github.com/teknology-hub/tek-steamclient/blob/main/include/tek-steamclient/content.h) - Content API.
- [sp.h](https://github.com/teknology-hub/tek-steamclient/blob/main/include/tek-steamclient/sp.h) - SteamPipe API.
- [am.h](https://github.com/teknology-hub/tek-steamclient/blob/main/include/tek-steamclient/am.h) - Application manager API.

## Project structure

- `include` - C header files providing public library interface.
- `pkgfiles` - Files or file templates for package managers to use.
- `po` - Localization files.
- `protos` - Protobuf definition files for various Steam messages. Based on data from [SteamDatabase/Protobufs](https://github.com/SteamDatabase/Protobufs) project.
- `res` - Resource files for Windows binaries
- `src` - Source code:
  + `cli` - tek-sc-cli program source code
  + `common` - headers used by both libtek-steamclient and tek-sc-cli
  + `lib` - libtek-steamclient library source code
- `subprojects` - Meson subproject directory. The repository includes wrap files and package files for dependencies that do not have their own packages in major distros. Currently the only such is [ValveFileVDF](https://github.com/TinyTinni/ValveFileVDF)
