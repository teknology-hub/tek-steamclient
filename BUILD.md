# Building tek-steamclient

This guide assumes that you have installed `curl` program, and `tar` or `git`, which in most systems are either pre-installed or can be easily acquired. On Windows, using [MSYS2](https://www.msys2.org/) is required, preferably with CLANG64 environment as the most tested during development.

## 1. Install dependencies

Package names and commands used to install them vary across systems, so they will net be given here for the time being.

### Toolchain requirements

- C and C++ compilers with decent support for C23/C++23 with GNU extensions (i.e. `-std=gnu23` and `-std=gnu++23`), most notable are GCC 13+ and Clang 18+.
- [Meson build system](https://mesonbuild.com) - must be installed to build the project.
- [CMake](https://cmake.org) - may be required to be present to correctly find certain dependencies.

### Dependencies

Here's the list of libraries that tek-steamclient depends on:

### Core dependencies

|Library|Usage|
|-|-|
|libcrypto from [OpenSSL](https://www.openssl.org)|AES-256 CBC and ECB decryption, SHA-1 hashing, RSA encryption|
|[libcurl](https://curl.se)|HTTP(S) downloads|
|[libwebsockets](https://libwebsockets.org)|WebSocket connections for Steam CM client|
|protobuf-lite from [Protobuf](https://protobuf.dev)|Serialization and deserialization of Protobuf messages used by Steam|
|pthreads|Threading and synchronization primitives. Most systems provide it by default|
|[RapidJSON](https://rapidjson.org/)|JSON serialization and parsing|
|[SQLite3](https://sqlite.org/index.html)|Cache and state storage in database files|
|[zlib](https://www.zlib.net) or [zlib-ng](https://github.com/zlib-ng/zlib-ng)|GZip decompression, CRC32 checksums|
|[GNU gettext](https://www.gnu.org/software/gettext/gettext.html) (optional)|Localization|

### Content API dependencies

|Library|Usage|
|-|-|
|[libzip](https://libzip.org)|Zip archive extraction|

### SteamPipe API dependencies

|Library|Usage|
|-|-|
|liblzma from [XZ Utils](https://tukaani.org/xz)|LZMA decompression|
|[libzip](https://libzip.org)|Zip archive extraction|
|[libzstd](https://github.com/facebook/zstd)|Zstandard decompression|

### Application manager API dependencies

|Library|Usage|
|-|-|
|[ValveFileVDF](https://github.com/TinyTinni/ValveFileVDF)|Valve Data File parsing. Provided via Meson wrap file in the repository, doesn't need to be installed separately|
|[liburing](https://github.com/axboe/liburing) (Linux-only, optional)|Slightly improves file read/write performance on kernels supporting io_uring|

### tek-sc-cli dependencies

|Library|Usage|
|-|-|
|[libqrencode](https://github.com/fukuchi/libqrencode) (optional)|QR code generation for QR code-based Steam sign-in|

## 2. Get source code

Clone this repository:
```sh
git clone https://github.com/teknology-hub/tek-steamclient.git
cd tek-steamclient
```
, or download a point release e.g.
```sh
curl -LOJ https://github.com/teknology-hub/tek-steamclient/releases/download/v1.0.0/tek-steamclient-1.0.0.tar.gz`
tar -xzf tek-steamclient-1.0.0.tar.gz
cd tek-steamclient-1.0.0
```

## 3. Setup build directory

At this stage you can set various build options. tek-steamclient's own options are listed in [meson.options](https://github.com/teknology-hub/tek-steamclient/blob/main/meson.options), other available options are described in [Meson documentation](https://mesonbuild.com/Commands.html#setup).
The simplest case that uses default options, debugoptimized build type (which uses -O2 optimization level instead of often overrated -O3 in release), and strips binaries of debug information during installing:
```sh
meson setup build --buildtype debugoptimized -Dstrip=true
```
On Windows in MSYS2 you way also want to set prefix to the one matching your environment, e.g for CLANG64 the option would be `--prefix=/clang64`.

## 4. Compile and install the project

```sh
meson install -C build
```
This will compile source files and install binaries into system locations, after which you can use them. If you're on MSYS2, keep in in mind that these binaries cannot be used outside of MSYS2 environment unless you copy **all** DLLs that they depends on into their directory. To circumvent that, you'd have to link all dependencies statically, which is not possible with official MSYS2 packages at the moment of writing this due to some of them not providing static library files, or correct package metadata for static linking, so those would have to be rebuilt with custom options. Doing so is possible (release binaries are built this way), but it's way out of the scope of this guide.
