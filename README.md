# SFUnpacker

Extract the files packed inside Setup Factory installers, on Windows and Linux, without running the installer.

Supported: Setup Factory 7, 8, 9 and 10. Version 5 and 6 are not handled.

## Download

Prebuilt binaries for Windows (x64) and Linux (x64) are attached to every [release](../../releases). They are self-contained, no runtime needs to be installed.

## Usage

    sfunpacker <installer.exe> [output-dir]

Files end up in `output-dir` (default `extracted`, relative to the current directory) with the folder layout stored in the installer, for example `extracted/%AppFolder%/Data/...`. The installer's own runtime files (`irsetup.exe`, `irsetup.dat`, `lua5.1.dll`) are extracted as well.

Every file is verified against the CRC stored in the installer. The exit code is 0 when everything was extracted and 1 otherwise. Paths in the installer that would escape the output directory (`..`) are skipped and reported.

Memory use is roughly the size of the largest file inside the installer, since each file is decompressed in memory.

## Building

You need a C++17 compiler and CMake 3.16 or newer. Nothing else, the LZMA SDK and the PKWare decoder are bundled.

    cmake -S . -B build
    cmake --build build --config Release

The binary is `build/sfunpacker` (Linux) or `build\Release\sfunpacker.exe` (Visual Studio).

## Tests

    python3 tests/run_tests.py build/sfunpacker

The script generates small synthetic installers for each supported version and compression method and compares the extracted bytes. Real installers can be put into `tests/non-synth/` (ignored by git) to try them by hand.

## Releases

Pushing a tag that starts with `v` builds and tests both platforms in GitHub Actions and publishes a release with a `.zip` (Windows) and a `.tar.gz` (Linux).

    git tag v1.0.0
    git push origin v1.0.0

## Credits and license

The installer format knowledge comes from [Observer](https://github.com/lazyhamster/Observer/). Bundled third party code: the [LZMA SDK](https://www.7-zip.org/sdk.html) (public domain) and `blast` by Mark Adler (zlib license).

SFUnpacker is [free](http://www.gnu.org/philosophy/free-sw.html) software: you can use it, redistribute it and/or modify it under the terms of the [GNU Lesser General Public License](http://www.gnu.org/licenses/lgpl.html) as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
