# Third-Party Notices

The ReverseShield source in this repository is the team's project code. The
following tools are **downloaded into `tools/` at setup time** and are not
committed to Git:

| Component | Version | Licence / source |
|---|---|---|
| Ghidra | 12.2 PUBLIC | Apache License 2.0 — <https://github.com/NationalSecurityAgency/ghidra> |
| Eclipse Temurin JDK | 25.0.5+8 | GPLv2 with Classpath Exception — <https://adoptium.net/> |
| MinGW-w64 / winlibs | 16.2.0 (optional) | GNU GPL/LGPL and runtime exceptions; see the winlibs archive |
| GNU binutils (`strip`, `objcopy`, `objdump`, `nm`, `readelf`) | distribution version | GPLv3+ — supplied by the OS or MinGW |
| Python | 3.11+ | PSF License — <https://www.python.org/> |

The bundled samples under `samples/src` are self-authored for this project. No
third-party executable, malware sample or customer binary is included.

The demonstration transformer is **not** a commercial protector and does not
include Tigress or any licensed obfuscator. Do not add a tool whose licence
forbids the event use or redistribution.

When distributing the optional Offline ZIP, keep the upstream licence files
inside each tool directory and include this notice. When distributing the Lite
ZIP, the setup script downloads the tools from their official releases.
