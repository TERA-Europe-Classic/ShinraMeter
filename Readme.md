Shinra Meter — TERA Europe Classic+ variant
============================================

This fork is the Classic+ variant of ShinraMeter, built for the
**TERA Europe Classic+** (v100.02) private server. It descends from the
Gothos / Neowutran lineage, via michaelcarno's .NET 8 rewrite ("Shinra Beta"),
via LukasTD's Yurian / Evervyn branches, with Classic+-specific connection,
region, and data pinning applied.

Only the `main` branch is maintained.

Features
--------

- Real-time DPS overlay (per-player, per-skill, per-encounter)
- Encounter log with automatic upload
- Damage / healing / abnormal-state breakdown
- Excel + 7z-compressed JSON export
- D3D9 in-game overlay
- TTS, Discord RPC, Twitch chat integration
- Dungeon / boss definitions and abnormality data

Connection mechanism
--------------------

ShinraMeter connects to `127.0.0.1:7803` over TCP and reads framed messages
from a local mirror socket exposed by the Noctenium proxy / DLL running in
the TERA client process. It does **not** sniff the wire (no pcap / WinPcap).

Frame format: `[u16 totalLen][u8 direction][payload]`, little-endian,
`totalLen` includes the direction byte. `direction = 1` → client-to-server,
`direction = 2` → server-to-client.

The proxy is responsible for replaying the session-key exchange as the first
two framed messages after each connect — the sniffer decrypts every frame
locally via `ConnectionDecrypter` keyed to the `"EUC"` region.

Shinra retries the connect every 2 s indefinitely. It does not probe for
`TERA.exe`; it simply dials the socket and waits.

Local build
-----------

Prereqs: .NET 8 SDK on Windows.

```
dotnet restore Tera.sln
dotnet build Tera.sln -c Release
dotnet publish DamageMeter.UI/DamageMeter.UI.csproj -c Release -f net8-windows -o ./publish/ShinraMeter
Copy-Item -Path ./resources -Destination ./publish/ShinraMeter -Recurse -Force
```

The DamageMeter.UI csproj already bundles `lib/7z*.dll` into the output via a
`Content` include; they are needed for the JSON export's 7z compressor.

Release
-------

Push a tag `v*.*.*` to `main`. GitHub Actions will build, publish, and attach
`ShinraMeter-v*.*.*.zip` to a Release.

Credits
-------

- Gothos — original TeraSniffer / DamageMeter
- Gl0, Yukikoo / neowutran — original ShinraMeter
- michaelcarno — .NET 8 rewrite ("Shinra Beta")
- Foglio1024 — Nostrum, TCC, companion tooling
- GoneUp, dezmen — opcode dumps
- Se7en-Hellas — logo
- TERA Europe Classic+ community — Classic+ connection protocol and data

Lineage
-------

```
Gothos/TeraDamageMeter → neowutran/ShinraMeter → michaelcarno/ShinraMeter
  → LukasTD/ShinraMeter → TERA-Europe-Classic/ShinraMeter (this fork)
```
