# NetworkNinja quick start

This archive holds two programs:

- `nn-server` watches DIS traffic and shows its problems in a dashboard.
- `nn-generator` sends synthetic DIS traffic, with faults if you want them, so you can try
  `nn-server` without a simulator.

There's nothing to install: run them from this folder. (On Windows they are `nn-server.exe`
and `nn-generator.exe`; type `.\nn-server.exe` where these steps say `./nn-server`.)

**Runs on:** Windows 10 or 11 (x86_64); macOS 11 or later (Apple Silicon or Intel); any
x86_64 Linux. Neither program needs any extra libraries, runtimes or drivers: no Visual C++
Redistributable, and no Npcap, WinPcap or libpcap (DIS is read from ordinary UDP sockets, and
pcap files are read directly).

**First launch:** the macOS programs are signed and notarized by Apple, so they open
normally (the Mac checks with Apple online the first time). The Windows build isn't signed
yet, so Windows warns the first time; [If it won't start](#if-it-wont-start) below has the
one-step fix.

## 1. Watch an exercise

On a machine that can see the exercise's DIS traffic (DIS usually uses UDP port 3000):

```
./nn-server serve --port 3000
```

Open http://127.0.0.1:8080 in a browser. Problems appear on the left, and the entities and
map on the right. Stop the server with Ctrl+C.

- To see the dashboard from other machines, add `--http 0.0.0.0:8080`.
- For multicast exercises, several ports or a chosen network card, copy `nn.example.toml` to
  `nn.toml`, edit it, and run `./nn-server serve --config nn.toml`. Run
  `./nn-server interfaces` to list the network cards.
- The first time you run it, Windows and macOS may ask whether `nn-server` may accept network
  connections. Allow it on private networks.

## 2. Try it without a simulator

Leave the server running and, in a second terminal:

```
./nn-generator --target 127.0.0.1:3000 --duration 300 --all-faults --all-controls --fire-every 10
```

The dashboard fills with entities, and with the faults the generator injects. Run
`./nn-generator --help` to list every fault and preset.

## 3. Optional extras

- **Enumeration checks:** NetworkNinja checks field values against SISO-REF-010, which is free
  from sisostandards.org. Download the XML file and run
  `./nn-server serve --port 3000 --siso SISO-REF-010.xml`.
- **Rule packs:** `rulepacks/dis-base.toml` is the built-in pack, copied here for reference.
  To change a threshold, write your own pack and add `--rulepack mine.toml`.
- **Accounts and HTTPS:** create an account with
  `./nn-server passwd users.txt --user NAME --pass PASSWORD`, then add `--users users.txt`. To
  turn on HTTPS, run `./nn-server cert nn` and add `--cert nn.crt --key nn.key`.
- Run `./nn-server --help` for the rest, and `./nn-server --version` to see which build you
  have.

## If it won't start

- **macOS: "“nn-server” Not Opened. Apple could not verify “nn-server” is free of malware…"**
  (older macOS: "cannot be opened because the developer cannot be verified"). The Mac couldn't
  reach Apple to confirm the notarization (offline machines), or this is an older unsigned
  build. Click Done, then in Terminal, in this folder, run `xattr -d com.apple.quarantine nn-server nn-generator` and start it again. Or
  open System Settings → Privacy & Security, scroll to the message about nn-server, click
  **Open Anyway** and confirm (once for each program).
- **Windows: "Windows protected your PC".** Choose More info, then Run anyway. If Windows
  blocks the programs when you start them from PowerShell, run
  `Unblock-File .\nn-server.exe, .\nn-generator.exe` in this folder first. Antivirus may also
  flag unsigned new programs; allow them, or add this folder as an exception.
- **Linux: "Permission denied".** Run `chmod +x nn-server nn-generator`.
- **"Address already in use".** Another program (often a simulator on the same machine) holds
  the port. Add `--share` to share it, or choose another port.

## Reporting a problem or feedback

Open an issue at <https://github.com/wsustone/NetworkNinja/issues/new/choose>: **Something went
wrong** for a crash, an error or a wrong or missing alert, **Feedback or idea** for anything else.
The form asks for:

- the version: `./nn-server --version`;
- your operating system, and how you ran it (the command line, and where the traffic came from);
- what happened and what you expected. For an alert, name the check and the entity or sender.

A fix report helps with alerts: open the problem card in the dashboard and use **fix report**, or
fetch `http://127.0.0.1:8080/api/report?sim=SITE:APP` and paste the Markdown. Please don't attach
recordings, pcaps or screenshots from a real exercise unless you're allowed to share them.

Copyright 2026 Juston Morgan. NetworkNinja is licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
