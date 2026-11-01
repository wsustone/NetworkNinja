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

- **macOS: "cannot be opened because the developer cannot be verified".** These builds aren't
  signed yet. Run `xattr -d com.apple.quarantine nn-server nn-generator` in this folder, or
  right-click the program, choose Open, then Open again.
- **Windows: "Windows protected your PC".** Choose More info, then Run anyway.
- **Linux: "Permission denied".** Run `chmod +x nn-server nn-generator`.
- **"Address already in use".** Another program (often a simulator on the same machine) holds
  the port. Add `--share` to share it, or choose another port.

NetworkNinja is proprietary software. See LICENSE.
