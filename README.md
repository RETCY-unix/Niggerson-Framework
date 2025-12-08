# VANGUARD - Niggerson Framework

**Linux-Only Network Security Framework**

```
╔══════════════════════════════════════════════════════════╗
║   ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗   ║
║   ██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗  ║
║   ██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║  ║
║   ╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║  ║
║    ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║  ║
║     ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝  ║
╚══════════════════════════════════════════════════════════╝
```

## Features

- **HYDRA** - Network discovery (WiFi, devices, ports)
- **REAPER** - MITM attacks via ARP poisoning
- **ZAWARUDO** - Linux payload generator

## Requirements

- Linux (tested on Arch)
- GCC compiler
- Root privileges for network operations

## Build & Run

```bash
make
sudo ./vanguard
```

## Commands

| Command | Description |
|---------|-------------|
| `hydra networks` | Scan nearby WiFi |
| `hydra devices` | Find LAN devices |
| `hydra scan <IP>` | Port scan target |
| `reaper poison <target> <gateway>` | ARP poison |
| `reaper stop` | Stop attack |
| `zawarudo help` | Payload options |
| `help` | Show all commands |

## Example Session

```
VANGUARD > hydra devices
[*] Scanning subnet...
[+] 192.168.1.1    aa:bb:cc:dd:ee:ff  [ROUTER]
[+] 192.168.1.50   11:22:33:44:55:66  
[+] 192.168.1.100  ab:cd:ef:12:34:56  [YOU]

VANGUARD > reaper poison 192.168.1.50 192.168.1.1
[+] ARP POISONING ACTIVE
[*] Target will lose connectivity!
```

## License

For educational purposes only. Use responsibly.
