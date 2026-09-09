# Distributed Monero Mining — Controller + Workers

```
Monero pool  <===>  main.py (YOUR PC: wallet + pool login)
                       ||  Cloudflare quick tunnel
                       \/
                 rxworker (SERVER 1: RandomX compute)
                 rxworker (SERVER 2: RandomX compute)
                 rxworker (SERVER N: ...)
```

One controller manages **N servers**. Your wallet and pool credentials stay on your PC.
Servers run pure compute — no pool code, no wallet, no credentials.

## Quick Start

### 1) On your PC (one time)

```bash
python main.py
```

First run walks you through setup:
- Enter your Monero wallet address
- Choose a mining pool (default: supportxmr)
- Server package is auto-generated in `server_package/`

### 2) On each server

Upload `server_package/` to the server, then:

```bash
sudo bash setup.sh
```

This automatically:
- Installs build dependencies
- Installs cloudflared
- Configures huge pages (critical for performance)
- Builds rxworker with full optimizations
- Creates a systemd service (auto-starts on boot)
- Prints the tunnel URL

### 3) Back on your PC

Copy the tunnel URL from each server and paste it when prompted (or add to `config.json`).

Mining starts automatically.

## Adding More Servers

1. Upload the same `server_package/` to the new server
2. Run `sudo bash setup.sh` on it
3. Add the tunnel URL to `config.json` on your PC:
   ```json
   {
       "workers": [
           {"name": "worker-1", "url": "wss://abc.trycloudflare.com"},
           {"name": "worker-2", "url": "wss://def.trycloudflare.com"}
       ]
   }
   ```
4. Restart the controller: `python main.py`

To regenerate the server package (e.g. after code changes):
```bash
python main.py --generate
```

## Performance

rxworker includes these optimizations for maximum hashrate:

| Feature | Impact |
|---|---|
| Huge pages (2 MB) | +30-50% hashrate |
| CPU core pinning | +5-15% hashrate |
| Pipelined hashing | +3-6% hashrate |
| Hardware auto-detection | Safe on all x86_64 CPUs |
| Thread-local counters | No cache-line bouncing |
| Fast 64-bit target check | Minimal hot-path overhead |

**Expected**: near XMRig-class performance with huge pages enabled.

## Files

| File | Where | Purpose |
|---|---|---|
| `main.py` | Your PC | Controller — manages pool + workers |
| `rxworker.cpp` | Your PC (source) | Worker source code |
| `config.json` | Your PC (auto-created) | Wallet, pool, token, worker list |
| `server_package/` | Upload to servers | Everything a server needs |

## Requirements

- **PC**: Python 3.8+, `websockets` (auto-installed)
- **Server**: Linux x86_64, root access for setup

## Notes

- Quick tunnel URLs change if cloudflared restarts. Grab the new URL:
  ```bash
  grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' tunnel.log | tail -1
  ```
- `rxworker` flags: `--port 8765` `--token <secret>` `--threads N` `--light`
  (`--light` uses 256 MB instead of ~2.3 GB RAM, slower)
- Huge pages are configured automatically by `setup.sh`. Verify with:
  ```bash
  cat /proc/meminfo | grep HugePages_
  ```
