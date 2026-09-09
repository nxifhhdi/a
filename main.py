#!/usr/bin/env python3
"""
Monero Distributed Mining — CONTROLLER
=======================================
Runs on your PC. Connects to your mining pool, distributes jobs to N worker
servers (rxworker instances) through Cloudflare quick tunnels, collects shares
and submits them to the pool under YOUR wallet.

    pool <--> [this controller] <-- cloudflare tunnel --> [rxworker 1]
                                <-- cloudflare tunnel --> [rxworker 2]
                                <-- cloudflare tunnel --> [rxworker N]

Usage:
    python main.py                  # first run: interactive setup, then mine
    python main.py                  # subsequent runs: load config, mine
    python main.py --generate       # regenerate server package only

Config is stored in config.json alongside this script.
Server deployment files are generated into server_package/.
"""

import asyncio, json, os, secrets, shutil, ssl, sys, time, subprocess, signal

# ---------------------------------------------------------------- paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
PACKAGE_DIR = os.path.join(BASE_DIR, "server_package")
RXWORKER_SRC = os.path.join(BASE_DIR, "rxworker.cpp")

# ---------------------------------------------------------------- dependency check
def ensure_websockets():
    try:
        import websockets  # noqa
    except ImportError:
        print("[setup] installing 'websockets' ...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "websockets"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception:
            sys.exit("Error: could not install 'websockets'. Run: pip install websockets")

ensure_websockets()
import websockets

# ================================================================ CONFIG
def load_config():
    if not os.path.exists(CONFIG_PATH):
        return None
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=4)

def setup_wizard():
    """Interactive first-run setup. Returns config dict."""
    print("\n\u2554" + "\u2550" * 44 + "\u2557")
    print("\u2551   Monero Distributed Mining Controller    \u2551")
    print("\u255a" + "\u2550" * 44 + "\u255d")
    print("\nNo configuration found. Starting setup...\n")

    wallet = ""
    while not wallet:
        wallet = input("  Wallet address: ").strip()
        if not wallet:
            print("  Wallet address is required.")

    pool_host = input("  Pool host [pool.supportxmr.com]: ").strip() or "pool.supportxmr.com"
    pool_port_s = input("  Pool port [3333]: ").strip() or "3333"
    pool_port = int(pool_port_s)
    tls_input = input("  Use TLS? (y/N): ").strip().lower()
    pool_tls = tls_input in ("y", "yes")

    token = secrets.token_hex(32)

    cfg = {
        "wallet": wallet,
        "pool_host": pool_host,
        "pool_port": pool_port,
        "pool_tls": pool_tls,
        "token": token,
        "workers": []
    }
    save_config(cfg)
    print(f"\n  \u2713 Configuration saved to config.json")
    print(f"  \u2713 Auth token auto-generated")
    return cfg

def prompt_add_workers(cfg):
    """Prompt user to add tunnel URLs interactively."""
    print("\n  Add server tunnel URLs (one per line, empty to finish):")
    while True:
        url = input("  URL: ").strip()
        if not url:
            break
        # Normalize: accept https:// and convert to wss://
        if url.startswith("https://"):
            url = "wss://" + url[8:]
        if not url.startswith("wss://") and not url.startswith("ws://"):
            url = "wss://" + url
        name = f"worker-{len(cfg['workers']) + 1}"
        cfg["workers"].append({"name": name, "url": url})
        print(f"  \u2713 Added {name}: {url}")
    save_config(cfg)

# ================================================================ SERVER PACKAGE GENERATION

BUILD_SH = r"""#!/bin/bash
set -e
cd "$(dirname "$0")"

# Check prerequisites
for cmd in cmake g++ git; do
    if ! command -v $cmd &>/dev/null; then
        echo "Error: $cmd not found. Run: sudo apt-get install -y build-essential cmake git"
        exit 1
    fi
done

if [ ! -d RandomX ]; then
    echo 'Cloning RandomX...'
    git clone --depth 1 https://github.com/tevador/RandomX.git
fi

echo 'Building RandomX...'
cmake -S RandomX -B RandomX/build \
    -DARCH=native \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="-flto" \
    -DCMAKE_CXX_FLAGS="-flto" \
    > /dev/null 2>&1
cmake --build RandomX/build -j"$(nproc)" > /dev/null 2>&1

echo 'Building rxworker...'
g++ -O3 -march=native -flto -pthread -std=c++17 \
    -I RandomX/src rxworker.cpp \
    RandomX/build/librandomx.a \
    -o rxworker

echo '  Built ./rxworker'
"""

def make_supervisor_sh(token):
    return f"""#!/bin/bash
# Watchdog: keeps rxworker + cloudflare tunnel alive
cd "$(dirname "$0")"

TOKEN="{token}"
THREADS=0
PORT=8765
CF="$(command -v cloudflared || echo /usr/local/bin/cloudflared)"

cleanup() {{ kill $(jobs -p) 2>/dev/null; exit 0; }}
trap cleanup SIGTERM SIGINT

RX_FAILS=0
CF_FAILS=0

while true; do
    # Log rotation: truncate if > 50 MB
    for f in rxworker.log tunnel.log; do
        if [ -f "$f" ] && [ "$(stat -c%s "$f" 2>/dev/null || echo 0)" -gt 52428800 ]; then
            : > "$f"
        fi
    done

    # rxworker
    if ! kill -0 "$(cat rxworker.pid 2>/dev/null)" 2>/dev/null; then
        ARGS="--port $PORT --token $TOKEN"
        [ "$THREADS" -gt 0 ] && ARGS="$ARGS --threads $THREADS"
        nohup ./rxworker $ARGS >> rxworker.log 2>&1 &
        echo $! > rxworker.pid
        RX_FAILS=$((RX_FAILS + 1))
    else
        RX_FAILS=0
    fi

    # cloudflared tunnel
    if ! kill -0 "$(cat tunnel.pid 2>/dev/null)" 2>/dev/null; then
        nohup "$CF" tunnel --url http://127.0.0.1:$PORT --no-autoupdate >> tunnel.log 2>&1 &
        echo $! > tunnel.pid
        CF_FAILS=$((CF_FAILS + 1))
    else
        CF_FAILS=0
    fi

    sleep 15
done
"""

SETUP_SH = r"""#!/bin/bash
set -e

echo ''
echo '=== Monero Mining Server Setup ==='
echo ''

if [ "$(id -u)" -ne 0 ]; then
    echo 'Error: run as root (sudo bash setup.sh)'
    exit 1
fi

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$WORKDIR"

# Install build dependencies
echo 'Installing dependencies...'
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq build-essential cmake git curl > /dev/null 2>&1
echo '  [OK] Build dependencies'

# Install cloudflared
if ! command -v cloudflared &>/dev/null; then
    echo 'Installing cloudflared...'
    curl -sL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
        -o /usr/local/bin/cloudflared
    chmod +x /usr/local/bin/cloudflared
    echo '  [OK] cloudflared installed'
else
    echo '  [OK] cloudflared already present'
fi

# Configure huge pages for RandomX performance (+30-50% hashrate)
HUGE=1280
echo "vm.nr_hugepages=$HUGE" > /etc/sysctl.d/99-hugepages.conf
sysctl -w vm.nr_hugepages=$HUGE > /dev/null 2>&1 || true
echo "  [OK] Huge pages configured ($HUGE)"

# Build rxworker
echo 'Building rxworker (this may take a few minutes)...'
chmod +x build.sh supervisor.sh
bash build.sh
echo '  [OK] rxworker built'

# Create systemd service
cat > /etc/systemd/system/rxworker.service <<UNIT
[Unit]
Description=rxworker mining + cloudflare tunnel
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=$WORKDIR
ExecStart=$WORKDIR/supervisor.sh
Restart=always
RestartSec=5
KillMode=control-group
[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now rxworker
echo '  [OK] systemd service started'

# Wait for tunnel URL
echo ''
echo 'Waiting for tunnel URL...'
for i in $(seq 1 30); do
    URL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' tunnel.log 2>/dev/null | tail -1 || true)
    if [ -n "$URL" ]; then
        WSS="wss://${URL#https://}"
        echo ''
        echo '================================================'
        echo "  TUNNEL URL: $WSS"
        echo '================================================'
        echo ''
        echo '  Copy this URL and add it to your controller.'
        echo '  (edit config.json on your PC, add to workers list)'
        echo ''
        exit 0
    fi
    sleep 2
done
echo ''
echo 'Tunnel URL not found yet. Check later with:'
echo "  grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' $WORKDIR/tunnel.log | tail -1"
echo ''
"""

def generate_server_package(cfg):
    """Generate the server deployment package."""
    # Check rxworker.cpp exists
    if not os.path.exists(RXWORKER_SRC):
        print(f"  Error: rxworker.cpp not found at {RXWORKER_SRC}")
        return False

    # Create package directory
    if os.path.exists(PACKAGE_DIR):
        shutil.rmtree(PACKAGE_DIR)
    os.makedirs(PACKAGE_DIR)

    # Copy rxworker.cpp
    shutil.copy2(RXWORKER_SRC, os.path.join(PACKAGE_DIR, "rxworker.cpp"))

    # Write build.sh
    with open(os.path.join(PACKAGE_DIR, "build.sh"), "w", newline="\n") as f:
        f.write(BUILD_SH)

    # Write supervisor.sh with token baked in
    with open(os.path.join(PACKAGE_DIR, "supervisor.sh"), "w", newline="\n") as f:
        f.write(make_supervisor_sh(cfg["token"]))

    # Write setup.sh
    with open(os.path.join(PACKAGE_DIR, "setup.sh"), "w", newline="\n") as f:
        f.write(SETUP_SH)

    print(f"\n  \u2713 Server package created: {PACKAGE_DIR}/")
    print(f"\n  Deploy to each server:")
    print(f"    1. Upload the server_package/ folder")
    print(f"    2. Run: sudo bash setup.sh")
    print(f"    3. Copy the tunnel URL it prints")
    return True


# ================================================================ POOL CLIENT

class Pool:
    """Stratum JSON-RPC client for Monero mining pools."""

    def __init__(self, config):
        self.host = config["pool_host"]
        self.port = config["pool_port"]
        self.tls = config.get("pool_tls", False)
        self.wallet = config["wallet"]
        self.worker_name = config.get("worker_name", "ctrl")
        self.session_id = None
        self.rpc_id = 0
        self.reader = None
        self.writer = None
        self.last_seed = None
        self.on_job = None       # async callback(job_id, blob, target, seed)
        self.accepted = 0
        self.rejected = 0
        self.jobs_sent = 0

    async def _send(self, obj):
        self.writer.write((json.dumps(obj) + "\n").encode())
        await self.writer.drain()

    async def connect(self):
        """Connect to pool and login. Returns after login succeeds."""
        ssl_ctx = True if self.tls else None
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port, ssl=ssl_ctx
        )
        self.rpc_id += 1
        await self._send({
            "id": self.rpc_id, "jsonrpc": "2.0", "method": "login",
            "params": {"login": self.wallet, "pass": self.worker_name, "agent": "ctrl/2.0"}
        })
        print(f"[pool] connected to {self.host}:{self.port}{' (TLS)' if self.tls else ''}")

    async def run(self):
        """Read pool messages in a loop. Raises on disconnect."""
        async for line in self.reader:
            try:
                msg = json.loads(line)
            except Exception:
                continue

            job = None
            if msg.get("method") == "job":
                job = msg.get("params", {})
            elif msg.get("result") and isinstance(msg["result"], dict) and "job" in msg["result"]:
                self.session_id = msg["result"].get("id")
                print(f"[pool] logged in, session {self.session_id}")
                job = msg["result"]["job"]
            elif msg.get("result") and isinstance(msg["result"], dict) and msg["result"].get("status") == "OK":
                self.accepted += 1
                print(f"[pool] share ACCEPTED (total {self.accepted})")
            elif msg.get("error"):
                self.rejected += 1
                print(f"[pool] share REJECTED: {msg['error']} (total rej {self.rejected})")

            if job and job.get("blob"):
                seed = job.get("seed_hash") or self.last_seed
                if not seed:
                    continue
                self.last_seed = seed
                self.jobs_sent += 1
                if self.on_job:
                    await self.on_job(job["job_id"], job["blob"], job["target"], seed)
                    print(f"[pool\u2192workers] job {job['job_id'][:8]}... "
                          f"height={job.get('height', '?')} diff={job.get('diff', '?')}")

    async def submit(self, job_id, nonce, result):
        """Submit a share found by a worker."""
        self.rpc_id += 1
        await self._send({
            "id": self.rpc_id, "jsonrpc": "2.0", "method": "submit",
            "params": {"id": self.session_id, "job_id": job_id,
                       "nonce": nonce, "result": result}
        })

    def close(self):
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass


# ================================================================ WORKER CLIENT

class Worker:
    """WebSocket client for one rxworker instance."""

    def __init__(self, name, url, token):
        self.name = name
        self.url = url
        self.token = token
        self.hashrate = 0
        self.threads = 0
        self.connected = False
        self.ws = None
        self.pending_job = None  # (job_id, blob, target, seed) — latest job to send on connect
        self._on_submit = None   # async callback(job_id, nonce, result)

    async def send_job(self, job_id, blob, target, seed):
        """Send a job to this worker. Stores as pending if not connected."""
        self.pending_job = (job_id, blob, target, seed)
        if self.connected and self.ws:
            try:
                await self.ws.send(f"JOB {job_id} {blob} {target} {seed}")
            except Exception:
                pass

    async def run(self, on_submit):
        """Connection loop with automatic reconnection."""
        self._on_submit = on_submit
        while True:
            try:
                await self._connect_and_listen()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.connected = False
                self.hashrate = 0
                print(f"[{self.name}] disconnected: {e}; reconnecting in 10s...")
                await asyncio.sleep(10)

    async def _connect_and_listen(self):
        print(f"[{self.name}] connecting to {self.url} ...")
        async with websockets.connect(
            self.url, ping_interval=20, ping_timeout=20
        ) as ws:
            self.ws = ws
            await ws.send("AUTH " + self.token)
            ready = await asyncio.wait_for(ws.recv(), 10)
            if not ready.startswith("READY"):
                raise RuntimeError(f"auth failed: {ready}")

            # Parse thread count
            try:
                self.threads = int(ready.split("threads=")[1])
            except Exception:
                self.threads = 0

            self.connected = True
            print(f"[{self.name}] online ({ready})")

            # Send pending job immediately so worker starts mining
            if self.pending_job:
                job_id, blob, target, seed = self.pending_job
                await ws.send(f"JOB {job_id} {blob} {target} {seed}")

            async for msg in ws:
                if msg.startswith("SUBMIT "):
                    parts = msg.split()
                    if len(parts) == 4 and self._on_submit:
                        await self._on_submit(parts[1], parts[2], parts[3])
                elif msg.startswith("HASHRATE "):
                    try:
                        self.hashrate = int(msg.split()[1])
                    except (ValueError, IndexError):
                        pass
                elif msg.startswith("ERR"):
                    print(f"[{self.name}] {msg}")

        self.connected = False
        self.ws = None
        self.hashrate = 0


# ================================================================ CONTROLLER (orchestrates pool + workers)

async def run_controller(cfg):
    """Main mining loop: connect to pool + all workers, distribute jobs."""
    pool = Pool(cfg)
    workers = [Worker(w["name"], w["url"], cfg["token"]) for w in cfg["workers"]]

    if not workers:
        print("\n[warn] no workers configured. Add tunnel URLs to config.json and restart.")
        return

    async def broadcast_job(job_id, blob, target, seed):
        """Send a new job to all connected workers."""
        coros = [w.send_job(job_id, blob, target, seed) for w in workers]
        await asyncio.gather(*coros, return_exceptions=True)

    async def on_submit(job_id, nonce, result):
        """A worker found a share — forward to pool."""
        await pool.submit(job_id, nonce, result)

    pool.on_job = broadcast_job

    # Stats printer
    async def stats_loop():
        while True:
            await asyncio.sleep(60)
            total_hr = sum(w.hashrate for w in workers)
            online = sum(1 for w in workers if w.connected)
            total_threads = sum(w.threads for w in workers if w.connected)
            uptime = int(time.time() - start_time)
            mins = uptime // 60
            per_worker = "  ".join(
                f"{w.name}:{w.hashrate}H/s" for w in workers if w.connected
            )
            print(f"[stats] {mins}m up | {online}/{len(workers)} workers | "
                  f"{total_threads} threads | {total_hr} H/s | "
                  f"acc={pool.accepted} rej={pool.rejected} jobs={pool.jobs_sent}")
            if per_worker:
                print(f"[stats] {per_worker}")

    start_time = time.time()

    # Pool connection loop (runs independently, reconnects on failure)
    async def pool_loop():
        while True:
            try:
                await pool.connect()
                await pool.run()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                print(f"[pool] disconnected: {e}; reconnecting in 10s...")
                pool.close()
                await asyncio.sleep(10)

    # Launch all tasks
    tasks = []
    tasks.append(asyncio.ensure_future(pool_loop()))
    tasks.append(asyncio.ensure_future(stats_loop()))
    for w in workers:
        tasks.append(asyncio.ensure_future(w.run(on_submit)))

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    finally:
        for t in tasks:
            t.cancel()
        pool.close()


# ================================================================ MAIN

def main():
    # Parse minimal flags
    generate_only = "--generate" in sys.argv

    # Load or create config
    cfg = load_config()

    if cfg is None:
        # First run: interactive setup
        cfg = setup_wizard()
        generate_server_package(cfg)
        if not generate_only:
            prompt_add_workers(cfg)
    elif generate_only:
        print("\n  Regenerating server package...")
        generate_server_package(cfg)
        return
    else:
        print("\n\u2554" + "\u2550" * 44 + "\u2557")
        print("\u2551   Monero Distributed Mining Controller    \u2551")
        print("\u255a" + "\u2550" * 44 + "\u255d")
        n = len(cfg.get("workers", []))
        print(f"\n  Config loaded: {n} worker(s)")

    if not cfg.get("workers"):
        print("\n  No workers configured yet.")
        prompt_add_workers(cfg)

    if not cfg.get("workers"):
        print("\n  No workers added. Exiting.")
        print("  To add workers later, edit config.json or run this script again.\n")
        return

    # Start mining
    print(f"\n  Starting mining with {len(cfg['workers'])} worker(s)...\n")

    try:
        asyncio.run(run_controller(cfg))
    except KeyboardInterrupt:
        print("\n\nStopped.")


if __name__ == "__main__":
    main()
