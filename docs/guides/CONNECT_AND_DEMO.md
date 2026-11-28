# TRAPSIG — Connect the Pi to your PC and run the demo

This is the **one guide to go from two powered-on machines to a live demonstration**.
It is written so you can copy-paste each step. It works whether your analysis PC
runs **Windows** or **Linux**; the Raspberry Pi runs **Raspberry Pi OS Lite**.

> **Which guide?** This one covers **one Raspberry Pi in Docker mode** (Cowrie plus the six
> original personas) and the analysis PC. To spread all **16 personas over several
> devices** (Pi OS Lite, Linux, Windows) with the fleet agent, use
> [DEPLOYMENT](DEPLOYMENT.md). To try everything on one PC first, see the main
> [README](../../README.md#run-everything-on-one-machine-no-pi-no-docker).

```
                 Tailscale overlay (stable addresses, any network)
   ┌─────────────────────────┐                      ┌──────────────────────────┐
   │  PC (Windows or Linux)   │◄───  SSH / logs  ───►│  Raspberry Pi (Pi OS Lite)│
   │  Elasticsearch, Logstash │                      │  5 honeypots + Filebeat   │
   │  Kibana, FastAPI, Next.js│                      └──────────────────────────┘
   └─────────────────────────┘                                   ▲
            ▲  dashboard                                          │ attacks (physical LAN)
            │                                           ┌──────────────────────┐
         You / browser                                  │ Attacker machine/VM  │
                                                        └──────────────────────┘
```

Two networks are in play and they are **different on purpose**:

- **Tailscale overlay** — carries only the PC↔Pi management + log traffic. Stable
  addresses that do not change when the Pi moves between your home Wi-Fi and a
  phone hotspot.
- **Physical lab LAN** (`LAB_SUBNET`) — where attacks come from. The attacker and
  the Pi are on the same local network; attacks never go over Tailscale.

---

## 0. What you need

| On the PC | On the Pi |
| --- | --- |
| Docker Desktop (Windows) or Docker Engine + Compose v2 (Linux) | Docker Engine + Compose v2 |
| Git, Python 3.12+ | A dedicated `trapsig` user (created below) |
| An OpenSSH client (`ssh`, `ssh-keyscan`) — preinstalled on Linux and Windows 10/11 | SSH enabled |
| A free [Tailscale](https://tailscale.com) account | The same Tailscale account |

Clone the repo on the PC and `cd` into it before starting.

---

## 1. One-time Tailscale setup (both machines)

Do this once. After it, the PC and Pi can always find each other by name.

**On the Pi:**
```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --hostname trapsig-pi
```

**On the PC — Linux:**
```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up --hostname trapsig-laptop
```

**On the PC — Windows:** install Tailscale from <https://tailscale.com/download/windows>,
sign in, then (optional) set the machine name to `trapsig-laptop` in the admin
console at <https://login.tailscale.com/admin/machines>.

Confirm both machines see each other (run on either):
```bash
tailscale status
```
You should see `trapsig-pi` and `trapsig-laptop` listed. Note their **MagicDNS
names** (e.g. `trapsig-pi.tailabcd.ts.net`) — prefer these over raw `100.x.y.z`
addresses because they survive the Pi being re-imaged.

> Tip: enable MagicDNS in the Tailscale admin console (DNS tab) so the `*.ts.net`
> names resolve.

---

## 2. Set up the Pi sensor

SSH into the Pi (first time, over its LAN address or `tailscale status` address):

```bash
ssh pi@trapsig-pi.<your-tailnet>.ts.net
```

Create the restricted management user and get the code:
```bash
sudo adduser --disabled-password --gecos "" trapsig
sudo usermod -aG docker trapsig          # lets trapsig run Docker (see SETUP.md note)
git clone <this-repo-url> /opt/trapsig && sudo chown -R trapsig:trapsig /opt/trapsig
cd /opt/trapsig/sensor
cp .env.example .env
```

Edit `sensor/.env` and set:
```
ANALYSIS_HOST=trapsig-laptop.<your-tailnet>.ts.net   # PC's Tailscale name
SENSOR_IP=<the Pi's address on the physical lab LAN>  # e.g. 192.168.50.10
BACKEND_URL=http://trapsig-laptop.<your-tailnet>.ts.net:8000  # enables RL hardening on the sensor
```

Install the PC's management SSH **public** key into the `trapsig` user's
`authorized_keys` with the forced command (full copy-paste block is in
[SETUP.md → Restricted backend management account](SETUP.md)). Then start the
honeypots:
```bash
./scripts/setup.sh
./scripts/start.sh
./scripts/status.sh      # all five containers + Filebeat should be healthy
```

---

## 3. Set up the PC analysis stack

Back on the PC, in the repo root:

```bash
cp .env.example .env
```

Generate the management SSH **key pair** if you do not have one, and place the
private key where Compose expects it:

**Linux / macOS:**
```bash
# only creates the key pair if you do not already have one:
test -f ~/.ssh/trapsig_pi || ssh-keygen -t ed25519 -f ~/.ssh/trapsig_pi -N ""   # copy the .pub to the Pi (step 2)
mkdir -p secrets && install -m 600 ~/.ssh/trapsig_pi secrets/pi_ssh_key
```
**Windows (PowerShell):**
```powershell
# only creates the key pair if you do not already have one:
if (-not (Test-Path $HOME\.ssh\trapsig_pi)) { ssh-keygen -t ed25519 -f $HOME\.ssh\trapsig_pi -N '""' }   # copy the .pub to the Pi
New-Item -ItemType Directory -Force secrets | Out-Null
Copy-Item $HOME\.ssh\trapsig_pi secrets\pi_ssh_key
```

Edit `.env` and set the lab subnet to your real attacker/Pi LAN (leave the
Tailscale name for `PI_HOST` — the next step fills the exact value):
```
LAB_SUBNET=192.168.50.0/24
```

---

## 4. Connect (the one command you re-run whenever the Pi moves)

```bash
python scripts/pi/connect.py --pi-name trapsig-pi
```

This resolves the Pi's current Tailscale address, writes `PI_HOST` into `.env`,
and refreshes `secrets/known_hosts`. **It prints the Pi host-key fingerprint —
compare it with the Pi** (run `sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`
on the Pi) before trusting it.

Then bring up the stack:
```bash
./scripts/dev/preflight.sh          # on Windows: python scripts/pi/connect.py handles PI_HOST; run docker compose directly
docker compose up -d --build
docker compose ps
```

Open:
- **Dashboard** → <http://localhost:3000>
- **API docs** → <http://localhost:8000/docs>
- **Kibana** → <http://localhost:5601>

> **Moving networks later** (home Wi-Fi ⇄ phone hotspot): just re-run
> `python scripts/pi/connect.py` and `docker compose up -d`. Nothing else changes.

---

## 5. The demonstration (≈5 minutes)

This is the script to follow on screen. It shows the three headline claims:
**learned detection**, **adaptive hardening**, and **the system improving itself**.

### 5.1 Show the baseline

Open the dashboard (<http://localhost:3000>). Walk through **Overview →
Honeypots → Detections → Adaptation**. The Adaptation page starts mostly empty —
that is the "before".

### 5.2 Launch a realistic attack (from the attacker machine on the lab LAN)

```bash
# one-time: pip install -r attacks/requirements.txt
export LAB_SUBNET=192.168.50.0/24
python -m attacks.realistic.credential_stuffing --target 192.168.50.10 \
    --services ssh camera --attempts 60 --workers 8
python -m attacks.realistic.http_fuzzing --target 192.168.50.10 --service camera
```

Within ~10–20 seconds (one processor cycle), the **Detections** page fills with
explainable detections — each with a reason, evidence IDs, a **confidence**, and
the **policy version** that fired.

### 5.3 Show the hardening react (reinforcement learning)

Open **Adaptive Defence**. Within one processor cycle the attacker IP appears
under **Hardened right now** with the action the agent chose (for example
`deny_auth` or `read_only`) and the sensor effects it enforces. **What changed
and why** shows the decision: the source's kill-chain stage, the previous and
new action, whether the agent explored or exploited, the expected reward of every
alternative, and, after the 5-minute window, the measured outcome (new
behaviours seen, whether the attacker still succeeded, reward).

Run a scenario whose success the hardening can prevent and repeat it, so the
agent has outcomes to learn from:

```bash
python -m attacks.runner.run camera-rtsp-default-creds --target 192.168.50.10
python -m attacks.runner.run ics-setpoint-tamper --target 192.168.50.10
```

Once a source is hardened with `deny_auth`, its next RTSP DESCRIBE with
`admin/admin` gets `401` even though the credentials are valid. With `read_only`,
Modbus writes return exception 04. The **What the agent has learned** table
fills in one context × action cell per evaluated decision.

### 5.4 Show it learning (the key moment)

Run an evaluation batch to generate labeled ground truth, then retrain:

```bash
# generates labeled experiments (attack + control) through the real API
python evaluation/run_matrix.py --execute --all-evaluation --repetitions 2

# retrain offline; the promotion gate only activates an improved policy
python -m backend.app.tools.train_detector

# compare the learned policy against the frozen rule baseline
python -m backend.app.tools.evaluate_detector
```

Refresh **Adaptation → Policy learning timeline**: a new generation appears with
its **held-out macro-F1**, marked `active` (or `candidate` if the gate rejected
it). This is the visible proof that detection changed **without a code deploy**.

> Want a dramatic before/after? Before retraining, run the low-and-slow attack
> (`python -m attacks.realistic.low_and_slow --target 192.168.50.10`), note
> whether it is caught, retrain, and show the decision can change.

### 5.5 Show the numbers (optional, strong for a viva)

```bash
python scripts/dev/benchmark.py            # feature extraction, detection latency, cycle time
curl -s http://localhost:8000/metrics  # live Prometheus metrics
```

---

## 6. Troubleshooting

| Symptom | Fix |
| --- | --- |
| `connect.py`: "no Tailscale peer named 'trapsig-pi'" | Run `tailscale status` on both; make sure the Pi shows `trapsig-pi` and is online. |
| `connect.py`: "tailscale CLI not found" | Install Tailscale; on Windows the script also checks `C:\Program Files\Tailscale\tailscale.exe`. |
| Dashboard loads but no data | Check `docker compose ps`; confirm the attack target IP equals the Pi's **LAN** `SENSOR_IP`, and that events appear in Kibana. |
| SSH to Pi fails after moving networks | Re-run `python scripts/pi/connect.py` (the Pi's address changed) and re-compare the fingerprint. |
| Hardening not visible on the Pi | Set `BACKEND_URL` (and `SENSOR_API_KEY` if API auth is on) in `sensor/.env` and restart the persona containers. Sensors fail open (no effect) when unset. |
| Want API auth on | Set `API_KEY` in `.env`, re-up Compose; the dashboard forwards it automatically. |

See [SETUP.md](SETUP.md) for the full security-hardened key/forced-command
details, [ARCHITECTURE.md](../reference/ARCHITECTURE.md) for how detection and hardening work,
and [EVALUATION.md](../research/EVALUATION.md) for the research method.
