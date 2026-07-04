# BugHunter Pro v3.1 — সম্পূর্ণ গাইড

## ফাইল Structure

```
bughunter_pro/
├── bughunter.sh
├── install.sh
├── setup_keys.sh
├── config.sh
├── core/
│   ├── bootstrap.sh
│   ├── cache.sh
│   ├── config.sh
│   ├── deps.sh
│   ├── queue.sh
│   ├── db.sh
│   ├── scoring.sh
│   └── plugins.sh
├── db/
│   └── assets_schema.sql
├── plugins/
│   └── README.md
├── modules/
│   ├── 01_subdomain.sh
│   ├── 02_urls_js.sh
│   ├── 03_api_nuclei_web.sh
│   ├── 04_sqli_secrets_recon.sh
│   ├── 05_report.sh
│   ├── 06_fixes.sh
│   └── 07_v4_engines.sh
└── reports/
```

---

## STEP 1 — ফাইল নামান ও Extract করুন

```bash
# ZIP নামানোর পর extract করুন
unzip bughunter_pro_v3.1.zip

# ফোল্ডারে ঢুকুন
cd bughunter_pro
```

---

## STEP 2 — Install (একবারই)

```bash
# Permission দিন
chmod +x install.sh

# Install চালান (ইন্টারনেট লাগবে, ১৫-৩০ মিনিট সময় লাগবে)
./install.sh
```

**install.sh যা করে:**

- Go 1.22 install করে
- ৩০+ Go tool install করে (subfinder, httpx, nuclei, dalfox ইত্যাদি)
- Python tool install করে (sqlmap, jwt_tool, trufflehog ইত্যাদি)
- Wordlist download করে
- Nuclei template update করে

**Install শেষে shell reload করুন:**

```bash
source ~/.bashrc
```

---

## STEP 3 — API Keys সেভ করুন (একবারই)

```bash
chmod +x setup_keys.sh
./setup_keys.sh
```

এটা চালালে প্রতিটা key এর জন্য prompt আসবে। **Blank রাখলে skip হবে** — সব key না
থাকলেও চলবে।

```
SHODAN_API_KEY: [আপনার key দিন অথবা Enter চাপুন]
GITHUB_TOKEN: [আপনার key দিন অথবা Enter চাপুন]
...
```

Key গুলো `~/.bughunter/config.sh` এ সেভ হয়। **পরের scan থেকে আর key দিতে হবে
না।**

Key আপডেট করতে চাইলে:

```bash
./setup_keys.sh          # আবার চালান
# অথবা সরাসরি edit করুন:
nano ~/.bughunter/config.sh
```

---

## STEP 4 — Scan চালান

```bash
chmod +x bughunter.sh

# Basic scan
./bughunter.sh -d example.com

# Low RAM VPS এ (512MB)
./bughunter.sh -d example.com -t 10 -j 2

# Normal VPS (2GB)
./bughunter.sh -d example.com -t 30 -j 3

# Advanced v4 engines + checkpoint/cache
./bughunter.sh -d example.com -m sub,url,js,api,nuclei,v4,report --checkpoint --cache

# Monitor mode
./bughunter.sh -d example.com --monitor --diff

# High-end VPS (8GB+)
./bughunter.sh -d example.com -t 80 -j 8

# Background এ চালাতে চাইলে
nohup ./bughunter.sh -d example.com > scan.log 2>&1 &

# Log দেখতে
tail -f scan.log
```

---

## STEP 5 — Report দেখুন

Scan শেষ হলে একটা folder তৈরি হবে:

```
results_example.com_20240101_120000/
```

**Report খুলুন:**

```bash
# HTML report (browser এ)
firefox results_example.com_*/reports/report.html
# অথবা
xdg-open results_example.com_*/reports/report.html

# Quick summary terminal এ
cat results_example.com_*/reports/summary.txt

# সব vulnerability দেখুন
cat results_example.com_*/findings.txt
```

---

## সব Options

```
./bughunter.sh -d <domain> [options]

  -d  Domain (required)        example.com
  -t  Threads (default 30)     -t 50
  -T  Timeout seconds (15)     -T 20
  -j  Parallel jobs (3)        -j 5      ← RAM control
  --resume                     Resume from checkpoint
  --checkpoint                 Save checkpoints after each module
  --cache                      Enable disk cache
  --parallel <n>               Alias for -j
  --memory-limit <profile>     512MB | 1GB | 2GB | 4GB | 8GB
  --cpu-limit <n|pct>          CPU cap (e.g. 2 or 75%)
  --continuous / --watch / --diff / --daily / --weekly / --monitor
  -o  Output folder            -o /tmp/results
  -m  Specific modules         -m sub,nuclei,report

  API keys (optional, config থেকে auto-load হয়):
  -s  Shodan key
  -g  GitHub token
  -C  Chaos key
  -c  Censys (id:secret)
```

---

## Specific Module চালানো

```bash
# শুধু subdomain বের করতে
./bughunter.sh -d example.com -m sub,report

# শুধু nuclei scan
./bughunter.sh -d example.com -m nuclei,report

# Subdomain + JS analysis + Nuclei
./bughunter.sh -d example.com -m sub,url,js,nuclei,report

# Available modules:
# sub, url, js, api, nuclei, v4, web, sqli, xxe,
# smuggle, secrets, takeover, recon, modern,
# github, extra, waf, report
```

---

## Output Folder Structure

```
results_example.com_TIMESTAMP/
├── findings.txt              ← সব vulnerability (timestamp সহ)
├── subdomains/
│   ├── all_subdomains.txt    ← সব subdomain
│   ├── live.txt              ← Live HTTP hosts
│   └── technologies.txt      ← কোন host এ কোন technology
├── urls/
│   ├── all_urls.txt          ← সব URL
│   ├── js_files.txt          ← JavaScript files
│   ├── unique_params.txt     ← সব parameter
│   └── gf_xss.txt            ← XSS candidate URLs
├── vulns/
│   ├── nuclei/               ← Nuclei results (15 ক্যাটাগরি)
│   ├── xss/                  ← XSS findings
│   ├── sqli/                 ← SQL injection
│   ├── graphql/              ← GraphQL issues
│   ├── jwt/                  ← JWT vulnerabilities
│   ├── cors/                 ← CORS misconfigs
│   ├── secrets/              ← API keys, passwords
│   ├── modern/               ← OAuth, WebSocket, Race condition
│   └── js/                   ← DOM XSS, prototype pollution
├── takeover/                 ← Subdomain takeover
├── recon/                    ← DNS, WHOIS, ports
├── screenshots/              ← Website screenshots
└── reports/
    ├── report.html           ← Full interactive HTML report
    └── summary.txt           ← Quick text summary
```

---

## API Key কোথায় পাবেন (সব Free)

| Key            | Link                                 | কী পাবেন          |
| -------------- | ------------------------------------ | ----------------- |
| Shodan         | https://account.shodan.io/           | Free tier আছে     |
| GitHub Token   | https://github.com/settings/tokens   | Completely free   |
| Chaos          | https://chaos.projectdiscovery.io/   | Free registration |
| SecurityTrails | https://securitytrails.com/          | Free 50 req/month |
| Censys         | https://search.censys.io/account/api | Free tier         |

---

## Telegram Notification Setup

Scan শেষ হলে phone এ message পাবেন:

**1. Bot বানান:**

- Telegram এ `@BotFather` তে যান
- `/newbot` টাইপ করুন
- Bot name দিন
- Token copy করুন

**2. Chat ID বের করুন:**

- `@userinfobot` এ `/start` পাঠান
- আপনার ID দেখাবে

**3. setup_keys.sh এ দিন:**

```bash
./setup_keys.sh
# Telegram Bot Token: [token]
# Telegram Chat ID: [id]
```

এখন প্রতিটা scan শেষে এরকম message আসবে:

```
🔍 BugHunter Pro v3.1
✅ Scan complete: example.com
⏱ Duration: 47m
🚨 Findings: 12
```

---

## Common Errors & Fix

**Error: `go: command not found`**

```bash
source ~/.bashrc
# অথবা
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
```

**Error: `nuclei: command not found`**

```bash
export PATH=$PATH:$HOME/go/bin
# অথবা install আবার চালান
./install.sh
```

**Error: `Permission denied`**

```bash
chmod +x bughunter.sh install.sh setup_keys.sh
chmod +x modules/*.sh
```

**Scan অনেক slow:**

```bash
# Thread কমান
./bughunter.sh -d example.com -t 10 -j 2
```

**Out of memory (VPS killed):**

```bash
# Job কমান
./bughunter.sh -d example.com -t 10 -j 1
```

---

## ⚠️ Important

```
শুধুমাত্র authorized target এ ব্যবহার করুন।
Bug bounty program: HackerOne, Bugcrowd, Intigriti
নিজের domain বা written permission আছে এমন target।
```
