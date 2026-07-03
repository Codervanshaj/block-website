# 🛡️ Prevent Visit

A simple Windows software that blocks adult/explicit content from search engines and websites.

**Works automatically for Chrome, Edge, and Brave - no manual browser configuration needed!**

---

## Features

- ✅ **Blocks explicit search results** - Search queries for adult content show "No results found"
- ✅ **Works for all browsers** - Chrome, Edge, Brave configured automatically
- ✅ **Auto-starts on login** - No need to manually start after rebooting
- ✅ **HTTPS inspection** - Intercepts encrypted search traffic to filter results
- ✅ **No browser configuration** - Installs and works automatically
- ✅ **Easy commands** - Simple install/uninstall/start/stop/status commands

---

## Installation

### 1. Clone the repository

```powershell
cd D:\
git clone https://github.com/Codervanshaj/block-website.git
```

### 2. Install the software

```powershell
cd D:\block-website
python run_guard.py install
```

Click **Yes** when the admin prompt appears.

That's it! The software will:
- Generate and install the root certificate
- Configure Chrome, Edge, and Brave automatically
- Set up auto-start on login
- Start the blocking service

---

## Commands

```powershell
# Install (first time only)
python run_guard.py install

# Check status
python run_guard.py status

# Stop blocking (temporarily)
python run_guard.py stop

# Start blocking again
python run_guard.py start

# Uninstall (complete removal)
python run_guard.py uninstall
```

---

## How It Works

1. **HTTPS Interception**: When you search on Google, Bing, DuckDuckGo, etc., the software intercepts the encrypted traffic
2. **Keyword Filtering**: It scans your search query against a list of blocked keywords
3. **Block Results**: If explicit content is detected, you see "No results found" instead
4. **Normal Browsing**: Gmail, GitHub, YouTube, and other normal sites work normally

### Search Engines Blocked
- Google (all country variants: google.com, google.co.uk, google.co.in, etc.)
- Bing
- DuckDuckGo
- Yahoo Search
- Brave Search
- Startpage
- Yandex
- Ecosia

### What Gets Blocked
- Search queries containing adult keywords
- Explicit website names in search
- Known adult domain requests

### What Stays Unblocked
- Gmail, Google Docs, Google Drive, Google Calendar
- YouTube, Google Maps
- All other normal websites
- System traffic

---

## Customizing the Block List

Edit these files to add/remove blocked keywords and domains:

### Blocked Keywords
File: `prevent_visit/data/blocked_keywords.txt`

Add any words or phrases you want to block (one per line)

### Blocked Domains
File: `prevent_visit/data/adult_domains.txt`

Add any adult websites you want to block (one per line)

After editing, stop and start the service:
```powershell
python run_guard.py stop
python run_guard.py start
```

---

## Troubleshooting

### Blocking not working?

1. Check if service is running:
```powershell
python run_guard.py status
```

2. If stopped, start it:
```powershell
python run_guard.py start
```

3. If not installed, reinstall:
```powershell
python run_guard.py install
```

### Still seeing explicit results?

Try searching for "porn" or "hentai" on Google. You should see "No results found".

---

## Project Structure

```
block-website/
├── run_guard.py           # Main entry point
├── prevent_visit/
│   ├── cli.py            # Command line interface
│   ├── proxy.py          # Local proxy server
│   ├── rules.py           # Blocking rules engine
│   ├── certs.py          # Certificate management
│   ├── config.py         # Configuration
│   ├── windows.py        # Windows integration
│   └── data/
│       ├── blocked_keywords.txt   # Keywords to block
│       └── adult_domains.txt     # Domains to block
├── config/               # Generated config (local only)
├── build/               # Generated files (local only)
└── logs/                # Event logs (local only)
```

---

## For Developers

### Run Tests
```powershell
python -m pytest
```

### Manual Service Run
```powershell
python run_guard.py run-service
```

---

## License

MIT License
