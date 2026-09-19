# Configuration & Watchlist Directory

This folder holds organizational profile configs, protected domain lists, and VIP identities for Business Email Compromise (BEC) detection.

- **`watchlist.json`**: Definition of internal domains, protected executive profiles (CEO, CFO, CISO), and financial trigger keywords.
- Use via CLI: `eft scan <path> --config data/config/watchlist.json` (or `--config watchlist.json`).
