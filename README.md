# Cloudflare Domain Email Security Lockdown

Bulk domain email security lockdown tool that prevents email phishing and spoofing attacks by automatically configuring SPF hard fail, null MX records, and DMARC rejection policies on unused Cloudflare-managed domains.

## Setup

1. Create `.env` file with your Cloudflare API token:
   ```
   CF_API_TOKEN=your_token_here
   ```

2. Create `domains.txt` with one domain per line:
   ```
   example.com
   unused-domain.org
   # comments allowed
   ```

## Usage

**Linux/Mac:**
```bash
./cf-lockdown.sh
```

## What it does

- Sets SPF record to `v=spf1 -all` (hard fail)
- Sets null MX record to prevent email delivery  
- Sets DMARC policy to `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;` (strict rejection)
- Protects against email-based phishing and spoofing using your domains

## Requirements

- Cloudflare account with domains managed via Cloudflare DNS
- Cloudflare API token with Zone DNS Edit permissions
- Domains listed in `domains.txt` must exist in your Cloudflare account

**For bash version (`cf-lockdown.sh`):**
- `curl` and `jq` commands installed
- Bash shell (Linux/Mac/WSL)
- Windows users: Run `wsl --install` in PowerShell as admin, then restart. [Full WSL guide](https://docs.microsoft.com/en-us/windows/wsl/install)

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.