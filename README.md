# Cloudflare Domain Email Security Lockdown
![Shell](https://img.shields.io/badge/shell-bash-green)

Bulk domain email security lockdown tool that prevents email phishing and spoofing attacks by automatically configuring SPF hard fail, null MX records, and DMARC rejection policies on unused Cloudflare-managed domains.

## Setup

1. **Get your Cloudflare API token:**
   - Go to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
   - Click "Create Token"
   - Use "Custom token" template
   - **Permissions:** Zone - DNS:Edit
   - **Zone Resources:** Include - All zones (or specific zones)
   - Click "Continue to summary" → "Create Token"
   - Copy the token (you won't see it again!)

2. Create `.env` file with your Cloudflare API token:
   ```
   CF_API_TOKEN=your_token_here
   ```

3. Create `domains.txt` with one domain per line:
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

The script will:
- Show a colorized interface with clear status messages
- Prompt for confirmation before modifying existing DNS records
- Create a timestamped log file (`cf-lockdown-YYYYMMDD-HHMMSS.log`) with all changes
- Display a summary report of successful, failed, and skipped domains

## What it does

- Sets SPF record to `v=spf1 -all` (hard fail)
- Sets null MX record to prevent email delivery  
- Sets DMARC policy to `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;` (strict rejection)
- **Interactive prompts** - asks before overwriting existing DNS records
- **Comprehensive logging** - saves detailed audit trail of all changes
- **Smart detection** - skips records that are already correctly configured
- Protects against email-based phishing and spoofing using your domains

## Requirements

- Cloudflare account with domains managed via Cloudflare DNS
- Cloudflare API token with Zone DNS Edit permissions
- Domains listed in `domains.txt` must exist in your Cloudflare account

**For bash version (`cf-lockdown.sh`):**
- `curl` and `jq` commands installed
- Bash shell (Linux/Mac/WSL)
- Windows users: Run `wsl --install` in PowerShell as admin, then restart. [Full WSL guide](https://docs.microsoft.com/en-us/windows/wsl/install)

## Features

### 🛡️ **Security**
- **Triple protection**: SPF hard fail + Null MX + DMARC reject
- Prevents email spoofing and phishing attacks using your unused domains

### 🎨 **User Experience** 
- **Colorized output** with emojis for clear status indication
- **Interactive prompts** - never overwrites existing records without permission
- **Smart detection** - automatically skips records that are already correct
- **Detailed feedback** shows current vs desired DNS record values

### 📊 **Reporting & Logging**
- **Real-time summary** - shows successful, failed, and skipped domains
- **Comprehensive audit log** - timestamped file with all DNS changes
- **Change tracking** - logs previous and new values for all modifications
- **Compliance ready** - detailed records for security audits

### 📝 **Log File Contents**
Each run creates a detailed log file with:
- Timestamp for every action
- Previous and new DNS record values  
- User decisions (skipped/updated/created)
- Zone lookup failures
- Final summary statistics

Example log entries:
```
2025-01-27 14:30:15 - example.com: PROCESSING STARTED
2025-01-27 14:30:16 - example.com TXT: UPDATED - Previous: "v=spf1 include:_spf.google.com ~all" | New: v=spf1 -all
2025-01-27 14:30:17 - example.com MX: CREATED - New: Priority 0: .
2025-01-27 14:30:18 - _dmarc.example.com TXT: CREATED - New: v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
