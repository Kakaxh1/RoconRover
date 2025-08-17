# ReconRover (Kkaxh1)

A comprehensive reconnaissance automation tool that performs end-to-end security reconnaissance on target organizations.

## Features

- **Real-Time Progress Bars**: Visual progress tracking for every process
- **Graceful Ctrl+C Handling**: Safe interruption with progress saving
- **Comprehensive Timeout Protection**: Module and overall timeouts with graceful handling
- **Domain Resolution**: Convert company names to main domains
- **Subdomain Enumeration**: Discover subdomains from multiple sources
- **DNS Resolution**: Resolve subdomains to IP addresses and DNS records
- **Port Scanning**: Identify open ports and services via Shodan & ZoomEye
- **Certificate Analysis**: Extract information from SSL certificates via Censys
- **Archived Endpoint Discovery**: Find historical endpoints via Wayback Machine
- **Technology Stack Detection**: Identify CMS, frameworks, and technologies
- **Email & Breach Enumeration**: Find email addresses and check for breaches
- **AI-Powered Reporting**: Generate comprehensive reconnaissance reports
- **Centralized API Management**: Secure API key configuration system

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd reconrover

# Install dependencies
pip install -r requirements.txt

# Create data directory
mkdir data
```

## Usage

### Individual Modules

```bash
# Domain resolution
python domain_resolver.py --company_name "Tesla Inc." --save_json

# Subdomain enumeration
python subdomain_enum.py --domain tesla.com --save_json

# DNS resolution
python dns_resolve.py --subdomains subdomains.txt --save_json

# Shodan scanning
python shodan_scan.py --ips ips.txt --save_json

# Technology stack detection
python techstack_enum.py --domains domains.txt --save_json

# Email and breach enumeration
python email_breach_enum.py --domain tesla.com --save_json

# AI report generation
python ai_report.py --json_inputs data/*.json --save_md
```

### Master CLI (All-in-One)

```bash
# Run complete reconnaissance (with beautiful hacker-style logo)
python reconrover.py --company_name "Tesla Inc." --save_all_json --save_report

# Or with existing domain
python reconrover.py --domain tesla.com --save_all_json --save_report

# Run specific modules only
python reconrover.py --domain tesla.com --modules domain_resolver,subdomain_enum,dns_resolve

# Run with custom timeouts
python reconrover.py --domain tesla.com --module_timeout 600 --overall_timeout 3600

# Run with aggressive timeouts for quick testing
python reconrover.py --domain example.com --module_timeout 30 --overall_timeout 120

```

## Output Structure

```
data/
├── domain.json          # Resolved main domain
├── domain.txt           # Domain in plain text
├── subdomains.json      # Discovered subdomains
├── subdomains.txt       # Subdomains list
├── dns.json            # DNS resolution results
├── dns.txt             # DNS records
├── shodan.json         # Shodan scan results
├── shodan.txt          # Port and service info
├── zoomeye.json        # ZoomEye scan results
├── zoomeye.txt         # ZoomEye port and service info
├── censys.json         # Certificate and service data
├── wayback.json        # Wayback Machine archived data
├── wayback.txt         # Archived endpoints and parameters
├── techstack.json      # Technology stack information
├── emails.json         # Email addresses and breaches
├── recon_report.md     # AI-generated report
└── recon_report.pdf    # PDF version of report
```

## Configuration

### API Keys Required

ReconRover uses a centralized API key management system. Create your configuration file:

1. **Copy the example configuration:**
   ```bash
   cp config/api_keys.yaml.example config/api_keys.yaml
   ```

2. **Edit the configuration file:**
   ```bash
   nano config/api_keys.yaml
   ```

3. **Fill in your API keys:**
   ```yaml
   # Required for port scanning
   shodan:
     key: "your_shodan_api_key"
   
   # Required for certificate analysis
   censys:
     api_id: "your_censys_api_id"
     api_secret: "your_censys_api_secret"
   
   # Required for technology detection
   builtwith:
     key: "your_builtwith_api_key"
   
   # Required for email discovery
   hunter:
     key: "your_hunter_api_key"
   
   # Required for breach checking
   haveibeenpwned:
     key: "your_hibp_api_key"
   
   # Required for AI reports
   openai:
     key: "your_openai_api_key"
   
   # Optional but recommended
   serpapi:
     key: "your_serpapi_key"
   
   securitytrails:
     key: "your_securitytrails_key"
   
   zoomeye:
     key: "your_zoomeye_key"
   ```

** Security Note:** The `config/api_keys.yaml` file is automatically excluded from version control. Never commit your actual API keys to any repository.

### Rate Limiting

The tool respects API rate limits:
- Shodan: 1 request/second (free tier)
- Censys: 100 queries/day (free tier)
- Hunter.io: 100 requests/month (free tier)

### API Credit Monitoring

ReconRover includes comprehensive API credit monitoring:

**Credit Display Options:**
```bash
# Check credits before running reconnaissance
python reconrover.py --show_credits

# Standalone credit checker
python check_credits.py
```

**Supported Services:**
- **Shodan**: Credits, scan credits, query credits, monitor credits
- **Censys**: Queries used, queries allowed, reset date
- **Hunter.io**: Requests used, requests limit, plan type
- **OpenAI**: API key validation for AI reports
- **ZoomEye**: Quota information for port scanning
- **BuiltWith**: API key validation for tech stack detection
- **HaveIBeenPwned**: API key validation for breach checking

**Features:**
- Real-time credit checking
- Detailed usage statistics
- Service status monitoring
- Visual summary tables
- Usage tips and recommendations

### Troubleshooting & Error Reporting

ReconRover includes comprehensive error reporting and troubleshooting tools:

**Enhanced Error Reporting:**
- Detailed failure reasons for each module
- Specific error analysis and suggestions
- Dependency tracking and validation
- Visual error summaries with troubleshooting tips

**Diagnostic Tools:**
```bash
# Check API credits and validity
python check_credits.py

# Quick credit check with main tool
python reconrover.py --show_credits
```

**Common Issues & Solutions:**

| Issue | Cause | Solution |
|-------|-------|----------|
| Module fails with "Import error" | Missing Python packages | `pip install -r requirements.txt` |
| Module fails with "HTTP 401" | Invalid API key | Check API key in `config/api_keys.yaml` |
| Module fails with "FileNotFoundError" | Missing input files | Run modules in correct order |
| Module fails with "HTTP 429" | Rate limit exceeded | Wait or upgrade API plan |
| Module fails with "timeout" | Network issues | Check internet connectivity |

**Error Analysis Features:**
- **Module Dependencies**: Shows what each module needs to run
- **Failure Analysis**: Detailed breakdown of why modules failed
- **Troubleshooting Tips**: Specific guidance for fixing issues
- **API Key Validation**: Checks validity of configured API keys
- **File Dependency Tracking**: Ensures required files exist

### Timeout Configuration

ReconRover includes comprehensive timeout protection:

**Module Timeout (Default: 300s)**
- Prevents individual modules from hanging indefinitely
- Configurable per module execution
- Graceful timeout handling with progress saving

**Overall Timeout (Default: 1800s)**
- Prevents entire reconnaissance from running too long
- Stops execution after specified time
- Saves partial results and shows timing information

**Usage Examples:**
```bash
# Conservative timeouts for large targets
python reconrover.py --domain large-company.com --module_timeout 600 --overall_timeout 3600

# Aggressive timeouts for quick testing
python reconrover.py --domain example.com --module_timeout 30 --overall_timeout 120

# Default timeouts
python reconrover.py --domain target.com
```

## Module Details

### 1. Domain Resolver (`domain_resolver.py`)
- Converts company names to main domains
- Uses search engines and WHOIS validation
- Supports caching to avoid repeat queries

### 2. Subdomain Enumeration (`subdomain_enum.py`)
- Queries multiple sources: crt.sh, SecurityTrails, Censys
- Async requests for faster enumeration
- Deduplication and validation

### 3. DNS Resolution (`dns_resolve.py`)
- Resolves A, AAAA, CNAME, MX, TXT records
- Async DNS queries for performance
- Caching to avoid repeat lookups

### 4. Shodan Scanning (`shodan_scan.py`)
- Identifies open ports and services
- Extracts banners and host information
- Geolocation and ISP data

### 5. ZoomEye Scanning (`zoomeye_scan.py`)
- Alternative port and service scanning
- Web application discovery
- Host and service enumeration

### 6. Censys Scanning (`censys_scan.py`)
- Certificate transparency data
- Service information and banners
- Subdomain discovery from certificates

### 7. Wayback Machine Scanning (`wayback_scan.py`)
- Historical endpoint discovery
- Archived URL parameters
- File extension enumeration

### 8. Technology Stack Detection (`techstack_enum.py`)
- CMS detection (WordPress, Shopify, etc.)
- JavaScript libraries and frameworks
- Analytics and CDN identification

### 9. Email & Breach Enumeration (`email_breach_enum.py`)
- Email address discovery
- Breach database checking
- Pastebin scraping (optional)

### 10. AI Report Generation (`ai_report.py`)
- Summarizes all reconnaissance data
- Highlights critical assets and attack surfaces
- Generates executive summaries

## Legal Disclaimer

This tool is for **authorized security testing only**. Always ensure you have proper authorization before performing reconnaissance on any target. The authors are not responsible for any misuse of this tool.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request


## Support

For issues and questions:
- Open an issue on GitHub
- Check the documentation
- Review the example outputs in the `data/` directory
