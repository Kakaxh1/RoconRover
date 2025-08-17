# ReconRover Setup Guide

This guide will help you set up ReconRover with your own API keys and get started with reconnaissance.

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Git

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/reconrover.git
   cd reconrover
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure API keys**
   ```bash
   # Copy the example configuration
   cp config/api_keys.yaml.example config/api_keys.yaml
   
   # Edit the configuration file with your API keys
   # Use your preferred text editor
   ```

## API Key Configuration

### Required API Keys

**Essential for core functionality:**
- **SerpAPI** - Domain discovery and search
- **SecurityTrails** - Subdomain enumeration
- **BuiltWith** - Technology stack detection

**Recommended for enhanced scanning:**
- **Shodan** - Port and service information
- **ZoomEye** - Alternative port scanning
- **Censys** - SSL certificate analysis
- **Hunter.io** - Email discovery
- **HaveIBeenPwned** - Breach database

**AI Report Generation (choose one):**
- **OpenAI** - GPT-4 powered reports
- **OpenRouter.ai** - Alternative AI provider

### Getting API Keys

1. **SerpAPI** - [https://serpapi.com/](https://serpapi.com/)
   - Free tier: 100 searches/month
   - Paid plans available

2. **SecurityTrails** - [https://securitytrails.com/](https://securitytrails.com/)
   - Free tier: 50 queries/month
   - Paid plans available

3. **BuiltWith** - [https://builtwith.com/](https://builtwith.com/)
   - Free tier: 1000 requests/day
   - Paid plans available

4. **Shodan** - [https://shodan.io/](https://shodan.io/)
   - Free tier: 100 queries/month
   - Paid plans available

5. **ZoomEye** - [https://zoomeye.org/](https://zoomeye.org/)
   - Free tier: 100 queries/month
   - Paid plans available

6. **Censys** - [https://censys.io/](https://censys.io/)
   - Free tier: 100 queries/month
   - Paid plans available

7. **Hunter.io** - [https://hunter.io/](https://hunter.io/)
   - Free tier: 100 searches/month
   - Paid plans available

8. **HaveIBeenPwned** - [https://haveibeenpwned.com/](https://haveibeenpwned.com/)
   - Free tier: 1500 queries/day
   - Paid plans available

9. **OpenAI** - [https://platform.openai.com/](https://platform.openai.com/)
   - Pay-per-use pricing
   - Requires credit card

10. **OpenRouter.ai** - [https://openrouter.ai/](https://openrouter.ai/)
    - Pay-per-use pricing
    - Multiple AI models available

## Configuration File Structure

Edit `config/api_keys.yaml` with your keys:

```yaml
# Example configuration
serpapi:
  key: "your_actual_serpapi_key_here"
  rate_limit: 100

securitytrails:
  key: "your_actual_securitytrails_key_here"
  rate_limit: 50

# ... add other services as needed
```

## Testing Your Setup

1. **Check API credits**
   ```bash
   python check_credits.py
   ```

2. **Test individual modules**
   ```bash
   # Test domain resolution
   python domain_resolver.py --company_name "example company"
   
   # Test subdomain enumeration
   python subdomain_enum.py --domain example.com
   
   # Test DNS resolution
   python dns_resolve.py --subdomains_file subdomains.txt
   ```

3. **Run full reconnaissance**
   ```bash
   python reconrover.py --domain example.com --modules all
   ```

## Security Notes

- **Never commit** `config/api_keys.yaml` to version control
- **Never share** your API keys publicly
- **Monitor usage** to avoid exceeding rate limits
- **Use responsibly** and in accordance with terms of service

## Troubleshooting

### Common Issues

1. **Module import errors**
   - Ensure all dependencies are installed: `pip install -r requirements.txt`

2. **API key errors**
   - Verify keys are correctly copied to `config/api_keys.yaml`
   - Check if services have sufficient credits

3. **Rate limiting**
   - Adjust `rate_limit` values in configuration
   - Wait between requests if hitting limits

4. **Timeout errors**
   - Increase timeout values in configuration
   - Check network connectivity

### Getting Help

- Check the main [README.md](README.md) for detailed usage
- Review error messages for specific issues
- Ensure you're using the latest version

## Next Steps

After setup, explore:
- [README.md](README.md) - Complete documentation
- Individual module files for detailed functionality
- Example usage patterns and best practices

Happy reconnaissance! 🕵️‍♂️
