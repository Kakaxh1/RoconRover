#!/usr/bin/env python3
"""
Technology Stack Enumeration Module for ReconRover
Detects CMS, frameworks, and technologies used by websites
"""

import argparse
import asyncio
import aiohttp
import json
import re
from typing import List, Dict, Any, Optional, Set
from bs4 import BeautifulSoup
from utils import (
    logger, save_json, save_txt, load_json, load_txt,
    deduplicate_list, format_table, RateLimiter, make_request
)

class TechStackEnumerator:
    """Enumerates technology stack information"""
    
    def __init__(self):
        self.rate_limiter = RateLimiter(calls_per_second=2.0)
        self.session = None
        self.cache = {}
        
        # Common technology signatures
        self.cms_signatures = {
            'WordPress': [
                r'wp-content',
                r'wp-includes',
                r'wordpress',
                r'wp-admin',
                r'wp-json'
            ],
            'Drupal': [
                r'drupal',
                r'sites/default',
                r'Drupal.settings'
            ],
            'Joomla': [
                r'joomla',
                r'components/com_',
                r'modules/mod_'
            ],
            'Shopify': [
                r'shopify',
                r'shopifycdn',
                r'cdn\.shopify\.com'
            ],
            'Magento': [
                r'magento',
                r'Mage\.',
                r'var/www/html/magento'
            ],
            'WooCommerce': [
                r'woocommerce',
                r'wc-',
                r'woo-'
            ]
        }
        
        self.framework_signatures = {
            'React': [
                r'react',
                r'ReactDOM',
                r'__REACT_DEVTOOLS_GLOBAL_HOOK__'
            ],
            'Angular': [
                r'angular',
                r'ng-',
                r'ng:',
                r'angular\.js'
            ],
            'Vue.js': [
                r'vue',
                r'Vue\.',
                r'v-',
                r'vue\.js'
            ],
            'jQuery': [
                r'jquery',
                r'jQuery',
                r'\$\(',
                r'jquery\.js'
            ],
            'Bootstrap': [
                r'bootstrap',
                r'Bootstrap',
                r'bs-',
                r'bootstrap\.css'
            ]
        }
        
        self.server_signatures = {
            'Apache': [
                r'apache',
                r'Apache',
                r'Server: Apache'
            ],
            'Nginx': [
                r'nginx',
                r'Nginx',
                r'Server: nginx'
            ],
            'IIS': [
                r'iis',
                r'IIS',
                r'Server: Microsoft-IIS'
            ]
        }
        
        self.analytics_signatures = {
            'Google Analytics': [
                r'google-analytics',
                r'gtag',
                r'ga\(',
                r'google\.com/analytics'
            ],
            'Google Tag Manager': [
                r'googletagmanager',
                r'gtm\.js',
                r'dataLayer'
            ],
            'Facebook Pixel': [
                r'facebook\.com/tr',
                r'fbq\(',
                r'fbevents\.js'
            ]
        }
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def scan_domain(self, domain: str) -> Dict[str, Any]:
        """Scan a single domain for technology stack"""
        if domain in self.cache:
            return self.cache[domain]
        
        logger.info(f"Scanning technology stack for {domain}")
        
        # Ensure domain has protocol
        if not domain.startswith(('http://', 'https://')):
            domain = f"https://{domain}"
        
        result = {
            'domain': domain,
            'cms': [],
            'frameworks': [],
            'servers': [],
            'analytics': [],
            'libraries': [],
            'cdn': [],
            'headers': {},
            'technologies': []
        }
        
        try:
            # Fetch the main page
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            html = await make_request(self.session, domain, headers, self.rate_limiter)
            if not html:
                return result
            
            # Parse HTML
            soup = BeautifulSoup(html, 'html.parser')
            
            # Extract headers (if available)
            # Note: We can't get response headers from make_request, so we'll focus on HTML analysis
            
            # Analyze HTML content
            self._analyze_html_content(soup, result)
            
            # Analyze JavaScript
            self._analyze_javascript(soup, result)
            
            # Analyze CSS
            self._analyze_css(soup, result)
            
            # Analyze meta tags
            self._analyze_meta_tags(soup, result)
            
            # Cache the result
            self.cache[domain] = result
            
            return result
            
        except Exception as e:
            logger.error(f"Error scanning {domain}: {e}")
            return result
    
    def _analyze_html_content(self, soup: BeautifulSoup, result: Dict[str, Any]):
        """Analyze HTML content for technology signatures"""
        html_text = str(soup).lower()
        
        # Check CMS signatures
        for cms, signatures in self.cms_signatures.items():
            for signature in signatures:
                if re.search(signature, html_text, re.IGNORECASE):
                    if cms not in result['cms']:
                        result['cms'].append(cms)
                    break
        
        # Check framework signatures
        for framework, signatures in self.framework_signatures.items():
            for signature in signatures:
                if re.search(signature, html_text, re.IGNORECASE):
                    if framework not in result['frameworks']:
                        result['frameworks'].append(framework)
                    break
        
        # Check server signatures
        for server, signatures in self.server_signatures.items():
            for signature in signatures:
                if re.search(signature, html_text, re.IGNORECASE):
                    if server not in result['servers']:
                        result['servers'].append(server)
                    break
        
        # Check analytics signatures
        for analytics, signatures in self.analytics_signatures.items():
            for signature in signatures:
                if re.search(signature, html_text, re.IGNORECASE):
                    if analytics not in result['analytics']:
                        result['analytics'].append(analytics)
                    break
    
    def _analyze_javascript(self, soup: BeautifulSoup, result: Dict[str, Any]):
        """Analyze JavaScript for technology signatures"""
        # Check script tags
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src', '')
            content = script.string or ''
            
            # Check for CDNs
            cdn_patterns = [
                r'cdn\.jsdelivr\.net',
                r'cdnjs\.cloudflare\.com',
                r'unpkg\.com',
                r'cdn\.bootstrapcdn\.com',
                r'ajax\.googleapis\.com'
            ]
            
            for pattern in cdn_patterns:
                if re.search(pattern, src, re.IGNORECASE):
                    cdn_name = re.search(pattern, src, re.IGNORECASE).group(0)
                    if cdn_name not in result['cdn']:
                        result['cdn'].append(cdn_name)
            
            # Check for libraries in src
            library_patterns = {
                'jQuery': r'jquery',
                'Bootstrap': r'bootstrap',
                'Font Awesome': r'fontawesome',
                'Lodash': r'lodash',
                'Moment.js': r'moment',
                'Chart.js': r'chart\.js'
            }
            
            for library, pattern in library_patterns.items():
                if re.search(pattern, src, re.IGNORECASE):
                    if library not in result['libraries']:
                        result['libraries'].append(library)
            
            # Check for technologies in content
            tech_patterns = {
                'React': r'React|react',
                'Vue': r'Vue|vue',
                'Angular': r'angular|ng-',
                'jQuery': r'\$\(|jQuery',
                'Bootstrap': r'bootstrap|bs-'
            }
            
            for tech, pattern in tech_patterns.items():
                if re.search(pattern, content):
                    if tech not in result['technologies']:
                        result['technologies'].append(tech)
    
    def _analyze_css(self, soup: BeautifulSoup, result: Dict[str, Any]):
        """Analyze CSS for technology signatures"""
        # Check link tags for CSS
        links = soup.find_all('link', rel='stylesheet')
        for link in links:
            href = link.get('href', '')
            
            # Check for CDNs
            cdn_patterns = [
                r'cdn\.jsdelivr\.net',
                r'cdnjs\.cloudflare\.com',
                r'fonts\.googleapis\.com',
                r'cdn\.bootstrapcdn\.com'
            ]
            
            for pattern in cdn_patterns:
                if re.search(pattern, href, re.IGNORECASE):
                    cdn_name = re.search(pattern, href, re.IGNORECASE).group(0)
                    if cdn_name not in result['cdn']:
                        result['cdn'].append(cdn_name)
            
            # Check for specific CSS frameworks
            css_patterns = {
                'Bootstrap': r'bootstrap',
                'Tailwind CSS': r'tailwind',
                'Foundation': r'foundation',
                'Bulma': r'bulma'
            }
            
            for framework, pattern in css_patterns.items():
                if re.search(pattern, href, re.IGNORECASE):
                    if framework not in result['frameworks']:
                        result['frameworks'].append(framework)
    
    def _analyze_meta_tags(self, soup: BeautifulSoup, result: Dict[str, Any]):
        """Analyze meta tags for technology information"""
        meta_tags = soup.find_all('meta')
        
        for meta in meta_tags:
            name = meta.get('name', '').lower()
            content = meta.get('content', '').lower()
            
            # Check for generator meta tag
            if name == 'generator':
                if 'wordpress' in content:
                    if 'WordPress' not in result['cms']:
                        result['cms'].append('WordPress')
                elif 'drupal' in content:
                    if 'Drupal' not in result['cms']:
                        result['cms'].append('Drupal')
                elif 'joomla' in content:
                    if 'Joomla' not in result['cms']:
                        result['cms'].append('Joomla')
            
            # Check for viewport meta tag (mobile responsive)
            elif name == 'viewport':
                if 'responsive' not in result['technologies']:
                    result['technologies'].append('Responsive Design')
    
    async def scan_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """Scan multiple domains"""
        results = []
        
        logger.info(f"Scanning technology stack for {len(domains)} domains")
        
        # Process domains in batches
        batch_size = 5
        for i in range(0, len(domains), batch_size):
            batch = domains[i:i + batch_size]
            
            # Scan each domain in the batch
            tasks = []
            for domain in batch:
                task = self.scan_domain(domain)
                tasks.append(task)
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for domain, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.warning(f"Failed to scan {domain}: {result}")
                elif result:
                    results.append(result)
            
            # Delay between batches
            await asyncio.sleep(1)
        
        return results
    
    def get_technology_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of technology findings"""
        summary = {
            'total_domains': len(results),
            'cms_usage': {},
            'framework_usage': {},
            'server_usage': {},
            'analytics_usage': {},
            'common_libraries': {},
            'cdn_usage': {}
        }
        
        for result in results:
            # Count CMS usage
            for cms in result.get('cms', []):
                summary['cms_usage'][cms] = summary['cms_usage'].get(cms, 0) + 1
            
            # Count framework usage
            for framework in result.get('frameworks', []):
                summary['framework_usage'][framework] = summary['framework_usage'].get(framework, 0) + 1
            
            # Count server usage
            for server in result.get('servers', []):
                summary['server_usage'][server] = summary['server_usage'].get(server, 0) + 1
            
            # Count analytics usage
            for analytics in result.get('analytics', []):
                summary['analytics_usage'][analytics] = summary['analytics_usage'].get(analytics, 0) + 1
            
            # Count library usage
            for library in result.get('libraries', []):
                summary['common_libraries'][library] = summary['common_libraries'].get(library, 0) + 1
            
            # Count CDN usage
            for cdn in result.get('cdn', []):
                summary['cdn_usage'][cdn] = summary['cdn_usage'].get(cdn, 0) + 1
        
        return summary
    
    def format_techstack_results(self, results: List[Dict[str, Any]]) -> str:
        """Format technology stack results as a human-readable table"""
        table_data = []
        
        for result in results:
            domain = result['domain']
            cms = ', '.join(result.get('cms', [])) or '-'
            frameworks = ', '.join(result.get('frameworks', [])) or '-'
            servers = ', '.join(result.get('servers', [])) or '-'
            analytics = ', '.join(result.get('analytics', [])) or '-'
            
            table_data.append({
                'Domain': domain,
                'CMS': cms,
                'Frameworks': frameworks,
                'Servers': servers,
                'Analytics': analytics
            })
        
        return format_table(table_data, ['Domain', 'CMS', 'Frameworks', 'Servers', 'Analytics'])

async def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Enumerate technology stack for domains")
    parser.add_argument("--domains", nargs="+", help="List of domains to scan")
    parser.add_argument("--domains_file", help="File containing domains (one per line)")
    parser.add_argument("--save_json", action="store_true", help="Save results to JSON")
    parser.add_argument("--save_txt", action="store_true", help="Save results to TXT")
    parser.add_argument("--api_key", help="BuiltWith API key (optional)")
    
    args = parser.parse_args()
    
    # Get domains from arguments or file
    domains = []
    if args.domains:
        domains = args.domains
    elif args.domains_file:
        domains = load_txt(args.domains_file)
    else:
        # Try to load from default domains file
        domains = load_txt("domains.txt")
    
    if not domains:
        print("No domains provided. Use --domains or --domains_file")
        return 1
    
    # Remove duplicates
    domains = deduplicate_list(domains)
    
    async with TechStackEnumerator() as enumerator:
        results = await enumerator.scan_domains(domains)
    
    if results:
        # Get technology summary
        tech_summary = enumerator.get_technology_summary(results)
        
        result = {
            "scanned_domains": len(results),
            "total_domains": len(domains),
            "results": results,
            "technology_summary": tech_summary,
            "timestamp": asyncio.get_event_loop().time()
        }
        
        print(f"Scanned {len(results)} out of {len(domains)} domains")
        print(f"Found {len(tech_summary['cms_usage'])} different CMS types")
        print(f"Found {len(tech_summary['framework_usage'])} different frameworks")
        
        if args.save_json:
            save_json(result, "techstack.json")
        
        if args.save_txt:
            # Save formatted table
            table_text = enumerator.format_techstack_results(results)
            save_txt([table_text], "techstack.txt")
    else:
        print("No technology stack results found")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
