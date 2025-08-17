#!/usr/bin/env python3
"""
Subdomain Enumeration Module for ReconRover
Discovers subdomains from multiple public sources
"""

import argparse
import asyncio
import aiohttp
import json
import re
from typing import List, Dict, Any, Optional, Set
from bs4 import BeautifulSoup
from api_loader import get_api_key, get_rate_limit
from utils import (
    logger, save_json, save_txt, load_json, 
    make_request, RateLimiter, validate_domain, 
    deduplicate_list, extract_domain_from_url
)

class SubdomainEnumerator:
    """Enumerates subdomains from various sources"""
    
    def __init__(self):
        self.rate_limiter = RateLimiter(calls_per_second=1.0)
        self.session = None
        # Load API keys from centralized config
        try:
            self.securitytrails_key = get_api_key('securitytrails')
            self.securitytrails_rate_limit = get_rate_limit('securitytrails')
        except KeyError:
            self.securitytrails_key = None
            self.securitytrails_rate_limit = 50
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def search_crtsh(self, domain: str) -> List[str]:
        """Search crt.sh for SSL certificates containing subdomains"""
        logger.info(f"Searching crt.sh for {domain}")
        
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            response = await make_request(url, rate_limiter=self.rate_limiter)
            if not response:
                return []
            
            data = json.loads(response)
            subdomains = set()
            
            for cert in data:
                if 'name_value' in cert:
                    names = cert['name_value'].split('\n')
                    for name in names:
                        name = name.strip().lower()
                        if name.endswith(f'.{domain}') and name != domain:
                            subdomains.add(name)
            
            logger.info(f"Found {len(subdomains)} subdomains from crt.sh")
            return list(subdomains)
            
        except json.JSONDecodeError:
            logger.error("Failed to parse crt.sh JSON response")
            return []
        except Exception as e:
            logger.error(f"Error searching crt.sh: {e}")
            return []
    
    async def search_securitytrails(self, domain: str) -> List[str]:
        """Search SecurityTrails API for subdomains"""
        if not self.securitytrails_key:
            logger.warning("SecurityTrails API key not configured, skipping")
            return []
        
        logger.info(f"Searching SecurityTrails for {domain}")
        
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {'apikey': self.securitytrails_key}
        
        try:
            response = await make_request(url, headers, rate_limiter=self.rate_limiter)
            if not response:
                return []
            
            data = json.loads(response)
            subdomains = []
            
            if 'subdomains' in data:
                for subdomain in data['subdomains']:
                    full_domain = f"{subdomain}.{domain}"
                    if validate_domain(full_domain):
                        subdomains.append(full_domain)
            
            logger.info(f"Found {len(subdomains)} subdomains from SecurityTrails")
            return subdomains
            
        except json.JSONDecodeError:
            logger.error("Failed to parse SecurityTrails JSON response")
            return []
        except Exception as e:
            logger.error(f"Error searching SecurityTrails: {e}")
            return []
    
    async def search_censys(self, domain: str, api_id: Optional[str] = None, 
                          api_secret: Optional[str] = None) -> List[str]:
        """Search Censys for certificates containing subdomains"""
        if not api_id or not api_secret:
            logger.warning("Censys API credentials not provided, skipping")
            return []
        
        logger.info(f"Searching Censys for {domain}")
        
        url = "https://search.censys.io/api/v2/certificates"
        headers = {
            'Authorization': f'Basic {api_id}:{api_secret}',
            'Content-Type': 'application/json'
        }
        
        query = {
            "query": f"parsed.names: {domain}",
            "fields": ["parsed.names"],
            "per_page": 100
        }
        
        try:
            async with self.session.post(url, headers=headers, json=query) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = set()
                    
                    for result in data.get('result', {}).get('hits', []):
                        names = result.get('parsed', {}).get('names', [])
                        for name in names:
                            name = name.lower()
                            if name.endswith(f'.{domain}') and name != domain:
                                subdomains.add(name)
                    
                    logger.info(f"Found {len(subdomains)} subdomains from Censys")
                    return list(subdomains)
                else:
                    logger.warning(f"Censys API returned status {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error searching Censys: {e}")
            return []
    
    async def search_hackertarget(self, domain: str) -> List[str]:
        """Search HackerTarget API for subdomains"""
        logger.info(f"Searching HackerTarget for {domain}")
        
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        
        try:
            response = await make_request(url, rate_limiter=self.rate_limiter)
            if not response:
                return []
            
            subdomains = []
            lines = response.strip().split('\n')
            
            for line in lines:
                if ',' in line:
                    subdomain = line.split(',')[0].strip()
                    if subdomain.endswith(f'.{domain}') and subdomain != domain:
                        subdomains.append(subdomain)
            
            logger.info(f"Found {len(subdomains)} subdomains from HackerTarget")
            return subdomains
            
        except Exception as e:
            logger.error(f"Error searching HackerTarget: {e}")
            return []
    
    async def search_threatcrowd(self, domain: str) -> List[str]:
        """Search ThreatCrowd API for subdomains"""
        logger.info(f"Searching ThreatCrowd for {domain}")
        
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        
        try:
            response = await make_request(url, rate_limiter=self.rate_limiter)
            if not response:
                return []
            
            data = json.loads(response)
            subdomains = []
            
            if 'subdomains' in data:
                for subdomain in data['subdomains']:
                    if subdomain.endswith(f'.{domain}') and subdomain != domain:
                        subdomains.append(subdomain)
            
            logger.info(f"Found {len(subdomains)} subdomains from ThreatCrowd")
            return subdomains
            
        except json.JSONDecodeError:
            logger.error("Failed to parse ThreatCrowd JSON response")
            return []
        except Exception as e:
            logger.error(f"Error searching ThreatCrowd: {e}")
            return []
    
    async def enumerate_subdomains(self, domain: str, 
                                 sources: List[str] = None,
                                 securitytrails_key: Optional[str] = None,
                                 censys_id: Optional[str] = None,
                                 censys_secret: Optional[str] = None) -> List[str]:
        """Main method to enumerate subdomains from all sources"""
        
        if sources is None:
            sources = ['crtsh', 'hackertarget', 'threatcrowd']
        
        all_subdomains = []
        
        # Search each source
        if 'crtsh' in sources:
            subdomains = await self.search_crtsh(domain)
            all_subdomains.extend(subdomains)
        
        if 'securitytrails' in sources and securitytrails_key:
            subdomains = await self.search_securitytrails(domain, securitytrails_key)
            all_subdomains.extend(subdomains)
        
        if 'censys' in sources and censys_id and censys_secret:
            subdomains = await self.search_censys(domain, censys_id, censys_secret)
            all_subdomains.extend(subdomains)
        
        if 'hackertarget' in sources:
            subdomains = await self.search_hackertarget(domain)
            all_subdomains.extend(subdomains)
        
        if 'threatcrowd' in sources:
            subdomains = await self.search_threatcrowd(domain)
            all_subdomains.extend(subdomains)
        
        # Deduplicate and validate
        unique_subdomains = deduplicate_list(all_subdomains)
        valid_subdomains = [s for s in unique_subdomains if validate_domain(s)]
        
        logger.info(f"Total unique subdomains found: {len(valid_subdomains)}")
        
        return valid_subdomains

async def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Enumerate subdomains from public sources")
    parser.add_argument("--domain", required=True, help="Target domain")
    parser.add_argument("--save_json", action="store_true", help="Save results to JSON")
    parser.add_argument("--save_txt", action="store_true", help="Save results to TXT")
    parser.add_argument("--sources", nargs="+", 
                       choices=['crtsh', 'securitytrails', 'censys', 'hackertarget', 'threatcrowd'],
                       default=['crtsh', 'hackertarget', 'threatcrowd'],
                       help="Sources to search")
    parser.add_argument("--securitytrails_key", help="SecurityTrails API key")
    parser.add_argument("--censys_id", help="Censys API ID")
    parser.add_argument("--censys_secret", help="Censys API secret")
    
    args = parser.parse_args()
    
    async with SubdomainEnumerator() as enumerator:
        subdomains = await enumerator.enumerate_subdomains(
            args.domain,
            sources=args.sources,
            securitytrails_key=args.securitytrails_key,
            censys_id=args.censys_id,
            censys_secret=args.censys_secret
        )
    
    if subdomains:
        result = {
            "domain": args.domain,
            "subdomains": subdomains,
            "count": len(subdomains),
            "sources": args.sources,
            "timestamp": asyncio.get_event_loop().time()
        }
        
        print(f"Found {len(subdomains)} subdomains for {args.domain}")
        
        if args.save_json:
            save_json(result, "subdomains.json")
        
        if args.save_txt:
            save_txt(subdomains, "subdomains.txt")
    else:
        print(f"No subdomains found for {args.domain}")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
