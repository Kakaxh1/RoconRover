#!/usr/bin/env python3
"""
Domain Resolver Module for ReconRover
Converts company names to main domains using search engines and validation
"""

import argparse
import asyncio
import aiohttp
import re
import json
from typing import Optional, List, Dict, Any
from bs4 import BeautifulSoup
import tldextract
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.console import Console
from api_loader import get_api_key, get_rate_limit
from utils import (
    logger, save_json, save_txt, load_json, 
    make_request, RateLimiter, validate_domain, 
    extract_domain_from_url, deduplicate_list
)

class DomainResolver:
    """Resolves company names to main domains"""
    
    def __init__(self):
        self.console = Console()
        self.rate_limiter = RateLimiter(calls_per_second=0.5)  # Conservative rate limiting
        self.cache_file = "data/domain_cache.json"
        self.cache = self._load_cache()
        # Load API keys from centralized config
        try:
            self.serpapi_key = get_api_key('serpapi')
            self.serpapi_rate_limit = get_rate_limit('serpapi')
        except KeyError:
            self.serpapi_key = None
            self.serpapi_rate_limit = 100
    
    def _load_cache(self) -> Dict[str, str]:
        """Load cached domain resolutions"""
        cached = load_json("domain_cache.json")
        return cached if cached else {}
    
    def _save_cache(self):
        """Save domain resolutions to cache"""
        save_json(self.cache, "domain_cache.json")
    
    async def search_duckduckgo(self, company_name: str) -> List[str]:
        """Search DuckDuckGo for company domain"""
        search_query = f'"{company_name}" official website'
        url = f"https://html.duckduckgo.com/html/?q={search_query}"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        async with aiohttp.ClientSession() as session:
            html = await make_request(session, url, headers, self.rate_limiter)
            if not html:
                return []
            
            return self._extract_domains_from_html(html)
    
    async def search_serpapi(self, company_name: str) -> List[str]:
        """Search using SerpAPI"""
        if not self.serpapi_key:
            logger.warning("SerpAPI key not configured, skipping SerpAPI search")
            return []
        
        search_query = f'"{company_name}" official website'
        url = f"https://serpapi.com/search.json?q={search_query}&api_key={self.serpapi_key}"
        
        async with aiohttp.ClientSession() as session:
            response = await make_request(session, url, self.rate_limiter)
            if not response:
                return []
            
            try:
                data = json.loads(response)
                domains = []
                
                if 'organic_results' in data:
                    for result in data['organic_results'][:5]:
                        if 'link' in result:
                            domain = extract_domain_from_url(result['link'])
                            if domain:
                                domains.append(domain)
                
                return domains
            except json.JSONDecodeError:
                logger.error("Failed to parse SerpAPI response")
                return []
    
    def _extract_domains_from_html(self, html: str) -> List[str]:
        """Extract domains from HTML search results"""
        soup = BeautifulSoup(html, 'html.parser')
        domains = []
        
        # Look for links in search results
        links = soup.find_all('a', href=True)
        
        for link in links:
            href = link['href']
            domain = extract_domain_from_url(href)
            if domain and validate_domain(domain):
                domains.append(domain)
        
        return domains
    
    async def validate_domain_with_whois(self, domain: str) -> bool:
        """Basic domain validation (simplified WHOIS check)"""
        # This is a simplified check - in production you might want to use a proper WHOIS library
        try:
            # Try to resolve the domain
            import socket
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False
    
    def _score_domain(self, domain: str, company_name: str) -> float:
        """Score domain based on relevance to company name"""
        if not domain:
            return 0.0
        
        score = 0.0
        company_words = company_name.lower().split()
        domain_lower = domain.lower()
        
        # Exact company name match
        if company_name.lower().replace(' ', '') in domain_lower:
            score += 10.0
        
        # Partial company name match
        for word in company_words:
            if len(word) > 2 and word in domain_lower:
                score += 2.0
        
        # Common TLDs get higher scores
        if domain.endswith('.com'):
            score += 1.0
        elif domain.endswith('.org'):
            score += 0.5
        
        # Penalize very long domains
        if len(domain) > 30:
            score -= 1.0
        
        return score
    
    async def resolve_domain(self, company_name: str, 
                           use_serpapi: bool = False) -> Optional[str]:
        """Main method to resolve company name to domain"""
        
        # Check cache first
        if company_name in self.cache:
            logger.info(f"Found cached domain for {company_name}: {self.cache[company_name]}")
            return self.cache[company_name]
        
        logger.info(f"Resolving domain for company: {company_name}")
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
            
            # Check cache
            task = progress.add_task("🔍 Checking cache...", total=100)
            progress.update(task, advance=20)
            
            all_domains = []
            
            # Search DuckDuckGo
            progress.update(task, advance=20, description="🔍 Searching DuckDuckGo...")
            ddg_domains = await self.search_duckduckgo(company_name)
            all_domains.extend(ddg_domains)
            
            # Search SerpAPI if enabled
            if use_serpapi:
                progress.update(task, advance=20, description="🔍 Searching SerpAPI...")
                serp_domains = await self.search_serpapi(company_name)
                all_domains.extend(serp_domains)
            else:
                progress.update(task, advance=20)
            
            # Deduplicate and filter
            progress.update(task, advance=15, description="🔍 Processing and filtering domains...")
            unique_domains = deduplicate_list(all_domains)
            valid_domains = [d for d in unique_domains if validate_domain(d)]
            
            if not valid_domains:
                progress.update(task, advance=25, description="❌ No valid domains found")
                logger.warning(f"No valid domains found for {company_name}")
                return None
            
            # Score and rank domains
            progress.update(task, advance=10, description="🔍 Scoring and ranking domains...")
            domain_scores = []
            for domain in valid_domains:
                score = self._score_domain(domain, company_name)
                domain_scores.append((domain, score))
            
            # Sort by score (highest first)
            domain_scores.sort(key=lambda x: x[1], reverse=True)
            
            # Validate top domains
            progress.update(task, advance=10, description="🔍 Validating top domains...")
            for domain, score in domain_scores[:3]:
                logger.info(f"Validating domain: {domain} (score: {score})")
                if await self.validate_domain_with_whois(domain):
                    progress.update(task, advance=5, description=f"✅ Successfully resolved to {domain}")
                    logger.info(f"Successfully resolved {company_name} to {domain}")
                    
                    # Cache the result
                    self.cache[company_name] = domain
                    self._save_cache()
                    
                    return domain
            
            progress.update(task, advance=5, description="❌ Could not validate any domains")
            logger.warning(f"Could not validate any domains for {company_name}")
            return None
        
        except KeyboardInterrupt:
            self.console.print("\n⚠️  Domain resolution interrupted by user", style="yellow")
            logger.info("Domain resolution interrupted by user")
            return None
        except Exception as e:
            self.console.print(f"\n❌ Error during domain resolution: {e}", style="red")
            logger.error(f"Error during domain resolution: {e}")
            return None

async def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Resolve company name to main domain")
    parser.add_argument("--company_name", required=True, help="Name of the company")
    parser.add_argument("--save_json", action="store_true", help="Save results to JSON")
    parser.add_argument("--save_txt", action="store_true", help="Save results to TXT")
    parser.add_argument("--use_serpapi", action="store_true", help="Use SerpAPI for additional search")
    args = parser.parse_args()
    
    resolver = DomainResolver()
    domain = await resolver.resolve_domain(
        args.company_name, 
        use_serpapi=args.use_serpapi
    )
    
    if domain:
        result = {
            "company": args.company_name,
            "domain": domain,
            "timestamp": asyncio.get_event_loop().time()
        }
        
        print(f"Resolved domain: {domain}")
        
        if args.save_json:
            save_json(result, "domain.json")
        
        if args.save_txt:
            save_txt([domain], "domain.txt")
    else:
        print(f"Could not resolve domain for {args.company_name}")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
