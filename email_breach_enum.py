#!/usr/bin/env python3
"""
Email and Breach Enumeration Module for ReconRover
Finds email addresses and checks for breaches
"""

import argparse
import asyncio
import aiohttp
import json
import hashlib
import re
from typing import List, Dict, Any, Optional, Set
from utils import (
    logger, save_json, save_txt, load_json, load_txt,
    deduplicate_list, format_table, RateLimiter, make_request
)

class EmailBreachEnumerator:
    """Enumerates email addresses and checks for breaches"""
    
    def __init__(self):
        self.rate_limiter = RateLimiter(calls_per_second=1.0)
        self.session = None
        self.cache = {}
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def search_hunter_emails(self, domain: str, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search for email addresses using Hunter.io API"""
        if not api_key:
            logger.warning("Hunter.io API key not provided, skipping email search")
            return []
        
        logger.info(f"Searching Hunter.io for emails from {domain}")
        
        url = f"https://api.hunter.io/v2/domain-search"
        params = {
            'domain': domain,
            'api_key': api_key,
            'limit': 100
        }
        
        try:
            response = await make_request(self.session, url, params=params, rate_limiter=self.rate_limiter)
            if not response:
                return []
            
            data = json.loads(response)
            emails = []
            
            if 'data' in data and 'emails' in data['data']:
                for email_data in data['data']['emails']:
                    email = {
                        'email': email_data.get('value', ''),
                        'first_name': email_data.get('first_name', ''),
                        'last_name': email_data.get('last_name', ''),
                        'confidence': email_data.get('confidence', 0),
                        'sources': email_data.get('sources', []),
                        'type': email_data.get('type', '')
                    }
                    emails.append(email)
            
            logger.info(f"Found {len(emails)} emails from Hunter.io")
            return emails
            
        except json.JSONDecodeError:
            logger.error("Failed to parse Hunter.io JSON response")
            return []
        except Exception as e:
            logger.error(f"Error searching Hunter.io: {e}")
            return []
    
    async def check_hibp_breach(self, email: str, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
        """Check if an email appears in HaveIBeenPwned breach database"""
        logger.info(f"Checking HIBP for email: {email}")
        
        # Hash the email (HIBP requires SHA1 hash)
        email_hash = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            'hibp-api-key': api_key,
            'user-agent': 'ReconRover-EmailBreachEnumerator'
        } if api_key else {
            'user-agent': 'ReconRover-EmailBreachEnumerator'
        }
        
        try:
            response = await make_request(self.session, url, headers, self.rate_limiter)
            if not response:
                return []
            
            breaches = json.loads(response)
            breach_list = []
            
            for breach in breaches:
                breach_data = {
                    'name': breach.get('Name', ''),
                    'title': breach.get('Title', ''),
                    'domain': breach.get('Domain', ''),
                    'breach_date': breach.get('BreachDate', ''),
                    'added_date': breach.get('AddedDate', ''),
                    'modified_date': breach.get('ModifiedDate', ''),
                    'pwn_count': breach.get('PwnCount', 0),
                    'description': breach.get('Description', ''),
                    'data_classes': breach.get('DataClasses', []),
                    'is_verified': breach.get('IsVerified', False),
                    'is_fabricated': breach.get('IsFabricated', False),
                    'is_sensitive': breach.get('IsSensitive', False),
                    'is_retired': breach.get('IsRetired', False),
                    'is_spam_list': breach.get('IsSpamList', False)
                }
                breach_list.append(breach_data)
            
            logger.info(f"Found {len(breach_list)} breaches for {email}")
            return breach_list
            
        except json.JSONDecodeError:
            logger.error("Failed to parse HIBP JSON response")
            return []
        except Exception as e:
            logger.error(f"Error checking HIBP for {email}: {e}")
            return []
    
    async def check_hibp_paste(self, email: str, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
        """Check if an email appears in HaveIBeenPwned paste database"""
        logger.info(f"Checking HIBP pastes for email: {email}")
        
        url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"
        headers = {
            'hibp-api-key': api_key,
            'user-agent': 'ReconRover-EmailBreachEnumerator'
        } if api_key else {
            'user-agent': 'ReconRover-EmailBreachEnumerator'
        }
        
        try:
            response = await make_request(self.session, url, headers, self.rate_limiter)
            if not response:
                return []
            
            pastes = json.loads(response)
            paste_list = []
            
            for paste in pastes:
                paste_data = {
                    'source': paste.get('Source', ''),
                    'id': paste.get('Id', ''),
                    'title': paste.get('Title', ''),
                    'date': paste.get('Date', ''),
                    'email_count': paste.get('EmailCount', 0)
                }
                paste_list.append(paste_data)
            
            logger.info(f"Found {len(paste_list)} pastes for {email}")
            return paste_list
            
        except json.JSONDecodeError:
            logger.error("Failed to parse HIBP paste JSON response")
            return []
        except Exception as e:
            logger.error(f"Error checking HIBP pastes for {email}: {e}")
            return []
    
    async def search_emails_from_webpage(self, domain: str) -> List[str]:
        """Extract email addresses from the main webpage"""
        logger.info(f"Extracting emails from webpage: {domain}")
        
        # Ensure domain has protocol
        if not domain.startswith(('http://', 'https://')):
            domain = f"https://{domain}"
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            html = await make_request(self.session, domain, headers, self.rate_limiter)
            if not html:
                return []
            
            # Extract emails using regex
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, html)
            
            # Filter emails to only include those from the target domain
            domain_emails = []
            for email in emails:
                if email.lower().endswith(f'@{domain.replace("https://", "").replace("http://", "")}'):
                    domain_emails.append(email.lower())
            
            logger.info(f"Found {len(domain_emails)} emails from webpage")
            return list(set(domain_emails))  # Remove duplicates
            
        except Exception as e:
            logger.error(f"Error extracting emails from {domain}: {e}")
            return []
    
    async def enumerate_emails_and_breaches(self, domain: str,
                                          hunter_api_key: Optional[str] = None,
                                          hibp_api_key: Optional[str] = None) -> Dict[str, Any]:
        """Main method to enumerate emails and check for breaches"""
        
        logger.info(f"Starting email and breach enumeration for {domain}")
        
        result = {
            'domain': domain,
            'emails': [],
            'breaches': [],
            'pastes': [],
            'webpage_emails': [],
            'total_emails': 0,
            'total_breaches': 0,
            'total_pastes': 0
        }
        
        # Search for emails using Hunter.io
        hunter_emails = await self.search_hunter_emails(domain, hunter_api_key)
        result['emails'] = hunter_emails
        
        # Extract emails from webpage
        webpage_emails = await self.search_emails_from_webpage(domain)
        result['webpage_emails'] = webpage_emails
        
        # Combine all emails
        all_emails = set()
        for email_data in hunter_emails:
            all_emails.add(email_data['email'].lower())
        all_emails.update(webpage_emails)
        
        # Check breaches for each email
        all_breaches = []
        all_pastes = []
        
        for email in all_emails:
            # Check breaches
            breaches = await self.check_hibp_breach(email, hibp_api_key)
            for breach in breaches:
                breach['email'] = email
                all_breaches.append(breach)
            
            # Check pastes
            pastes = await self.check_hibp_paste(email, hibp_api_key)
            for paste in pastes:
                paste['email'] = email
                all_pastes.append(paste)
        
        result['breaches'] = all_breaches
        result['pastes'] = all_pastes
        result['total_emails'] = len(all_emails)
        result['total_breaches'] = len(all_breaches)
        result['total_pastes'] = len(all_pastes)
        
        return result
    
    def get_breach_summary(self, breaches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of breach findings"""
        summary = {
            'total_breaches': len(breaches),
            'unique_breaches': {},
            'breach_years': {},
            'data_classes': {},
            'affected_emails': set()
        }
        
        for breach in breaches:
            breach_name = breach.get('name', 'Unknown')
            email = breach.get('email', 'Unknown')
            breach_date = breach.get('breach_date', '')
            data_classes = breach.get('data_classes', [])
            
            # Count unique breaches
            summary['unique_breaches'][breach_name] = summary['unique_breaches'].get(breach_name, 0) + 1
            
            # Count by year
            if breach_date:
                year = breach_date.split('-')[0] if '-' in breach_date else 'Unknown'
                summary['breach_years'][year] = summary['breach_years'].get(year, 0) + 1
            
            # Count data classes
            for data_class in data_classes:
                summary['data_classes'][data_class] = summary['data_classes'].get(data_class, 0) + 1
            
            # Track affected emails
            summary['affected_emails'].add(email)
        
        # Convert set to list for JSON serialization
        summary['affected_emails'] = list(summary['affected_emails'])
        
        return summary
    
    def format_email_results(self, result: Dict[str, Any]) -> str:
        """Format email and breach results as a human-readable table"""
        table_data = []
        
        # Create email table
        for email_data in result.get('emails', []):
            table_data.append({
                'Email': email_data.get('email', ''),
                'Name': f"{email_data.get('first_name', '')} {email_data.get('last_name', '')}".strip(),
                'Confidence': email_data.get('confidence', 0),
                'Type': email_data.get('type', ''),
                'Sources': len(email_data.get('sources', []))
            })
        
        # Add webpage emails
        for email in result.get('webpage_emails', []):
            table_data.append({
                'Email': email,
                'Name': 'Extracted from webpage',
                'Confidence': 'N/A',
                'Type': 'Webpage',
                'Sources': 1
            })
        
        return format_table(table_data, ['Email', 'Name', 'Confidence', 'Type', 'Sources'])
    
    def format_breach_results(self, breaches: List[Dict[str, Any]]) -> str:
        """Format breach results as a human-readable table"""
        table_data = []
        
        for breach in breaches:
            table_data.append({
                'Email': breach.get('email', ''),
                'Breach': breach.get('name', ''),
                'Date': breach.get('breach_date', ''),
                'Data Classes': ', '.join(breach.get('data_classes', [])[:3]),
                'Verified': breach.get('is_verified', False),
                'Sensitive': breach.get('is_sensitive', False)
            })
        
        return format_table(table_data, ['Email', 'Breach', 'Date', 'Data Classes', 'Verified', 'Sensitive'])

async def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Enumerate emails and check for breaches")
    parser.add_argument("--domain", required=True, help="Target domain")
    parser.add_argument("--save_json", action="store_true", help="Save results to JSON")
    parser.add_argument("--save_txt", action="store_true", help="Save results to TXT")
    parser.add_argument("--hunter_api", help="Hunter.io API key")
    parser.add_argument("--hibp_api", help="HaveIBeenPwned API key")
    
    args = parser.parse_args()
    
    # Get API keys
    hunter_api_key = args.hunter_api
    hibp_api_key = args.hibp_api
    
    if not hunter_api_key:
        import os
        hunter_api_key = os.getenv('HUNTER_API_KEY')
    
    if not hibp_api_key:
        import os
        hibp_api_key = os.getenv('HIBP_API_KEY')
    
    async with EmailBreachEnumerator() as enumerator:
        result = await enumerator.enumerate_emails_and_breaches(
            args.domain,
            hunter_api_key=hunter_api_key,
            hibp_api_key=hibp_api_key
        )
    
    if result:
        # Get breach summary
        breach_summary = enumerator.get_breach_summary(result['breaches'])
        result['breach_summary'] = breach_summary
        
        print(f"Found {result['total_emails']} unique emails")
        print(f"Found {result['total_breaches']} breaches")
        print(f"Found {result['total_pastes']} pastes")
        print(f"Affected {len(breach_summary['affected_emails'])} unique emails")
        
        if args.save_json:
            save_json(result, "emails.json")
        
        if args.save_txt:
            # Save email table
            email_table = enumerator.format_email_results(result)
            save_txt([email_table], "emails.txt")
            
            # Save breach table
            if result['breaches']:
                breach_table = enumerator.format_breach_results(result['breaches'])
                save_txt([breach_table], "breaches.txt")
    else:
        print(f"No email or breach data found for {args.domain}")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
