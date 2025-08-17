#!/usr/bin/env python3
"""
DNS Resolution Module for ReconRover
Resolves subdomains to IP addresses and DNS records
"""

import argparse
import asyncio
import aiohttp
import dns.resolver
import dns.exception
import socket
from typing import List, Dict, Any, Optional, Set
from utils import (
    logger, save_json, save_txt, load_json, load_txt,
    validate_domain, deduplicate_list, format_table
)

class DNSResolver:
    """Resolves DNS records for domains"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5
        self.cache = {}
    
    async def resolve_a_record(self, domain: str) -> List[str]:
        """Resolve A records for a domain"""
        try:
            answers = self.resolver.resolve(domain, 'A')
            return [str(answer) for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception as e:
            logger.debug(f"Error resolving A record for {domain}: {e}")
            return []
    
    async def resolve_aaaa_record(self, domain: str) -> List[str]:
        """Resolve AAAA records for a domain"""
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            return [str(answer) for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception as e:
            logger.debug(f"Error resolving AAAA record for {domain}: {e}")
            return []
    
    async def resolve_cname_record(self, domain: str) -> List[str]:
        """Resolve CNAME records for a domain"""
        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            return [str(answer) for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception as e:
            logger.debug(f"Error resolving CNAME record for {domain}: {e}")
            return []
    
    async def resolve_mx_record(self, domain: str) -> List[str]:
        """Resolve MX records for a domain"""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            return [str(answer.exchange) for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception as e:
            logger.debug(f"Error resolving MX record for {domain}: {e}")
            return []
    
    async def resolve_txt_record(self, domain: str) -> List[str]:
        """Resolve TXT records for a domain"""
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            return [str(answer) for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception as e:
            logger.debug(f"Error resolving TXT record for {domain}: {e}")
            return []
    
    async def resolve_ns_record(self, domain: str) -> List[str]:
        """Resolve NS records for a domain"""
        try:
            answers = self.resolver.resolve(domain, 'NS')
            return [str(answer) for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception as e:
            logger.debug(f"Error resolving NS record for {domain}: {e}")
            return []
    
    async def resolve_all_records(self, domain: str) -> Dict[str, Any]:
        """Resolve all DNS records for a domain"""
        if domain in self.cache:
            return self.cache[domain]
        
        logger.info(f"Resolving DNS records for {domain}")
        
        # Resolve all record types concurrently
        tasks = [
            self.resolve_a_record(domain),
            self.resolve_aaaa_record(domain),
            self.resolve_cname_record(domain),
            self.resolve_mx_record(domain),
            self.resolve_txt_record(domain),
            self.resolve_ns_record(domain)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        dns_records = {
            'A': results[0] if not isinstance(results[0], Exception) else [],
            'AAAA': results[1] if not isinstance(results[1], Exception) else [],
            'CNAME': results[2] if not isinstance(results[2], Exception) else [],
            'MX': results[3] if not isinstance(results[3], Exception) else [],
            'TXT': results[4] if not isinstance(results[4], Exception) else [],
            'NS': results[5] if not isinstance(results[5], Exception) else []
        }
        
        # Cache the result
        self.cache[domain] = dns_records
        
        return dns_records
    
    async def resolve_subdomains(self, subdomains: List[str], 
                               record_types: List[str] = None) -> Dict[str, Dict[str, Any]]:
        """Resolve DNS records for a list of subdomains"""
        
        if record_types is None:
            record_types = ['A', 'AAAA', 'CNAME']
        
        results = {}
        valid_subdomains = [s for s in subdomains if validate_domain(s)]
        
        logger.info(f"Resolving DNS records for {len(valid_subdomains)} subdomains")
        
        # Process subdomains in batches to avoid overwhelming DNS servers
        batch_size = 5
        for i in range(0, len(valid_subdomains), batch_size):
            batch = valid_subdomains[i:i + batch_size]
            
            # Resolve each subdomain in the batch
            tasks = []
            for subdomain in batch:
                task = self.resolve_all_records(subdomain)
                tasks.append(task)
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for subdomain, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.warning(f"Failed to resolve {subdomain}: {result}")
                    results[subdomain] = {'error': str(result)}
                else:
                    # Filter to only requested record types
                    filtered_result = {rt: result.get(rt, []) for rt in record_types}
                    results[subdomain] = filtered_result
            
            # Small delay between batches
            await asyncio.sleep(0.05)
        
        return results
    
    def get_all_ips(self, dns_results: Dict[str, Dict[str, Any]]) -> List[str]:
        """Extract all IP addresses from DNS results"""
        ips = set()
        
        for domain, records in dns_results.items():
            if 'error' in records:
                continue
            
            # Add A record IPs
            if 'A' in records:
                ips.update(records['A'])
            
            # Add AAAA record IPs
            if 'AAAA' in records:
                ips.update(records['AAAA'])
        
        return list(ips)
    
    def format_dns_results(self, dns_results: Dict[str, Dict[str, Any]]) -> str:
        """Format DNS results as a human-readable table"""
        table_data = []
        
        for domain, records in dns_results.items():
            if 'error' in records:
                table_data.append({
                    'Domain': domain,
                    'A': 'ERROR',
                    'AAAA': 'ERROR',
                    'CNAME': 'ERROR',
                    'MX': 'ERROR',
                    'TXT': 'ERROR'
                })
                continue
            
            row = {'Domain': domain}
            for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT']:
                if record_type in records and records[record_type]:
                    row[record_type] = ', '.join(records[record_type][:3])  # Limit to first 3
                    if len(records[record_type]) > 3:
                        row[record_type] += f" (+{len(records[record_type]) - 3} more)"
                else:
                    row[record_type] = '-'
            
            table_data.append(row)
        
        return format_table(table_data, ['Domain', 'A', 'AAAA', 'CNAME', 'MX', 'TXT'])

async def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Resolve DNS records for subdomains")
    parser.add_argument("--subdomains", nargs="+", help="List of subdomains to resolve")
    parser.add_argument("--subdomains_file", help="File containing subdomains (one per line)")
    parser.add_argument("--save_json", action="store_true", help="Save results to JSON")
    parser.add_argument("--save_txt", action="store_true", help="Save results to TXT")
    parser.add_argument("--record_types", nargs="+", 
                       choices=['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'],
                       default=['A', 'AAAA', 'CNAME'],
                       help="DNS record types to resolve")
    
    args = parser.parse_args()
    
    # Get subdomains from arguments or file
    subdomains = []
    if args.subdomains:
        subdomains = args.subdomains
    elif args.subdomains_file:
        subdomains = load_txt(args.subdomains_file)
        if not subdomains:
            print(f"❌ No subdomains found in file: {args.subdomains_file}")
            print("💡 Make sure to run subdomain enumeration first")
            return 1
    else:
        # Try to load from default subdomains file
        subdomains = load_txt("subdomains.txt")
        if not subdomains:
            print("❌ No subdomains found in subdomains.txt")
            print("💡 Make sure to run subdomain enumeration first")
            return 1
    
    if not subdomains:
        print("No subdomains provided. Use --subdomains or --subdomains_file")
        return 1
    
    # Remove duplicates
    subdomains = deduplicate_list(subdomains)
    
    resolver = DNSResolver()
    dns_results = await resolver.resolve_subdomains(subdomains, args.record_types)
    
    if dns_results:
        # Extract all IPs
        all_ips = resolver.get_all_ips(dns_results)
        
        result = {
            "subdomains": dns_results,
            "total_subdomains": len(dns_results),
            "total_ips": len(all_ips),
            "record_types": args.record_types,
            "timestamp": asyncio.get_event_loop().time()
        }
        
        print(f"Resolved DNS records for {len(dns_results)} subdomains")
        print(f"Found {len(all_ips)} unique IP addresses")
        
        if args.save_json:
            save_json(result, "dns.json")
        
        if args.save_txt:
            # Save formatted table
            table_text = resolver.format_dns_results(dns_results)
            save_txt([table_text], "dns.txt")
            
            # Save IP list
            save_txt(all_ips, "ips.txt")
    else:
        print("No DNS records resolved")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
