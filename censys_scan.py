#!/usr/bin/env python3
"""
Censys Scanning Module for ReconRover
Fetches certificates and service information from Censys
"""

import argparse
import asyncio
import json
import base64
from typing import List, Dict, Any, Optional
import censys.certificates
import censys.ipv4
from utils import (
    logger, save_json, save_txt, load_json, load_txt,
    deduplicate_list, format_table, RateLimiter
)

class CensysScanner:
    """Scans using Censys API"""
    
    def __init__(self, api_id: str, api_secret: str):
        self.api_id = api_id
        self.api_secret = api_secret
        self.certificates = censys.certificates.CensysCertificates(api_id, api_secret)
        self.ipv4 = censys.ipv4.CensysIPv4(api_id, api_secret)
        self.rate_limiter = RateLimiter(calls_per_second=0.5)  # Conservative rate limiting
        self.cache = {}
    
    async def search_certificates(self, domain: str) -> List[Dict[str, Any]]:
        """Search for SSL certificates containing the domain"""
        logger.info(f"Searching Censys certificates for {domain}")
        
        try:
            await self.rate_limiter.wait()
            
            # Search for certificates
            query = f"parsed.names: {domain}"
            certificates = []
            
            for cert in self.certificates.search(query, max_records=100):
                cert_data = {
                    'fingerprint': cert.get('parsed.fingerprint_sha256', ''),
                    'subject': cert.get('parsed.subject_dn', ''),
                    'issuer': cert.get('parsed.issuer_dn', ''),
                    'validity_start': cert.get('parsed.validity.start', ''),
                    'validity_end': cert.get('parsed.validity.end', ''),
                    'names': cert.get('parsed.names', []),
                    'subject_alt_names': cert.get('parsed.extensions.subject_alt_name.dns_names', []),
                    'key_algorithm': cert.get('parsed.signature_algorithm.name', ''),
                    'key_size': cert.get('parsed.signature_algorithm.oid', ''),
                }
                certificates.append(cert_data)
            
            logger.info(f"Found {len(certificates)} certificates for {domain}")
            return certificates
            
        except Exception as e:
            logger.error(f"Error searching certificates for {domain}: {e}")
            return []
    
    async def search_services(self, domain: str) -> List[Dict[str, Any]]:
        """Search for services associated with the domain"""
        logger.info(f"Searching Censys services for {domain}")
        
        try:
            await self.rate_limiter.wait()
            
            # Search for services
            query = f"hostnames: {domain}"
            services = []
            
            for service in self.ipv4.search(query, max_records=100):
                service_data = {
                    'ip': service.get('ip', ''),
                    'ports': service.get('ports', []),
                    'protocols': service.get('protocols', []),
                    'hostnames': service.get('hostnames', []),
                    'location': {
                        'country': service.get('location.country', ''),
                        'city': service.get('location.city', ''),
                        'coordinates': service.get('location.coordinates', {})
                    },
                    'autonomous_system': {
                        'asn': service.get('autonomous_system.asn', ''),
                        'description': service.get('autonomous_system.description', '')
                    },
                    'http': service.get('http', {}),
                    'https': service.get('https', {}),
                    'ssl': service.get('ssl', {})
                }
                services.append(service_data)
            
            logger.info(f"Found {len(services)} services for {domain}")
            return services
            
        except Exception as e:
            logger.error(f"Error searching services for {domain}: {e}")
            return []
    
    async def search_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Search for information about a specific IP"""
        logger.info(f"Searching Censys for IP: {ip}")
        
        try:
            await self.rate_limiter.wait()
            
            # Get IP information
            ip_info = self.ipv4.view(ip)
            
            result = {
                'ip': ip,
                'ports': ip_info.get('ports', []),
                'protocols': ip_info.get('protocols', []),
                'hostnames': ip_info.get('hostnames', []),
                'location': {
                    'country': ip_info.get('location.country', ''),
                    'city': ip_info.get('location.city', ''),
                    'coordinates': ip_info.get('location.coordinates', {})
                },
                'autonomous_system': {
                    'asn': ip_info.get('autonomous_system.asn', ''),
                    'description': ip_info.get('autonomous_system.description', '')
                },
                'services': []
            }
            
            # Extract service information
            for port in ip_info.get('ports', []):
                service_key = f"{ip}:{port}"
                if service_key in ip_info:
                    service_data = ip_info[service_key]
                    service = {
                        'port': port,
                        'protocol': service_data.get('protocol', ''),
                        'service': service_data.get('service', {}),
                        'http': service_data.get('http', {}),
                        'https': service_data.get('https', {}),
                        'ssl': service_data.get('ssl', {})
                    }
                    result['services'].append(service)
            
            return result
            
        except Exception as e:
            logger.error(f"Error searching IP {ip}: {e}")
            return None
    
    async def scan_domain(self, domain: str) -> Dict[str, Any]:
        """Comprehensive scan of a domain"""
        logger.info(f"Starting comprehensive Censys scan for {domain}")
        
        # Search certificates and services concurrently
        cert_task = self.search_certificates(domain)
        services_task = self.search_services(domain)
        
        certificates, services = await asyncio.gather(cert_task, services_task)
        
        # Extract subdomains from certificates
        subdomains = set()
        for cert in certificates:
            subdomains.update(cert.get('names', []))
            subdomains.update(cert.get('subject_alt_names', []))
        
        # Filter subdomains to only include those for the target domain
        filtered_subdomains = []
        for subdomain in subdomains:
            if subdomain.endswith(f'.{domain}') and subdomain != domain:
                filtered_subdomains.append(subdomain)
        
        result = {
            'domain': domain,
            'certificates': certificates,
            'services': services,
            'subdomains': list(filtered_subdomains),
            'certificate_count': len(certificates),
            'service_count': len(services),
            'subdomain_count': len(filtered_subdomains)
        }
        
        return result
    
    async def scan_ips(self, ips: List[str]) -> List[Dict[str, Any]]:
        """Scan multiple IP addresses"""
        results = []
        
        logger.info(f"Scanning {len(ips)} IP addresses with Censys")
        
        # Process IPs in batches
        batch_size = 5
        for i in range(0, len(ips), batch_size):
            batch = ips[i:i + batch_size]
            
            # Scan each IP in the batch
            tasks = []
            for ip in batch:
                task = self.search_by_ip(ip)
                tasks.append(task)
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for ip, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.warning(f"Failed to scan {ip}: {result}")
                elif result:
                    results.append(result)
            
            # Delay between batches
            await asyncio.sleep(2)
        
        return results
    
    def get_certificate_summary(self, certificates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of certificate findings"""
        summary = {
            'total_certificates': len(certificates),
            'issuers': {},
            'expiring_soon': [],
            'weak_keys': []
        }
        
        import datetime
        now = datetime.datetime.now()
        
        for cert in certificates:
            # Count issuers
            issuer = cert.get('issuer', 'Unknown')
            summary['issuers'][issuer] = summary['issuers'].get(issuer, 0) + 1
            
            # Check for expiring certificates
            try:
                end_date = datetime.datetime.fromisoformat(cert.get('validity_end', '').replace('Z', '+00:00'))
                days_until_expiry = (end_date - now).days
                if days_until_expiry < 30:
                    summary['expiring_soon'].append({
                        'fingerprint': cert.get('fingerprint', ''),
                        'days_until_expiry': days_until_expiry,
                        'subject': cert.get('subject', '')
                    })
            except:
                pass
            
            # Check for weak keys
            key_size = cert.get('key_size', '')
            if key_size and key_size.isdigit() and int(key_size) < 2048:
                summary['weak_keys'].append({
                    'fingerprint': cert.get('fingerprint', ''),
                    'key_size': key_size,
                    'subject': cert.get('subject', '')
                })
        
        return summary
    
    def format_censys_results(self, results: List[Dict[str, Any]]) -> str:
        """Format Censys results as a human-readable table"""
        table_data = []
        
        for result in results:
            ip = result.get('ip', '')
            ports = ', '.join(map(str, result.get('ports', [])[:5]))
            if len(result.get('ports', [])) > 5:
                ports += f" (+{len(result.get('ports', [])) - 5} more)"
            
            hostnames = ', '.join(result.get('hostnames', [])[:3])
            if len(result.get('hostnames', [])) > 3:
                hostnames += f" (+{len(result.get('hostnames', [])) - 3} more)"
            
            country = result.get('location', {}).get('country', 'Unknown')
            asn = result.get('autonomous_system', {}).get('asn', 'Unknown')
            
            table_data.append({
                'IP': ip,
                'Ports': ports,
                'Hostnames': hostnames,
                'Country': country,
                'ASN': asn
            })
        
        return format_table(table_data, ['IP', 'Ports', 'Hostnames', 'Country', 'ASN'])

async def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Scan using Censys API")
    parser.add_argument("--domain", help="Domain to scan")
    parser.add_argument("--ips", nargs="+", help="List of IPs to scan")
    parser.add_argument("--ips_file", help="File containing IPs (one per line)")
    parser.add_argument("--save_json", action="store_true", help="Save results to JSON")
    parser.add_argument("--api_id", help="Censys API ID")
    parser.add_argument("--api_secret", help="Censys API secret")
    
    args = parser.parse_args()
    
    # Get API credentials
    api_id = args.api_id
    api_secret = args.api_secret
    
    if not api_id or not api_secret:
        import os
        api_id = api_id or os.getenv('CENSYS_API_ID')
        api_secret = api_secret or os.getenv('CENSYS_API_SECRET')
    
    if not api_id or not api_secret:
        print("Censys API credentials required. Use --api_id and --api_secret or set environment variables")
        return 1
    
    scanner = CensysScanner(api_id, api_secret)
    
    if args.domain:
        # Scan domain
        result = await scanner.scan_domain(args.domain)
        
        if result:
            # Add certificate summary
            cert_summary = scanner.get_certificate_summary(result['certificates'])
            result['certificate_summary'] = cert_summary
            
            print(f"Found {result['certificate_count']} certificates")
            print(f"Found {result['service_count']} services")
            print(f"Found {result['subdomain_count']} subdomains")
            
            if args.save_json:
                save_json(result, "censys.json")
    
    elif args.ips or args.ips_file:
        # Scan IPs
        ips = []
        if args.ips:
            ips = args.ips
        elif args.ips_file:
            ips = load_txt(args.ips_file)
        
        if not ips:
            print("No IPs provided")
            return 1
        
        # Remove duplicates
        ips = deduplicate_list(ips)
        
        results = await scanner.scan_ips(ips)
        
        if results:
            result = {
                "scanned_ips": len(results),
                "total_ips": len(ips),
                "results": results,
                "timestamp": asyncio.get_event_loop().time()
            }
            
            print(f"Scanned {len(results)} out of {len(ips)} IPs")
            
            if args.save_json:
                save_json(result, "censys.json")
            
            # Save formatted table
            table_text = scanner.format_censys_results(results)
            save_txt([table_text], "censys.txt")
    
    else:
        print("Either --domain or --ips/--ips_file must be provided")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
