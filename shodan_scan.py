#!/usr/bin/env python3
"""
Shodan Scanning Module for ReconRover
Fetches open ports, services, and banners from Shodan
"""

import argparse
import asyncio
import json
import time
from typing import List, Dict, Any, Optional
import shodan
from utils import (
    logger, save_json, save_txt, load_json, load_txt,
    deduplicate_list, format_table, RateLimiter
)

class ShodanScanner:
    """Scans IPs using Shodan API"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.api = shodan.Shodan(api_key)
        self.rate_limiter = RateLimiter(calls_per_second=1.0)  # Shodan free tier limit
        self.cache = {}
    
    async def scan_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Scan a single IP address"""
        if ip in self.cache:
            return self.cache[ip]
        
        logger.info(f"Scanning IP: {ip}")
        
        try:
            await self.rate_limiter.wait()
            host_info = self.api.host(ip)
            
            # Extract relevant information
            result = {
                'ip': ip,
                'ports': host_info.get('ports', []),
                'hostnames': host_info.get('hostnames', []),
                'country_name': host_info.get('country_name', 'Unknown'),
                'city': host_info.get('city', 'Unknown'),
                'isp': host_info.get('isp', 'Unknown'),
                'org': host_info.get('org', 'Unknown'),
                'asn': host_info.get('asn', 'Unknown'),
                'last_update': host_info.get('last_update', 'Unknown'),
                'services': []
            }
            
            # Extract service information
            for port_data in host_info.get('data', []):
                service = {
                    'port': port_data.get('port'),
                    'transport': port_data.get('transport', 'tcp'),
                    'product': port_data.get('product', ''),
                    'version': port_data.get('version', ''),
                    'banner': port_data.get('data', '')[:500],  # Limit banner length
                    'ssl': port_data.get('ssl', {}),
                    'http': port_data.get('http', {})
                }
                result['services'].append(service)
            
            # Cache the result
            self.cache[ip] = result
            return result
            
        except shodan.APIError as e:
            logger.error(f"Shodan API error for {ip}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error scanning {ip}: {e}")
            return None
    
    async def scan_ips(self, ips: List[str], top_ports: Optional[int] = None) -> List[Dict[str, Any]]:
        """Scan multiple IP addresses"""
        results = []
        valid_ips = [ip for ip in ips if self._is_valid_ip(ip)]
        
        logger.info(f"Scanning {len(valid_ips)} IP addresses")
        
        # Process IPs in batches to respect rate limits
        batch_size = 5
        for i in range(0, len(valid_ips), batch_size):
            batch = valid_ips[i:i + batch_size]
            
            # Scan each IP in the batch
            tasks = []
            for ip in batch:
                task = self.scan_ip(ip)
                tasks.append(task)
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for ip, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.warning(f"Failed to scan {ip}: {result}")
                elif result:
                    results.append(result)
            
            # Delay between batches
            await asyncio.sleep(1)
        
        return results
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Basic IP validation"""
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ip_pattern, ip))
    
    def get_top_ports(self, results: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
        """Get the most common open ports"""
        port_count = {}
        
        for result in results:
            for port in result.get('ports', []):
                port_count[port] = port_count.get(port, 0) + 1
        
        # Sort by count (descending)
        sorted_ports = sorted(port_count.items(), key=lambda x: x[1], reverse=True)
        
        return [{'port': port, 'count': count} for port, count in sorted_ports[:limit]]
    
    def get_services_summary(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get summary of services found"""
        service_count = {}
        
        for result in results:
            for service in result.get('services', []):
                product = service.get('product', 'Unknown')
                if product:
                    service_count[product] = service_count.get(product, 0) + 1
        
        return service_count
    
    def format_shodan_results(self, results: List[Dict[str, Any]]) -> str:
        """Format Shodan results as a human-readable table"""
        table_data = []
        
        for result in results:
            ip = result['ip']
            ports = ', '.join(map(str, result.get('ports', [])[:5]))  # Show first 5 ports
            if len(result.get('ports', [])) > 5:
                ports += f" (+{len(result.get('ports', [])) - 5} more)"
            
            services = []
            for service in result.get('services', [])[:3]:  # Show first 3 services
                service_str = f"{service.get('port')}/{service.get('transport', 'tcp')}"
                if service.get('product'):
                    service_str += f" ({service['product']})"
                services.append(service_str)
            
            services_str = ', '.join(services)
            if len(result.get('services', [])) > 3:
                services_str += f" (+{len(result.get('services', [])) - 3} more)"
            
            table_data.append({
                'IP': ip,
                'Ports': ports,
                'Services': services_str,
                'Country': result.get('country_name', 'Unknown'),
                'City': result.get('city', 'Unknown'),
                'ISP': result.get('isp', 'Unknown')[:30]  # Truncate long ISP names
            })
        
        return format_table(table_data, ['IP', 'Ports', 'Services', 'Country', 'City', 'ISP'])
    
    def get_critical_findings(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify potentially critical findings"""
        critical_findings = []
        
        critical_ports = {21, 22, 23, 25, 53, 80, 443, 3389, 5432, 3306, 6379, 27017}
        critical_services = {'ssh', 'telnet', 'ftp', 'rdp', 'mysql', 'postgresql', 'redis', 'mongodb'}
        
        for result in results:
            for service in result.get('services', []):
                port = service.get('port')
                product = service.get('product', '').lower()
                
                # Check for critical ports
                if port in critical_ports:
                    critical_findings.append({
                        'ip': result['ip'],
                        'port': port,
                        'service': service.get('product', 'Unknown'),
                        'risk': 'Critical Port',
                        'details': f"Port {port} is commonly targeted"
                    })
                
                # Check for critical services
                for critical_service in critical_services:
                    if critical_service in product:
                        critical_findings.append({
                            'ip': result['ip'],
                            'port': port,
                            'service': service.get('product', 'Unknown'),
                            'risk': 'Critical Service',
                            'details': f"Found {critical_service} service"
                        })
                        break
        
        return critical_findings

async def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Scan IPs using Shodan")
    parser.add_argument("--ips", nargs="+", help="List of IPs to scan")
    parser.add_argument("--ips_file", help="File containing IPs (one per line)")
    parser.add_argument("--save_json", action="store_true", help="Save results to JSON")
    parser.add_argument("--save_txt", action="store_true", help="Save results to TXT")
    parser.add_argument("--top_ports", type=int, default=10, help="Number of top ports to show")
    parser.add_argument("--api_key", help="Shodan API key")
    
    args = parser.parse_args()
    
    # Get API key
    api_key = args.api_key
    if not api_key:
        # Try to load from environment or config
        import os
        api_key = os.getenv('SHODAN_API_KEY')
    
    if not api_key:
        print("Shodan API key required. Use --api_key or set SHODAN_API_KEY environment variable")
        return 1
    
    # Get IPs from arguments or file
    ips = []
    if args.ips:
        ips = args.ips
    elif args.ips_file:
        ips = load_txt(args.ips_file)
    else:
        # Try to load from default IPs file
        ips = load_txt("ips.txt")
    
    if not ips:
        print("No IPs provided. Use --ips or --ips_file")
        return 1
    
    # Remove duplicates
    ips = deduplicate_list(ips)
    
    scanner = ShodanScanner(api_key)
    results = await scanner.scan_ips(ips, args.top_ports)
    
    if results:
        # Get summaries
        top_ports = scanner.get_top_ports(results, args.top_ports)
        services_summary = scanner.get_services_summary(results)
        critical_findings = scanner.get_critical_findings(results)
        
        result = {
            "scanned_ips": len(results),
            "total_ips": len(ips),
            "results": results,
            "top_ports": top_ports,
            "services_summary": services_summary,
            "critical_findings": critical_findings,
            "timestamp": asyncio.get_event_loop().time()
        }
        
        print(f"Scanned {len(results)} out of {len(ips)} IPs")
        print(f"Found {len(critical_findings)} critical findings")
        
        if args.save_json:
            save_json(result, "shodan.json")
        
        if args.save_txt:
            # Save formatted table
            table_text = scanner.format_shodan_results(results)
            save_txt([table_text], "shodan.txt")
            
            # Save critical findings
            if critical_findings:
                critical_text = "Critical Findings:\n" + format_table(
                    critical_findings, 
                    ['IP', 'Port', 'Service', 'Risk', 'Details']
                )
                save_txt([critical_text], "critical_findings.txt")
    else:
        print("No Shodan results found")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
