"""
ZoomEye Scanner Module for ReconRover
Provides port and service information using ZoomEye API
"""

import asyncio
import aiohttp
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from api_loader import get_api_key, get_rate_limit
from utils import RateLimiter, save_json, save_txt, format_table

logger = logging.getLogger(__name__)

class ZoomEyeScanner:
    """ZoomEye API integration for port and service scanning"""
    
    def __init__(self):
        """Initialize ZoomEye scanner"""
        self.api_key = get_api_key('zoomeye')
        self.rate_limit = get_rate_limit('zoomeye')
        self.rate_limiter = RateLimiter(self.rate_limit, 3600)  # per hour
        self.base_url = "https://api.zoomeye.org"
        self.headers = {
            "API-KEY": self.api_key,
            "User-Agent": "ReconRover/1.0"
        }
    
    async def search_hosts(self, query: str, page: int = 1, facets: str = "app,os") -> Dict[str, Any]:
        """
        Search for hosts using ZoomEye API
        
        Args:
            query: Search query (domain, IP, or service)
            page: Page number for pagination
            facets: Facets to include in response
            
        Returns:
            Dictionary containing search results
        """
        await self.rate_limiter.wait()
        
        url = f"{self.base_url}/host/search"
        params = {
            "query": query,
            "page": page,
            "facets": facets
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"ZoomEye search successful for query: {query}")
                        return data
                    else:
                        logger.error(f"ZoomEye API error: {response.status} - {await response.text()}")
                        return {"error": f"API error: {response.status}"}
        except Exception as e:
            logger.error(f"Error in ZoomEye search: {e}")
            return {"error": str(e)}
    
    async def search_web(self, query: str, page: int = 1) -> Dict[str, Any]:
        """
        Search for web applications using ZoomEye API
        
        Args:
            query: Search query (domain, IP, or service)
            page: Page number for pagination
            
        Returns:
            Dictionary containing web search results
        """
        await self.rate_limiter.wait()
        
        url = f"{self.base_url}/web/search"
        params = {
            "query": query,
            "page": page
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"ZoomEye web search successful for query: {query}")
                        return data
                    else:
                        logger.error(f"ZoomEye API error: {response.status} - {await response.text()}")
                        return {"error": f"API error: {response.status}"}
        except Exception as e:
            logger.error(f"Error in ZoomEye web search: {e}")
            return {"error": str(e)}
    
    async def get_host_details(self, ip: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific host
        
        Args:
            ip: IP address to get details for
            
        Returns:
            Dictionary containing host details
        """
        await self.rate_limiter.wait()
        
        url = f"{self.base_url}/host/{ip}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"ZoomEye host details successful for IP: {ip}")
                        return data
                    else:
                        logger.error(f"ZoomEye API error: {response.status} - {await response.text()}")
                        return {"error": f"API error: {response.status}"}
        except Exception as e:
            logger.error(f"Error in ZoomEye host details: {e}")
            return {"error": str(e)}
    
    async def scan_domain(self, domain: str) -> Dict[str, Any]:
        """
        Scan a domain for hosts and services
        
        Args:
            domain: Domain to scan
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Starting ZoomEye scan for domain: {domain}")
        
        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "hosts": [],
            "web_apps": [],
            "ports": set(),
            "services": set(),
            "os_info": {},
            "summary": {}
        }
        
        # Search for hosts
        host_query = f"hostname:{domain}"
        host_results = await self.search_hosts(host_query, page=1)
        
        if "matches" in host_results:
            for match in host_results["matches"]:
                host_info = {
                    "ip": match.get("ip", ""),
                    "port": match.get("portinfo", {}).get("port", ""),
                    "service": match.get("portinfo", {}).get("service", ""),
                    "banner": match.get("portinfo", {}).get("banner", ""),
                    "os": match.get("portinfo", {}).get("os", ""),
                    "timestamp": match.get("timestamp", "")
                }
                results["hosts"].append(host_info)
                
                if host_info["port"]:
                    results["ports"].add(host_info["port"])
                if host_info["service"]:
                    results["services"].add(host_info["service"])
                if host_info["os"]:
                    results["os_info"][host_info["os"]] = results["os_info"].get(host_info["os"], 0) + 1
        
        # Search for web applications
        web_query = f"hostname:{domain}"
        web_results = await self.search_web(web_query, page=1)
        
        if "matches" in web_results:
            for match in web_results["matches"]:
                web_info = {
                    "ip": match.get("ip", ""),
                    "domain": match.get("domain", ""),
                    "title": match.get("title", ""),
                    "headers": match.get("headers", {}),
                    "server": match.get("server", ""),
                    "timestamp": match.get("timestamp", "")
                }
                results["web_apps"].append(web_info)
        
        # Convert sets to lists for JSON serialization
        results["ports"] = list(results["ports"])
        results["services"] = list(results["services"])
        
        # Generate summary
        results["summary"] = {
            "total_hosts": len(results["hosts"]),
            "total_web_apps": len(results["web_apps"]),
            "unique_ports": len(results["ports"]),
            "unique_services": len(results["services"]),
            "top_ports": sorted(results["ports"])[:10],
            "top_services": list(results["services"])[:10],
            "os_distribution": results["os_info"]
        }
        
        logger.info(f"ZoomEye scan completed for {domain}: {results['summary']['total_hosts']} hosts found")
        return results
    
    async def scan_ips(self, ips: List[str]) -> Dict[str, Any]:
        """
        Scan multiple IP addresses for detailed information
        
        Args:
            ips: List of IP addresses to scan
            
        Returns:
            Dictionary containing scan results for all IPs
        """
        logger.info(f"Starting ZoomEye scan for {len(ips)} IP addresses")
        
        results = {
            "ips": {},
            "timestamp": datetime.now().isoformat(),
            "summary": {}
        }
        
        # Process IPs in batches to respect rate limits
        batch_size = 5
        for i in range(0, len(ips), batch_size):
            batch = ips[i:i + batch_size]
            tasks = [self.get_host_details(ip) for ip in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for ip, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    results["ips"][ip] = {"error": str(result)}
                else:
                    results["ips"][ip] = result
        
        # Generate summary
        successful_scans = sum(1 for data in results["ips"].values() if "error" not in data)
        results["summary"] = {
            "total_ips": len(ips),
            "successful_scans": successful_scans,
            "failed_scans": len(ips) - successful_scans
        }
        
        logger.info(f"ZoomEye IP scan completed: {successful_scans}/{len(ips)} successful")
        return results
    
    def get_top_ports(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract top ports from scan results
        
        Args:
            results: ZoomEye scan results
            
        Returns:
            List of top ports with counts
        """
        port_counts = {}
        
        if "hosts" in results:
            for host in results["hosts"]:
                port = host.get("port")
                if port:
                    port_counts[port] = port_counts.get(port, 0) + 1
        
        return [{"port": port, "count": count} for port, count in sorted(port_counts.items(), key=lambda x: x[1], reverse=True)]
    
    def get_services_summary(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract services summary from scan results
        
        Args:
            results: ZoomEye scan results
            
        Returns:
            List of services with counts
        """
        service_counts = {}
        
        if "hosts" in results:
            for host in results["hosts"]:
                service = host.get("service")
                if service:
                    service_counts[service] = service_counts.get(service, 0) + 1
        
        return [{"service": service, "count": count} for service, count in sorted(service_counts.items(), key=lambda x: x[1], reverse=True)]
    
    def get_critical_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Identify critical findings from scan results
        
        Args:
            results: ZoomEye scan results
            
        Returns:
            List of critical findings
        """
        critical_findings = []
        critical_services = {
            "ssh", "telnet", "ftp", "smtp", "pop3", "imap", "rdp", "vnc", "mysql", "postgresql",
            "mongodb", "redis", "elasticsearch", "kibana", "jenkins", "docker", "kubernetes"
        }
        
        if "hosts" in results:
            for host in results["hosts"]:
                service = host.get("service", "").lower()
                if service in critical_services:
                    critical_findings.append({
                        "ip": host.get("ip"),
                        "port": host.get("port"),
                        "service": host.get("service"),
                        "banner": host.get("banner", "")[:200],
                        "risk_level": "high" if service in ["ssh", "rdp", "vnc"] else "medium"
                    })
        
        return critical_findings
    
    def format_zoomeye_results(self, results: Dict[str, Any]) -> str:
        """
        Format ZoomEye results as a table
        
        Args:
            results: ZoomEye scan results
            
        Returns:
            Formatted table string
        """
        if "error" in results:
            return f"Error: {results['error']}"
        
        summary = results.get("summary", {})
        
        table_data = [
            ["Metric", "Value"],
            ["Total Hosts", str(summary.get("total_hosts", 0))],
            ["Total Web Apps", str(summary.get("total_web_apps", 0))],
            ["Unique Ports", str(summary.get("unique_ports", 0))],
            ["Unique Services", str(summary.get("unique_services", 0))]
        ]
        
        # Add top ports
        top_ports = summary.get("top_ports", [])
        if top_ports:
            table_data.append(["", ""])
            table_data.append(["Top Ports", ", ".join(map(str, top_ports[:5]))])
        
        # Add top services
        top_services = summary.get("top_services", [])
        if top_services:
            table_data.append(["Top Services", ", ".join(top_services[:5])])
        
        return format_table(table_data, title="ZoomEye Scan Results")
    
    async def save_results(self, results: Dict[str, Any], domain: str) -> None:
        """
        Save ZoomEye scan results to files
        
        Args:
            results: Scan results to save
            domain: Domain that was scanned
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON results
        json_filename = f"data/zoomeye_scan_{domain}_{timestamp}.json"
        save_json(results, json_filename)
        
        # Save formatted text results
        txt_filename = f"data/zoomeye_scan_{domain}_{timestamp}.txt"
        txt_content = f"ZoomEye Scan Results for {domain}\n"
        txt_content += f"Timestamp: {results.get('timestamp', '')}\n\n"
        
        if "summary" in results:
            summary = results["summary"]
            txt_content += f"Summary:\n"
            txt_content += f"- Total Hosts: {summary.get('total_hosts', 0)}\n"
            txt_content += f"- Total Web Apps: {summary.get('total_web_apps', 0)}\n"
            txt_content += f"- Unique Ports: {summary.get('unique_ports', 0)}\n"
            txt_content += f"- Unique Services: {summary.get('unique_services', 0)}\n\n"
        
        if "hosts" in results and results["hosts"]:
            txt_content += "Hosts Found:\n"
            for host in results["hosts"][:20]:  # Limit to first 20
                txt_content += f"- {host.get('ip', '')}:{host.get('port', '')} ({host.get('service', '')})\n"
        
        if "web_apps" in results and results["web_apps"]:
            txt_content += "\nWeb Applications:\n"
            for app in results["web_apps"][:10]:  # Limit to first 10
                txt_content += f"- {app.get('ip', '')} - {app.get('title', '')}\n"
        
        save_txt(txt_content, txt_filename)
        
        logger.info(f"ZoomEye results saved to {json_filename} and {txt_filename}")
