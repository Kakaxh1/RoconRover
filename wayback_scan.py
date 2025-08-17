"""
Wayback Machine Scanner Module for ReconRover
Discovers archived endpoints and historical data using Wayback Machine API
"""

import asyncio
import aiohttp
import json
import logging
import re
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
from urllib.parse import urljoin, urlparse

from api_loader import get_rate_limit
from utils import RateLimiter, save_json, save_txt, format_table, deduplicate_list

logger = logging.getLogger(__name__)

class WaybackScanner:
    """Wayback Machine API integration for archived endpoint discovery"""
    
    def __init__(self):
        """Initialize Wayback Machine scanner"""
        self.rate_limit = get_rate_limit('wayback_machine')
        self.rate_limiter = RateLimiter(self.rate_limit)  # calls per second
        self.base_url = "https://web.archive.org"
        self.cdx_url = "https://web.archive.org/cdx/search/cdx"
        self.headers = {
            "User-Agent": "ReconRover/1.0"
        }
    
    async def search_snapshots(self, domain: str, match_type: str = "domain", 
                             output: str = "json", collapse: str = "urlkey") -> Dict[str, Any]:
        """
        Search for archived snapshots using Wayback Machine CDX API
        
        Args:
            domain: Domain to search for
            match_type: Type of matching (domain, exact, prefix, host)
            output: Output format (json, xml, text)
            collapse: Collapse parameter for deduplication
            
        Returns:
            Dictionary containing search results
        """
        await self.rate_limiter.wait()
        
        params = {
            "url": f"*.{domain}/*",
            "output": output,
            "collapse": collapse,
            "fl": "original,timestamp,statuscode,mimetype,length"
        }
        
        try:
            timeout = aiohttp.ClientTimeout(total=15)  # 15 second timeout
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.cdx_url, headers=self.headers, params=params) as response:
                    if response.status == 200:
                        text = await response.text()
                        if output == "json":
                            try:
                                data = json.loads(text)
                                logger.info(f"Wayback Machine search successful for domain: {domain}")
                                return {"snapshots": data}
                            except json.JSONDecodeError as e:
                                logger.error(f"JSON decode error: {e}")
                                return {"error": f"Invalid JSON response: {e}"}
                        else:
                            # Parse text format
                            lines = text.strip().split('\n')
                            snapshots = []
                            for line in lines:
                                if line and not line.startswith('original'):
                                    parts = line.split()
                                    if len(parts) >= 4:
                                        snapshots.append({
                                            "original": parts[0],
                                            "timestamp": parts[1],
                                            "statuscode": parts[2],
                                            "mimetype": parts[3],
                                            "length": parts[4] if len(parts) > 4 else ""
                                        })
                            return {"snapshots": snapshots}
                    else:
                        logger.error(f"Wayback Machine API error: {response.status} - {await response.text()}")
                        return {"error": f"API error: {response.status}"}
        except asyncio.TimeoutError:
            logger.error(f"Wayback Machine API request timed out for domain: {domain}")
            return {"error": "API request timed out"}
        except Exception as e:
            logger.error(f"Error in Wayback Machine search: {e}")
            return {"error": str(e)}
    
    async def get_snapshot_info(self, url: str, timestamp: str = None) -> Dict[str, Any]:
        """
        Get information about a specific snapshot
        
        Args:
            url: URL to get snapshot info for
            timestamp: Specific timestamp (optional)
            
        Returns:
            Dictionary containing snapshot information
        """
        await self.rate_limiter.wait()
        
        if timestamp:
            snapshot_url = f"{self.base_url}/web/{timestamp}/{url}"
        else:
            snapshot_url = f"{self.base_url}/web/*/{url}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(snapshot_url, headers=self.headers) as response:
                    if response.status == 200:
                        # Extract information from the response
                        content = await response.text()
                        
                        # Look for snapshot metadata
                        info = {
                            "url": url,
                            "snapshot_url": snapshot_url,
                            "status_code": response.status,
                            "content_length": len(content),
                            "has_content": bool(content.strip())
                        }
                        
                        # Try to extract more metadata from the page
                        if "Wayback Machine" in content:
                            info["is_archived"] = True
                            
                            # Extract available timestamps
                            timestamp_pattern = r'(\d{14})'
                            timestamps = re.findall(timestamp_pattern, content)
                            if timestamps:
                                info["available_timestamps"] = timestamps[:10]  # Limit to 10
                        
                        return info
                    else:
                        return {"error": f"HTTP {response.status}"}
        except Exception as e:
            logger.error(f"Error getting snapshot info: {e}")
            return {"error": str(e)}
    
    async def scan_domain(self, domain: str) -> Dict[str, Any]:
        """
        Scan a domain for archived endpoints and historical data
        
        Args:
            domain: Domain to scan
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Starting Wayback Machine scan for domain: {domain}")
        
        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "snapshots": [],
            "endpoints": set(),
            "parameters": set(),
            "file_extensions": set(),
            "status_codes": {},
            "mime_types": {},
            "summary": {}
        }
        
        # Search for snapshots
        snapshot_results = await self.search_snapshots(domain)
        
        if "error" in snapshot_results:
            logger.warning(f"Wayback Machine search failed: {snapshot_results['error']}")
            # Return a minimal result with error information
            results["error"] = snapshot_results["error"]
            results["summary"] = {
                "total_snapshots": 0,
                "unique_endpoints": 0,
                "unique_parameters": 0,
                "unique_file_extensions": 0,
                "top_endpoints": [],
                "top_parameters": [],
                "top_file_extensions": [],
                "status_code_distribution": {},
                "mime_type_distribution": {}
            }
            return results
        
        if "snapshots" in snapshot_results:
            for snapshot in snapshot_results["snapshots"]:
                if isinstance(snapshot, list) and len(snapshot) >= 4:
                    # Handle JSON array format
                    snapshot_data = {
                        "original": snapshot[0],
                        "timestamp": snapshot[1],
                        "statuscode": snapshot[2],
                        "mimetype": snapshot[3],
                        "length": snapshot[4] if len(snapshot) > 4 else ""
                    }
                elif isinstance(snapshot, dict):
                    # Handle dictionary format
                    snapshot_data = snapshot
                else:
                    continue
                
                results["snapshots"].append(snapshot_data)
                
                # Extract endpoints
                original_url = snapshot_data.get("original", "")
                if original_url:
                    parsed = urlparse(original_url)
                    path = parsed.path
                    
                    # Extract path endpoints
                    if path and path != "/":
                        results["endpoints"].add(path)
                        
                        # Extract parameters
                        if "?" in original_url:
                            query = parsed.query
                            if query:
                                params = query.split("&")
                                for param in params:
                                    if "=" in param:
                                        param_name = param.split("=")[0]
                                        results["parameters"].add(param_name)
                        
                        # Extract file extensions
                        if "." in path:
                            ext = path.split(".")[-1].lower()
                            if len(ext) <= 5:  # Reasonable extension length
                                results["file_extensions"].add(ext)
                
                # Count status codes
                status = snapshot_data.get("statuscode", "")
                if status:
                    results["status_codes"][status] = results["status_codes"].get(status, 0) + 1
                
                # Count MIME types
                mime_type = snapshot_data.get("mimetype", "")
                if mime_type:
                    results["mime_types"][mime_type] = results["mime_types"].get(mime_type, 0) + 1
        
        # Convert sets to lists for JSON serialization
        results["endpoints"] = list(results["endpoints"])
        results["parameters"] = list(results["parameters"])
        results["file_extensions"] = list(results["file_extensions"])
        
        # Generate summary
        results["summary"] = {
            "total_snapshots": len(results["snapshots"]),
            "unique_endpoints": len(results["endpoints"]),
            "unique_parameters": len(results["parameters"]),
            "unique_file_extensions": len(results["file_extensions"]),
            "top_endpoints": sorted(results["endpoints"])[:20],
            "top_parameters": list(results["parameters"])[:10],
            "top_file_extensions": list(results["file_extensions"])[:10],
            "status_code_distribution": results["status_codes"],
            "mime_type_distribution": results["mime_types"]
        }
        
        logger.info(f"Wayback Machine scan completed for {domain}: {results['summary']['total_snapshots']} snapshots found")
        return results
    
    async def get_interesting_endpoints(self, domain: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get interesting endpoints from archived data
        
        Args:
            domain: Domain to search
            limit: Maximum number of endpoints to return
            
        Returns:
            List of interesting endpoints
        """
        results = await self.scan_domain(domain)
        
        interesting_endpoints = []
        interesting_patterns = [
            r'admin', r'login', r'wp-admin', r'phpmyadmin', r'config', r'backup',
            r'api', r'v1', r'v2', r'beta', r'test', r'dev', r'staging',
            r'\.php$', r'\.asp$', r'\.jsp$', r'\.aspx$', r'\.cgi$',
            r'\.bak$', r'\.old$', r'\.tmp$', r'\.log$', r'\.sql$',
            r'\.git', r'\.svn', r'\.env', r'\.htaccess', r'robots\.txt'
        ]
        
        for endpoint in results.get("endpoints", []):
            score = 0
            reasons = []
            
            # Check for interesting patterns
            for pattern in interesting_patterns:
                if re.search(pattern, endpoint, re.IGNORECASE):
                    score += 1
                    reasons.append(f"Matches pattern: {pattern}")
            
            # Check for parameters
            if "?" in endpoint:
                score += 2
                reasons.append("Contains parameters")
            
            # Check for file extensions
            if "." in endpoint.split("/")[-1]:
                score += 1
                reasons.append("Has file extension")
            
            # Check for long paths (potential sensitive directories)
            if len(endpoint.split("/")) > 3:
                score += 1
                reasons.append("Deep path structure")
            
            if score > 0:
                interesting_endpoints.append({
                    "endpoint": endpoint,
                    "score": score,
                    "reasons": reasons
                })
        
        # Sort by score and limit results
        interesting_endpoints.sort(key=lambda x: x["score"], reverse=True)
        return interesting_endpoints[:limit]
    
    async def check_endpoint_accessibility(self, domain: str, endpoints: List[str]) -> List[Dict[str, Any]]:
        """
        Check if discovered endpoints are still accessible
        
        Args:
            domain: Domain to check
            endpoints: List of endpoints to check
            
        Returns:
            List of accessibility results
        """
        logger.info(f"Checking accessibility of {len(endpoints)} endpoints for {domain}")
        
        results = []
        
        # Check endpoints in batches
        batch_size = 10
        for i in range(0, len(endpoints), batch_size):
            batch = endpoints[i:i + batch_size]
            tasks = []
            
            for endpoint in batch:
                url = f"https://{domain}{endpoint}"
                tasks.append(self._check_url_accessibility(url))
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for endpoint, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    results.append({
                        "endpoint": endpoint,
                        "accessible": False,
                        "error": str(result)
                    })
                else:
                    results.append({
                        "endpoint": endpoint,
                        "accessible": result["accessible"],
                        "status_code": result.get("status_code"),
                        "content_length": result.get("content_length", 0)
                    })
        
        return results
    
    async def _check_url_accessibility(self, url: str) -> Dict[str, Any]:
        """
        Check if a URL is accessible
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with accessibility information
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers, timeout=10) as response:
                    return {
                        "accessible": True,
                        "status_code": response.status,
                        "content_length": len(await response.text())
                    }
        except Exception as e:
            return {
                "accessible": False,
                "error": str(e)
            }
    
    def format_wayback_results(self, results: Dict[str, Any]) -> str:
        """
        Format Wayback Machine results as a table
        
        Args:
            results: Wayback Machine scan results
            
        Returns:
            Formatted table string
        """
        if "error" in results:
            return f"Error: {results['error']}"
        
        summary = results.get("summary", {})
        
        table_data = [
            ["Metric", "Value"],
            ["Total Snapshots", str(summary.get("total_snapshots", 0))],
            ["Unique Endpoints", str(summary.get("unique_endpoints", 0))],
            ["Unique Parameters", str(summary.get("unique_parameters", 0))],
            ["File Extensions", str(summary.get("unique_file_extensions", 0))]
        ]
        
        # Add top endpoints
        top_endpoints = summary.get("top_endpoints", [])
        if top_endpoints:
            table_data.append(["", ""])
            table_data.append(["Top Endpoints", ", ".join(top_endpoints[:5])])
        
        # Add top parameters
        top_parameters = summary.get("top_parameters", [])
        if top_parameters:
            table_data.append(["Top Parameters", ", ".join(top_parameters[:5])])
        
        return format_table(table_data, title="Wayback Machine Scan Results")
    
    async def save_results(self, results: Dict[str, Any], domain: str) -> None:
        """
        Save Wayback Machine scan results to files
        
        Args:
            results: Scan results to save
            domain: Domain that was scanned
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON results (save_json prepends data/)
        json_filename = f"wayback_scan_{domain}_{timestamp}.json"
        save_json(results, json_filename)
        
        # Save formatted text results (save_txt prepends data/)
        txt_filename = f"wayback_scan_{domain}_{timestamp}.txt"
        txt_content = f"Wayback Machine Scan Results for {domain}\n"
        txt_content += f"Timestamp: {results.get('timestamp', '')}\n\n"
        
        if "summary" in results:
            summary = results["summary"]
            txt_content += f"Summary:\n"
            txt_content += f"- Total Snapshots: {summary.get('total_snapshots', 0)}\n"
            txt_content += f"- Unique Endpoints: {summary.get('unique_endpoints', 0)}\n"
            txt_content += f"- Unique Parameters: {summary.get('unique_parameters', 0)}\n"
            txt_content += f"- File Extensions: {summary.get('unique_file_extensions', 0)}\n\n"
        
        if "endpoints" in results and results["endpoints"]:
            txt_content += "Discovered Endpoints:\n"
            for endpoint in results["endpoints"][:50]:  # Limit to first 50
                txt_content += f"- {endpoint}\n"
        
        if "parameters" in results and results["parameters"]:
            txt_content += "\nDiscovered Parameters:\n"
            for param in results["parameters"][:20]:  # Limit to first 20
                txt_content += f"- {param}\n"
        
        save_txt([txt_content], txt_filename)
        
        logger.info(f"Wayback Machine results saved to {json_filename} and {txt_filename}")

async def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Scan domain using Wayback Machine")
    parser.add_argument("--domain", required=True, help="Domain to scan")
    parser.add_argument("--save_json", action="store_true", help="Save results to JSON")
    parser.add_argument("--save_txt", action="store_true", help="Save results to TXT")
    parser.add_argument("--match_type", default="domain", 
                       choices=["domain", "exact", "prefix", "host"],
                       help="Type of URL matching")
    parser.add_argument("--output", default="json", 
                       choices=["json", "xml", "text"],
                       help="Output format for CDX API")
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = WaybackScanner()
    
    print(f"🔍 Scanning {args.domain} using Wayback Machine...")
    
    # Perform scan
    results = await scanner.scan_domain(args.domain)
    
    if "error" in results:
        print(f"❌ Error: {results['error']}")
        return 1
    
    # Display results
    print(f"✅ Scan completed successfully!")
    print(f"📊 Found {results.get('summary', {}).get('total_snapshots', 0)} snapshots")
    print(f"🔗 Discovered {results.get('summary', {}).get('unique_endpoints', 0)} unique endpoints")
    
    # Save results if requested
    if args.save_json or args.save_txt:
        await scanner.save_results(results, args.domain)
        print("💾 Results saved to files")
    
    # Display formatted results
    formatted_results = scanner.format_wayback_results(results)
    print("\n" + formatted_results)
    
    return 0

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)