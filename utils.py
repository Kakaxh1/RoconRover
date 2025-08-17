#!/usr/bin/env python3
"""
Utility functions for ReconRover modules
"""

import json
import logging
import time
import asyncio
import aiohttp
import requests
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from rich.console import Console
from rich.table import Table
import functools

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

console = Console()

class RateLimiter:
    """Rate limiter for API calls"""
    
    def __init__(self, calls_per_second: int = 1):
        self.calls_per_second = calls_per_second
        self.last_call = 0
    
    async def wait(self):
        """Wait if necessary to respect rate limit"""
        now = time.time()
        time_since_last = now - self.last_call
        min_interval = 1.0 / self.calls_per_second
        
        if time_since_last < min_interval:
            wait_time = min_interval - time_since_last
            await asyncio.sleep(wait_time)
        
        self.last_call = time.time()

def timeout_handler(timeout_seconds: int = 30):
    """Decorator to add timeout to async functions"""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout_seconds)
            except asyncio.TimeoutError:
                logger.warning(f"Function {func.__name__} timed out after {timeout_seconds} seconds")
                return None
        return wrapper
    return decorator

def save_json(data: Dict[str, Any], filename: str) -> bool:
    """Save data to JSON file"""
    try:
        Path('data').mkdir(exist_ok=True)
        filepath = Path('data') / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"Data saved to {filepath}")
        return True
    except Exception as e:
        logger.error(f"Error saving JSON file {filename}: {e}")
        return False

def save_txt(data: Union[str, List[str]], filename: str) -> bool:
    """Save data to TXT file"""
    try:
        Path('data').mkdir(exist_ok=True)
        filepath = Path('data') / filename
        
        if isinstance(data, list):
            content = '\n'.join(data)
        else:
            content = str(data)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"Data saved to {filepath}")
        return True
    except Exception as e:
        logger.error(f"Error saving TXT file {filename}: {e}")
        return False

def load_json(filename: str) -> Optional[Dict[str, Any]]:
    """Load data from JSON file"""
    try:
        filepath = Path('data') / filename
        if filepath.exists():
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        return None
    except Exception as e:
        logger.error(f"Error loading JSON file {filename}: {e}")
        return None

def load_txt(filename: str) -> Optional[List[str]]:
    """Load data from TXT file"""
    try:
        filepath = Path('data') / filename
        if filepath.exists():
            with open(filepath, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        return None
    except Exception as e:
        logger.error(f"Error loading TXT file {filename}: {e}")
        return None

@timeout_handler(30)
async def make_request(url: str, headers: Optional[Dict[str, str]] = None, 
                      timeout: int = 30, rate_limiter: Optional[RateLimiter] = None) -> Optional[str]:
    """Make HTTP request with timeout and optional rate limiting"""
    try:
        # Apply rate limiting if provided
        if rate_limiter:
            await rate_limiter.wait()
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    logger.warning(f"HTTP {response.status} for {url}")
                    return None
    except asyncio.TimeoutError:
        logger.warning(f"Request to {url} timed out after {timeout}s")
        return None
    except Exception as e:
        logger.error(f"Error making request to {url}: {e}")
        return None

def make_sync_request(url: str, headers: Optional[Dict[str, str]] = None, 
                     timeout: int = 30) -> Optional[Dict[str, Any]]:
    """Make synchronous HTTP request with timeout"""
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200:
            return response.json()
        else:
            logger.warning(f"HTTP {response.status_code} for {url}")
            return None
    except requests.Timeout:
        logger.warning(f"Request to {url} timed out after {timeout}s")
        return None
    except Exception as e:
        logger.error(f"Error making request to {url}: {e}")
        return None

def validate_domain(domain: str) -> bool:
    """Validate domain format"""
    import re
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain))

def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL"""
    import tldextract
    
    try:
        extracted = tldextract.extract(url)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return None
    except Exception:
        return None

def deduplicate_list(items: List[str]) -> List[str]:
    """Remove duplicates while preserving order"""
    seen = set()
    return [x for x in items if not (x in seen or seen.add(x))]

def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split list into chunks"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def format_table(data: List[Dict[str, Any]], headers: List[str]) -> str:
    """Format data as a table string"""
    if not data:
        return "No data available"
    
    # Calculate column widths
    col_widths = {header: len(header) for header in headers}
    
    for row in data:
        for header in headers:
            value = str(row.get(header, ''))
            col_widths[header] = max(col_widths[header], len(value))
    
    # Create header
    table = []
    header_row = " | ".join(header.ljust(col_widths[header]) for header in headers)
    table.append(header_row)
    table.append("-" * len(header_row))
    
    # Add data rows
    for row in data:
        row_str = " | ".join(str(row.get(header, '')).ljust(col_widths[header]) 
                           for header in headers)
        table.append(row_str)
    
    return "\n".join(table)

def create_table(title: str, columns: List[str]) -> Table:
    """Create a rich table"""
    table = Table(title=title)
    for col in columns:
        table.add_column(col, style="cyan", no_wrap=True)
    return table

def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"

def safe_filename(filename: str) -> str:
    """Convert string to safe filename"""
    import re
    # Remove or replace unsafe characters
    safe = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Limit length
    if len(safe) > 100:
        safe = safe[:100]
    return safe

def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    """Decorator to retry functions on failure"""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        logger.error(f"Function {func.__name__} failed after {max_retries} attempts: {e}")
                        raise
                    logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}")
                    await asyncio.sleep(delay * (2 ** attempt))  # Exponential backoff
            return None
        return wrapper
    return decorator
