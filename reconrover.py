#!/usr/bin/env python3
"""
ReconRover - Master CLI Module
One-command wrapper to run all reconnaissance modules sequentially
"""

import argparse
import asyncio
import subprocess
import sys
import os
import signal
import time
from typing import List, Dict, Any, Optional
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.panel import Panel
from api_loader import get_api_loader, get_api_key
from utils import (
    logger, save_json, save_txt, load_json, load_txt
)
from logo import get_logo, get_mini_logo, get_banner

class ReconRover:
    """Master reconnaissance orchestrator"""
    
    def __init__(self, module_timeout: int = 300, overall_timeout: int = 1800):
        self.console = Console()
        self.api_loader = get_api_loader()
        self.results = {}
        self.interrupted = False
        self.module_timeout = module_timeout  # 5 minutes per module
        self.overall_timeout = overall_timeout  # 30 minutes total
        self.start_time = None
        
        # Define module execution order
        self.modules = [
            'domain_resolver',
            'subdomain_enum',
            'dns_resolve',
            'shodan_scan',
            'zoomeye_scan',
            'censys_scan',
            'wayback_scan',
            'techstack_enum',
            'email_breach_enum',
            'ai_report'
        ]
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully"""
        if not self.interrupted:
            self.interrupted = True
            self.console.print("\n\n⚠️  Interrupt received! Gracefully shutting down...", style="yellow")
            self.console.print("💾 Saving current progress...", style="cyan")
            time.sleep(1)  # Give time for cleanup
    
    def _check_interruption(self) -> bool:
        """Check if the process has been interrupted"""
        return self.interrupted
    
    def _check_overall_timeout(self) -> bool:
        """Check if overall timeout has been exceeded"""
        if self.start_time and time.time() - self.start_time > self.overall_timeout:
            self.console.print(f"\n⏰ Overall timeout ({self.overall_timeout}s) exceeded!", style="yellow")
            return True
        return False
    
    def print_banner(self):
        """Print ReconRover banner"""
        logo = get_logo()
        self.console.print(logo, style="bold cyan")
    
    def check_dependencies(self) -> bool:
        """Check if all required dependencies are installed"""
        self.console.print("🔍 Checking dependencies...", style="yellow")
        
        required_modules = [
            'requests', 'bs4', 'tldextract', 'dns',
            'shodan', 'censys', 'openai', 'rich', 'aiohttp'
        ]
        
        missing_modules = []
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
        
        if missing_modules:
            self.console.print(f"❌ Missing dependencies: {', '.join(missing_modules)}", style="red")
            self.console.print("Run: pip install -r requirements.txt", style="yellow")
            return False
        
        self.console.print("✅ All dependencies found", style="green")
        return True
    
    def check_api_keys(self, modules_to_run: List[str]) -> Dict[str, bool]:
        """Check and validate required API keys"""
        validation_results = {}
        
        try:
            # Validate all configured services
            validation_results = self.api_loader.validate_config()
            
            # Check specific modules
            for module in modules_to_run:
                if module == 'shodan_scan' and not validation_results.get('shodan', False):
                    self.console.print("⚠️  Shodan API key not configured", style="yellow")
                elif module == 'censys_scan' and not validation_results.get('censys', False):
                    self.console.print("⚠️  Censys API credentials not configured", style="yellow")
                elif module == 'zoomeye_scan' and not validation_results.get('zoomeye', False):
                    self.console.print("⚠️  ZoomEye API key not configured", style="yellow")
                elif module == 'techstack_enum' and not validation_results.get('builtwith', False):
                    self.console.print("⚠️  BuiltWith API key not configured", style="yellow")
                elif module == 'email_breach_enum' and not validation_results.get('hunter', False):
                    self.console.print("⚠️  Hunter.io API key not configured", style="yellow")
                elif module == 'ai_report' and not validation_results.get('openai', False):
                    self.console.print("⚠️  OpenAI API key not configured", style="yellow")
                    
        except Exception as e:
            self.console.print(f"❌ Error checking API keys: {e}", style="red")
            return {}
        
        return validation_results
    
    async def display_api_credits(self):
        """Display API credits and usage information"""
        self.console.print("\n💰 API Credits & Usage Information", style="bold cyan")
        self.console.print("=" * 50)
        
        try:
            credits = await self.api_loader.check_api_credits()
            
            if not credits:
                self.console.print("❌ No API keys configured or no credits available", style="red")
                return
            
            for service, credit_info in credits.items():
                status_style = "green" if credit_info.get('status') == 'active' else "red"
                self.console.print(f"\n🔑 {service.upper()}", style="bold")
                
                if credit_info.get('status') == 'active':
                    # Display specific credit information for each service
                    if service == 'shodan':
                        self.console.print(f"  ✅ Status: {credit_info.get('status', 'Unknown')}")
                        self.console.print(f"  💳 Credits: {credit_info.get('credits', 'Unknown')}")
                        self.console.print(f"  🔍 Scan Credits: {credit_info.get('scan_credits', 'Unknown')}")
                        self.console.print(f"  🔎 Query Credits: {credit_info.get('query_credits', 'Unknown')}")
                        self.console.print(f"  📊 Monitor Credits: {credit_info.get('monitor_credits', 'Unknown')}")
                    
                    elif service == 'censys':
                        self.console.print(f"  ✅ Status: {credit_info.get('status', 'Unknown')}")
                        quota = credit_info.get('quota', {})
                        if quota:
                            self.console.print(f"  📊 Queries Used: {quota.get('used', 'Unknown')}")
                            self.console.print(f"  📈 Queries Allowed: {quota.get('allowance', 'Unknown')}")
                            self.console.print(f"  🔄 Reset Date: {quota.get('resets_at', 'Unknown')}")
                    
                    elif service == 'hunter':
                        self.console.print(f"  ✅ Status: {credit_info.get('status', 'Unknown')}")
                        self.console.print(f"  📧 Requests Used: {credit_info.get('requests_used', 'Unknown')}")
                        self.console.print(f"  📊 Requests Limit: {credit_info.get('requests_limit', 'Unknown')}")
                        self.console.print(f"  💼 Plan: {credit_info.get('plan', 'Unknown')}")
                    
                    elif service == 'openai':
                        self.console.print(f"  ✅ Status: {credit_info.get('status', 'Unknown')}")
                        self.console.print(f"  🤖 Message: {credit_info.get('message', 'API key is valid')}")
                    
                    elif service == 'zoomeye':
                        self.console.print(f"  ✅ Status: {credit_info.get('status', 'Unknown')}")
                        self.console.print(f"  👁️ Quota: {credit_info.get('quota', 'Unknown')}")
                        self.console.print(f"  🤖 Message: {credit_info.get('message', 'API key is valid')}")
                    
                    else:
                        self.console.print(f"  ✅ Status: {credit_info.get('status', 'Unknown')}")
                        self.console.print(f"  💬 Message: {credit_info.get('message', 'API key is valid')}")
                
                else:
                    self.console.print(f"  ❌ Status: {credit_info.get('status', 'Unknown')}")
                    self.console.print(f"  ⚠️ Error: {credit_info.get('message', 'Unknown error')}")
            
            self.console.print(f"\n💡 Tips:", style="bold yellow")
            self.console.print("  • Monitor your API usage to avoid hitting limits")
            self.console.print("  • Some services offer free tiers with limited requests")
            self.console.print("  • Consider upgrading plans for higher limits")
            self.console.print("  • Use --show_credits anytime to check current status")
            
        except Exception as e:
            self.console.print(f"❌ Error checking API credits: {e}", style="red")
    
    async def run_module(self, module_name: str, args: List[str]) -> bool:
        """Run a single module with timeout and detailed error reporting"""
        try:
            # Check for interruption
            if self.interrupted:
                self.console.print(f"⏸️  Skipping {module_name} due to interruption", style="yellow")
                return False
            
            # Check overall timeout
            if self._check_overall_timeout():
                return False
            
            # Check if module file exists
            module_file = Path(f"{module_name}.py")
            if not module_file.exists():
                self.console.print(f"❌ {module_name} failed: Module file {module_file} not found", style="red")
                return False
            
            # Build command
            cmd = [sys.executable, f"{module_name}.py"] + args
            
            # Run module with timeout
            try:
                process = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    ),
                    timeout=self.module_timeout
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.module_timeout
                )
                
            except asyncio.TimeoutError:
                self.console.print(f"⏰ {module_name} timed out after {self.module_timeout}s", style="yellow")
                return False
            
            # Check for interruption after module completion
            if self.interrupted:
                self.console.print(f"⏸️  {module_name} completed but interruption detected", style="yellow")
                return False
            
            if process.returncode == 0:
                self.console.print(f"✅ {module_name} completed successfully", style="green")
                return True
            else:
                # Enhanced error reporting
                error_msg = stderr.decode().strip() if stderr else "Unknown error"
                self.console.print(f"❌ {module_name} failed (exit code: {process.returncode})", style="red")
                
                # Provide specific error analysis
                if "ModuleNotFoundError" in error_msg:
                    self.console.print(f"   💡 Reason: Missing Python module - check requirements.txt", style="yellow")
                elif "ImportError" in error_msg:
                    self.console.print(f"   💡 Reason: Import error - check dependencies", style="yellow")
                elif "FileNotFoundError" in error_msg:
                    self.console.print(f"   💡 Reason: Required input file not found", style="yellow")
                elif "KeyError" in error_msg:
                    self.console.print(f"   💡 Reason: Missing API key or configuration", style="yellow")
                elif "HTTP" in error_msg and "401" in error_msg:
                    self.console.print(f"   💡 Reason: Invalid API key", style="yellow")
                elif "HTTP" in error_msg and "429" in error_msg:
                    self.console.print(f"   💡 Reason: API rate limit exceeded", style="yellow")
                elif "timeout" in error_msg.lower():
                    self.console.print(f"   💡 Reason: Network timeout", style="yellow")
                else:
                    self.console.print(f"   💡 Reason: {error_msg[:100]}...", style="yellow")
                
                return False
                
        except Exception as e:
            if self.interrupted:
                self.console.print(f"⏸️  {module_name} interrupted", style="yellow")
                return False
            else:
                self.console.print(f"❌ Error running {module_name}: {e}", style="red")
                return False
    
    async def run_domain_resolver(self, company_name: str, save_json: bool, save_txt: bool) -> bool:
        """Run domain resolver module"""
        args = ["--company_name", company_name]
        if save_json:
            args.append("--save_json")
        if save_txt:
            args.append("--save_txt")
        
        return await self.run_module("domain_resolver", args)
    
    async def run_subdomain_enum(self, domain: str, save_json: bool, save_txt: bool, api_keys: Dict[str, str]) -> bool:
        """Run subdomain enumeration module"""
        args = ["--domain", domain, "--save_json", "--save_txt"]
        
        # Add API keys if available
        if api_keys.get('CENSYS_API_ID') and api_keys.get('CENSYS_API_SECRET'):
            args.extend(["--censys_id", api_keys['CENSYS_API_ID'], "--censys_secret", api_keys['CENSYS_API_SECRET']])
        
        return await self.run_module("subdomain_enum", args)
    
    async def run_dns_resolve(self, save_json: bool, save_txt: bool) -> bool:
        """Run DNS resolution module"""
        args = ["--subdomains_file", "subdomains.txt", "--save_json", "--save_txt"]
        return await self.run_module("dns_resolve", args)
    
    async def run_shodan_scan(self, save_json: bool, save_txt: bool, api_keys: Dict[str, str]) -> bool:
        """Run Shodan scanning module"""
        args = ["--save_json", "--save_txt"]
        
        if api_keys.get('SHODAN_API_KEY'):
            args.extend(["--api_key", api_keys['SHODAN_API_KEY']])
        
        return await self.run_module("shodan_scan", args)
    
    async def run_censys_scan(self, domain: str, save_json: bool, api_keys: Dict[str, str]) -> bool:
        """Run Censys scanning module"""
        args = ["--domain", domain, "--save_json"]
        
        if api_keys.get('CENSYS_API_ID') and api_keys.get('CENSYS_API_SECRET'):
            args.extend(["--api_id", api_keys['CENSYS_API_ID'], "--api_secret", api_keys['CENSYS_API_SECRET']])
        
        return await self.run_module("censys_scan", args)
    
    async def run_zoomeye_scan(self, domain: str, save_json: bool, save_txt: bool) -> bool:
        """Run ZoomEye scanning module"""
        args = ["--domain", domain]
        
        if save_json:
            args.append("--save_json")
        if save_txt:
            args.append("--save_txt")
        
        return await self.run_module("zoomeye_scan", args)
    
    async def run_wayback_scan(self, domain: str, save_json: bool, save_txt: bool) -> bool:
        """Run Wayback Machine scanning module"""
        args = ["--domain", domain]
        
        if save_json:
            args.append("--save_json")
        if save_txt:
            args.append("--save_txt")
        
        return await self.run_module("wayback_scan", args)
    
    async def run_techstack_enum(self, save_json: bool, save_txt: bool) -> bool:
        """Run technology stack enumeration module"""
        args = ["--save_json", "--save_txt"]
        return await self.run_module("techstack_enum", args)
    
    async def run_email_breach_enum(self, domain: str, save_json: bool, save_txt: bool, api_keys: Dict[str, str]) -> bool:
        """Run email and breach enumeration module"""
        args = ["--domain", domain, "--save_json", "--save_txt"]
        
        if api_keys.get('HUNTER_API_KEY'):
            args.extend(["--hunter_api", api_keys['HUNTER_API_KEY']])
        
        if api_keys.get('HIBP_API_KEY'):
            args.extend(["--hibp_api", api_keys['HIBP_API_KEY']])
        
        return await self.run_module("email_breach_enum", args)
    
    async def run_ai_report(self, save_md: bool, save_txt: bool, save_pdf: bool, api_keys: Dict[str, str]) -> bool:
        """Run AI report generation module"""
        args = []
        
        if save_md:
            args.append("--save_md")
        if save_txt:
            args.append("--save_txt")
        if save_pdf:
            args.append("--save_pdf")
        
        # Check for OpenRouter configuration first
        api_loader = get_api_loader()
        openrouter_config = api_loader.get_service_config('openrouter')
        openai_config = api_loader.get_service_config('openai')
        
        if openrouter_config.get('key'):
            # Use OpenRouter
            args.extend(["--provider", "openrouter"])
            args.extend(["--api_key", openrouter_config['key']])
            if openrouter_config.get('base_url'):
                args.extend(["--base_url", openrouter_config['base_url']])
            if openrouter_config.get('model'):
                args.extend(["--ai_model", openrouter_config['model']])
        elif openai_config.get('key'):
            # Use OpenAI
            args.extend(["--provider", "openai"])
            args.extend(["--api_key", openai_config['key']])
            if openai_config.get('model'):
                args.extend(["--ai_model", openai_config['model']])
        
        return await self.run_module("ai_report", args)
    
    def create_summary_table(self, results: Dict[str, bool]) -> Table:
        """Create a summary table of module results"""
        table = Table(title="Reconnaissance Summary")
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Status", style="magenta")
        table.add_column("Description", style="green")
        table.add_column("Dependencies", style="yellow")
        
        module_descriptions = {
            'domain_resolver': 'Resolved company name to main domain',
            'subdomain_enum': 'Enumerated subdomains from multiple sources',
            'dns_resolve': 'Resolved DNS records for subdomains',
            'shodan_scan': 'Scanned IPs for open ports and services',
            'zoomeye_scan': 'Scanned IPs for ports and services using ZoomEye',
            'censys_scan': 'Analyzed certificates and services',
            'wayback_scan': 'Discovered archived endpoints and historical data',
            'techstack_enum': 'Detected technology stack',
            'email_breach_enum': 'Found emails and checked for breaches',
            'ai_report': 'Generated comprehensive report'
        }
        
        module_dependencies = {
            'domain_resolver': 'SerpAPI key',
            'subdomain_enum': 'SecurityTrails key',
            'dns_resolve': 'subdomains.json',
            'shodan_scan': 'Shodan key + dns.json',
            'zoomeye_scan': 'ZoomEye key',
            'censys_scan': 'Censys credentials',
            'wayback_scan': 'None (free)',
            'techstack_enum': 'BuiltWith key',
            'email_breach_enum': 'Hunter + HIBP keys',
            'ai_report': 'OpenAI key + other results'
        }
        
        for module in self.modules:
            status = "✅ Success" if results.get(module, False) else "❌ Failed"
            description = module_descriptions.get(module, "Unknown module")
            dependencies = module_dependencies.get(module, "Unknown")
            table.add_row(module, status, description, dependencies)
        
        return table
    
    def analyze_failures(self, results: Dict[str, bool]) -> None:
        """Analyze and display reasons for module failures"""
        failed_modules = [module for module, success in results.items() if not success]
        
        if not failed_modules:
            return
        
        self.console.print(f"\n🔍 Failure Analysis for {len(failed_modules)} failed modules:", style="bold yellow")
        
        # Check common issues
        api_loader = get_api_loader()
        validation_results = api_loader.validate_config()
        
        for module in failed_modules:
            self.console.print(f"\n❌ {module}:", style="bold red")
            
            # Check specific dependencies for each module
            if module == 'domain_resolver':
                if not validation_results.get('serpapi', False):
                    self.console.print("   💡 Missing: SerpAPI key in config/api_keys.yaml", style="yellow")
                else:
                    self.console.print("   💡 Check: SerpAPI key validity and rate limits", style="yellow")
            
            elif module == 'subdomain_enum':
                if not validation_results.get('securitytrails', False):
                    self.console.print("   💡 Missing: SecurityTrails key in config/api_keys.yaml", style="yellow")
                else:
                    self.console.print("   💡 Check: SecurityTrails key validity", style="yellow")
            
            elif module == 'dns_resolve':
                subdomain_file = Path('data/subdomains.json')
                if not subdomain_file.exists():
                    self.console.print("   💡 Missing: subdomains.json file (run subdomain_enum first)", style="yellow")
                else:
                    self.console.print("   💡 Check: subdomains.json file format and content", style="yellow")
            
            elif module == 'shodan_scan':
                if not validation_results.get('shodan', False):
                    self.console.print("   💡 Missing: Shodan API key in config/api_keys.yaml", style="yellow")
                else:
                    dns_file = Path('data/dns.json')
                    if not dns_file.exists():
                        self.console.print("   💡 Missing: dns.json file (run dns_resolve first)", style="yellow")
                    else:
                        self.console.print("   💡 Check: Shodan key validity and rate limits", style="yellow")
            
            elif module == 'zoomeye_scan':
                if not validation_results.get('zoomeye', False):
                    self.console.print("   💡 Missing: ZoomEye API key in config/api_keys.yaml", style="yellow")
                else:
                    self.console.print("   💡 Check: ZoomEye key validity and quota", style="yellow")
            
            elif module == 'censys_scan':
                if not validation_results.get('censys', False):
                    self.console.print("   💡 Missing: Censys API credentials in config/api_keys.yaml", style="yellow")
                else:
                    self.console.print("   💡 Check: Censys credentials validity and quota", style="yellow")
            
            elif module == 'wayback_scan':
                self.console.print("   💡 Check: Network connectivity and Wayback Machine availability", style="yellow")
            
            elif module == 'techstack_enum':
                if not validation_results.get('builtwith', False):
                    self.console.print("   💡 Missing: BuiltWith API key in config/api_keys.yaml", style="yellow")
                else:
                    self.console.print("   💡 Check: BuiltWith key validity", style="yellow")
            
            elif module == 'email_breach_enum':
                missing_keys = []
                if not validation_results.get('hunter', False):
                    missing_keys.append("Hunter.io")
                if not validation_results.get('haveibeenpwned', False):
                    missing_keys.append("HaveIBeenPwned")
                
                if missing_keys:
                    self.console.print(f"   💡 Missing: {', '.join(missing_keys)} API key(s) in config/api_keys.yaml", style="yellow")
                else:
                    self.console.print("   💡 Check: API key validity and rate limits", style="yellow")
            
            elif module == 'ai_report':
                if not validation_results.get('openai', False):
                    self.console.print("   💡 Missing: OpenAI API key in config/api_keys.yaml", style="yellow")
                else:
                    self.console.print("   💡 Check: OpenAI key validity and credit balance", style="yellow")
        
        # General troubleshooting tips
        self.console.print(f"\n💡 General Troubleshooting Tips:", style="bold cyan")
        self.console.print("   • Run 'python check_credits.py' to verify API keys", style="yellow")
        self.console.print("   • Check 'pip install -r requirements.txt' for dependencies", style="yellow")
        self.console.print("   • Ensure modules run in correct order (dependencies)", style="yellow")
        self.console.print("   • Check network connectivity for external APIs", style="yellow")
        self.console.print("   • Verify config/api_keys.yaml file exists and is valid", style="yellow")
    
    async def run_reconnaissance(self, company_name: Optional[str], domain: Optional[str],
                               modules: Optional[List[str]], save_all_json: bool,
                               save_all_txt: bool, save_report: bool) -> bool:
        """Run complete reconnaissance workflow"""
        
        self.print_banner()
        
        # Start timing
        self.start_time = time.time()
        
        # Check dependencies
        if not self.check_dependencies():
            return False
        
        # Determine target
        if not company_name and not domain:
            self.console.print("❌ Either --company_name or --domain must be provided", style="red")
            return False
        
        # Determine modules to run
        modules_to_run = modules if modules else self.modules
        
        # Check API credits and block modules with insufficient credits
        self.console.print("\n💰 Checking API credits...", style="yellow")
        api_loader = get_api_loader()
        credits_data = await api_loader.check_api_credits()
        
        # Map modules to their required services
        module_services = {
            'shodan_scan': 'shodan',
            'zoomeye_scan': 'zoomeye',
            'censys_scan': 'censys',
            'techstack_enum': 'builtwith',
            'email_breach_enum': ['hunter', 'haveibeenpwned'],
            'ai_report': ['openai', 'openrouter'],  # Can use either OpenAI or OpenRouter
            'domain_resolver': 'serpapi',
            'subdomain_enum': 'securitytrails',
            'dns_resolve': None,  # No API required
            'wayback_scan': None  # No API required
        }
        
        blocked_modules = []
        available_modules = []
        
        for module in modules_to_run:
            required_services = module_services.get(module, [])
            if required_services is None:
                # Module doesn't require API
                available_modules.append(module)
                continue
            
            if isinstance(required_services, str):
                required_services = [required_services]
            
            module_blocked = False
            block_reasons = []
            
            for service in required_services:
                status = api_loader.get_service_status(service, credits_data)
                if status['blocked']:
                    module_blocked = True
                    block_reasons.append(f"{service}: {status['reason']}")
            
            if module_blocked:
                blocked_modules.append((module, block_reasons))
            else:
                available_modules.append(module)
        
        # Display blocked modules
        if blocked_modules:
            self.console.print("\n🚫 Blocked Modules (Insufficient Credits/API Keys):", style="bold red")
            for module, reasons in blocked_modules:
                self.console.print(f"   ❌ {module}:", style="red")
                for reason in reasons:
                    self.console.print(f"      • {reason}", style="yellow")
        
        # Display available modules
        if available_modules:
            self.console.print(f"\n✅ Available Modules ({len(available_modules)}):", style="bold green")
            for module in available_modules:
                self.console.print(f"   • {module}", style="green")
        
        # If no modules are available, exit
        if not available_modules:
            self.console.print("\n❌ No modules available to run. Please check API keys and credits.", style="red")
            return False
        
        # Update modules list to only include available modules
        modules_to_run = available_modules
        
        # Check API keys
        api_keys = self.check_api_keys(modules_to_run)
        
        # Create data directory
        Path('data').mkdir(exist_ok=True)
        
        # Run modules
        results = {}
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                console=self.console
            ) as progress:
                
                # Domain resolution (only if company_name is provided, not domain)
                if 'domain_resolver' in modules_to_run and company_name and not domain and not self.interrupted and not self._check_overall_timeout():
                    task = progress.add_task("🔍 Resolving domain from company name...", total=100)
                    progress.update(task, advance=20, description="🔍 Searching for company domain...")
                    success = await self.run_domain_resolver(company_name, save_all_json, save_all_txt)
                    if not self.interrupted:
                        progress.update(task, advance=80, description="✅ Domain resolution completed")
                        results['domain_resolver'] = success
                    
                    # Load resolved domain
                    if not self.interrupted:
                        domain_data = load_json("domain.json")
                        if domain_data and not domain:
                            domain = domain_data.get('domain')
                
                # Subdomain enumeration
                if 'subdomain_enum' in modules_to_run and domain and not self.interrupted and not self._check_overall_timeout():
                    task = progress.add_task("🌐 Enumerating subdomains from multiple sources...", total=100)
                    progress.update(task, advance=15, description="🌐 Querying SecurityTrails...")
                    progress.update(task, advance=15, description="🌐 Querying crt.sh...")
                    progress.update(task, advance=15, description="🌐 Querying ThreatCrowd...")
                    progress.update(task, advance=15, description="🌐 Querying HackerTarget...")
                    progress.update(task, advance=20, description="🌐 Querying Censys...")
                    success = await self.run_subdomain_enum(domain, save_all_json, save_all_txt, api_keys)
                    progress.update(task, advance=20, description="✅ Subdomain enumeration completed")
                    results['subdomain_enum'] = success
                
                # DNS resolution
                if 'dns_resolve' in modules_to_run and not self.interrupted and not self._check_overall_timeout():
                    task = progress.add_task("🔗 Resolving DNS records for subdomains...", total=100)
                    progress.update(task, advance=30, description="🔗 Loading subdomain list...")
                    progress.update(task, advance=30, description="🔗 Resolving A records...")
                    progress.update(task, advance=20, description="🔗 Resolving CNAME records...")
                    success = await self.run_dns_resolve(save_all_json, save_all_txt)
                    progress.update(task, advance=20, description="✅ DNS resolution completed")
                    results['dns_resolve'] = success
                
                # Shodan scanning
                if 'shodan_scan' in modules_to_run and not self.interrupted and not self._check_overall_timeout():
                    task = progress.add_task("🔍 Scanning IPs with Shodan...", total=100)
                    progress.update(task, advance=25, description="🔍 Loading IP addresses...")
                    progress.update(task, advance=25, description="🔍 Querying Shodan API...")
                    progress.update(task, advance=25, description="🔍 Processing scan results...")
                    success = await self.run_shodan_scan(save_all_json, save_all_txt, api_keys)
                    progress.update(task, advance=25, description="✅ Shodan scanning completed")
                    results['shodan_scan'] = success
                
                # ZoomEye scanning
                if 'zoomeye_scan' in modules_to_run and domain and not self.interrupted and not self._check_overall_timeout():
                    task = progress.add_task("👁️ Scanning with ZoomEye...", total=100)
                    progress.update(task, advance=30, description="👁️ Querying ZoomEye hosts...")
                    progress.update(task, advance=30, description="👁️ Querying ZoomEye web apps...")
                    progress.update(task, advance=20, description="👁️ Processing port data...")
                    success = await self.run_zoomeye_scan(domain, save_all_json, save_all_txt)
                    progress.update(task, advance=20, description="✅ ZoomEye scanning completed")
                    results['zoomeye_scan'] = success
                
                # Censys scanning
                if 'censys_scan' in modules_to_run and domain and not self.interrupted and not self._check_overall_timeout():
                    task = progress.add_task("🔐 Scanning SSL certificates with Censys...", total=100)
                    progress.update(task, advance=30, description="🔐 Querying Censys certificates...")
                    progress.update(task, advance=30, description="🔐 Querying Censys hosts...")
                    progress.update(task, advance=20, description="🔐 Processing certificate data...")
                    success = await self.run_censys_scan(domain, save_all_json, api_keys)
                    progress.update(task, advance=20, description="✅ Censys scanning completed")
                    results['censys_scan'] = success
                
                # Wayback Machine scanning
                if 'wayback_scan' in modules_to_run and domain and not self.interrupted and not self._check_overall_timeout():
                    task = progress.add_task("📚 Scanning Wayback Machine archives...", total=100)
                    progress.update(task, advance=40, description="📚 Querying Wayback Machine CDX...")
                    progress.update(task, advance=30, description="📚 Processing archived snapshots...")
                    progress.update(task, advance=20, description="📚 Extracting endpoints and parameters...")
                    success = await self.run_wayback_scan(domain, save_all_json, save_all_txt)
                    progress.update(task, advance=10, description="✅ Wayback Machine scanning completed")
                    results['wayback_scan'] = success
                
                # Technology stack enumeration
                if 'techstack_enum' in modules_to_run and not self.interrupted and not self._check_overall_timeout():
                    task = progress.add_task("⚙️ Analyzing technology stack...", total=100)
                    progress.update(task, advance=30, description="⚙️ Querying BuiltWith API...")
                    progress.update(task, advance=30, description="⚙️ Analyzing web technologies...")
                    progress.update(task, advance=20, description="⚙️ Processing framework data...")
                    success = await self.run_techstack_enum(save_all_json, save_all_txt)
                    progress.update(task, advance=20, description="✅ Technology stack analysis completed")
                    results['techstack_enum'] = success
                
                # Email and breach enumeration
                if 'email_breach_enum' in modules_to_run and domain and not self.interrupted and not self._check_overall_timeout():
                    task = progress.add_task("📧 Enumerating emails and checking breaches...", total=100)
                    progress.update(task, advance=25, description="📧 Querying Hunter.io for emails...")
                    progress.update(task, advance=25, description="📧 Checking HaveIBeenPwned...")
                    progress.update(task, advance=25, description="📧 Searching Pastebin dorks...")
                    progress.update(task, advance=15, description="📧 Processing breach data...")
                    success = await self.run_email_breach_enum(domain, save_all_json, save_all_txt, api_keys)
                    progress.update(task, advance=10, description="✅ Email and breach enumeration completed")
                    results['email_breach_enum'] = success
                
                # AI report generation
                if 'ai_report' in modules_to_run and save_report and not self.interrupted and not self._check_overall_timeout():
                    task = progress.add_task("🤖 Generating AI-powered report...", total=100)
                    progress.update(task, advance=20, description="🤖 Loading reconnaissance data...")
                    progress.update(task, advance=30, description="🤖 Analyzing findings with OpenAI...")
                    progress.update(task, advance=30, description="🤖 Generating comprehensive report...")
                    progress.update(task, advance=10, description="🤖 Saving report files...")
                    success = await self.run_ai_report(True, save_all_txt, False, api_keys)
                    progress.update(task, advance=10, description="✅ AI report generation completed")
                    results['ai_report'] = success
        
        except KeyboardInterrupt:
            self.console.print("\n\n⚠️  Keyboard interrupt detected!", style="yellow")
            self.console.print("💾 Saving current progress...", style="cyan")
            self.interrupted = True
        except Exception as e:
            self.console.print(f"\n\n❌ Unexpected error: {e}", style="red")
            self.interrupted = True
        
        # Calculate elapsed time
        elapsed_time = time.time() - self.start_time if self.start_time else 0
        
        # Check if interrupted or timed out
        if self.interrupted:
            self.console.print("\n" + "="*60)
            self.console.print("RECONNAISSANCE INTERRUPTED", style="bold yellow")
            self.console.print("="*60)
        elif self._check_overall_timeout():
            self.console.print("\n" + "="*60)
            self.console.print("RECONNAISSANCE TIMED OUT", style="bold yellow")
            self.console.print("="*60)
        else:
            # Display summary
            self.console.print("\n" + "="*60)
            self.console.print("RECONNAISSANCE COMPLETE", style="bold green")
            self.console.print("="*60)
        
        # Show timing information
        self.console.print(f"⏱️  Total execution time: {elapsed_time:.1f}s", style="cyan")
        
        summary_table = self.create_summary_table(results)
        self.console.print(summary_table)
        
        # Analyze failures if any
        if any(not success for success in results.values()):
            self.analyze_failures(results)
        
        # Show output files
        self.console.print("\n📁 Output Files:", style="bold")
        data_dir = Path('data')
        if data_dir.exists():
            for file in data_dir.glob('*'):
                if file.is_file():
                    size = file.stat().st_size
                    self.console.print(f"  📄 {file.name} ({size} bytes)")
        
        # Success/failure summary
        successful_modules = sum(1 for success in results.values() if success)
        total_modules = len(results)
        
        if successful_modules == total_modules:
            self.console.print(f"\n🎉 All {total_modules} modules completed successfully!", style="bold green")
        else:
            self.console.print(f"\n⚠️  {successful_modules}/{total_modules} modules completed successfully", style="yellow")
        
        return successful_modules > 0

async def main():
    """Main function"""
    try:
        parser = argparse.ArgumentParser(
            description="ReconRover - Comprehensive Reconnaissance Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Run complete reconnaissance on a company
  python reconrover.py --company_name "Tesla Inc." --save_all_json --save_report

  # Run reconnaissance on a specific domain
  python reconrover.py --domain tesla.com --save_all_json --save_report

  # Run only specific modules
  python reconrover.py --domain tesla.com --modules domain_resolver,subdomain_enum,dns_resolve

  # Run with custom output options
  python reconrover.py --company_name "Tesla Inc." --save_all_json --save_all_txt --save_report

  # Run with custom timeouts
  python reconrover.py --domain tesla.com --module_timeout 600 --overall_timeout 3600

  # Check API credits and usage
  python reconrover.py --show_credits
            """
        )
        
        # Target specification
        target_group = parser.add_mutually_exclusive_group(required=False)
        target_group.add_argument("--company_name", help="Name of the company to research")
        target_group.add_argument("--domain", help="Target domain to analyze")
        
        # Output options
        parser.add_argument("--save_all_json", action="store_true", help="Save all results to JSON files")
        parser.add_argument("--save_all_txt", action="store_true", help="Save all results to TXT files")
        parser.add_argument("--save_report", action="store_true", help="Generate AI-powered report")
        
        # Module selection
        parser.add_argument("--modules", help="Comma-separated list of modules to run")
        
        # Timeout options
        parser.add_argument("--module_timeout", type=int, default=300, 
                          help="Timeout per module in seconds (default: 300)")
        parser.add_argument("--overall_timeout", type=int, default=1800, 
                          help="Overall timeout in seconds (default: 1800)")
        
        # API credit display
        parser.add_argument("--show_credits", action="store_true", 
                          help="Display API credits and usage information")
        
        args = parser.parse_args()
        
        # Parse modules
        modules = None
        if args.modules:
            modules = [m.strip() for m in args.modules.split(',')]
            valid_modules = [
                'domain_resolver', 'subdomain_enum', 'dns_resolve',
                'shodan_scan', 'zoomeye_scan', 'censys_scan', 'wayback_scan',
                'techstack_enum', 'email_breach_enum', 'ai_report'
            ]
            
            # Handle "all" modules
            if "all" in modules:
                modules = valid_modules
            else:
                for module in modules:
                    if module not in valid_modules:
                        print(f"❌ Invalid module: {module}")
                        print(f"Valid modules: {', '.join(valid_modules)}")
                        return 1
        
        # Initialize ReconRover with timeouts
        reconrover = ReconRover(
            module_timeout=args.module_timeout,
            overall_timeout=args.overall_timeout
        )
        
        # Show API credits if requested
        if args.show_credits:
            await reconrover.display_api_credits()
            return 0
        
        # Validate that target is provided when not showing credits
        if not args.company_name and not args.domain:
            parser.error("Either --company_name or --domain must be provided (unless using --show_credits)")
        
        # Run reconnaissance
        success = await reconrover.run_reconnaissance(
            company_name=args.company_name,
            domain=args.domain,
            modules=modules,
            save_all_json=args.save_all_json,
            save_all_txt=args.save_all_txt,
            save_report=args.save_report
        )
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n⚠️  Process interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
