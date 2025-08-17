#!/usr/bin/env python3
"""
API Credits Checker for ReconRover
Standalone script to check API credits and usage
"""

import asyncio
import sys
from api_loader import get_api_loader
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

async def check_all_credits():
    """Check and display all API credits"""
    
    # Print banner
    console.print(Panel.fit(
        "💰 ReconRover API Credits Checker",
        style="bold cyan"
    ))
    
    # Get API loader
    api_loader = get_api_loader()
    
    # Check if config exists
    if not api_loader.config_path:
        console.print("❌ No API configuration file found!", style="red")
        console.print("Please create config/api_keys.yaml with your API keys", style="yellow")
        return False
    
    console.print(f"📁 Config file: {api_loader.config_path}", style="cyan")
    
    # Check credits
    console.print("\n🔍 Checking API credits...", style="yellow")
    
    try:
        credits = await api_loader.check_api_credits()
        
        if not credits:
            console.print("❌ No API keys configured or no credits available", style="red")
            return False
        
        # Create summary table
        table = Table(title="API Credits Summary")
        table.add_column("Service", style="cyan", no_wrap=True)
        table.add_column("Status", style="magenta")
        table.add_column("Credits/Usage", style="green")
        table.add_column("Details", style="yellow")
        table.add_column("Modules Affected", style="red")
        
        # Map services to modules
        service_modules = {
            'shodan': 'shodan_scan',
            'zoomeye': 'zoomeye_scan',
            'censys': 'censys_scan',
            'builtwith': 'techstack_enum',
            'hunter': 'email_breach_enum',
            'haveibeenpwned': 'email_breach_enum',
            'openai': 'ai_report',
            'openrouter': 'ai_report',
            'serpapi': 'domain_resolver',
            'securitytrails': 'subdomain_enum'
        }
        
        total_services = len(credits)
        active_services = 0
        
        for service, credit_info in credits.items():
            status = credit_info.get('status', 'unknown')
            if status == 'active':
                active_services += 1
                status_emoji = "✅"
                status_style = "green"
            else:
                status_emoji = "❌"
                status_style = "red"
            
            # Format credits/usage info
            if service == 'shodan':
                credits_info = f"Credits: {credit_info.get('credits', 'Unknown')}"
                details = f"Scan: {credit_info.get('scan_credits', 'Unknown')}"
            elif service == 'censys':
                quota = credit_info.get('quota', {})
                credits_info = f"Used: {quota.get('used', 'Unknown')}"
                details = f"Limit: {quota.get('allowance', 'Unknown')}"
            elif service == 'hunter':
                credits_info = f"Used: {credit_info.get('requests_used', 'Unknown')}"
                details = f"Limit: {credit_info.get('requests_limit', 'Unknown')}"
            elif service == 'openai':
                credits_info = "Valid API Key"
                details = "Ready for AI reports"
            elif service == 'zoomeye':
                credits_info = f"Quota: {credit_info.get('quota', 'Unknown')}"
                details = "Ready for scanning"
            else:
                credits_info = "Valid API Key"
                details = "Ready to use"
            
            # Get affected modules
            affected_modules = service_modules.get(service, 'N/A')
            if status == 'active':
                affected_modules = f"✅ {affected_modules}"
            else:
                affected_modules = f"❌ {affected_modules}"
            
            table.add_row(
                f"{status_emoji} {service.upper()}",
                f"[{status_style}]{status}[/{status_style}]",
                credits_info,
                details,
                affected_modules
            )
        
        console.print(table)
        
        # Summary
        console.print(f"\n📊 Summary:", style="bold")
        console.print(f"  • Total services configured: {total_services}")
        console.print(f"  • Active services: {active_services}")
        console.print(f"  • Inactive services: {total_services - active_services}")
        
        if active_services > 0:
            console.print(f"\n🎉 {active_services} services are ready to use!", style="bold green")
        else:
            console.print(f"\n⚠️ No active services found. Check your API keys.", style="bold yellow")
        
        # Show module availability
        console.print(f"\n🔍 Module Availability Check:", style="bold cyan")
        
        # Check which modules would be blocked
        blocked_modules = []
        available_modules = []
        
        for service, credit_info in credits.items():
            module = service_modules.get(service)
            if module:
                if credit_info.get('status') == 'active':
                    if module not in available_modules:
                        available_modules.append(module)
                else:
                    if module not in blocked_modules:
                        blocked_modules.append(module)
        
        if available_modules:
            console.print(f"\n✅ Available Modules ({len(available_modules)}):", style="bold green")
            for module in available_modules:
                console.print(f"   • {module}", style="green")
        
        if blocked_modules:
            console.print(f"\n🚫 Blocked Modules ({len(blocked_modules)}):", style="bold red")
            for module in blocked_modules:
                console.print(f"   • {module}", style="red")
        
        # Show modules that don't require API keys
        no_api_modules = ['dns_resolve', 'wayback_scan']
        console.print(f"\n🔓 No-API Modules ({len(no_api_modules)}):", style="bold blue")
        for module in no_api_modules:
            console.print(f"   • {module}", style="blue")
        
        # Detailed information
        console.print(f"\n📋 Detailed Information:", style="bold cyan")
        for service, credit_info in credits.items():
            if credit_info.get('status') == 'active':
                console.print(f"\n🔑 {service.upper()}:", style="bold")
                
                if service == 'shodan':
                    console.print(f"  💳 Total Credits: {credit_info.get('credits', 'Unknown')}")
                    console.print(f"  🔍 Scan Credits: {credit_info.get('scan_credits', 'Unknown')}")
                    console.print(f"  🔎 Query Credits: {credit_info.get('query_credits', 'Unknown')}")
                    console.print(f"  📊 Monitor Credits: {credit_info.get('monitor_credits', 'Unknown')}")
                
                elif service == 'censys':
                    quota = credit_info.get('quota', {})
                    console.print(f"  📊 Queries Used: {quota.get('used', 'Unknown')}")
                    console.print(f"  📈 Queries Allowed: {quota.get('allowance', 'Unknown')}")
                    console.print(f"  🔄 Reset Date: {quota.get('resets_at', 'Unknown')}")
                
                elif service == 'hunter':
                    console.print(f"  📧 Requests Used: {credit_info.get('requests_used', 'Unknown')}")
                    console.print(f"  📊 Requests Limit: {credit_info.get('requests_limit', 'Unknown')}")
                    console.print(f"  💼 Plan: {credit_info.get('plan', 'Unknown')}")
                
                elif service == 'openai':
                    console.print(f"  🤖 Status: API key is valid and ready for AI reports")
                
                elif service == 'zoomeye':
                    console.print(f"  👁️ Quota: {credit_info.get('quota', 'Unknown')}")
                    console.print(f"  🔍 Status: Ready for port scanning")
                
                else:
                    console.print(f"  ✅ Status: API key is valid and ready to use")
        
        # Tips
        console.print(f"\n💡 Tips:", style="bold yellow")
        console.print("  • Monitor your API usage to avoid hitting limits")
        console.print("  • Some services offer free tiers with limited requests")
        console.print("  • Consider upgrading plans for higher limits")
        console.print("  • Use this script anytime to check current status")
        console.print("  • Run 'python reconrover.py --show_credits' for quick check")
        
        return active_services > 0
        
    except Exception as e:
        console.print(f"❌ Error checking API credits: {e}", style="red")
        return False

async def main():
    """Main function"""
    try:
        success = await check_all_credits()
        return 0 if success else 1
    except KeyboardInterrupt:
        console.print("\n⚠️ Process interrupted by user", style="yellow")
        return 1
    except Exception as e:
        console.print(f"\n❌ Error: {e}", style="red")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
