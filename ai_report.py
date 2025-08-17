#!/usr/bin/env python3
"""
AI Report Generation Module for ReconRover
Summarizes all reconnaissance data into a comprehensive report
"""

import argparse
import asyncio
import json
import os
from typing import List, Dict, Any, Optional
from pathlib import Path
import openai
import requests
from utils import (
    logger, save_json, save_txt, load_json, load_txt,
    format_table
)

class AIReportGenerator:
    """Generates AI-powered reconnaissance reports"""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o-mini", 
                 provider: str = "openai", base_url: Optional[str] = None):
        self.api_key = api_key
        self.model = model
        self.provider = provider
        self.base_url = base_url
        self.client = None
        
        if api_key:
            try:
                if provider == "openrouter":
                    # Use OpenRouter.ai
                    self.client = openai.OpenAI(
                        api_key=api_key,
                        base_url=base_url or "https://openrouter.ai/api/v1"
                    )
                else:
                    # Use OpenAI
                    self.client = openai.OpenAI(api_key=api_key)
            except Exception as e:
                logger.error(f"Failed to initialize {provider} client: {e}")
    
    def load_reconnaissance_data(self, json_files: List[str]) -> Dict[str, Any]:
        """Load all reconnaissance data from JSON files"""
        data = {}
        
        for file_path in json_files:
            # Extract just the filename for load_json (it prepends data/)
            filename = Path(file_path).name
            
            try:
                file_data = load_json(filename)
                if file_data:
                    # Extract filename without extension as key
                    key = Path(filename).stem
                    data[key] = file_data
                    logger.info(f"Loaded data from {filename}")
            except Exception as e:
                logger.error(f"Error loading {filename}: {e}")
        
        return data
    
    def prepare_report_context(self, data: Dict[str, Any]) -> str:
        """Prepare context for AI report generation"""
        context = "Reconnaissance Data Summary:\n\n"
        
        # Domain information
        if 'domain' in data:
            domain_info = data['domain']
            context += f"Target Domain: {domain_info.get('domain', 'Unknown')}\n"
            context += f"Company: {domain_info.get('company', 'Unknown')}\n\n"
        
        # Subdomain information
        if 'subdomains' in data:
            subdomain_info = data['subdomains']
            context += f"Subdomains Found: {subdomain_info.get('count', 0)}\n"
            context += f"Sources: {', '.join(subdomain_info.get('sources', []))}\n\n"
        
        # DNS information
        if 'dns' in data:
            dns_info = data['dns']
            context += f"DNS Records Resolved: {dns_info.get('total_subdomains', 0)}\n"
            context += f"Unique IPs: {dns_info.get('total_ips', 0)}\n\n"
        
        # Shodan information
        if 'shodan' in data:
            shodan_info = data['shodan']
            context += f"Shodan Scanned IPs: {shodan_info.get('scanned_ips', 0)}\n"
            context += f"Critical Findings: {len(shodan_info.get('critical_findings', []))}\n"
            
            # Top ports
            top_ports = shodan_info.get('top_ports', [])
            if top_ports:
                context += "Top Open Ports:\n"
                for port_info in top_ports[:5]:
                    context += f"  - Port {port_info.get('port')}: {port_info.get('count')} hosts\n"
            context += "\n"
        
        # Censys information
        if 'censys' in data:
            censys_info = data['censys']
            if 'certificate_count' in censys_info:
                context += f"Censys Certificates: {censys_info.get('certificate_count', 0)}\n"
                context += f"Censys Services: {censys_info.get('service_count', 0)}\n"
                context += f"Censys Subdomains: {censys_info.get('subdomain_count', 0)}\n\n"
        
        # Technology stack information
        if 'techstack' in data:
            tech_info = data['techstack']
            context += f"Technology Stack Analysis:\n"
            context += f"  - Domains Scanned: {tech_info.get('scanned_domains', 0)}\n"
            
            tech_summary = tech_info.get('technology_summary', {})
            if 'cms_usage' in tech_summary and tech_summary['cms_usage']:
                context += f"  - CMS Types: {len(tech_summary['cms_usage'])}\n"
            if 'framework_usage' in tech_summary and tech_summary['framework_usage']:
                context += f"  - Frameworks: {len(tech_summary['framework_usage'])}\n"
            context += "\n"
        
        # Email and breach information
        if 'emails' in data:
            email_info = data['emails']
            context += f"Email Analysis:\n"
            context += f"  - Total Emails: {email_info.get('total_emails', 0)}\n"
            context += f"  - Total Breaches: {email_info.get('total_breaches', 0)}\n"
            context += f"  - Total Pastes: {email_info.get('total_pastes', 0)}\n"
            
            breach_summary = email_info.get('breach_summary', {})
            if 'affected_emails' in breach_summary:
                context += f"  - Affected Emails: {len(breach_summary['affected_emails'])}\n"
            context += "\n"
        
        return context
    
    def generate_ai_report(self, context: str, report_type: str = "comprehensive") -> str:
        """Generate AI-powered report"""
        if not self.client:
            logger.warning("OpenAI client not available, generating basic report")
            return self.generate_basic_report(context)
        
        # Define prompt based on report type
        if report_type == "executive":
            prompt = f"""
You are a cybersecurity expert. Based on the following reconnaissance data, create an executive summary report for senior management.

{context}

Please provide:
1. Executive Summary (2-3 sentences)
2. Key Findings (bullet points)
3. Risk Assessment (High/Medium/Low)
4. Recommendations (3-5 actionable items)

Format the report professionally for executive presentation.
"""
        elif report_type == "technical":
            prompt = f"""
You are a cybersecurity expert. Based on the following reconnaissance data, create a detailed technical report for security professionals.

{context}

Please provide:
1. Executive Summary
2. Detailed Technical Findings
3. Attack Surface Analysis
4. Critical Vulnerabilities
5. Security Recommendations
6. Next Steps for Penetration Testing

Include specific technical details and actionable insights.
"""
        else:  # comprehensive
            prompt = f"""
You are a cybersecurity expert. Based on the following reconnaissance data, create a comprehensive reconnaissance report.

{context}

Please provide:
1. Executive Summary
2. Methodology Overview
3. Detailed Findings:
   - Domain and Subdomain Analysis
   - DNS and Network Infrastructure
   - Open Ports and Services
   - Technology Stack Analysis
   - Email and Breach Analysis
4. Risk Assessment
5. Attack Surface Mapping
6. Security Recommendations
7. Next Steps for Security Assessment

Make the report comprehensive yet readable for both technical and non-technical audiences.
"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a professional cybersecurity consultant specializing in reconnaissance and security assessments."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.7
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Error generating AI report: {e}")
            return self.generate_basic_report(context)
    
    def generate_basic_report(self, context: str) -> str:
        """Generate a basic report without AI"""
        report = """# Reconnaissance Report

## Executive Summary
This report presents the findings from a comprehensive reconnaissance assessment of the target organization.

## Methodology
The reconnaissance was conducted using multiple automated tools and techniques including:
- Domain resolution and subdomain enumeration
- DNS record analysis
- Port scanning and service identification
- Technology stack analysis
- Email enumeration and breach checking

## Key Findings

"""
        
        # Add context data to report
        report += context
        
        report += """
## Risk Assessment
Based on the findings, the following risk areas have been identified:
- Open ports and services that may be vulnerable
- Technology stack vulnerabilities
- Email addresses exposed in breaches
- Subdomain enumeration revealing additional attack surface

## Recommendations
1. Review and secure all open ports and services
2. Update and patch identified technologies
3. Implement email security best practices
4. Conduct regular security assessments
5. Monitor for new subdomains and assets

## Next Steps
1. Perform detailed vulnerability assessment
2. Conduct penetration testing
3. Implement security controls
4. Establish monitoring and alerting
5. Regular security reviews

---
*Report generated by ReconRover*
"""
        
        return report
    
    def save_report(self, report: str, output_format: str = "markdown", filename: str = "recon_report"):
        """Save report in specified format"""
        if output_format == "markdown":
            save_txt([report], f"{filename}.md")
        elif output_format == "txt":
            # Convert markdown to plain text
            import re
            plain_text = re.sub(r'#+\s*', '', report)  # Remove markdown headers
            plain_text = re.sub(r'\*\*(.*?)\*\*', r'\1', plain_text)  # Remove bold
            plain_text = re.sub(r'\*(.*?)\*', r'\1', plain_text)  # Remove italic
            save_txt([plain_text], f"{filename}.txt")
        elif output_format == "pdf":
            try:
                import markdown2
                import pdfkit
                
                # Convert markdown to HTML
                html = markdown2.markdown(report)
                
                # Convert HTML to PDF
                pdfkit.from_string(html, f"{filename}.pdf")
                logger.info(f"PDF report saved as {filename}.pdf")
            except ImportError:
                logger.error("PDF generation requires markdown2 and pdfkit packages")
                save_txt([report], f"{filename}.md")
            except Exception as e:
                logger.error(f"Error generating PDF: {e}")
                save_txt([report], f"{filename}.md")

async def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Generate AI-powered reconnaissance report")
    parser.add_argument("--json_inputs", nargs="+", help="List of JSON files to include")
    parser.add_argument("--save_md", action="store_true", help="Save report as Markdown")
    parser.add_argument("--save_txt", action="store_true", help="Save report as plain text")
    parser.add_argument("--save_pdf", action="store_true", help="Save report as PDF")
    parser.add_argument("--ai_model", default="gpt-4o-mini", help="AI model to use")
    parser.add_argument("--report_type", choices=["executive", "technical", "comprehensive"], 
                       default="comprehensive", help="Type of report to generate")
    parser.add_argument("--api_key", help="API key")
    parser.add_argument("--provider", choices=["openai", "openrouter"], default="openai", 
                       help="AI provider to use")
    parser.add_argument("--base_url", help="Base URL for API (for OpenRouter)")
    
    args = parser.parse_args()
    
    # Get API key and provider configuration
    api_key = args.api_key
    provider = args.provider
    base_url = args.base_url
    
    if not api_key:
        # Try to get from environment or config
        import os
        if provider == "openrouter":
            api_key = os.getenv('OPENROUTER_API_KEY')
        else:
            api_key = os.getenv('OPENAI_API_KEY')
    
    # Get JSON files
    json_files = args.json_inputs
    if not json_files:
        # Try to find JSON files in data directory
        data_dir = Path('data')
        if data_dir.exists():
            json_files = list(data_dir.glob('*.json'))
            json_files = [str(f) for f in json_files]
    
    if not json_files:
        print("No JSON files provided or found in data directory")
        return 1
    
    # Initialize report generator
    generator = AIReportGenerator(api_key, args.ai_model, provider, base_url)
    
    # Load reconnaissance data
    data = generator.load_reconnaissance_data(json_files)
    
    if not data:
        print("No reconnaissance data found")
        return 1
    
    # Prepare context
    context = generator.prepare_report_context(data)
    
    # Generate report
    print("Generating AI-powered report...")
    report = generator.generate_ai_report(context, args.report_type)
    
    if report:
        print("Report generated successfully!")
        
        # Save report in requested formats
        if args.save_md or not (args.save_txt or args.save_pdf):
            generator.save_report(report, "markdown", "recon_report")
        
        if args.save_txt:
            generator.save_report(report, "txt", "recon_report")
        
        if args.save_pdf:
            generator.save_report(report, "pdf", "recon_report")
        
        # Print report preview
        print("\n" + "="*50)
        print("REPORT PREVIEW")
        print("="*50)
        print(report[:1000] + "..." if len(report) > 1000 else report)
        print("="*50)
    else:
        print("Failed to generate report")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
