#!/usr/bin/env python3
"""
API Key Loader for ReconRover
Centralized API key management and validation
"""

import os
import yaml
import requests
import asyncio
import aiohttp
from typing import Dict, Any, Optional, List
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class APILoader:
    """Centralized API key loader and validator"""
    
    def __init__(self):
        self.config = None
        self.config_path = self._find_config_file()
        self._load_config()
    
    def _find_config_file(self) -> Optional[Path]:
        """Find the API configuration file"""
        possible_paths = [
            Path('config/api_keys.yaml'),
            Path('~/.config/reconrover/api_keys.yaml').expanduser(),
            Path('api_keys.yaml'),
        ]
        
        for path in possible_paths:
            if path.exists():
                logger.info(f"Found API config at: {path}")
                return path
        
        logger.warning("No API configuration file found")
        return None
    
    def _load_config(self):
        """Load configuration from YAML file"""
        if not self.config_path or not self.config_path.exists():
            self.config = {}
            return
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f) or {}
            logger.info(f"Successfully loaded API configuration from {self.config_path}")
        except Exception as e:
            logger.error(f"Error loading API configuration: {e}")
            self.config = {}
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a specific service"""
        if not self.config:
            return None
        
        service_config = self.config.get(service, {})
        return service_config.get('key') or service_config.get('api_key')
    
    def get_service_config(self, service: str) -> Dict[str, Any]:
        """Get full configuration for a service"""
        if not self.config:
            return {}
        
        return self.config.get(service, {})
    
    def get_rate_limit(self, service: str) -> int:
        """Get rate limit for a service (requests per second)"""
        if not self.config:
            return 1
        
        service_config = self.config.get(service, {})
        return service_config.get('rate_limit', 1)
    
    def validate_config(self) -> Dict[str, bool]:
        """Validate all configured services"""
        validation_results = {}
        
        services = [
            'shodan', 'censys', 'hunter', 'haveibeenpwned', 
            'openai', 'openrouter', 'builtwith', 'serpapi', 'securitytrails',
            'zoomeye', 'wayback'
        ]
        
        for service in services:
            validation_results[service] = bool(self.get_api_key(service))
        
        return validation_results

    async def check_api_credits(self) -> Dict[str, Dict[str, Any]]:
        """Check API credits/usage for all configured services"""
        credits = {}
        
        # Check Shodan credits
        shodan_key = self.get_api_key('shodan')
        if shodan_key:
            credits['shodan'] = await self._check_shodan_credits(shodan_key)
        
        # Check Censys credits
        censys_config = self.get_service_config('censys')
        if censys_config.get('api_id') and censys_config.get('api_secret'):
            credits['censys'] = await self._check_censys_credits(censys_config)
        
        # Check Hunter.io credits
        hunter_key = self.get_api_key('hunter')
        if hunter_key:
            credits['hunter'] = await self._check_hunter_credits(hunter_key)
        
        # Check HaveIBeenPwned credits
        hibp_key = self.get_api_key('haveibeenpwned')
        if hibp_key:
            credits['haveibeenpwned'] = await self._check_hibp_credits(hibp_key)
        
        # Check OpenAI credits
        openai_key = self.get_api_key('openai')
        if openai_key:
            credits['openai'] = await self._check_openai_credits(openai_key)
        
        # Check OpenRouter credits
        openrouter_key = self.get_api_key('openrouter')
        if openrouter_key:
            credits['openrouter'] = await self._check_openrouter_credits(openrouter_key)
        
        # Check BuiltWith credits
        builtwith_key = self.get_api_key('builtwith')
        if builtwith_key:
            credits['builtwith'] = await self._check_builtwith_credits(builtwith_key)
        
        # Check ZoomEye credits
        zoomeye_key = self.get_api_key('zoomeye')
        if zoomeye_key:
            credits['zoomeye'] = await self._check_zoomeye_credits(zoomeye_key)
        
        return credits

    def should_block_service(self, service: str) -> Dict[str, Any]:
        """Check if a service should be blocked due to missing API key or zero credits"""
        result = {
            'blocked': False,
            'reason': None,
            'status': 'available'
        }
        
        # Check if API key exists
        api_key = self.get_api_key(service)
        if not api_key:
            result['blocked'] = True
            result['reason'] = f"No API key configured for {service}"
            result['status'] = 'no_api_key'
            return result
        
        # For services that don't have credit checking, just validate the key
        if service in ['serpapi', 'securitytrails', 'wayback']:
            result['status'] = 'api_key_configured'
            return result
        
        # For other services, we need to check credits (this will be done asynchronously)
        result['status'] = 'needs_credit_check'
        return result

    def get_service_status(self, service: str, credits_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get comprehensive status for a service including credit information"""
        status = self.should_block_service(service)
        
        if status['blocked']:
            return status
        
        if credits_data and service in credits_data:
            credit_info = credits_data[service]
            if credit_info.get('status') == 'error':
                status['blocked'] = True
                status['reason'] = f"API key error: {credit_info.get('message', 'Unknown error')}"
                status['status'] = 'api_error'
            elif credit_info.get('status') == 'active':
                # Check for zero credits
                if service == 'shodan':
                    credits = credit_info.get('credits', 0)
                    if credits == 0:
                        status['blocked'] = True
                        status['reason'] = "Shodan credits exhausted (0 remaining)"
                        status['status'] = 'zero_credits'
                elif service == 'hunter':
                    used = credit_info.get('requests_used', 0)
                    limit = credit_info.get('requests_limit', 0)
                    if used >= limit:
                        status['blocked'] = True
                        status['reason'] = f"Hunter.io requests limit reached ({used}/{limit})"
                        status['status'] = 'limit_reached'
                elif service == 'censys':
                    used = credit_info.get('queries_used', 0)
                    allowed = credit_info.get('queries_allowed', 0)
                    if used >= allowed:
                        status['blocked'] = True
                        status['reason'] = f"Censys queries limit reached ({used}/{allowed})"
                        status['status'] = 'limit_reached'
        
        return status

    async def _check_shodan_credits(self, api_key: str) -> Dict[str, Any]:
        """Check Shodan API credits"""
        try:
            url = f"https://api.shodan.io/api-info?key={api_key}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'credits': data.get('credits', 'Unknown'),
                            'scan_credits': data.get('scan_credits', 'Unknown'),
                            'query_credits': data.get('query_credits', 'Unknown'),
                            'monitor_credits': data.get('monitor_credits', 'Unknown'),
                            'status': 'active'
                        }
                    else:
                        return {'status': 'error', 'message': f'HTTP {response.status}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    async def _check_censys_credits(self, config: Dict[str, str]) -> Dict[str, Any]:
        """Check Censys API credits"""
        try:
            url = "https://search.censys.io/api/v1/account"
            auth = (config['api_id'], config['api_secret'])
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, auth=aiohttp.BasicAuth(auth[0], auth[1])) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'quota': data.get('quota', {}),
                            'queries_used': data.get('queries_used', 'Unknown'),
                            'queries_allowed': data.get('queries_allowed', 'Unknown'),
                            'status': 'active'
                        }
                    else:
                        return {'status': 'error', 'message': f'HTTP {response.status}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    async def _check_hunter_credits(self, api_key: str) -> Dict[str, Any]:
        """Check Hunter.io API credits"""
        try:
            url = f"https://api.hunter.io/v2/account?api_key={api_key}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        account_data = data.get('data', {})
                        return {
                            'requests_used': account_data.get('requests_used', 'Unknown'),
                            'requests_limit': account_data.get('requests_limit', 'Unknown'),
                            'plan': account_data.get('plan', 'Unknown'),
                            'status': 'active'
                        }
                    else:
                        return {'status': 'error', 'message': f'HTTP {response.status}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    async def _check_hibp_credits(self, api_key: str) -> Dict[str, Any]:
        """Check HaveIBeenPwned API credits"""
        try:
            url = "https://haveibeenpwned.com/api/v3/breaches"
            headers = {'hibp-api-key': api_key, 'user-agent': 'ReconRover/1.0'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        return {
                            'status': 'active',
                            'message': 'API key is valid'
                        }
                    elif response.status == 401:
                        return {'status': 'error', 'message': 'Invalid API key'}
                    else:
                        return {'status': 'error', 'message': f'HTTP {response.status}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    async def _check_openai_credits(self, api_key: str) -> Dict[str, Any]:
        """Check OpenAI API credits"""
        try:
            url = "https://api.openai.com/v1/models"
            headers = {'Authorization': f'Bearer {api_key}'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        return {
                            'status': 'active',
                            'message': 'API key is valid'
                        }
                    elif response.status == 401:
                        return {'status': 'error', 'message': 'Invalid API key'}
                    else:
                        return {'status': 'error', 'message': f'HTTP {response.status}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    async def _check_openrouter_credits(self, api_key: str) -> Dict[str, Any]:
        """Check OpenRouter API credits"""
        try:
            url = "https://openrouter.ai/api/v1/auth/key"
            headers = {'Authorization': f'Bearer {api_key}'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'status': 'active',
                            'message': 'API key is valid',
                            'credits': data.get('credits', 'Unknown'),
                            'models': data.get('models', [])
                        }
                    elif response.status == 401:
                        return {'status': 'error', 'message': 'Invalid API key'}
                    else:
                        return {'status': 'error', 'message': f'HTTP {response.status}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    async def _check_builtwith_credits(self, api_key: str) -> Dict[str, Any]:
        """Check BuiltWith API credits"""
        try:
            url = f"https://api.builtwith.com/v20/api.json?KEY={api_key}&LOOKUP=example.com"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        return {
                            'status': 'active',
                            'message': 'API key is valid'
                        }
                    elif response.status == 401:
                        return {'status': 'error', 'message': 'Invalid API key'}
                    else:
                        return {'status': 'error', 'message': f'HTTP {response.status}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    async def _check_zoomeye_credits(self, api_key: str) -> Dict[str, Any]:
        """Check ZoomEye API credits"""
        try:
            url = "https://api.zoomeye.org/user/login"
            headers = {'API-KEY': api_key}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'status': 'active',
                            'message': 'API key is valid',
                            'quota': data.get('quota', 'Unknown')
                        }
                    elif response.status == 401:
                        return {'status': 'error', 'message': 'Invalid API key'}
                    else:
                        return {'status': 'error', 'message': f'HTTP {response.status}'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

def get_api_loader() -> APILoader:
    """Get API loader instance"""
    return APILoader()

def get_api_key(service: str) -> Optional[str]:
    """Get API key for a service"""
    loader = get_api_loader()
    return loader.get_api_key(service)

def get_rate_limit(service: str) -> int:
    """Get rate limit for a service (requests per second)"""
    loader = get_api_loader()
    return loader.get_rate_limit(service)
