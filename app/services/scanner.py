import asyncio
import subprocess
from typing import Dict, Any, List
from app.services.tools import SecurityTools

class SecurityScanner:
    def __init__(self):
        self.tools = SecurityTools()
    
    async def full_scan(self, target: str) -> Dict[str, Any]:
        """Run a comprehensive security scan"""
        results = {}
        
        try:
            # Run all scans sequentially with proper await
            nmap_result = await self.tools.run_nmap_scan(target)
            results['nmap_scan'] = {
                'status': 'completed',
                'raw_output': nmap_result,
                'open_ports': self._parse_nmap_ports(nmap_result)
            }
        except Exception as e:
            results['nmap_scan'] = {
                'status': 'failed',
                'error': str(e)
            }
        
        try:
            # Run subdomain enumeration
            subdomain_result = await self.tools.run_subdomain_enum(target)
            results['subdomain_enum'] = {
                'status': 'completed',
                'subdomains': subdomain_result,
                'count': len(subdomain_result)
            }
        except Exception as e:
            results['subdomain_enum'] = {
                'status': 'failed',
                'error': str(e)
            }
        
        try:
            # Run vulnerability scan
            vuln_result = await self.tools.run_vulnerability_scan(target)
            results['vulnerability_scan'] = {
                'status': 'completed',
                'vulnerabilities': vuln_result,
                'count': len(vuln_result)
            }
        except Exception as e:
            results['vulnerability_scan'] = {
                'status': 'failed',
                'error': str(e)
            }
        
        try:
            # Check security headers
            headers_result = await self.tools.check_security_headers(target)
            results['security_headers'] = headers_result
        except Exception as e:
            results['security_headers'] = {
                'status': 'failed',
                'error': str(e)
            }
        
        return results
    
    async def port_scan(self, target: str) -> Dict[str, Any]:
        """Run port scan only"""
        try:
            nmap_result = await self.tools.run_nmap_scan(target)
            return {
                'nmap_scan': {
                    'status': 'completed',
                    'raw_output': nmap_result,
                    'open_ports': self._parse_nmap_ports(nmap_result)
                }
            }
        except Exception as e:
            return {
                'nmap_scan': {
                    'status': 'failed',
                    'error': str(e)
                }
            }
    
    async def subdomain_scan(self, target: str) -> Dict[str, Any]:
        """Run subdomain enumeration only"""
        try:
            subdomain_result = await self.tools.run_subdomain_enum(target)
            return {
                'subdomain_enum': {
                    'status': 'completed',
                    'subdomains': subdomain_result,
                    'count': len(subdomain_result)
                }
            }
        except Exception as e:
            return {
                'subdomain_enum': {
                    'status': 'failed',
                    'error': str(e)
                }
            }
    
    async def vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """Run vulnerability scan only"""
        try:
            vuln_result = await self.tools.run_vulnerability_scan(target)
            headers_result = await self.tools.check_security_headers(target)
            
            return {
                'vulnerability_scan': {
                    'status': 'completed',
                    'vulnerabilities': vuln_result,
                    'count': len(vuln_result)
                },
                'security_headers': headers_result
            }
        except Exception as e:
            return {
                'vulnerability_scan': {
                    'status': 'failed',
                    'error': str(e)
                }
            }
    
    def _parse_nmap_ports(self, nmap_output: str) -> List[Dict[str, Any]]:
        """Parse Nmap output to extract open ports"""
        open_ports = []
        
        if not nmap_output:
            return open_ports
        
        lines = nmap_output.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    
                    if '/' in port_info:
                        port_num = port_info.split('/')[0]
                        try:
                            port_int = int(port_num)
                            open_ports.append({
                                'port': port_int,
                                'state': state,
                                'service': service
                            })
                        except ValueError:
                            continue
        
        return open_ports
