import asyncio
import subprocess
from typing import Dict, Any, List
from app.services.tools import SecurityTools
import logging
import re

logger = logging.getLogger(__name__)

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
                'output': nmap_result,  # Add both for compatibility
                'open_ports': self._parse_nmap_ports(nmap_result)
            }
            logger.info(f"Full scan nmap result: {len(results['nmap_scan']['open_ports'])} ports found")
        except Exception as e:
            logger.error(f"Nmap scan failed: {str(e)}")
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
            logger.info(f"Starting port scan for target: {target}")
            nmap_result = await self.tools.run_nmap_scan(target)
            open_ports = self._parse_nmap_ports(nmap_result)
            
            logger.info(f"Port scan completed. Found {len(open_ports)} open ports")
            for port in open_ports:
                logger.info(f"Open port: {port['port']} ({port['service']})")
            
            return {
                'nmap_scan': {
                    'status': 'completed',
                    'raw_output': nmap_result,
                    'output': nmap_result,  # Add both for compatibility
                    'open_ports': open_ports
                }
            }
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
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
        """Enhanced Nmap output parser to extract open ports"""
        open_ports = []
        
        if not nmap_output:
            logger.warning("Empty nmap output received")
            return open_ports
        
        logger.info("Parsing nmap output...")
        logger.debug(f"Nmap output:\n{nmap_output}")
        
        lines = nmap_output.split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Look for lines containing port information
            # Format: PORT     STATE SERVICE
            # Example: 22/tcp   open  ssh
            # Example: 80/tcp   open  http
            # Example: 443/tcp  open  https
            
            if '/tcp' in line and 'open' in line:
                logger.debug(f"Line {line_num}: Found potential port line: {line}")
                
                # Split by whitespace and filter empty strings
                parts = [part for part in line.split() if part]
                
                if len(parts) >= 3:
                    port_info = parts[0]  # e.g., "22/tcp"
                    state = parts[1]      # e.g., "open"
                    service = parts[2]    # e.g., "ssh"
                    
                    logger.debug(f"Parsed parts: port_info={port_info}, state={state}, service={service}")
                    
                    # Extract port number
                    if '/' in port_info and state.lower() == 'open':
                        try:
                            port_num = int(port_info.split('/')[0])
                            
                            port_entry = {
                                'port': port_num,
                                'state': state,
                                'service': service
                            }
                            
                            open_ports.append(port_entry)
                            logger.info(f"Added open port: {port_num} ({service})")
                            
                        except ValueError as e:
                            logger.warning(f"Failed to parse port number from '{port_info}': {e}")
                            continue
                else:
                    logger.debug(f"Line has insufficient parts ({len(parts)}): {line}")
            
            # Also try regex pattern matching as fallback
            elif re.search(r'\d+/tcp.*open', line, re.IGNORECASE):
                logger.debug(f"Line {line_num}: Regex matched port line: {line}")
                
                # Use regex to extract port, state, and service
                match = re.match(r'(\d+)/tcp\s+(\w+)\s+(\w+)', line)
                if match:
                    port_num = int(match.group(1))
                    state = match.group(2)
                    service = match.group(3)
                    
                    if state.lower() == 'open':
                        port_entry = {
                            'port': port_num,
                            'state': state,
                            'service': service
                        }
                        
                        # Avoid duplicates
                        if not any(p['port'] == port_num for p in open_ports):
                            open_ports.append(port_entry)
                            logger.info(f"Added open port (regex): {port_num} ({service})")
        
        logger.info(f"Total open ports found: {len(open_ports)}")
        return open_ports
