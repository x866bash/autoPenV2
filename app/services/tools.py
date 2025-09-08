import asyncio
import subprocess
import json
import aiohttp
from typing import List, Dict, Any

class SecurityTools:
    """Security tools for scanning and penetration testing"""
    
    async def run_nmap_scan(self, target: str, ports: str = "1-1000") -> str:
        """Run nmap scan asynchronously"""
        try:
            cmd = ["nmap", "-sS", "-O", "-sV", "-p", ports, target]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return stdout.decode('utf-8')
            else:
                return f"Nmap scan failed: {stderr.decode('utf-8')}"
                
        except Exception as e:
            return f"Error running nmap: {str(e)}"
    
    async def run_subdomain_enum(self, target: str) -> List[str]:
        """Run subdomain enumeration"""
        subdomains = []
        
        try:
            # Common subdomain wordlist
            common_subdomains = [
                "www", "mail", "ftp", "admin", "test", "dev", "staging", 
                "api", "blog", "shop", "support", "docs", "cdn", "app",
                "secure", "portal", "dashboard", "login", "panel"
            ]
            
            # Test each subdomain
            tasks = []
            for sub in common_subdomains:
                full_domain = f"{sub}.{target}"
                tasks.append(self._check_subdomain(full_domain))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if result and not isinstance(result, Exception):
                    subdomains.append(f"{common_subdomains[i]}.{target}")
                    
        except Exception as e:
            print(f"Subdomain enumeration error: {e}")
        
        return subdomains
    
    async def _check_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain exists"""
        try:
            process = await asyncio.create_subprocess_exec(
                "nslookup", subdomain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            output = stdout.decode('utf-8')
            return "can't find" not in output.lower() and "nxdomain" not in output.lower()
            
        except Exception:
            return False
    
    async def run_vulnerability_scan(self, target: str) -> List[str]:
        """Run basic vulnerability checks"""
        vulnerabilities = []
        
        try:
            # Check for common vulnerabilities
            vuln_checks = [
                self._check_ssl_vulnerabilities(target),
                self._check_common_ports(target),
                self._check_directory_traversal(target)
            ]
            
            results = await asyncio.gather(*vuln_checks, return_exceptions=True)
            
            for result in results:
                if result and not isinstance(result, Exception):
                    vulnerabilities.extend(result)
                    
        except Exception as e:
            print(f"Vulnerability scan error: {e}")
        
        return vulnerabilities
    
    async def _check_ssl_vulnerabilities(self, target: str) -> List[str]:
        """Check SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test SSL connection
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(f"https://{target}", timeout=10) as response:
                        if response.status == 200:
                            # Check for weak ciphers or protocols
                            if hasattr(response, 'connection') and response.connection:
                                vulnerabilities.append("SSL/TLS connection established - check cipher strength")
                except:
                    vulnerabilities.append("SSL/TLS connection failed or not available")
                    
        except Exception as e:
            print(f"SSL check error: {e}")
        
        return vulnerabilities
    
    async def _check_common_ports(self, target: str) -> List[str]:
        """Check for dangerous open ports"""
        vulnerabilities = []
        dangerous_ports = [21, 23, 25, 53, 135, 139, 445, 1433, 3389]
        
        try:
            for port in dangerous_ports:
                if await self._check_port_open(target, port):
                    vulnerabilities.append(f"Potentially dangerous port {port} is open")
                    
        except Exception as e:
            print(f"Port check error: {e}")
        
        return vulnerabilities
    
    async def _check_port_open(self, target: str, port: int) -> bool:
        """Check if a specific port is open"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=3
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    async def _check_directory_traversal(self, target: str) -> List[str]:
        """Check for directory traversal vulnerabilities"""
        vulnerabilities = []
        
        try:
            test_paths = [
                "/../../../etc/passwd",
                "/..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "/.env",
                "/config.php"
            ]
            
            async with aiohttp.ClientSession() as session:
                for path in test_paths:
                    try:
                        async with session.get(f"http://{target}{path}", timeout=5) as response:
                            if response.status == 200:
                                content = await response.text()
                                if "root:" in content or "[drivers]" in content:
                                    vulnerabilities.append(f"Potential directory traversal vulnerability: {path}")
                    except:
                        continue
                        
        except Exception as e:
            print(f"Directory traversal check error: {e}")
        
        return vulnerabilities
    
    async def check_security_headers(self, target: str) -> Dict[str, Any]:
        """Check security headers"""
        security_info = {
            "security_score": 0,
            "missing_headers": [],
            "present_headers": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{target}", timeout=10) as response:
                    headers = response.headers
                    
                    # Check for important security headers
                    security_headers = {
                        "X-Frame-Options": 10,
                        "X-Content-Type-Options": 10,
                        "X-XSS-Protection": 10,
                        "Strict-Transport-Security": 20,
                        "Content-Security-Policy": 30,
                        "Referrer-Policy": 10,
                        "Feature-Policy": 10
                    }
                    
                    total_score = 0
                    max_score = sum(security_headers.values())
                    
                    for header, score in security_headers.items():
                        if header in headers:
                            security_info["present_headers"].append(header)
                            total_score += score
                        else:
                            security_info["missing_headers"].append(header)
                    
                    security_info["security_score"] = (total_score / max_score) * 100
                    
        except Exception as e:
            print(f"Security headers check error: {e}")
            security_info["error"] = str(e)
        
        return security_info

# Hydra brute force functions
async def run_hydra_bruteforce(target: str, service: str, port: int, 
                              username_list: List[str] = None, 
                              password_list: List[str] = None) -> Dict[str, Any]:
    """Run Hydra brute force attack"""
    
    if username_list is None:
        username_list = ["admin", "root", "user", "test", "guest", "administrator"]
    
    if password_list is None:
        password_list = ["password", "123456", "admin", "root", "test", "guest", ""]
    
    results = {
        "service": service,
        "port": port,
        "target": target,
        "status": "completed",
        "credentials_found": [],
        "count": 0
    }
    
    try:
        # Create temporary files for usernames and passwords
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as user_file:
            user_file.write('\n'.join(username_list))
            user_file_path = user_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as pass_file:
            pass_file.write('\n'.join(password_list))
            pass_file_path = pass_file.name
        
        # Build hydra command
        cmd = [
            "hydra", 
            "-L", user_file_path,
            "-P", pass_file_path,
            "-s", str(port),
            "-t", "4",  # 4 threads
            "-w", "10", # 10 second timeout
            f"{target}",
            service
        ]
        
        # Run hydra
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        output = stdout.decode('utf-8')
        
        # Parse hydra output for found credentials
        credentials = parse_hydra_output(output)
        results["credentials_found"] = credentials
        results["count"] = len(credentials)
        
        # Clean up temporary files
        os.unlink(user_file_path)
        os.unlink(pass_file_path)
        
    except Exception as e:
        results["status"] = "failed"
        results["error"] = str(e)
    
    return results

def parse_hydra_output(output: str) -> List[Dict[str, str]]:
    """Parse Hydra output to extract found credentials"""
    credentials = []
    
    try:
        lines = output.split('\n')
        for line in lines:
            if '[' in line and ']' in line and 'login:' in line and 'password:' in line:
                # Extract username and password from hydra output
                parts = line.split()
                username = None
                password = None
                
                for i, part in enumerate(parts):
                    if part == 'login:' and i + 1 < len(parts):
                        username = parts[i + 1]
                    elif part == 'password:' and i + 1 < len(parts):
                        password = parts[i + 1]
                
                if username and password:
                    credentials.append({
                        "username": username,
                        "password": password
                    })
    except Exception as e:
        print(f"Error parsing hydra output: {e}")
    
    return credentials
