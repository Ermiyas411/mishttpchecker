#!/usr/bin/env python3
"""
Advanced HTTP Header Security Scanner
A comprehensive tool for analyzing HTTP security headers and identifying misconfigurations
"""

import requests
import ssl
import socket
import json
import csv
import argparse
import sys
import urllib3
import re
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import dns.resolver
import concurrent.futures
import time
import hashlib
import base64
from pathlib import Path


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class SecurityFinding:
    """Data class for security findings"""
    severity: str
    title: str
    description: str
    recommendation: str
    confidence: str = "high"
    reference: str = ""

class HTTPHeaderScanner:
    """Advanced HTTP security header scanner"""
    
    SEVERITY_CRITICAL = "critical"
    SEVERITY_HIGH = "high"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_LOW = "low"
    SEVERITY_INFO = "info"
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = True, user_agent: str = None):
        self.session = requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or "SecurityHeaderScanner/2.0"
        self.session.headers.update({'User-Agent': self.user_agent})
        self.findings: List[SecurityFinding] = []
        self.redirect_history = []
        
    def scan(self, url: str) -> Dict[str, Any]:
        """Perform comprehensive security scan of a URL"""
        start_time = time.time()
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        results = {
            'scan_date': datetime.now().isoformat(),
            'target_url': url,
            'base_url': base_url,
            'scan_duration': 0,
            'headers': {},
            'security_checks': {},
            'ssl_info': {},
            'network_info': {},
            'findings': [],
            'risk_score': 0,
            'grade': 'F'
        }
        
        response = self._make_request(url)
        if not response:
            results['risk_score'], results['grade'] = self._calculate_risk_score()
            results['scan_duration'] = round(time.time() - start_time, 2)
            results['findings'] = [asdict(f) for f in self.findings]
            return results

        results['headers'] = dict(response.headers)
        results['status_code'] = response.status_code
        results['final_url'] = response.url

        
        stages = [
            ("header analysis", lambda: results.__setitem__(
                'security_checks', self._analyze_headers(response.headers, response.url))),
            ("security.txt check", lambda: results['security_checks'].__setitem__(
                'security_txt', self._check_security_txt(base_url))),
            ("SSL/TLS check", lambda: results.__setitem__(
                'ssl_info', self._check_ssl(response.url) if response.url.startswith('https') else {})),
            ("network/DNS check", lambda: results.__setitem__(
                'network_info', self._get_network_info(parsed_url.hostname))),
            ("content checks", lambda: self._perform_additional_checks(response)),
        ]

        for stage_name, stage_fn in stages:
            try:
                stage_fn()
            except Exception as e:
                self._add_finding(
                    self.SEVERITY_INFO,
                    f"{stage_name.title()} Incomplete",
                    f"The {stage_name} could not finish: {str(e)}",
                    "Re-run the scan; if this persists, investigate connectivity or target-specific issues."
                )

        results['risk_score'], results['grade'] = self._calculate_risk_score()

        results['scan_duration'] = round(time.time() - start_time, 2)
        results['findings'] = [asdict(f) for f in self.findings]
        
        return results
    
    def _make_request(self, url: str) -> Optional[requests.Response]:
        """Make HTTP request with redirect handling"""
        try:
            response = self.session.get(
                url, 
                timeout=self.timeout, 
                allow_redirects=True,
                verify=self.verify_ssl
            )
            
            if response.history:
                self.redirect_history = [{
                    'url': resp.url,
                    'status_code': resp.status_code,
                    'headers': dict(resp.headers)
                } for resp in response.history]
                
            return response
            
        except requests.RequestException as e:
            self._add_finding(self.SEVERITY_MEDIUM, "Connection Error", f"Failed to connect to {url}: {str(e)}")
            return None
    
    def _analyze_headers(self, headers: Dict[str, str], url: str) -> Dict[str, Any]:
        """Comprehensive header security analysis"""
        checks = {}
        
        checks['hsts'] = self._check_hsts(headers, url)
        checks['csp'] = self._check_csp(headers)
        checks['x_content_type_options'] = self._check_x_content_type_options(headers)
        checks['x_frame_options'] = self._check_x_frame_options(headers)
        checks['x_xss_protection'] = self._check_x_xss_protection(headers)
        checks['referrer_policy'] = self._check_referrer_policy(headers)
        checks['permissions_policy'] = self._check_permissions_policy(headers)
        checks['cookies'] = self._check_cookies(headers)
        
        checks['security_headers'] = self._check_security_headers_presence(headers)
        checks['server_info'] = self._check_server_info(headers)
        checks['cache_headers'] = self._check_cache_headers(headers)
        checks['cross_origin_isolation'] = self._check_cross_origin_isolation(headers)

        return checks

    def _check_cross_origin_isolation(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check the modern cross-origin isolation headers (COOP/COEP/CORP)."""
        coop = headers.get('Cross-Origin-Opener-Policy', '')
        coep = headers.get('Cross-Origin-Embedder-Policy', '')
        corp = headers.get('Cross-Origin-Resource-Policy', '')

        result = {
            'coop': coop,
            'coep': coep,
            'corp': corp,
            'issues': []
        }

        if not coop:
            self._add_finding(
                self.SEVERITY_LOW,
                "Missing Cross-Origin-Opener-Policy",
                "Cross-Origin-Opener-Policy header is missing, which weakens process isolation and can enable "
                "cross-window attacks such as Spectre-style side channels.",
                "Add 'Cross-Origin-Opener-Policy: same-origin'.",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
            )
            result['issues'].append('COOP missing')

        if not coep:
            self._add_finding(
                self.SEVERITY_LOW,
                "Missing Cross-Origin-Embedder-Policy",
                "Cross-Origin-Embedder-Policy header is missing, which is required for full cross-origin isolation.",
                "Add 'Cross-Origin-Embedder-Policy: require-corp' if the site needs isolated contexts.",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
            )
            result['issues'].append('COEP missing')

        if not corp:
            self._add_finding(
                self.SEVERITY_LOW,
                "Missing Cross-Origin-Resource-Policy",
                "Cross-Origin-Resource-Policy header is missing, which can let other origins embed this site's "
                "resources without restriction.",
                "Add 'Cross-Origin-Resource-Policy: same-origin' or 'same-site' as appropriate.",
                reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
            )
            result['issues'].append('CORP missing')

        return result

    def _check_security_txt(self, base_url: str) -> Dict[str, Any]:
        """Check for an RFC 9116 security.txt file (well-known and legacy locations)."""
        result = {'present': False, 'location': None, 'issues': []}

        for path in ('/.well-known/security.txt', '/security.txt'):
            try:
                resp = self.session.get(
                    urljoin(base_url, path),
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )
                if resp.status_code == 200 and 'Contact:' in resp.text:
                    result['present'] = True
                    result['location'] = path
                    break
            except requests.RequestException:
                continue

        if not result['present']:
            self._add_finding(
                self.SEVERITY_INFO,
                "Missing security.txt",
                "No RFC 9116 security.txt file was found, which makes it harder for researchers to report "
                "vulnerabilities responsibly.",
                "Publish a security.txt file at /.well-known/security.txt with a Contact field.",
                reference="https://www.rfc-editor.org/rfc/rfc9116"
            )
            result['issues'].append('security.txt missing')

        return result
    
    def _check_hsts(self, headers: Dict[str, str], url: str) -> Dict[str, Any]:
        """Comprehensive HSTS check"""
        hsts = headers.get('Strict-Transport-Security', '')
        result = {
            'present': bool(hsts),
            'value': hsts,
            'max_age': 0,
            'includes_subdomains': False,
            'preload': False,
            'issues': []
        }
        
        if not hsts:
            self._add_finding(
                self.SEVERITY_HIGH, 
                "Missing HSTS Header", 
                "The Strict-Transport-Security header is missing, which can leave users vulnerable to MITM attacks.",
                "Implement HSTS with a minimum max-age of 31536000 (1 year) and includeSubDomains directive."
            )
            result['issues'].append('HSTS header missing')
            return result
        
        max_age_match = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
        if max_age_match:
            result['max_age'] = int(max_age_match.group(1))
            if result['max_age'] < 31536000:
                self._add_finding(
                    self.SEVERITY_MEDIUM,
                    "HSTS Max-Age Too Short",
                    f"HSTS max-age is {result['max_age']} seconds, which is less than the recommended 31536000 seconds (1 year).",
                    "Increase HSTS max-age to at least 31536000 seconds."
                )
                result['issues'].append('max-age too short')
        else:
            self._add_finding(
                self.SEVERITY_HIGH,
                "HSTS Missing Max-Age",
                "HSTS header is present but missing the required max-age directive.",
                "Add max-age directive to HSTS header with a value of at least 31536000."
            )
            result['issues'].append('max-age directive missing')
        
        result['includes_subdomains'] = 'includeSubDomains' in hsts or 'includesubdomains' in hsts
        if not result['includes_subdomains']:
            self._add_finding(
                self.SEVERITY_MEDIUM,
                "HSTS Missing includeSubDomains",
                "HSTS header does not include the includeSubDomains directive.",
                "Add includeSubDomains directive to protect all subdomains."
            )
            result['issues'].append('includeSubDomains directive missing')
        
        result['preload'] = 'preload' in hsts.lower()
        
        return result
    
    def _check_csp(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Comprehensive CSP analysis"""
        csp = headers.get('Content-Security-Policy', '')
        report_only = headers.get('Content-Security-Policy-Report-Only', '')
        
        result = {
            'present': bool(csp),
            'value': csp,
            'report_only_present': bool(report_only),
            'report_only_value': report_only,
            'issues': [],
            'directives': self._parse_csp_directives(csp)
        }
        
        if not csp and not report_only:
            self._add_finding(
                self.SEVERITY_HIGH,
                "Missing CSP Header",
                "Content Security Policy headers are missing, which can leave the site vulnerable to XSS attacks.",
                "Implement a strong Content Security Policy."
            )
            result['issues'].append('CSP header missing')
            return result
        
        if 'unsafe-inline' in csp.lower():
            self._add_finding(
                self.SEVERITY_MEDIUM,
                "CSP Contains unsafe-inline",
                "CSP contains 'unsafe-inline' which can reduce protection against XSS attacks.",
                "Remove unsafe-inline and use nonces or hashes instead."
            )
            result['issues'].append('unsafe-inline directive found')
            
        if 'unsafe-eval' in csp.lower():
            self._add_finding(
                self.SEVERITY_MEDIUM,
                "CSP Contains unsafe-eval",
                "CSP contains 'unsafe-eval' which can allow script execution from strings.",
                "Remove unsafe-eval and use alternative approaches."
            )
            result['issues'].append('unsafe-eval directive found')
            
        if not any(directive in csp.lower() for directive in ['default-src', 'script-src']):
            self._add_finding(
                self.SEVERITY_MEDIUM,
                "CSP Missing Key Directives",
                "CSP is missing essential directives like default-src or script-src.",
                "Add essential CSP directives to provide adequate protection."
            )
            result['issues'].append('missing essential directives')
            
        return result
    
    def _parse_csp_directives(self, csp: str) -> Dict[str, List[str]]:
        """Parse CSP directives into a structured format"""
        directives = {}
        if not csp:
            return directives
            
        for directive in csp.split(';'):
            directive = directive.strip()
            if not directive:
                continue
                
            if ' ' in directive:
                name, values = directive.split(' ', 1)
                directives[name.strip().lower()] = [v.strip() for v in values.split() if v.strip()]
            else:
                directives[directive.lower()] = []
                
        return directives
    
    def _check_x_content_type_options(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check X-Content-Type-Options header"""
        xcto = headers.get('X-Content-Type-Options', '')
        result = {
            'present': bool(xcto),
            'value': xcto,
            'issues': []
        }
        
        if not xcto:
            self._add_finding(
                self.SEVERITY_MEDIUM,
                "Missing X-Content-Type-Options",
                "X-Content-Type-Options header is missing, which can lead to MIME type confusion attacks.",
                "Add 'X-Content-Type-Options: nosniff' header."
            )
            result['issues'].append('header missing')
        elif 'nosniff' not in xcto.lower():
            self._add_finding(
                self.SEVERITY_HIGH,
                "Misconfigured X-Content-Type-Options",
                f"X-Content-Type-Options header is present but misconfigured: {xcto}",
                "Set X-Content-Type-Options to 'nosniff'."
            )
            result['issues'].append('misconfigured - should be nosniff')
            
        return result
    
    def _check_x_frame_options(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check X-Frame-Options header"""
        xfo = headers.get('X-Frame-Options', '')
        result = {
            'present': bool(xfo),
            'value': xfo,
            'issues': []
        }
        
        if not xfo:
            self._add_finding(
                self.SEVERITY_MEDIUM,
                "Missing X-Frame-Options",
                "X-Frame-Options header is missing, which can make the site vulnerable to clickjacking.",
                "Add X-Frame-Options header with value 'DENY' or 'SAMEORIGIN'."
            )
            result['issues'].append('header missing')
        else:
            xfo_lower = xfo.lower()
            if 'deny' not in xfo_lower and 'sameorigin' not in xfo_lower:
                self._add_finding(
                    self.SEVERITY_MEDIUM,
                    "Misconfigured X-Frame-Options",
                    f"X-Frame-Options header has an invalid value: {xfo}",
                    "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'."
                )
                result['issues'].append('invalid value')
                
        return result
    
    def _check_x_xss_protection(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check X-XSS-Protection header"""
        xxss = headers.get('X-XSS-Protection', '')
        result = {
            'present': bool(xxss),
            'value': xxss,
            'issues': []
        }
        
        if not xxss:
            self._add_finding(
                self.SEVERITY_LOW,
                "Missing X-XSS-Protection",
                "X-XSS-Protection header is missing (note: this header is deprecated in modern browsers).",
                "Consider using Content Security Policy instead for XSS protection."
            )
            result['issues'].append('header missing')
        else:
            xxss_lower = xxss.lower()
            if '1; mode=block' not in xxss_lower:
                self._add_finding(
                    self.SEVERITY_LOW,
                    "Suboptimal X-XSS-Protection",
                    f"X-XSS-Protection header is not optimally configured: {xxss}",
                    "Set X-XSS-Protection to '1; mode=block' or consider using CSP instead."
                )
                result['issues'].append('suboptimal configuration')
                
        return result
    
    def _check_referrer_policy(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check Referrer-Policy header"""
        referrer = headers.get('Referrer-Policy', '')
        result = {
            'present': bool(referrer),
            'value': referrer,
            'issues': []
        }
        
        if not referrer:
            self._add_finding(
                self.SEVERITY_LOW,
                "Missing Referrer-Policy",
                "Referrer-Policy header is missing, which can lead to information leakage via referrer URLs.",
                "Implement a Referrer-Policy header with a value like 'strict-origin-when-cross-origin'."
            )
            result['issues'].append('header missing')
        elif 'unsafe-url' in referrer.lower():
            self._add_finding(
                self.SEVERITY_MEDIUM,
                "Insecure Referrer-Policy",
                "Referrer-Policy is set to 'unsafe-url' which can leak sensitive information in URLs.",
                "Use a more restrictive Referrer-Policy value like 'strict-origin-when-cross-origin'."
            )
            result['issues'].append('insecure policy')
            
        return result
    
    def _check_permissions_policy(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check Permissions-Policy header"""
        permissions = headers.get('Permissions-Policy', '') or headers.get('Feature-Policy', '')
        result = {
            'present': bool(permissions),
            'value': permissions,
            'issues': []
        }
        
        if not permissions:
            self._add_finding(
                self.SEVERITY_LOW,
                "Missing Permissions-Policy",
                "Permissions-Policy (or Feature-Policy) header is missing.",
                "Consider implementing a Permissions-Policy header to restrict browser features."
            )
            result['issues'].append('header missing')
            
        return result
    
    def _check_cookies(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check cookie security attributes"""
        cookie_headers = headers.get('Set-Cookie', '')
        if isinstance(cookie_headers, str):
            cookie_headers = [cookie_headers]
            
        cookies = []
        issues = []
        
        for cookie_header in cookie_headers:
            cookie = {
                'name': self._extract_cookie_name(cookie_header),
                'secure': 'Secure' in cookie_header,
                'httponly': 'HttpOnly' in cookie_header or 'HTTPOnly' in cookie_header,
                'samesite': self._extract_samesite(cookie_header),
                'path': self._extract_cookie_attribute(cookie_header, 'Path'),
                'domain': self._extract_cookie_attribute(cookie_header, 'Domain'),
                'max_age': self._extract_cookie_attribute(cookie_header, 'Max-Age'),
                'expires': self._extract_cookie_attribute(cookie_header, 'Expires')
            }
            cookies.append(cookie)
            
            if not cookie['secure']:
                issues.append(f"Cookie '{cookie['name']}' missing Secure flag")
                
            if not cookie['httponly']:
                issues.append(f"Cookie '{cookie['name']}' missing HttpOnly flag")
                
            if not cookie['samesite']:
                issues.append(f"Cookie '{cookie['name']}' missing SameSite attribute")
            elif cookie['samesite'].lower() not in ['strict', 'lax']:
                issues.append(f"Cookie '{cookie['name']}' has weak SameSite value: {cookie['samesite']}")
                
        result = {
            'cookies': cookies,
            'issues': issues
        }
        
        for issue in issues:
            if 'missing Secure flag' in issue:
                self._add_finding(
                    self.SEVERITY_HIGH,
                    "Insecure Cookie",
                    issue,
                    "Add Secure flag to cookies to prevent transmission over unencrypted connections."
                )
            elif 'missing HttpOnly flag' in issue:
                self._add_finding(
                    self.SEVERITY_MEDIUM,
                    "Cookie Accessible to JavaScript",
                    issue,
                    "Add HttpOnly flag to prevent JavaScript access to cookies."
                )
                
        return result
    
    def _extract_cookie_name(self, cookie_header: str) -> str:
        """Extract cookie name from Set-Cookie header"""
        match = re.match(r'^([^=]+)=', cookie_header)
        return match.group(1) if match else 'unknown'
    
    def _extract_samesite(self, cookie_header: str) -> str:
        """Extract SameSite attribute from cookie"""
        match = re.search(r'SameSite=([^;]+)', cookie_header, re.IGNORECASE)
        return match.group(1) if match else ''
    
    def _extract_cookie_attribute(self, cookie_header: str, attr: str) -> str:
        """Extract specific attribute from cookie"""
        match = re.search(f'{attr}=([^;]+)', cookie_header, re.IGNORECASE)
        return match.group(1) if match else ''
    
    def _check_security_headers_presence(self, headers: Dict[str, str]) -> Dict[str, bool]:
        """Check presence of various security headers"""
        security_headers = {
            'Strict-Transport-Security': bool(headers.get('Strict-Transport-Security')),
            'Content-Security-Policy': bool(headers.get('Content-Security-Policy')),
            'X-Content-Type-Options': bool(headers.get('X-Content-Type-Options')),
            'X-Frame-Options': bool(headers.get('X-Frame-Options')),
            'X-XSS-Protection': bool(headers.get('X-XSS-Protection')),
            'Referrer-Policy': bool(headers.get('Referrer-Policy')),
            'Permissions-Policy': bool(headers.get('Permissions-Policy') or headers.get('Feature-Policy')),
            'Expect-CT': bool(headers.get('Expect-CT')),
            'Public-Key-Pins': bool(headers.get('Public-Key-Pins')),
        }
        return security_headers
    
    def _check_server_info(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze server information headers"""
        server = headers.get('Server', '')
        powered_by = headers.get('X-Powered-By', '')
        
        result = {
            'server': server,
            'x_powered_by': powered_by,
            'issues': []
        }
        
        if server:
            self._add_finding(
                self.SEVERITY_LOW,
                "Server Information Disclosure",
                f"Server header reveals technology: {server}",
                "Consider removing or genericizing the Server header."
            )
            result['issues'].append('server information disclosed')
            
        if powered_by:
            self._add_finding(
                self.SEVERITY_LOW,
                "X-Powered-By Information Disclosure",
                f"X-Powered-By header reveals technology: {powered_by}",
                "Remove the X-Powered-By header to avoid information disclosure."
            )
            result['issues'].append('x-powered-by information disclosed')
            
        return result
    
    def _check_cache_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check cache control headers"""
        cache_control = headers.get('Cache-Control', '')
        pragma = headers.get('Pragma', '')
        expires = headers.get('Expires', '')
        
        result = {
            'cache_control': cache_control,
            'pragma': pragma,
            'expires': expires,
            'issues': []
        }
        
        sensitive_paths = ['login', 'auth', 'session', 'token', 'password', 'credit', 'bank']
        if any(path in cache_control.lower() for path in ['public', 'max-age']):
            if any(sensitive in headers.get('Content-Type', '').lower() for sensitive in ['html', 'json']):
                self._add_finding(
                    self.SEVERITY_MEDIUM,
                    "Potential Sensitive Content Caching",
                    "Cache-Control headers may allow caching of sensitive content.",
                    "Review caching policies for sensitive pages and API endpoints."
                )
                result['issues'].append('potential sensitive content caching')
                
        return result
    
    def _check_ssl(self, url: str) -> Dict[str, Any]:
        """Comprehensive SSL/TLS check"""
        hostname = urlparse(url).hostname
        port = 443
        
        result = {
            'valid': False,
            'certificate': {},
            'protocols': {},
            'ciphers': [],
            'issues': []
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    result['certificate'] = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert.get('version', 'Unknown'),
                        'serialNumber': cert.get('serialNumber', 'Unknown'),
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter'],
                        'subjectAltName': cert.get('subjectAltName', []),
                    }
                    
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now() + timedelta(days=30):
                        self._add_finding(
                            self.SEVERITY_HIGH,
                            "SSL Certificate Expiring Soon",
                            f"SSL certificate expires on {not_after.strftime('%Y-%m-%d')}",
                            "Renew SSL certificate before expiration."
                        )
                        result['issues'].append('certificate expiring soon')
                    
                    result['valid'] = True
                    result['protocol'] = ssock.version()
                    result['cipher'] = {
                        'name': cipher[0],
                        'version': cipher[1],
                        'bits': cipher[2]
                    }
                    
        except ssl.SSLCertVerificationError as e:
            self._add_finding(
                self.SEVERITY_HIGH,
                "SSL Certificate Verification Failed",
                f"SSL certificate verification failed: {str(e)}",
                "Fix SSL certificate configuration issues."
            )
            result['issues'].append('certificate verification failed')
            
        except Exception as e:
            self._add_finding(
                self.SEVERITY_MEDIUM,
                "SSL Check Failed",
                f"SSL/TLS check failed: {str(e)}",
                "Investigate SSL/TLS configuration issues."
            )
            result['issues'].append(f'ssl check failed: {str(e)}')
            
        return result
    
    def _get_network_info(self, hostname: str) -> Dict[str, Any]:
        """Get network and DNS information"""
        result = {
            'hostname': hostname,
            'ip_addresses': [],
            'dns_records': {},
            'issues': []
        }
        
        try:
            answers = dns.resolver.resolve(hostname, 'A')
            result['ip_addresses'] = [str(r) for r in answers]
            
            record_types = ['MX', 'TXT', 'NS', 'CNAME']
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(hostname, record_type)
                    result['dns_records'][record_type] = [str(r) for r in answers]
                except:
                    result['dns_records'][record_type] = []
                    
        except Exception as e:
            result['issues'].append(f'dns resolution failed: {str(e)}')
            
        return result
    
    def _perform_additional_checks(self, response: requests.Response):
        """Perform additional security checks"""
        self._check_for_exposed_information(response)
        self._check_for_debug_features(response)
        
    def _check_for_exposed_information(self, response: requests.Response):
        """Check for potentially exposed sensitive information"""
        content = response.text.lower()
        
        sensitive_patterns = {
            'email': r'[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}',
            'api_key': r'[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}',
            'password': r'password[=:]\s*[\w]+',
            'credit_card': r'\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}',
        }
        
        for pattern_name, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self._add_finding(
                    self.SEVERITY_HIGH,
                    f"Potential {pattern_name.replace('_', ' ').title()} Exposure",
                    f"Possible {pattern_name} found in response content",
                    "Review response content and remove any sensitive information."
                )
    
    def _check_for_debug_features(self, response: requests.Response):
        """Check for enabled debug features"""
        content = response.text.lower()
        headers = response.headers
        
        if 'debug' in str(headers).lower() or 'test' in str(headers).lower():
            self._add_finding(
                self.SEVERITY_MEDIUM,
                "Debug Information in Headers",
                "Debug or test information found in response headers",
                "Disable debug features in production environment."
            )
            
        debug_indicators = ['debug', 'console.log', 'var_dump', 'print_r', 'stack trace']
        if any(indicator in content for indicator in debug_indicators):
            self._add_finding(
                self.SEVERITY_MEDIUM,
                "Debug Information in Content",
                "Debug information found in response content",
                "Disable debug features and error reporting in production environment."
            )
    
    def _calculate_risk_score(self) -> Tuple[int, str]:
        """Calculate overall risk score based on findings"""
        severity_weights = {
            self.SEVERITY_CRITICAL: 10,
            self.SEVERITY_HIGH: 7,
            self.SEVERITY_MEDIUM: 4,
            self.SEVERITY_LOW: 1,
            self.SEVERITY_INFO: 0
        }
        
        total_score = sum(severity_weights.get(f.severity, 0) for f in self.findings)
        
        max_possible_score = 10 * len(self.findings) if self.findings else 1
        risk_score = min(100, int((total_score / max_possible_score) * 100))
        
        if risk_score >= 80:
            grade = 'F'
        elif risk_score >= 60:
            grade = 'D'
        elif risk_score >= 40:
            grade = 'C'
        elif risk_score >= 20:
            grade = 'B'
        else:
            grade = 'A'
            
        return risk_score, grade
    
    def _add_finding(self, severity: str, title: str, description: str, recommendation: str = "", confidence: str = "high", reference: str = ""):
        """Add a security finding"""
        finding = SecurityFinding(
            severity=severity,
            title=title,
            description=description,
            recommendation=recommendation or f"Consider addressing this {severity} issue.",
            confidence=confidence,
            reference=reference
        )
        self.findings.append(finding)
    
    def scan_multiple(self, urls: List[str], max_workers: int = 5) -> List[Dict[str, Any]]:
        """Scan multiple URLs concurrently"""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(self.scan, url): url for url in urls}
            
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({
                        'url': url,
                        'error': str(e),
                        'scan_date': datetime.now().isoformat()
                    })
        
        return results

class ReportGenerator:
    """Generate reports in various formats"""
    
    @staticmethod
    def generate_text_report(results: Dict[str, Any]) -> str:
        """Generate human-readable text report"""
        report = []
        report.append("=" * 60)
        report.append("HTTP HEADER SECURITY SCAN REPORT")
        report.append("=" * 60)
        report.append(f"Target URL: {results.get('target_url', 'N/A')}")
        report.append(f"Scan Date: {results.get('scan_date', 'N/A')}")
        report.append(f"Final URL: {results.get('final_url', 'N/A')}")
        report.append(f"Status Code: {results.get('status_code', 'N/A')}")
        report.append(f"Scan Duration: {results.get('scan_duration', 0)} seconds")
        report.append(f"Risk Score: {results.get('risk_score', 0)}/100")
        report.append(f"Security Grade: {results.get('grade', 'F')}")
        report.append("")
        
        findings = results.get('findings', [])
        if findings:
            report.append("SECURITY FINDINGS:")
            report.append("-" * 40)
            
            by_severity = {}
            for finding in findings:
                severity = finding.get('severity', 'info')
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(finding)
            
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity in by_severity:
                    report.append(f"\n{severity.upper()} SEVERITY FINDINGS:")
                    for i, finding in enumerate(by_severity[severity], 1):
                        report.append(f"{i}. {finding.get('title', 'Unknown')}")
                        report.append(f"   Description: {finding.get('description', '')}")
                        report.append(f"   Recommendation: {finding.get('recommendation', '')}")
                        report.append("")
        else:
            report.append("No security findings detected.")
            report.append("")
        
        headers = results.get('headers', {})
        if headers:
            report.append("DETECTED HEADERS:")
            report.append("-" * 40)
            for header, value in headers.items():
                report.append(f"{header}: {value}")
            report.append("")
        
        return "\n".join(report)
    
    @staticmethod
    def generate_json_report(results: Dict[str, Any]) -> str:
        """Generate JSON report"""
        return json.dumps(results, indent=2, default=str)
    
    @staticmethod
    def generate_csv_report(results: Dict[str, Any]) -> str:
        """Generate CSV report"""
        output = []
        
        output.append("Category,Key,Value")
        output.append(f"Scan,Target URL,{results.get('target_url', '')}")
        output.append(f"Scan,Scan Date,{results.get('scan_date', '')}")
        output.append(f"Scan,Final URL,{results.get('final_url', '')}")
        output.append(f"Scan,Status Code,{results.get('status_code', '')}")
        output.append(f"Scan,Risk Score,{results.get('risk_score', '')}")
        output.append(f"Scan,Security Grade,{results.get('grade', '')}")
        
        for finding in results.get('findings', []):
            output.append(f"Finding,{finding.get('severity', '')},{finding.get('title', '')}")
        
        for header, value in results.get('headers', {}).items():
            output.append(f"Header,{header},{value}")
        
        return "\n".join(output)
    
    @staticmethod
    def generate_html_report(results: Dict[str, Any]) -> str:
        """Generate a styled, severity-colored HTML report."""
        severity_colors = {
            'critical': '#7f1d1d', 'high': '#dc2626', 'medium': '#d97706',
            'low': '#2563eb', 'info': '#6b7280'
        }
        grade_colors = {'A': '#16a34a', 'B': '#65a30d', 'C': '#d97706', 'D': '#ea580c', 'F': '#dc2626'}

        findings = results.get('findings', [])
        by_severity: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            by_severity.setdefault(f.get('severity', 'info'), []).append(f)

        findings_html = ""
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            group = by_severity.get(severity, [])
            if not group:
                continue
            color = severity_colors.get(severity, '#6b7280')
            findings_html += f'<h3 style="color:{color};text-transform:uppercase;margin-top:24px;">{severity} ({len(group)})</h3>'
            for f in group:
                ref = f.get('reference')
                ref_html = f'<div class="ref"><a href="{ref}" target="_blank">{ref}</a></div>' if ref else ''
                findings_html += f"""
                <div class="finding" style="border-left:4px solid {color};">
                    <div class="finding-title">{f.get('title', 'Unknown')}</div>
                    <div class="finding-desc">{f.get('description', '')}</div>
                    <div class="finding-rec"><strong>Fix:</strong> {f.get('recommendation', '')}</div>
                    {ref_html}
                </div>"""

        if not findings:
            findings_html = '<p class="none">No security findings detected.</p>'

        headers_html = "".join(
            f'<tr><td class="hkey">{k}</td><td>{v}</td></tr>'
            for k, v in results.get('headers', {}).items()
        )

        grade = results.get('grade', 'F')
        grade_color = grade_colors.get(grade, '#dc2626')

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Scan Report - {results.get('target_url', '')}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#0f1115; color:#e5e7eb; margin:0; padding:32px; }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 22px; word-break: break-all; }}
  .meta {{ color:#9ca3af; font-size:14px; margin-bottom:24px; }}
  .scorebox {{ display:flex; align-items:center; gap:20px; background:#161a22; border-radius:12px; padding:20px; margin-bottom:24px; }}
  .grade {{ font-size:48px; font-weight:800; color:{grade_color}; width:80px; text-align:center; }}
  .score {{ font-size:16px; color:#d1d5db; }}
  .finding {{ background:#161a22; border-radius:6px; padding:12px 16px; margin:10px 0; }}
  .finding-title {{ font-weight:700; margin-bottom:4px; }}
  .finding-desc {{ color:#cbd5e1; font-size:14px; margin-bottom:6px; }}
  .finding-rec {{ font-size:14px; color:#a7f3d0; }}
  .ref a {{ color:#60a5fa; font-size:12px; }}
  table {{ width:100%; border-collapse: collapse; margin-top:12px; font-size:13px; }}
  td {{ padding:6px 8px; border-bottom:1px solid #262b36; vertical-align:top; word-break:break-all; }}
  .hkey {{ color:#93c5fd; width:260px; font-weight:600; }}
  .none {{ color:#4ade80; }}
</style>
</head>
<body>
<div class="container">
  <h1>Security Scan Report</h1>
  <div class="meta">
    Target: {results.get('target_url', 'N/A')}<br>
    Final URL: {results.get('final_url', 'N/A')}<br>
    Scanned: {results.get('scan_date', 'N/A')} &middot; Duration: {results.get('scan_duration', 0)}s &middot; Status: {results.get('status_code', 'N/A')}
  </div>
  <div class="scorebox">
    <div class="grade">{grade}</div>
    <div class="score">Risk Score<br><strong style="font-size:20px;">{results.get('risk_score', 0)}/100</strong></div>
  </div>
  <h2>Findings</h2>
  {findings_html}
  <h2>Detected Headers</h2>
  <table>{headers_html}</table>
</div>
</body>
</html>"""

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Advanced HTTP Header Security Scanner')
    parser.add_argument('url', nargs='*', help='URL(s) to scan')
    parser.add_argument('--input', '-i', help='Input file containing URLs (one per line)')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--format', '-f', choices=['text', 'json', 'csv', 'html'], default='text', help='Output format')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL verification')
    parser.add_argument('--user-agent', '-ua', help='Custom User-Agent string')
    parser.add_argument('--workers', '-w', type=int, default=5, help='Number of concurrent workers for multiple URLs')
    
    args = parser.parse_args()
    
    # Get URLs to scan
    urls = args.url
    if args.input:
        try:
            with open(args.input, 'r') as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"Error: Input file '{args.input}' not found.")
            sys.exit(1)
    
    if not urls:
        print("Error: No URLs specified. Use --help for usage information.")
        sys.exit(1)
    
    scanner = HTTPHeaderScanner(
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        user_agent=args.user_agent
    )
    
    # Perform scan
    if len(urls) == 1:
        results = scanner.scan(urls[0])
    else:
        results = scanner.scan_multiple(urls, max_workers=args.workers)
    
    # Generate report
    if args.format == 'json':
        report = ReportGenerator.generate_json_report(results)
    elif args.format == 'csv':
        report = ReportGenerator.generate_csv_report(results)
    elif args.format == 'html':
        report = ReportGenerator.generate_html_report(results)
    else:
        if isinstance(results, list):
            report = "\n\n".join([ReportGenerator.generate_text_report(r) for r in results])
        else:
            report = ReportGenerator.generate_text_report(results)
    
    # Output results
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"Report saved to {args.output}")
        except IOError as e:
            print(f"Error writing to file: {e}")
            print(report)
    else:
        print(report)

if __name__ == "__main__":
    main()