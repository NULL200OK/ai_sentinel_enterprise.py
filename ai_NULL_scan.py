print("""

███╗░░██╗██╗░░░██╗██╗░░░░░██╗░░░░░██████╗░░█████╗░░█████╗░  ░█████╗░██╗░░██╗
████╗░██║██║░░░██║██║░░░░░██║░░░░░╚════██╗██╔══██╗██╔══██╗  ██╔══██╗██║░██╔╝
██╔██╗██║██║░░░██║██║░░░░░██║░░░░░░░███╔═╝██║░░██║██║░░██║  ██║░░██║█████═╝░
██║╚████║██║░░░██║██║░░░░░██║░░░░░██╔══╝░░██║░░██║██║░░██║  ██║░░██║██╔═██╗░
██║░╚███║╚██████╔╝███████╗███████╗███████╗╚█████╔╝╚█████╔╝  ╚█████╔╝██║░╚██╗
╚═╝░░╚══╝░╚═════╝░╚══════╝╚══════╝╚══════╝░╚════╝░░╚════╝░  ░╚════╝░╚═╝░░╚═╝
AI-SENTINEL v4.0  – ENTERPRISE GRADE – NULL200OK-AI 💀🔥created by NABEEL 🔥💀

Modular engine, intelligent crawler, parallel scanning, WAF detection, 20+ attack vectors.
""")

import asyncio, aiohttp, ssl, socket, argparse, json, pathlib, datetime, hashlib, random, string, sys, re, time, threading
from collections import defaultdict, deque
from urllib.parse import urljoin, urlparse, parse_qs, quote, unquote, urlsplit
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Any, Tuple, Callable
from enum import Enum, auto
from pathlib import Path
from rich.console import Console; console = Console()
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.logging import RichHandler
from rich.panel import Panel
from rich.columns import Columns
import logging
import dns.resolver
import dns.asyncresolver
import ipaddress

# Enterprise-grade logging
logging.basicConfig(level=logging.INFO, format="%(message)s", datefmt="[%X]", handlers=[RichHandler(show_path=False, markup=True)])
log = logging.getLogger("SENTINEL")

# --------------------------------------------------------------------------- #
# VULNERABILITY DATA STRUCTURES
# --------------------------------------------------------------------------- #
class Severity(Enum):
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()

@dataclass
class Vulnerability:
    vid: str
    type: str
    url: str
    severity: Severity
    description: str
    proof: str
    payload: str = ""
    parameter: str = ""
    remediation: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)
    references: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "id": self.vid,
            "type": self.type,
            "url": self.url,
            "severity": self.severity.name,
            "description": self.description,
            "proof": self.proof,
            "payload": self.payload,
            "parameter": self.parameter,
            "remediation": self.remediation,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "timestamp": self.timestamp.isoformat(),
            "references": self.references
        }

# --------------------------------------------------------------------------- #
# AI MUTATION ENGINE
# --------------------------------------------------------------------------- #
class MicroLLM:
    """Minimal AI for payload mutation"""
    def mutate(self, payload: str) -> str:
        mutations = [
            lambda p: p + "/*" + ''.join(random.choices(string.ascii_letters, k=3)) + "*/",
            lambda p: p.replace("'", "%27").replace('"', "%22"),
            lambda p: p.upper(),
            lambda p: p + chr(random.randint(0, 31)),
            lambda p: p + "-- -",
            lambda p: "/*!00000" + p + "*/",
            lambda p: p + " AND 1=1",
            lambda p: p + " OR 1=1",
            lambda p: p.replace("<", "&lt;"),
            lambda p: p.replace(">", "&gt;"),
        ]
        return random.choice(mutations)(payload)

# --------------------------------------------------------------------------- #
# ENTERPRISE CONFIGURATION
# --------------------------------------------------------------------------- #
CONFIG = {
    "max_depth": 3,
    "max_concurrent": 100,
    "rate_limit": 50,  # requests per second
    "timeout": 10,
    "user_agents": [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    ],
    "scan_modes": ["passive", "active", "aggressive"],
    "payloads": {
        "sqli": ["'", "')", "''", "' OR '1'='1", "' UNION SELECT NULL--", "sleep(5)"],
        "xss": ["<svg onload=alert(1)>", "\"><script>alert(1)</script>", "javascript:alert(1)"],
        "ssrf": ["gopher://127.0.0.1:6379/_info", "http://169.254.169.254/latest/meta-data", "file:///etc/passwd"],
        "lfi": ["../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
        "cmdi": [";id", "|id", "`id`", "$(id)"],
    },
    "waf_signatures": {
        "cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
        "akamai": ["akamai", "x-akamai"],
        "imperva": ["x-iinfo", "x-distil-cs"],
    },
    "tech_signatures": {
        "nginx": ["nginx", "x-powered-by"],
        "apache": ["apache", "x-powered-by"],
        "node.js": ["node.js", "express"],
        "php": ["x-powered-by: php", "php-"],
        "wordpress": ["wp-", "wordpress"],
        "drupal": ["drupal", "x-generator: drupal"],
        "joomla": ["joomla"],
    }
}

# Common subdomain wordlist
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "secure", "api", "dev", "test", "stage", "staging",
    "app", "apps", "web", "webmail", "portal", "cdn", "m", "mobile", "static", "img",
    "images", "support", "help", "blog", "news", "forum", "shop", "store", "payment",
    "payments", "login", "signin", "account", "dashboard", "panel", "control", "cpanel",
    "whm", "webdisk", "webadmin", "server", "ns1", "ns2", "dns", "mx", "mail2", "smtp",
    "pop", "imap", "git", "svn", "vpn", "remote", "ssh", "ftp2", "backup", "demo",
    "beta", "alpha", "live", "prod", "production", "intranet", "extranet", "partner",
    "partners", "client", "clients", "customer", "customers", "member", "members",
    "community", "social", "media", "share", "sharing", "upload", "download", "files",
    "file", "docs", "documents", "wiki", "knowledge", "kb", "helpdesk", "ticket",
    "tickets", "status", "monitor", "monitoring", "stats", "statistics", "analytics",
    "track", "tracking", "ads", "ad", "advert", "advertising", "market", "marketing",
    "campaign", "campaigns", "event", "events", "calendar", "schedule", "scheduler",
    "time", "clock", "timer", "countdown", "counter", "vote", "poll", "survey",
    "quiz", "test", "exam", "assessment", "result", "results", "score", "scores",
    "leaderboard", "rank", "ranking", "top", "best", "worst", "first", "last"
]

# --------------------------------------------------------------------------- #
# SUBDOMAIN DISCOVERY MODULE
# --------------------------------------------------------------------------- #
class SubdomainHunter:
    def __init__(self, domain: str):
        self.domain = domain
        self.live_subdomains = set()
        self.all_subdomains = set()
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        self.common_subdomains = SUBDOMAIN_WORDLIST
    
    async def discover_subdomains(self) -> List[str]:
        """Discover subdomains using multiple techniques"""
        console.print(f"[bold cyan]Phase 0: Subdomain Discovery for {self.domain}[/bold cyan]")
        
        tasks = []
        # Brute force with common subdomains
        for sub in self.common_subdomains[:20]:  # Limit to first 20 for speed
            tasks.append(self.check_subdomain(f"{sub}.{self.domain}"))
        
        # Also check without subdomain
        tasks.append(self.check_subdomain(self.domain))
        
        # Check common variations
        variations = ["m", "mobile", "api", "admin", "dev", "test", "staging"]
        for var in variations:
            tasks.append(self.check_subdomain(f"{var}.{self.domain}"))
            tasks.append(self.check_subdomain(f"{var}-{self.domain}"))
            tasks.append(self.check_subdomain(f"{self.domain}-{var}"))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        live_subs = []
        for result in results:
            if isinstance(result, str) and result:
                live_subs.append(result)
                self.live_subdomains.add(result)
        
        # Sort and deduplicate
        self.live_subdomains = sorted(set(self.live_subdomains))
        
        # Save discovered subdomains
        self.save_subdomains()
        
        console.print(f"[green]✓ Found {len(self.live_subdomains)} live subdomains[/green]")
        for sub in self.live_subdomains:
            console.print(f"  - {sub}")
        
        return list(self.live_subdomains)
    
    async def check_subdomain(self, subdomain: str) -> Optional[str]:
        """Check if a subdomain exists and is reachable"""
        try:
            # Check DNS resolution first
            try:
                answers = await self.resolver.resolve(subdomain, 'A')
                if answers:
                    # Check if it's reachable via HTTP/HTTPS
                    for protocol in ['https', 'http']:
                        url = f"{protocol}://{subdomain}"
                        try:
                            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
                                async with session.head(url, allow_redirects=True, ssl=False) as response:
                                    if response.status < 400:
                                        console.print(f"[yellow]Found live subdomain: {subdomain} ({protocol})[/yellow]")
                                        return f"{protocol}://{subdomain}"
                        except:
                            continue
                    return f"https://{subdomain}"  # Return even if HTTP check fails but DNS resolves
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                return None
        except Exception as e:
            return None
        return None
    
    def save_subdomains(self):
        """Save discovered subdomains to file"""
        if not self.live_subdomains:
            return
        
        filename = f"results/{self.domain}_subdomains.txt"
        Path("results").mkdir(exist_ok=True)
        
        with open(filename, "w") as f:
            f.write(f"# Subdomains discovered for {self.domain} on {datetime.datetime.now()}\n")
            f.write("#" * 50 + "\n\n")
            for sub in sorted(self.live_subdomains):
                f.write(f"{sub}\n")
        
        console.print(f"[green]Subdomains saved to: {filename}[/green]")

# --------------------------------------------------------------------------- #
# ENDPOINT DISCOVERY AND TRACKING
# --------------------------------------------------------------------------- #
class EndpointTracker:
    def __init__(self, domain: str):
        self.domain = domain
        self.discovered_endpoints = defaultdict(list)  # subdomain -> [endpoints]
        self.scanned_endpoints = defaultdict(list)     # subdomain -> [endpoints]
        self.vulnerable_endpoints = defaultdict(list)  # subdomain -> [endpoints with vulns]
    
    def add_endpoint(self, subdomain: str, endpoint: str):
        """Add discovered endpoint"""
        if endpoint not in self.discovered_endpoints[subdomain]:
            self.discovered_endpoints[subdomain].append(endpoint)
    
    def mark_scanned(self, subdomain: str, endpoint: str):
        """Mark endpoint as scanned"""
        if endpoint not in self.scanned_endpoints[subdomain]:
            self.scanned_endpoints[subdomain].append(endpoint)
    
    def mark_vulnerable(self, subdomain: str, endpoint: str, vulnerability: str):
        """Mark endpoint as vulnerable"""
        self.vulnerable_endpoints[subdomain].append({
            "url": endpoint,
            "vulnerability": vulnerability,
            "timestamp": datetime.datetime.now().isoformat()
        })
    
    def get_stats(self) -> Dict:
        """Get statistics about endpoints"""
        total_discovered = sum(len(endpoints) for endpoints in self.discovered_endpoints.values())
        total_scanned = sum(len(endpoints) for endpoints in self.scanned_endpoints.values())
        total_vulnerable = sum(len(endpoints) for endpoints in self.vulnerable_endpoints.values())
        
        return {
            "total_discovered": total_discovered,
            "total_scanned": total_scanned,
            "total_vulnerable": total_vulnerable,
            "subdomains_count": len(self.discovered_endpoints),
            "discovered_by_subdomain": {k: len(v) for k, v in self.discovered_endpoints.items()},
            "vulnerable_by_subdomain": {k: len(v) for k, v in self.vulnerable_endpoints.items()}
        }
    
    def save_endpoints(self):
        """Save all endpoints to files"""
        Path("results").mkdir(exist_ok=True)
        
        # Save discovered endpoints
        with open(f"results/{self.domain}_discovered_endpoints.txt", "w") as f:
            f.write(f"# Discovered Endpoints for {self.domain}\n")
            f.write(f"# Generated: {datetime.datetime.now()}\n")
            f.write("#" * 60 + "\n\n")
            
            for subdomain, endpoints in self.discovered_endpoints.items():
                f.write(f"\n[ {subdomain} ]\n")
                f.write("-" * 40 + "\n")
                for endpoint in sorted(endpoints):
                    f.write(f"{endpoint}\n")
        
        # Save vulnerable endpoints
        if any(self.vulnerable_endpoints.values()):
            with open(f"results/{self.domain}_vulnerable_endpoints.txt", "w") as f:
                f.write(f"# Vulnerable Endpoints for {self.domain}\n")
                f.write(f"# Generated: {datetime.datetime.now()}\n")
                f.write("#" * 60 + "\n\n")
                
                for subdomain, vulnerabilities in self.vulnerable_endpoints.items():
                    f.write(f"\n[ {subdomain} ]\n")
                    f.write("-" * 40 + "\n")
                    for vuln in vulnerabilities:
                        f.write(f"URL: {vuln['url']}\n")
                        f.write(f"Vulnerability: {vuln['vulnerability']}\n")
                        f.write(f"Time: {vuln['timestamp']}\n")
                        f.write("-" * 30 + "\n")
        
        # Save JSON summary
        summary = {
            "domain": self.domain,
            "timestamp": datetime.datetime.now().isoformat(),
            "stats": self.get_stats(),
            "discovered_endpoints": self.discovered_endpoints,
            "vulnerable_endpoints": self.vulnerable_endpoints
        }
        
        with open(f"results/{self.domain}_endpoints_summary.json", "w") as f:
            json.dump(summary, f, indent=2, default=str)
        
        console.print(f"[green]Endpoints saved to results/{self.domain}_* files[/green]")

# --------------------------------------------------------------------------- #
# PLUGIN ARCHITECTURE – PLUGGABLE SCANNERS
# --------------------------------------------------------------------------- #
class ScannerPlugin:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    async def scan(self, url: str, engine) -> Optional[Any]:
        raise NotImplementedError

class SQLiPlugin(ScannerPlugin):
    def __init__(self):
        super().__init__("SQLi", "SQL Injection detector")

    async def scan(self, url: str, engine) -> Optional[Vulnerability]:
        parsed = urlparse(url)
        if not parsed.query:
            return None
            
        for param, vals in parse_qs(parsed.query).items():
            for bp in CONFIG["payloads"]["sqli"]:
                p = engine.ai_mutate(bp)
                test_url = url.replace(f"{param}={vals[0]}", f"{param}={quote(p)}")
                req, resp = await engine.capture("GET", test_url, {}, b"")
                if resp and any(err in resp.body.decode(errors="ignore").lower() for err in ["sql", "mysql", "syntax", "warning", "mysql_fetch", "mysql_"]):
                    return Vulnerability(
                        vid=engine.digest("SQLi", url, p),
                        type="SQL_INJECTION",
                        url=test_url,
                        severity=Severity.CRITICAL,
                        description=f"Boolean-based SQL injection via parameter '{param}'",
                        proof=f"Payload '{p}' triggered SQL error response",
                        payload=p,
                        parameter=param,
                        remediation="Use parameterized queries and prepared statements",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cvss_score=9.8,
                    )
        return None

class XSSPlugin(ScannerPlugin):
    def __init__(self):
        super().__init__("XSS", "Cross-Site Scripting detector")

    async def scan(self, url: str, engine) -> Optional[Vulnerability]:
        parsed = urlparse(url)
        if not parsed.query:
            return None
            
        for param, vals in parse_qs(parsed.query).items():
            for bp in CONFIG["payloads"]["xss"]:
                p = engine.ai_mutate(bp)
                test_url = url.replace(f"{param}={vals[0]}", f"{param}={quote(p)}")
                req, resp = await engine.capture("GET", test_url, {}, b"")
                if resp and p in resp.body.decode(errors="ignore"):
                    return Vulnerability(
                        vid=engine.digest("XSS", url, p),
                        type="CROSS_SITE_SCRIPTING",
                        url=test_url,
                        severity=Severity.HIGH,
                        description=f"Reflected XSS via parameter '{param}'",
                        proof=f"Payload '{p}' reflected verbatim in response",
                        payload=p,
                        parameter=param,
                        remediation="Implement proper output encoding and Content-Security-Policy",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        cvss_score=6.1,
                    )
        return None

class SSRFPlugin(ScannerPlugin):
    def __init__(self):
        super().__init__("SSRF", "Server-Side Request Forgery detector")

    async def scan(self, url: str, engine) -> Optional[Vulnerability]:
        parsed = urlparse(url)
        if not parsed.query: 
            return None
            
        for param, vals in parse_qs(parsed.query).items():
            for payload in CONFIG["payloads"]["ssrf"]:
                test_url = url.replace(f"{param}={vals[0]}", f"{param}={quote(payload)}")
                req, resp = await engine.capture("GET", test_url, {}, b"")
                if resp and (b"root:" in resp.body or b"127.0.0.1" in resp.body or b"aws" in resp.body.lower()):
                    return Vulnerability(
                        vid=engine.digest("SSRF", url, param),
                        type="SSRF",
                        url=test_url,
                        severity=Severity.CRITICAL,
                        description=f"Server-Side Request Forgery via parameter '{param}'",
                        proof=f"Payload '{payload}' triggered internal service response",
                        payload=payload,
                        parameter=param,
                        remediation="Implement allowlists for internal resources, validate URLs",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cvss_score=9.8,
                    )
        return None

class LFIPlugin(ScannerPlugin):
    def __init__(self):
        super().__init__("LFI", "Local File Inclusion detector")

    async def scan(self, url: str, engine) -> Optional[Vulnerability]:
        parsed = urlparse(url)
        if not parsed.query: 
            return None
            
        for param, vals in parse_qs(parsed.query).items():
            for bp in CONFIG["payloads"]["lfi"]:
                p = engine.ai_mutate(bp)
                test_url = url.replace(f"{param}={vals[0]}", f"{param}={quote(p)}")
                req, resp = await engine.capture("GET", test_url, {}, b"")
                if resp and (b"root:" in resp.body or b"127.0.0.1" in resp.body or b"<html" not in resp.body.lower()):
                    return Vulnerability(
                        vid=engine.digest("LFI", url, p),
                        type="LOCAL_FILE_INCLUSION",
                        url=test_url,
                        severity=Severity.CRITICAL,
                        description=f"Local File Inclusion via parameter '{param}'",
                        proof=f"Payload '{p}' triggered file content disclosure",
                        payload=p,
                        parameter=param,
                        remediation="Implement proper file path validation and use allowlists",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cvss_score=9.8,
                    )
        return None

class CMDiPlugin(ScannerPlugin):
    def __init__(self):
        super().__init__("CMDi", "Command Injection detector")

    async def scan(self, url: str, engine) -> Optional[Vulnerability]:
        parsed = urlparse(url)
        if not parsed.query: 
            return None
            
        for param, vals in parse_qs(parsed.query).items():
            for bp in CONFIG["payloads"]["cmdi"]:
                p = engine.ai_mutate(bp)
                test_url = url.replace(f"{param}={vals[0]}", f"{param}={quote(p)}")
                req, resp = await engine.capture("GET", test_url, {}, b"")
                if resp and (b"uid=" in resp.body or b"gid=" in resp.body or b"root:" in resp.body):
                    return Vulnerability(
                        vid=engine.digest("CMDi", url, p),
                        type="COMMAND_INJECTION",
                        url=test_url,
                        severity=Severity.CRITICAL,
                        description=f"Command Injection via parameter '{param}'",
                        proof=f"Payload '{p}' executed system command",
                        payload=p,
                        parameter=param,
                        remediation="Use parameterized APIs and avoid shell command execution",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cvss_score=9.8,
                    )
        return None

class PassivePlugin(ScannerPlugin):
    def __init__(self):
        super().__init__("Passive", "Passive information gathering")

    async def scan(self, url: str, engine) -> List[Vulnerability]:
        vulns = []
        req, resp = await engine.capture("GET", url, {}, b"")
        if not resp:
            return vulns
            
        # Check for security headers
        security_headers = {
            "X-Frame-Options": "Missing X-Frame-Options (Clickjacking)",
            "X-Content-Type-Options": "Missing X-Content-Type-Options (MIME sniffing)",
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing CSP",
            "X-XSS-Protection": "Missing XSS protection header",
        }
        
        for header, desc in security_headers.items():
            if header not in resp.headers:
                vulns.append(Vulnerability(
                    vid=engine.digest("MISSING_HEADER", url, header),
                    type="MISSING_SECURITY_HEADER",
                    url=url,
                    severity=Severity.MEDIUM,
                    description=desc,
                    proof=f"Header '{header}' not present in response",
                    remediation=f"Add '{header}' header with appropriate value",
                ))

        # Check for tech stack disclosure
        headers_str = str(resp.headers).lower()
        body_str = resp.body.decode(errors="ignore").lower()
        
        for tech, signatures in CONFIG["tech_signatures"].items():
            for sig in signatures:
                if sig.lower() in headers_str or sig.lower() in body_str:
                    vulns.append(Vulnerability(
                        vid=engine.digest("TECH_DISCLOSURE", url, tech),
                        type="INFORMATION_DISCLOSURE",
                        url=url,
                        severity=Severity.LOW,
                        description=f"Technology stack disclosed: {tech}",
                        proof=f"Signature '{sig}' found in response",
                        remediation="Remove tech stack headers and comments",
                    ))

        # Check CSP
        csp = resp.headers.get("Content-Security-Policy", "")
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            vulns.append(Vulnerability(
                vid=engine.digest("CSP_WEAK", url),
                type="WEAK_CSP",
                url=url,
                severity=Severity.MEDIUM,
                description="CSP contains unsafe directives",
                proof=f"CSP: {csp}",
                remediation="Remove unsafe-inline and unsafe-eval directives",
            ))

        return vulns

# --------------------------------------------------------------------------- #
# RATE LIMITER – TOKEN BUCKET
# --------------------------------------------------------------------------- #
class RateLimiter:
    def __init__(self, max_rate: int):
        self.max_rate = max_rate
        self.tokens = max_rate
        self.last_update = time.time()
        self.lock = threading.Lock()

    async def consume(self):
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            self.last_update = now
            self.tokens = min(self.max_rate, self.tokens + elapsed * self.max_rate)
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            await asyncio.sleep(1 / self.max_rate)
            return False

# --------------------------------------------------------------------------- #
# INTELLIGENT CRAWLER – DISCOVERS ALL ENDPOINTS
# --------------------------------------------------------------------------- #
class SmartCrawler:
    def __init__(self, engine, max_depth: int = 3):
        self.engine = engine
        self.max_depth = max_depth
        self.visited: Set[str] = set()
        self.forms: List[Dict] = []
        self.js_endpoints: Set[str] = set()

    async def crawl(self, start_url: str) -> Set[str]:
        urls = {start_url}
        console.print(f"[yellow]Starting crawl from {start_url} (max depth: {self.max_depth})[/yellow]")
        
        total_crawled = 0
        
        for depth in range(self.max_depth):
            next_batch = set()
            console.print(f"[cyan]Crawling depth {depth+1}/{self.max_depth}...[/cyan]")
            
            for url in urls:
                if url in self.visited: 
                    continue
                self.visited.add(url)
                
                try:
                    req, resp = await self.engine.capture("GET", url, {}, b"")
                    if not resp or resp.status != 200: 
                        continue
                        
                    content = resp.body.decode(errors="ignore")
                    
                    # Extract links
                    links = re.findall(r'href=[\'"]?([^\'" >]+)', content)
                    for link in links:
                        full = urljoin(url, link)
                        if self.engine.target in full and full not in self.visited:
                            next_batch.add(full)
                    
                    # Extract forms
                    forms = re.findall(r'<form[^>]+action=[\'"]?([^\'" >]+)[^>]*>', content)
                    for form in forms:
                        self.forms.append({"action": form, "method": "POST"})
                    
                    # Extract JS endpoints
                    js_files = re.findall(r'src=[\'"]?([^\'"\s]+\.js)', content)
                    for js in js_files:
                        js_url = urljoin(url, js)
                        await self.analyze_js(js_url)
                        
                    # Extract API endpoints
                    api_patterns = [
                        r'(?:fetch|axios|\.ajax|XMLHttpRequest)\([\'"`]([^\'"`]+)',
                        r'\.get\([\'"`]([^\'"`]+)',
                        r'\.post\([\'"`]([^\'"`]+)',
                        r'\.put\([\'"`]([^\'"`]+)',
                        r'\.delete\([\'"`]([^\'"`]+)',
                    ]
                    
                    for pattern in api_patterns:
                        matches = re.findall(pattern, content)
                        self.js_endpoints.update(matches)
                        
                except Exception as e:
                    log.debug(f"Crawl error on {url}: {e}")
                    
                total_crawled += 1
                if total_crawled % 10 == 0:
                    console.print(f"[yellow]  Crawled {total_crawled} URLs, found {len(next_batch)} new URLs[/yellow]")
                    
            urls = next_batch
            console.print(f"[green]Depth {depth+1} complete: Found {len(urls)} new URLs[/green]")
            
            if not urls:
                break
    
        total_endpoints = self.visited | {urljoin(start_url, e) for e in self.js_endpoints}
        console.print(f"[green]✓ Crawl complete: {len(total_endpoints)} endpoints discovered[/green]")
        return total_endpoints

    async def analyze_js(self, js_url: str):
        try:
            req, resp = await self.engine.capture("GET", js_url, {}, b"")
            if not resp or resp.status != 200: 
                return
            js_content = resp.body.decode(errors="ignore")
            
            # Extract API paths from JS
            api_patterns = [
                r'(?:fetch|axios|\.ajax|XMLHttpRequest)\([\'"`]([^\'"`]+)',
                r'\.get\([\'"`]([^\'"`]+)',
                r'\.post\([\'"`]([^\'"`]+)',
                r'\.put\([\'"`]([^\'"`]+)',
                r'\.delete\([\'"`]([^\'"`]+)',
                r'api[\/\.][\w\/\.\-]+',
                r'\/api\/[^\'"`\s]+',
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, js_content)
                self.js_endpoints.update(matches)
        except:
            pass

# --------------------------------------------------------------------------- #
# MAIN ENGINE – ORCHESTRATES EVERYTHING
# --------------------------------------------------------------------------- #
class AISentinelEngine:
    def __init__(self, target: str, mode: str = "active", max_depth: int = 3):
        # Parse target
        if "://" in target:
            parsed = urlparse(target)
            self.target = parsed.netloc
            self.base = f"{parsed.scheme}://{self.target}"
        else:
            self.target = target
            self.base = f"https://{self.target}"
        
        self.mode = mode
        self.max_depth = max_depth
        self.session = None
        self.vulns: List[Vulnerability] = []
        self.seen: Set[str] = set()
        self.llm = MicroLLM()
        self.rate_limiter = RateLimiter(CONFIG["max_concurrent"])
        self.plugins = self._load_plugins()
        self.endpoint_tracker = EndpointTracker(self.target)
        self.subdomain_hunter = SubdomainHunter(self.target)
        self.stats = {
            "status_codes": defaultdict(int),
            "vulns_by_type": defaultdict(int),
            "vulns_by_severity": defaultdict(int),
            "waf": None,
            "tech": set(),
            "start_time": time.time(),
            "end_time": None
        }
        self.lock = asyncio.Lock()
        
        # Create results directory
        Path("results").mkdir(exist_ok=True)

    def _load_plugins(self) -> List[ScannerPlugin]:
        plugins = [PassivePlugin()]
        if self.mode in ["active", "aggressive"]:
            plugins.extend([SQLiPlugin(), XSSPlugin(), SSRFPlugin(), LFIPlugin(), CMDiPlugin()])
        return plugins

    async def capture(self, method: str, url: str, headers: dict, body: bytes) -> tuple:
        """Capture HTTP request/response"""
        if self.session is None:
            self.session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False, limit=0),
                timeout=aiohttp.ClientTimeout(total=CONFIG["timeout"]),
                headers={"User-Agent": random.choice(CONFIG["user_agents"])}
            )
        
        try:
            async with self.session.request(method, url, headers=headers, data=body) as resp:
                resp_body = await resp.read()
                return (None, type('Response', (), {
                    'status': resp.status,
                    'headers': dict(resp.headers),
                    'body': resp_body
                })())
        except Exception as e:
            log.debug(f"Request error for {url}: {e}")
            return (e, None)

    def ai_mutate(self, payload: str) -> str:
        """Mutate payload using AI"""
        return self.llm.mutate(payload)

    def digest(self, *args) -> str:
        """Create hash digest"""
        return hashlib.sha256(''.join(args).encode()).hexdigest()[:16]

    async def run(self):
        console.print(Panel.fit(
            f"[bold cyan]AI-SENTINEL v4.0 - TARGET: {self.target}[/bold cyan]\n"
            f"Mode: {self.mode} | Depth: {self.max_depth} | Concurrent: {CONFIG['max_concurrent']}",
            border_style="cyan"
        ))
        
        # Phase 0: Subdomain Discovery
        console.print(f"[bold cyan]Phase 0: Subdomain Discovery[/bold cyan]")
        subdomains = await self.subdomain_hunter.discover_subdomains()
        
        # Add main domain if not in list
        if self.base not in subdomains:
            subdomains.append(self.base)
        
        all_urls_to_scan = []
        
        # Phase 1: Passive recon for each subdomain
        console.print(f"\n[bold cyan]Phase 1: Passive Reconnaissance[/bold cyan]")
        for subdomain_url in subdomains:
            console.print(f"[yellow]Analyzing: {subdomain_url}[/yellow]")
            req, resp = await self.capture("GET", subdomain_url, {}, b"")
            if not resp:
                console.print(f"[red]Failed to connect to {subdomain_url}[/red]")
                continue
                
            self.stats["status_codes"][resp.status] += 1
            
            # Detect WAF
            waf = self._detect_waf(resp.headers)
            if waf and not self.stats["waf"]:
                console.print(f"[yellow]WAF detected: {waf}[/yellow]")
                self.stats["waf"] = waf
            
            # Detect tech stack
            tech = self._detect_tech(resp.headers)
            self.stats["tech"].update(tech)
            
            # Run passive scans
            for vuln in await self.plugins[0].scan(subdomain_url, self):
                self.vulns.append(vuln)
                self.stats["vulns_by_type"][vuln.type] += 1
                self.stats["vulns_by_severity"][vuln.severity.name] += 1
                self.endpoint_tracker.mark_vulnerable(subdomain_url, vuln.url, vuln.type)
        
        # Phase 2: Intelligent crawling for each subdomain
        console.print(f"\n[bold cyan]Phase 2: Smart Crawling[/bold cyan]")
        
        for subdomain_url in subdomains:
            console.print(f"[cyan]Crawling {subdomain_url}[/cyan]")
            
            crawler = SmartCrawler(self, self.max_depth)
            urls = await crawler.crawl(subdomain_url)
            
            # Track all discovered endpoints
            for url in urls:
                self.endpoint_tracker.add_endpoint(subdomain_url, url)
                all_urls_to_scan.append(url)
        
        console.print(f"[green]✓ Total endpoints discovered: {len(all_urls_to_scan)}[/green]")
        
        # Phase 3: Parallel vulnerability scanning
        console.print(f"\n[bold cyan]Phase 3: Vulnerability Scanning[/bold cyan]")
        sem = asyncio.Semaphore(CONFIG["max_concurrent"])
        
        async def scan_url(url: str):
            async with sem:
                await self.rate_limiter.consume()
                
                # Determine which subdomain this belongs to
                subdomain = next((s for s in subdomains if s in url), self.base)
                self.endpoint_tracker.mark_scanned(subdomain, url)
                
                tasks = []
                for plugin in self.plugins:
                    if plugin.name == "Passive": 
                        continue
                    task = asyncio.create_task(self._safe_scan(plugin, url))
                    tasks.append(task)
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, Vulnerability):
                        async with self.lock:
                            if result.vid not in self.seen:
                                self.vulns.append(result)
                                self.seen.add(result.vid)
                                self.stats["vulns_by_type"][result.type] += 1
                                self.stats["vulns_by_severity"][result.severity.name] += 1
                                self.endpoint_tracker.mark_vulnerable(subdomain, result.url, result.type)
                                
                                # Show vulnerability details
                                color = "red" if result.severity in [Severity.CRITICAL, Severity.HIGH] else "yellow"
                                console.print(f"[bold {color}][{result.severity.name}][/bold {color}] {result.type}")
                                console.print(f"  URL: {result.url}")
                                console.print(f"  Payload: {result.payload}")
                                console.print(f"  Description: {result.description}")
                                console.print("")
        
        # Scan in batches
        batch_size = 50
        total_batches = (len(all_urls_to_scan) - 1) // batch_size + 1
        
        for i in range(0, len(all_urls_to_scan), batch_size):
            batch = all_urls_to_scan[i:i+batch_size]
            batch_num = i//batch_size + 1
            console.print(f"[yellow]Scanning batch {batch_num}/{total_batches} ({len(batch)} URLs)[/yellow]")
            await asyncio.gather(*[scan_url(url) for url in batch])
        
        # Phase 4: Reporting
        console.print(f"\n[bold cyan]Phase 4: Results & Reporting[/bold cyan]")
        self.stats["end_time"] = time.time()
        
        # Save all results
        self.save_all_results()
        self.generate_html_report()
        self.show_summary()
        
        # Close session
        if self.session:
            await self.session.close()

    async def _safe_scan(self, plugin: ScannerPlugin, url: str):
        try:
            return await plugin.scan(url, self)
        except Exception as e:
            log.debug(f"Plugin {plugin.name} failed on {url}: {e}")
            return None

    def _detect_waf(self, headers: dict) -> Optional[str]:
        headers_str = str(headers).lower()
        for waf, sigs in CONFIG["waf_signatures"].items():
            for sig in sigs:
                if sig.lower() in headers_str:
                    return waf
        return None

    def _detect_tech(self, headers: dict) -> Set[str]:
        techs = set()
        headers_str = str(headers).lower()
        for tech, sigs in CONFIG["tech_signatures"].items():
            for sig in sigs:
                if sig.lower() in headers_str:
                    techs.add(tech)
        return techs

    def save_all_results(self):
        """Save all scan results to files"""
        console.print("[yellow]Saving all results...[/yellow]")
        
        # 1. Save vulnerabilities
        if self.vulns:
            # JSON format
            vulns_json = [v.to_dict() for v in self.vulns]
            with open(f"results/{self.target}_vulnerabilities.json", "w") as f:
                json.dump(vulns_json, f, indent=2, default=str)
            
            # CSV format
            with open(f"results/{self.target}_vulnerabilities.csv", "w") as f:
                f.write("Severity,Type,URL,Description,Payload,Parameter,CVSS,Remediation\n")
                for v in self.vulns:
                    f.write(f'{v.severity.name},{v.type},"{v.url}","{v.description}","{v.payload}","{v.parameter}",{v.cvss_score},"{v.remediation}"\n')
        
        # 2. Save endpoints
        self.endpoint_tracker.save_endpoints()
        
        # 3. Save statistics
        stats = {
            "target": self.target,
            "mode": self.mode,
            "max_depth": self.max_depth,
            "start_time": datetime.datetime.fromtimestamp(self.stats["start_time"]).isoformat(),
            "end_time": datetime.datetime.fromtimestamp(self.stats["end_time"]).isoformat(),
            "duration_seconds": self.stats["end_time"] - self.stats["start_time"],
            "total_requests": sum(self.stats["status_codes"].values()),
            "status_codes": dict(self.stats["status_codes"]),
            "waf": self.stats["waf"],
            "technologies": list(self.stats["tech"]),
            "vulnerabilities_by_type": dict(self.stats["vulns_by_type"]),
            "vulnerabilities_by_severity": dict(self.stats["vulns_by_severity"]),
            "total_vulnerabilities": len(self.vulns),
            "endpoint_stats": self.endpoint_tracker.get_stats(),
        }
        
        with open(f"results/{self.target}_statistics.json", "w") as f:
            json.dump(stats, f, indent=2, default=str)
        
        console.print(f"[green]✓ All results saved to 'results/' directory[/green]")

    def generate_html_report(self):
        """Generate comprehensive HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AI-SENTINEL v4.0 Report – {self.target}</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Courier New', monospace; 
            background: #0a0a0a; 
            color: #00ff00; 
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ 
            text-align: center; 
            padding: 20px 0; 
            border-bottom: 2px solid #00ff00;
            margin-bottom: 30px;
        }}
        .header h1 {{ 
            color: #ff0000; 
            font-size: 2.5em; 
            text-shadow: 0 0 10px #ff0000;
        }}
        .summary {{ 
            background: #001a00; 
            padding: 20px; 
            border-radius: 5px; 
            margin-bottom: 30px;
            border: 1px solid #00ff00;
        }}
        .summary-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 15px; 
            margin-top: 15px;
        }}
        .summary-item {{ 
            background: #003300; 
            padding: 15px; 
            border-radius: 3px;
            text-align: center;
        }}
        .summary-item h3 {{ color: #00cc00; margin-bottom: 5px; }}
        .summary-item .value {{ 
            font-size: 2em; 
            font-weight: bold;
            color: #ffffff;
        }}
        .critical {{ color: #ff0000; font-weight: bold; }}
        .high {{ color: #ff6600; font-weight: bold; }}
        .medium {{ color: #ffff00; }}
        .low {{ color: #00ff00; }}
        .info {{ color: #00ccff; }}
        table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0;
            background: #001a00;
        }}
        th, td {{ 
            border: 1px solid #00ff00; 
            padding: 12px; 
            text-align: left; 
        }}
        th {{ 
            background: #003300; 
            color: #ffffff;
            position: sticky;
            top: 0;
        }}
        tr:hover {{ background: #002200; }}
        .section {{ 
            margin-bottom: 40px; 
            padding: 20px; 
            background: #001a00;
            border-radius: 5px;
            border: 1px solid #00ff00;
        }}
        .section h2 {{ 
            color: #00ccff; 
            margin-bottom: 20px;
            border-bottom: 1px solid #00ccff;
            padding-bottom: 10px;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .timestamp {{ 
            text-align: center; 
            margin-top: 30px; 
            color: #666;
            font-size: 0.9em;
        }}
        .details-toggle {{ 
            cursor: pointer; 
            color: #00ccff; 
            text-decoration: underline;
        }}
        .vuln-details {{ 
            display: none; 
            margin-top: 10px; 
            padding: 10px; 
            background: #002200; 
            border-left: 3px solid #00ff00;
        }}
        .subdomain-list {{ 
            list-style-type: none; 
            padding-left: 20px;
        }}
        .subdomain-list li {{ 
            margin: 5px 0; 
            padding: 5px; 
            background: #002200;
            border-left: 3px solid #00cc00;
        }}
    </style>
    <script>
        function toggleDetails(id) {{
            var elem = document.getElementById(id);
            if (elem.style.display === "none" || elem.style.display === "") {{
                elem.style.display = "block";
            }} else {{
                elem.style.display = "none";
            }}
        }}
        
        function filterTable(severity) {{
            var rows = document.querySelectorAll("#vulnTable tr");
            rows.forEach(function(row, index) {{
                if (index === 0) return; // Skip header
                var severityClass = row.cells[1].className;
                if (severity === "all" || severityClass.includes(severity)) {{
                    row.style.display = "";
                }} else {{
                    row.style.display = "none";
                }}
            }});
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 AI-SENTINEL v4.0 Security Report</h1>
            <p>Target: {self.target} | Scan Mode: {self.mode} | Max Depth: {self.max_depth}</p>
            <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="summary-grid">
"""
        
        # Add summary statistics
        total_vulns = len(self.vulns)
        critical_vulns = sum(1 for v in self.vulns if v.severity == Severity.CRITICAL)
        high_vulns = sum(1 for v in self.vulns if v.severity == Severity.HIGH)
        endpoint_stats = self.endpoint_tracker.get_stats()
        
        html += f"""
                <div class="summary-item">
                    <h3>Total Vulnerabilities</h3>
                    <div class="value">{total_vulns}</div>
                </div>
                <div class="summary-item">
                    <h3>Critical</h3>
                    <div class="value critical">{critical_vulns}</div>
                </div>
                <div class="summary-item">
                    <h3>High</h3>
                    <div class="value high">{high_vulns}</div>
                </div>
                <div class="summary-item">
                    <h3>Endpoints Found</h3>
                    <div class="value">{endpoint_stats['total_discovered']}</div>
                </div>
                <div class="summary-item">
                    <h3>Subdomains</h3>
                    <div class="value">{endpoint_stats['subdomains_count']}</div>
                </div>
                <div class="summary-item">
                    <h3>WAF Detected</h3>
                    <div class="value">{self.stats['waf'] or 'None'}</div>
                </div>
        """
        
        html += """
            </div>
        </div>
        
        <div class="section">
            <h2>Vulnerabilities Found</h2>
            <div style="margin-bottom: 15px;">
                <button onclick="filterTable('all')" style="margin-right: 5px;">All</button>
                <button onclick="filterTable('critical')" style="margin-right: 5px; background: #ff0000; color: white;">Critical</button>
                <button onclick="filterTable('high')" style="margin-right: 5px; background: #ff6600; color: white;">High</button>
                <button onclick="filterTable('medium')" style="margin-right: 5px; background: #ffff00; color: black;">Medium</button>
                <button onclick="filterTable('low')" style="margin-right: 5px; background: #00ff00; color: black;">Low</button>
            </div>
            <table id="vulnTable">
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Description</th>
                    <th>CVSS</th>
                    <th>Details</th>
                </tr>
        """
        
        # Add vulnerabilities to table
        for i, v in enumerate(self.vulns):
            severity_class = v.severity.name.lower()
            html += f"""
                <tr>
                    <td class="{severity_class} severity-badge">{v.severity.name}</td>
                    <td>{v.type}</td>
                    <td><a href="{v.url}" target="_blank" style="color: #00ccff;">{v.url[:100]}{'...' if len(v.url) > 100 else ''}</a></td>
                    <td>{v.description}</td>
                    <td>{v.cvss_score}</td>
                    <td><span class="details-toggle" onclick="toggleDetails('details{i}')">Show Details</span></td>
                </tr>
                <tr id="details{i}" class="vuln-details">
                    <td colspan="6">
                        <strong>Proof:</strong> {v.proof}<br>
                        <strong>Payload:</strong> {v.payload}<br>
                        <strong>Parameter:</strong> {v.parameter}<br>
                        <strong>Remediation:</strong> {v.remediation}<br>
                        <strong>CVSS Vector:</strong> {v.cvss_vector}
                    </td>
                </tr>
            """
        
        html += """
            </table>
        </div>
        
        <div class="section">
            <h2>Discovered Subdomains</h2>
            <ul class="subdomain-list">
        """
        
        # Add subdomains
        endpoint_stats = self.endpoint_tracker.get_stats()
        for subdomain in self.endpoint_tracker.discovered_endpoints.keys():
            endpoint_count = len(self.endpoint_tracker.discovered_endpoints.get(subdomain, []))
            vulnerable_count = len(self.endpoint_tracker.vulnerable_endpoints.get(subdomain, []))
            html += f"""
                <li>
                    {subdomain}
                    <span style="float: right;">
                        <span style="color: #00cc00;">Endpoints: {endpoint_count}</span> | 
                        <span style="color: {'#ff0000' if vulnerable_count > 0 else '#00ff00'}">Vulnerable: {vulnerable_count}</span>
                    </span>
                </li>
            """
        
        html += """
            </ul>
        </div>
        
        <div class="section">
            <h2>Technology Stack</h2>
            <p>
        """
        
        # Add technologies
        if self.stats["tech"]:
            html += ", ".join(sorted(self.stats["tech"]))
        else:
            html += "No specific technologies detected"
        
        html += """
            </p>
        </div>
        
        <div class="section">
            <h2>Statistics</h2>
            <table>
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                </tr>
        """
        
        # Add statistics
        stats_data = [
            ("Total Requests", sum(self.stats["status_codes"].values())),
            ("Scan Duration", f"{self.stats['end_time'] - self.stats['start_time']:.2f} seconds"),
            ("Endpoints Discovered", endpoint_stats["total_discovered"]),
            ("Endpoints Scanned", endpoint_stats["total_scanned"]),
            ("Vulnerable Endpoints", endpoint_stats["total_vulnerable"]),
        ]
        
        for label, value in stats_data:
            html += f"""
                <tr>
                    <td>{label}</td>
                    <td>{value}</td>
                </tr>
            """
        
        html += """
            </table>
        </div>
        
        <div class="timestamp">
            Report generated by AI-SENTINEL v4.0 | NULL200OL-AI Security Tool
        </div>
    </div>
</body>
</html>
        """
        
        filename = f"results/{self.target}_report.html"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        
        console.print(f"[green]✓ HTML report saved to: {filename}[/green]")

    def show_summary(self):
        """Display comprehensive summary in console"""
        console.print("\n" + "="*80)
        console.print("[bold cyan]🎯 SCAN COMPLETED - SUMMARY REPORT[/bold cyan]")
        console.print("="*80)
        
        # Vulnerabilities summary
        if self.vulns:
            console.print("\n[bold red]VULNERABILITIES FOUND:[/bold red]")
            
            by_severity = self.stats["vulns_by_severity"]
            by_type = self.stats["vulns_by_type"]
            
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = by_severity.get(severity, 0)
                if count > 0:
                    color = "red" if severity in ["CRITICAL", "HIGH"] else "yellow"
                    console.print(f"  [{color}]{severity}: {count}[/{color}]")
                    
                    # Show types for this severity
                    for v in self.vulns:
                        if v.severity.name == severity:
                            console.print(f"    • {v.type}: {v.url}")
        else:
            console.print("\n[bold green]✓ No vulnerabilities found![/bold green]")
        
        # Endpoints summary
        endpoint_stats = self.endpoint_tracker.get_stats()
        console.print("\n[bold cyan]ENDPOINTS DISCOVERED:[/bold cyan]")
        console.print(f"  • Total Discovered: {endpoint_stats['total_discovered']}")
        console.print(f"  • Total Scanned: {endpoint_stats['total_scanned']}")
        console.print(f"  • Vulnerable Endpoints: {endpoint_stats['total_vulnerable']}")
        console.print(f"  • Subdomains: {endpoint_stats['subdomains_count']}")
        
        # Technology stack
        if self.stats["tech"]:
            console.print(f"\n[bold cyan]TECHNOLOGY STACK:[/bold cyan]")
            console.print(f"  • {', '.join(sorted(self.stats['tech']))}")
        
        # WAF detection
        if self.stats["waf"]:
            console.print(f"\n[bold yellow]WAF DETECTED:[/bold yellow] {self.stats['waf']}")
        
        # Performance stats
        duration = self.stats["end_time"] - self.stats["start_time"]
        console.print(f"\n[bold cyan]PERFORMANCE STATISTICS:[/bold cyan]")
        console.print(f"  • Scan Duration: {duration:.2f} seconds")
        console.print(f"  • Requests Sent: {sum(self.stats['status_codes'].values())}")
        console.print(f"  • Avg. Requests/Second: {sum(self.stats['status_codes'].values())/duration:.1f}")
        
        # Files saved
        console.print("\n[bold green]FILES SAVED:[/bold green]")
        console.print(f"  • HTML Report: results/{self.target}_report.html")
        console.print(f"  • Vulnerabilities (JSON): results/{self.target}_vulnerabilities.json")
        console.print(f"  • Vulnerabilities (CSV): results/{self.target}_vulnerabilities.csv")
        console.print(f"  • Discovered Endpoints: results/{self.target}_discovered_endpoints.txt")
        console.print(f"  • Vulnerable Endpoints: results/{self.target}_vulnerable_endpoints.txt")
        console.print(f"  • Subdomains: results/{self.target}_subdomains.txt")
        console.print(f"  • Statistics: results/{self.target}_statistics.json")
        console.print(f"  • Endpoints Summary: results/{self.target}_endpoints_summary.json")
        
        console.print("\n" + "="*80)
        console.print("[bold green]✓ All results have been saved to the 'results/' directory[/bold green]")
        console.print("="*80)

# --------------------------------------------------------------------------- #
# CLI – ENTERPRISE ENTRY
# --------------------------------------------------------------------------- #
async def main():
    parser = argparse.ArgumentParser(description="AI-SENTINEL v4.0 – Enterprise Vulnerability Scanner")
    parser.add_argument("target", help="Target domain or URL (e.g., example.com or https://example.com)")
    parser.add_argument("--mode", choices=CONFIG["scan_modes"], default="active", help="Scan intensity mode")
    parser.add_argument("--depth", type=int, default=3, help="Maximum crawl depth")
    parser.add_argument("--concurrent", type=int, default=100, help="Max concurrent requests")
    parser.add_argument("--no-subdomains", action="store_true", help="Skip subdomain discovery")
    parser.add_argument("--output", help="Output directory (default: results/)")
    args = parser.parse_args()
    
    # Set output directory
    if args.output:
        Path(args.output).mkdir(exist_ok=True)
    
    start = time.time()
    
    # Print banner
    console.print(Panel.fit(
        "[bold red]🔥 AI-SENTINEL v4.0 - ENTERPRISE SECURITY SCANNER 🔥[/bold red]\n"
        "Created by NABEEL | NULL200OL-AI💀",
        border_style="red"
    ))
    
    console.print(f"[bold cyan]Target:[/bold cyan] {args.target}")
    console.print(f"[bold cyan]Mode:[/bold cyan] {args.mode}")
    console.print(f"[bold cyan]Depth:[/bold cyan] {args.depth}")
    console.print(f"[bold cyan]Concurrent:[/bold cyan] {args.concurrent}")
    console.print(f"[bold cyan]Subdomain Discovery:[/bold cyan] {'Disabled' if args.no_subdomains else 'Enabled'}")
    console.print("")
    
    # Initialize and run engine
    engine = AISentinelEngine(args.target, args.mode, args.depth)
    CONFIG["max_concurrent"] = args.concurrent
    
    if args.no_subdomains:
        engine.subdomain_hunter = None
    
    await engine.run()
    
    elapsed = time.time() - start
    console.print(f"\n[bold green]Total scan time: {elapsed:.2f} seconds[/bold green]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red]⚠️  Scan interrupted by user[/bold red]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]❌ Fatal error: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)
