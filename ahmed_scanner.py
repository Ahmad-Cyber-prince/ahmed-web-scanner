#!/usr/bin/env python3
"""
AHMED WEB IP SCANNER
Cross-Platform Website Security Scanner
Created by Ahmad Cyber Prince
GitHub: https://github.com/Ahmad-Cyber-prince
"""

import sys
import platform

# Check and install required packages
def install_packages():
    required_packages = ['requests', 'python-whois', 'dnspython', 'rich']
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'python-whois':
                import whois
            elif package == 'dnspython':
                import dns.resolver
            elif package == 'rich':
                from rich.console import Console
            else:
                __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("Installing missing packages...")
        import subprocess
        import importlib.util
        
        for package in missing_packages:
            install_name = package
            if package == 'python-whois':
                install_name = 'python-whois'
            elif package == 'dnspython':
                install_name = 'dnspython'
            
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', install_name])
                print(f"✅ {package} installed successfully")
            except Exception as e:
                print(f"❌ Failed to install {package}: {e}")
                sys.exit(1)

# Install packages before importing
install_packages()

# Now import all packages
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.style import Style
from rich.text import Text
from rich.align import Align
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
import requests
import socket
import ssl
import whois
import dns.resolver
from datetime import datetime
import urllib.parse
import time
import concurrent.futures
import os

# Cross-platform color support
COLORS = {
    'primary': 'cyan',
    'secondary': 'blue', 
    'success': 'green',
    'warning': 'yellow',
    'error': 'red',
    'info': 'magenta',
    'text': 'white',
    'highlight': 'bright_cyan',
    'accent': 'bright_magenta'
}

console = Console()

def clean_screen():
    """Cross-platform screen clearing"""
    os.system('cls' if os.name == 'nt' else 'clear')

def create_banner():
    """Create ASCII banner"""
    banner = r"""
    ___    __                       __   _       __     __       _     
   /   |  / /_  ____ ___  ___  ____/ /  | |     / /__  / /_     (_)___ 
  / /| | / __ \/ __ `__ \/ _ \/ __  /   | | /| / / _ \/ __ \   / / __ \
 / ___ |/ / / / / / / / /  __/ /_/ /    | |/ |/ /  __/ /_/ /  / / /_/ /
/_/  |_/_/ /_/_/ /_/ /_/\___/\__,_/     |__/|__/\___/_.___/  /_/ .___/ 
                                                              /_/       
                   AHMED WEB IP SCANNER
            Cross-Platform Security Tool
"""
    return banner

def create_header():
    """Create tool header"""
    header = Panel(
        Align.center(
            Text().append("🔍 ", style=COLORS['primary'])
                  .append("AHMED WEB IP SCANNER", style=f"bold {COLORS['primary']}")
                  .append("\nCreated by Ahmad Cyber Prince", style=f"bold {COLORS['accent']}")
                  .append("\nGitHub: https://github.com/Ahmad-Cyber-prince", style=f"italic {COLORS['info']}")
                  .append(f"\nPlatform: {platform.system()} {platform.release()}", style=COLORS['text'])
        ),
        style=Style(color=COLORS['secondary']),
        border_style=Style(color=COLORS['primary'])
    )
    return header

def clean_url(url):
    """Clean and validate URL"""
    url = url.strip().lower()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def get_domain(url):
    """Extract domain from URL"""
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc

def format_date(date_str):
    """Format date for display"""
    if not date_str:
        return "Not Available"
    try:
        if isinstance(date_str, str):
            # Try different date formats
            for fmt in ["%b %d %H:%M:%S %Y GMT", "%Y-%m-%d", "%d-%b-%Y"]:
                try:
                    date_obj = datetime.strptime(date_str, fmt)
                    return date_obj.strftime("%d %B %Y")
                except ValueError:
                    continue
            return date_str
        else:
            date_obj = date_str
            return date_obj.strftime("%d %B %Y")
    except Exception:
        return str(date_str)

def get_security_headers(headers):
    """Extract security headers"""
    security_headers = {
        'Strict-Transport-Security': 'HSTS',
        'Content-Security-Policy': 'CSP', 
        'X-Frame-Options': 'X-Frame',
        'X-Content-Type-Options': 'X-Content-Type',
        'X-XSS-Protection': 'XSS Protection',
        'Referrer-Policy': 'Referrer Policy'
    }
    return {new_name: headers.get(header, 'Not Available') 
            for header, new_name in security_headers.items()}

def check_admin_panel(url, timeout=5):
    """Check for admin panels"""
    admin_paths = [
        '/admin', '/administrator', '/wp-admin', '/login',
        '/panel', '/admin.php', '/admin/login', '/cp',
        '/backend', '/manager', '/webadmin', '/cpanel'
    ]
    found_paths = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        def check_path(path):
            try:
                test_url = url.rstrip('/') + path
                response = requests.get(test_url, timeout=timeout, allow_redirects=False, verify=False)
                if response.status_code in [200, 301, 302, 403, 401]:
                    return f"{test_url} (Status: {response.status_code})"
            except:
                pass
            return None
        
        futures = [executor.submit(check_path, path) for path in admin_paths]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found_paths.append(result)
    
    return found_paths

def grab_banner(url, timeout=10):
    """Grab server banner information"""
    try:
        response = requests.get(url, timeout=timeout, verify=False)
        server = response.headers.get('Server', 'Not Available')
        x_powered_by = response.headers.get('X-Powered-By', 'Not Available')
        return server, x_powered_by
    except Exception as e:
        return f'Error: {str(e)}', 'Not Available'

def get_technologies(url):
    """Detect web technologies"""
    try:
        response = requests.get(url, timeout=10, verify=False)
        tech_info = []
        
        # Simple technology detection
        headers = response.headers
        if 'Server' in headers:
            tech_info.append(f"Server: {headers['Server']}")
        if 'X-Powered-By' in headers:
            tech_info.append(f"Powered by: {headers['X-Powered-By']}")
        if 'X-AspNet-Version' in headers:
            tech_info.append(f"ASP.NET: {headers['X-AspNet-Version']}")
            
        return "\n".join(tech_info) if tech_info else "Basic detection only"
    except:
        return "Not Available"

def get_server_location(url):
    """Get server location info"""
    try:
        response = requests.get(url, timeout=10, verify=False)
        domain = get_domain(url)
        ip = socket.gethostbyname(domain)
        
        # Use ipapi.co for location info
        location_data = requests.get(f"http://ipapi.co/{ip}/json/").json()
        city = location_data.get('city', 'Not Available')
        country = location_data.get('country_name', 'Not Available')
        return city, country
    except:
        return "Not Available", "Not Available"

def create_styled_table(title):
    """Create a styled results table"""
    table = Table(
        title=title,
        title_style=Style(color=COLORS['primary'], bold=True),
        border_style=Style(color=COLORS['secondary']),
        header_style=Style(color=COLORS['highlight'], bold=True),
        pad_edge=False,
        expand=True,
        show_lines=False
    )
    table.add_column("Category", style=Style(color=COLORS['info']), no_wrap=True, min_width=20)
    table.add_column("Details", style=Style(color=COLORS['text']))
    return table

def scan_website(url):
    """Main website scanning function"""
    try:
        url = clean_url(url)
        domain = get_domain(url)
        
        console.print(create_header())
        
        with Progress(
            SpinnerColumn(style=COLORS['primary']),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style=COLORS['success'], finished_style=COLORS['success']),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            
            main_table = create_styled_table(f"🌐 Scan Results: {url}")
            scan_task = progress.add_task(f"[{COLORS['info']}]Initializing scan...", total=100)
            
            # 1. Network & DNS Scan
            progress.update(scan_task, advance=10, description=f"[{COLORS['info']}]Checking network...")
            try:
                ip = socket.gethostbyname(domain)
                main_table.add_row("🌐 IP Address", ip)
                
                dns_records = dns.resolver.resolve(domain, 'A')
                dns_ips = [str(record) for record in dns_records]
                if dns_ips:
                    main_table.add_row("📡 DNS Records", "\n".join(dns_ips))
            except Exception as e:
                main_table.add_row("🌐 Network Info", f"❌ Error: {str(e)}")
            
            # 2. SSL Check
            progress.update(scan_task, advance=15, description=f"[{COLORS['info']}]Checking SSL...")
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        main_table.add_row("🔒 SSL Valid From", format_date(cert['notBefore']))
                        main_table.add_row("🔒 SSL Valid Until", format_date(cert['notAfter']))
                        main_table.add_row("🔒 SSL Issuer", cert['issuer'][0][0][1])
            except Exception as e:
                main_table.add_row("🔒 SSL Status", f"❌ Error: {str(e)}")
            
            # 3. HTTP Headers
            progress.update(scan_task, advance=20, description=f"[{COLORS['info']}]Checking headers...")
            try:
                response = requests.get(url, timeout=10, verify=False)
                status_color = COLORS['success'] if response.status_code == 200 else COLORS['warning']
                main_table.add_row(
                    "📡 HTTP Status",
                    f"[{status_color}]{response.status_code} ({response.reason})[/{status_color}]"
                )
                
                security_headers = get_security_headers(response.headers)
                for header, value in security_headers.items():
                    if value != 'Not Available':
                        main_table.add_row(f"🛡️ {header}", value)
            except Exception as e:
                main_table.add_row("📡 HTTP Status", f"❌ Error: {str(e)}")
            
            # 4. WHOIS Information
            progress.update(scan_task, advance=15, description=f"[{COLORS['info']}]WHOIS lookup...")
            try:
                domain_info = whois.whois(domain)
                if domain_info.creation_date:
                    creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
                    main_table.add_row("📅 Domain Created", format_date(creation_date))
                if domain_info.expiration_date:
                    expiration_date = domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date
                    main_table.add_row("📅 Domain Expires", format_date(expiration_date))
                if domain_info.registrar:
                    main_table.add_row("🏢 Registrar", str(domain_info.registrar))
            except Exception as e:
                main_table.add_row("📅 WHOIS Info", f"❌ Error: {str(e)}")
            
            # 5. Admin Panel Scan
            progress.update(scan_task, advance=15, description=f"[{COLORS['info']}]Scanning admin panels...")
            admin_panels = check_admin_panel(url)
            if admin_panels:
                main_table.add_row("⚙️ Admin Panels Found", "\n".join(admin_panels[:3]))  # Show first 3
            else:
                main_table.add_row("⚙️ Admin Panels", "❌ Not Found")
            
            # 6. Server Info
            progress.update(scan_task, advance=15, description=f"[{COLORS['info']}]Server info...")
            server, x_powered_by = grab_banner(url)
            main_table.add_row("🖥️ Server", server)
            if x_powered_by != 'Not Available':
                main_table.add_row("⚡ X-Powered-By", x_powered_by)
            
            # 7. Technologies
            progress.update(scan_task, advance=5, description=f"[{COLORS['info']}]Detecting tech...")
            technologies = get_technologies(url)
            main_table.add_row("🔧 Technologies", technologies)
            
            # 8. Location
            progress.update(scan_task, advance=5, description=f"[{COLORS['info']}]Getting location...")
            city, country = get_server_location(url)
            main_table.add_row("📍 Server Location", f"{city}, {country}")
            
            progress.update(scan_task, completed=100, description=f"[{COLORS['success']}]Scan complete!")
            time.sleep(1)
        
        # Display results
        console.print(main_table)
        
        # Footer
        footer = Panel(
            Align.center(
                Text().append("🔒 Scan completed by ", style=COLORS['text'])
                      .append("Ahmad Cyber Prince", style=f"bold {COLORS['accent']}")
                      .append("\n📍 GitHub: ", style=COLORS['text'])
                      .append("https://github.com/Ahmad-Cyber-prince", style=f"italic {COLORS['info']}")
            ),
            style=Style(color=COLORS['secondary'])
        )
        console.print(footer)
        
    except Exception as e:
        console.print(Panel(f"❌ Scan Error: {str(e)}", 
                          style=Style(color=COLORS['error'])))

def main():
    """Main function"""
    clean_screen()
    
    # Display banner
    console.print(Panel(
        Align.center(create_banner()),
        style=Style(color=COLORS['primary']),
        border_style=Style(color=COLORS['secondary'])
    ))
    
    try:
        url_input = console.input(f"\n[{COLORS['primary']}]🌐 Enter website URL (e.g., example.com): [/{COLORS['primary']}] ").strip()
        if not url_input:
            console.print(Panel("❌ URL cannot be empty!", 
                              style=Style(color=COLORS['error'])))
            return
        
        console.print(f"\n[{COLORS['info']}]🚀 Starting scan for: {url_input}[/{COLORS['info']}]\n")
        scan_website(url_input)
        
    except KeyboardInterrupt:
        console.print(Panel("\n🛑 Scan canceled by user.", 
                          style=Style(color=COLORS['warning'])))
    except Exception as e:
        console.print(Panel(f"❌ Unexpected error: {str(e)}", 
                          style=Style(color=COLORS['error'])))

if __name__ == "__main__":
    main()
