#!/usr/bin/env python3
"""
DOM-XRAY V3.1 - FULL SPECTRUM (Headers + HTML + JS Hunter + Pause)
Autor: Bruno Rodrigo
"""
import requests
import re
import sys
import argparse
import concurrent.futures
from urllib.parse import urljoin
from urllib3.exceptions import InsecureRequestWarning

# Desativa alertas de SSL (para não poluir o terminal)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Colors:
    GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"; 
    BLUE = "\033[96m"; MAGENTA = "\033[95m"; CYAN = "\033[36m"; BOLD = "\033[1m"; RESET = "\033[0m"

# --- 1. CONFIGURAÇÃO DE SEGURANÇA (HEADERS) ---
SECURITY_HEADERS = {
    "X-Frame-Options": "Proteção contra Clickjacking",
    "Content-Security-Policy": "Proteção contra XSS/Injection",
    "Strict-Transport-Security": "Força HTTPS (HSTS)",
    "X-Content-Type-Options": "Previne MIME Sniffing",
    "X-XSS-Protection": "Filtro XSS (Antigo mas válido)"
}

# --- 2. CONFIGURAÇÃO DE INTELIGÊNCIA (REGEX) ---
PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret": r"[0-9a-zA-Z/+]{40}",
    "Generic Key": r"(api_key|apikey|access_token|auth_token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-\._]{20,})['\"]?",
    "Bearer Token": r"Bearer [a-zA-Z0-9\-\._~\+\/]{20,}",
    "S3 Bucket": r"[a-z0-9.-]+\.s3\.amazonaws\.com",
    "IP Interno": r"\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
    "Comentários Dev": r"|//.*(TODO|FIXME|BUG|HACK).*"
}

HEADERS_UA = {"User-Agent": "Mozilla/5.0 (DOM-XRAY V3.1)"}
REPORT_FINDINGS = []

def log(msg, type="INFO"):
    if type == "SUCCESS": print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
    elif type == "ALERT":   print(f"{Colors.RED}[!] {msg}{Colors.RESET}")
    elif type == "INFO":    print(f"{Colors.BLUE}[*] {msg}{Colors.RESET}")
    elif type == "WARN":    print(f"{Colors.YELLOW}[~] {msg}{Colors.RESET}")
    elif type == "SEC":     print(f"{Colors.CYAN}[🛡] {msg}{Colors.RESET}")

# --- MÓDULO 1: ANÁLISE DE HEADERS ---
def analyze_security_headers(headers):
    print(f"\n{Colors.BOLD}=== 1. ANÁLISE DE SEGURANÇA (HEADERS) ==={Colors.RESET}")
    missing_count = 0
    for header, desc in SECURITY_HEADERS.items():
        if header not in headers:
            print(f"  {Colors.RED}[✖] Faltando: {header}{Colors.RESET} ({desc})")
            missing_count += 1
        else:
            print(f"  {Colors.GREEN}[✔] Presente: {header}{Colors.RESET}")
    
    if missing_count == 0:
        log("Site blindado! Todos os headers de segurança presentes.", "SUCCESS")
    else:
        log(f"Site vulnerável a configurações básicas ({missing_count} falhas).", "WARN")

# --- MÓDULO 2: CAÇA AOS SEGREDOS (REGEX) ---
def scan_text(content, source_name):
    count = 0
    for name, pattern in PATTERNS.items():
        matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
        if matches:
            unique = list(set(matches))
            for m in unique:
                if len(str(m)) < 6: continue
                count += 1
                clean_match = str(m)[:60].replace('\n', ' ')
                
                # Exibe no terminal e salva na lista do relatório
                msg = f"[{name}] encontrado em {source_name}"
                print(f"  {Colors.RED}└── {msg}: {Colors.YELLOW}{clean_match}...{Colors.RESET}")
                REPORT_FINDINGS.append(f"{msg} -> {clean_match}")
    return count

# --- MÓDULO 3: DOWNLOAD DE SCRIPTS ---
def analyze_external_js(js_url):
    try:
        r = requests.get(js_url, headers=HEADERS_UA, timeout=5, verify=False)
        if r.status_code == 200:
            hits = scan_text(r.text, js_url)
            if hits > 0: return js_url
    except: pass
    return None

# --- ENGINE ---
def run_full_scan(target):
    if not target.startswith("http"): target = "http://" + target
    
    print(f"\n{Colors.BOLD}ALVO: {target}{Colors.RESET}")
    
    try:
        # Requisição Principal
        r = requests.get(target, headers=HEADERS_UA, timeout=10, verify=False)
        html = r.text
        
        # PASSO 1: Headers
        analyze_security_headers(r.headers)
        
        # PASSO 2: HTML & Inline JS
        print(f"\n{Colors.BOLD}=== 2. INTELIGÊNCIA (CÓDIGO FONTE) ==={Colors.RESET}")
        log("Analisando HTML Principal...", "INFO")
        scan_text(html, "HTML Principal")
        
        # Inline Scripts (Scripts escritos direto no HTML)
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
        if inline_scripts:
            log(f"Analisando {len(inline_scripts)} scripts inline (direto no código)...", "INFO")
            for i, script in enumerate(inline_scripts):
                scan_text(script, f"Script Inline #{i+1}")

        # PASSO 3: Scripts Externos (.js)
        print(f"\n{Colors.BOLD}=== 3. VARREDURA DE ARQUIVOS JS ==={Colors.RESET}")
        external_scripts = re.findall(r'<script[^>]+src=["\'](.*?)["\']', html)
        js_links = set()
        for s in external_scripts:
            full = urljoin(target, s)
            # Ignora Google e Facebook para focar no site
            if "google" not in full and "facebook" not in full:
                js_links.add(full)
        
        log(f"Encontrados {len(js_links)} arquivos .js externos.", "INFO")
        
        if js_links:
            log("Baixando e analisando scripts em paralelo...", "WARN")
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                ex.map(analyze_external_js, js_links)

        # Relatório Final
        if REPORT_FINDINGS:
            with open("dom_xray_report.txt", "w") as f:
                for line in REPORT_FINDINGS: f.write(line + "\n")
            print(f"\n{Colors.GREEN}[★] SCAN COMPLETO. {len(REPORT_FINDINGS)} segredos salvos em 'dom_xray_report.txt'.{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}[✔] SCAN LIMPO. Nenhum segredo crítico vazado.{Colors.RESET}")

    except Exception as e:
        log(f"Erro fatal: {e}", "ALERT")

def banner():
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print(r"""
    ██████╗  ██████╗ ███╗   ███╗      ██╗  ██╗██████╗  █████╗ ██╗   ██╗
    ██╔══██╗██╔═══██╗████╗ ████║      ╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝
    ██║  ██║██║   ██║██╔████╔██║█████╗ ╚███╔╝ ██████╔╝███████║ ╚████╔╝ 
    ██║  ██║██║   ██║██║╚██╔╝██║╚════╝ ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝  
    ██████╔╝╚██████╔╝██║ ╚═╝ ██║      ██╔╝ ██╗██║  ██║██║  ██║   ██║   V3.1
    ╚═════╝  ╚═════╝ ╚═╝     ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   
          [ FULL SPECTRUM EDITION - By Bruno Rodrigo ]
    """)
    print(f"{Colors.RESET}")

if __name__ == "__main__":
    banner()
    if len(sys.argv) > 1:
        run_full_scan(sys.argv[1])
    else:
        try:
            target = input(f"{Colors.YELLOW}[?] Alvo (ex: juice-shop.herokuapp.com): {Colors.RESET}")
            if target: run_full_scan(target)
        except: pass
    
    # --- A TRAVA DE SEGURANÇA ---
    # Isso impede que o terminal feche sozinho no final
    try:
        input(f"\n{Colors.RED}[!] Pressione ENTER para sair...{Colors.RESET}")
    except:
        pass
