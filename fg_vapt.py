from flask import Flask, request, jsonify, send_file, Response
from gtts import gTTS
import subprocess, datetime, socket, os, random, re, json, shutil

try:
    import requests as http_requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

app = Flask(__name__)
VOICE_FILE = "/tmp/FG_voice.mp3"

# ═══════════════════════════════════════════════════════
#  SCAN STATUS TRACKING
# ═══════════════════════════════════════════════════════
import threading, time
scan_status = {
    "active": False,
    "tool": "",
    "tool_display": "",
    "target": "",
    "category": "",
    "phase": "idle",       # idle, initializing, scanning, analyzing, complete, error
    "percent": 0,
    "start_time": 0,
    "elapsed": 0,
    "message": "Ready",
    "history": []          # last 10 completed scans
}
scan_lock = threading.Lock()

def update_scan_status(**kwargs):
    with scan_lock:
        for k, v in kwargs.items():
            scan_status[k] = v
        if scan_status["start_time"] > 0:
            scan_status["elapsed"] = round(time.time() - scan_status["start_time"], 1)

# Tool display names for UI
TOOL_DISPLAY = {
    "nmap_quick":"Port Scanner (Quick)","nmap_full":"Port Scanner (Full)","nmap_vuln":"Vulnerability Scan",
    "nmap_os":"OS Detection","nmap_udp":"UDP Scan","nmap_firewall":"Firewall Detect",
    "nmap_banner":"Banner Grab","arp_scan":"ARP Scan","smb_enum":"SMB Enumeration",
    "snmp_enum":"SNMP Enumeration","dns_zone":"DNS Zone Transfer",
    "web_headers":"HTTP Header Audit","web_ssl":"SSL/TLS Analysis","web_waf":"WAF Detection",
    "web_nikto":"Nikto Web Scan","web_dirscan":"Directory Enumeration","web_admin":"Admin Panel Finder",
    "web_cms":"CMS Detection","web_cors":"CORS Check","web_sqli":"SQL Injection Test",
    "web_xss":"XSS Scanner","web_methods":"HTTP Methods","web_subdomain":"Subdomain Enumeration",
    "infra_ssh":"SSH Audit","infra_ftp":"FTP Check","infra_rdp":"RDP Check",
    "infra_db":"Database Exposure","infra_docker":"Docker/K8s Check","infra_cve":"CVE Scan",
    "infra_winrm":"WinRM Check","infra_snmp":"SNMP Audit",
    "whois":"WHOIS Lookup","dns":"DNS Records","ip_info":"IP Info","ping":"Ping",
    "traceroute":"Traceroute","network_scan":"Local Network Scan","my_ip":"My IP","system_info":"System Info",
    "weather":"Weather","nuclei_full":"Nuclei Full Scan","nuclei_cve":"Nuclei CVE Scan",
    "nuclei_misconfig":"Nuclei Misconfig Scan","nuclei_tech":"Nuclei Tech Detect",
    "nuclei_critical":"Nuclei Critical/High","nuclei_network":"Nuclei Network Scan"
}

# Estimated scan durations (seconds) for progress calculation
TOOL_DURATION = {
    "nmap_quick":20,"nmap_full":60,"nmap_vuln":120,"nmap_os":45,"nmap_udp":40,
    "nmap_firewall":25,"nmap_banner":20,"arp_scan":15,"smb_enum":20,"snmp_enum":20,
    "dns_zone":15,"web_headers":8,"web_ssl":12,"web_waf":10,"web_nikto":60,
    "web_dirscan":45,"web_admin":30,"web_cms":15,"web_cors":8,"web_sqli":20,
    "web_xss":25,"web_methods":10,"web_subdomain":30,"infra_ssh":20,"infra_ftp":15,
    "infra_rdp":15,"infra_db":25,"infra_docker":20,"infra_cve":120,"infra_winrm":15,
    "infra_snmp":25,"whois":10,"dns":12,"ip_info":5,"ping":10,"traceroute":15,
    "network_scan":20,"my_ip":5,"system_info":3,"weather":5,
    "nuclei_full":180,"nuclei_cve":180,"nuclei_misconfig":150,"nuclei_tech":60,
    "nuclei_critical":180,"nuclei_network":150
}

# ═══════════════════════════════════════════════════════
#  SEARCH ENGINES — Wikipedia + Google
# ═══════════════════════════════════════════════════════
def clean_search_query(raw):
    """Extract the core search terms from a natural language question."""
    q = raw.lower().strip().rstrip('?!.')
    # Remove conversational prefixes
    prefixes = [
        "can you tell me ", "could you tell me ", "please tell me ",
        "i want to know ", "i'd like to know ", "do you know ",
        "can you explain ", "please explain ", "explain me ",
        "what do you know about ", "tell me about ", "tell me ",
        "search for ", "look up ", "google ", "search ",
        "who is the ", "who is ", "who are the ", "who are ",
        "what is the ", "what is a ", "what is an ", "what is ",
        "what are the ", "what are ", "where is the ", "where is ",
        "when was the ", "when was ", "when did ", "when is ",
        "how does ", "how do ", "how is ", "how to ",
        "why is the ", "why is ", "why do ", "why are ",
        "define ", "meaning of ",
    ]
    for p in prefixes:
        if q.startswith(p):
            q = q[len(p):]
            break
    return q.strip()

def search_wikipedia(query, sentences=4):
    """Search Wikipedia and return a summary."""
    if not HAS_REQUESTS:
        return None
    try:
        search_url = "https://en.wikipedia.org/w/api.php"
        search_params = {
            "action": "query", "list": "search",
            "srsearch": query, "srlimit": 3,
            "format": "json", "utf8": 1
        }
        resp = http_requests.get(search_url, params=search_params, timeout=10)
        data = resp.json()
        results = data.get("query", {}).get("search", [])
        if not results:
            return None

        # Try each result until we get a good summary
        for result in results[:3]:
            title = result["title"]
            try:
                summary_url = "https://en.wikipedia.org/api/rest_v1/page/summary/" + title.replace(" ", "_")
                resp2 = http_requests.get(summary_url, timeout=10,
                    headers={"User-Agent": "FG-AI/7.0 (Python; VAPT Suite)"})
                if resp2.status_code != 200:
                    continue
                sdata = resp2.json()
                extract = sdata.get("extract", "")
                if not extract or len(extract) < 30:
                    continue

                parts = extract.split(". ")
                if len(parts) > sentences:
                    extract = ". ".join(parts[:sentences]) + "."

                page_url = sdata.get("content_urls", {}).get("desktop", {}).get("page", "")
                return {"title": title, "summary": extract, "url": page_url}
            except Exception:
                continue
        return None
    except Exception as e:
        return None

def search_duckduckgo(query):
    """Search DuckDuckGo instant answers API."""
    if not HAS_REQUESTS:
        return None
    try:
        url = "https://api.duckduckgo.com/"
        params = {"q": query, "format": "json", "no_html": 1, "skip_disambig": 1}
        resp = http_requests.get(url, params=params, timeout=10,
            headers={"User-Agent": "FG-AI/7.0 (Python; VAPT Suite)"})
        data = resp.json()

        # Priority 1: Abstract text (best quality)
        abstract = data.get("AbstractText", "")
        if abstract and len(abstract) > 40:
            return {"answer": abstract, "source": data.get("AbstractSource", "DuckDuckGo"),
                    "url": data.get("AbstractURL", "")}

        # Priority 2: Answer box
        answer = data.get("Answer", "")
        if answer and len(str(answer)) > 5:
            return {"answer": str(answer), "source": "DuckDuckGo", "url": ""}

        # Priority 3: Definition
        defn = data.get("Definition", "")
        if defn and len(defn) > 20:
            return {"answer": defn, "source": data.get("DefinitionSource", ""), "url": ""}

        # Priority 4: Infobox
        infobox = data.get("Infobox", {})
        if isinstance(infobox, dict) and infobox.get("content"):
            items = infobox["content"]
            info_parts = []
            for item in items[:6]:
                if isinstance(item, dict) and item.get("label") and item.get("value"):
                    info_parts.append(item["label"] + ": " + str(item["value"]))
            if info_parts:
                heading = data.get("Heading", query.title())
                return {"answer": heading + " — " + " | ".join(info_parts),
                        "source": data.get("AbstractSource", "DuckDuckGo"), "url": ""}

        # Priority 5: Related topics
        topics = data.get("RelatedTopics", [])
        if topics:
            results = []
            for t in topics[:3]:
                if isinstance(t, dict) and "Text" in t and len(t["Text"]) > 20:
                    results.append(t["Text"])
            if results:
                return {"answer": " | ".join(results), "source": "DuckDuckGo", "url": ""}

        return None
    except Exception:
        return None

def ai_search_answer(query):
    """Smart search: clean query, try multiple engines, multiple strategies."""
    raw_query = query
    clean_q = clean_search_query(query)

    if not clean_q or len(clean_q) < 2:
        return None

    # Strategy 1: Try Wikipedia with cleaned query
    wiki = search_wikipedia(clean_q)
    if wiki:
        return f"📖 {wiki['title']}: {wiki['summary']} (Source: Wikipedia)"

    # Strategy 2: Try DuckDuckGo with cleaned query
    ddg = search_duckduckgo(clean_q)
    if ddg:
        answer = f"🔍 {ddg['answer']}"
        if ddg.get('source') and ddg['source'] != 'DuckDuckGo':
            answer += f" (Source: {ddg['source']})"
        return answer

    # Strategy 3: Try with original query if different
    if clean_q != raw_query.lower().strip():
        wiki2 = search_wikipedia(raw_query)
        if wiki2:
            return f"📖 {wiki2['title']}: {wiki2['summary']} (Source: Wikipedia)"

        ddg2 = search_duckduckgo(raw_query)
        if ddg2:
            answer = f"🔍 {ddg2['answer']}"
            if ddg2.get('source'):
                answer += f" (Source: {ddg2['source']})"
            return answer

    # Strategy 4: Try reformulated queries
    reformulations = []
    q_lower = raw_query.lower()
    if "ceo" in q_lower:
        company = clean_q.replace("ceo of", "").replace("ceo", "").strip()
        if company:
            reformulations.append(company + " company")
            reformulations.append(company)
    elif "founder" in q_lower:
        entity = clean_q.replace("founder of", "").replace("founder", "").strip()
        if entity:
            reformulations.append(entity)
    elif "president" in q_lower or "prime minister" in q_lower:
        country = clean_q.replace("president of", "").replace("prime minister of", "").replace("president", "").replace("prime minister", "").strip()
        if country:
            reformulations.append(country)

    for rq in reformulations:
        wiki3 = search_wikipedia(rq)
        if wiki3:
            return f"📖 {wiki3['title']}: {wiki3['summary']} (Source: Wikipedia)"
        ddg3 = search_duckduckgo(rq + " " + ("CEO" if "ceo" in q_lower else ""))
        if ddg3:
            return f"🔍 {ddg3['answer']} (Source: {ddg3.get('source', '')})"

    return None

# ═══════════════════════════════════════════════════════
#  PORT KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════
PORT_DB = {
    20:{"service":"FTP-DATA","severity":"HIGH","desc":"FTP data transfer port. Plain-text traffic sniffable.","fix":"Disable FTP. Use SFTP instead."},
    21:{"service":"FTP","severity":"HIGH","desc":"FTP control port. Credentials in plain text. Anonymous login risk.","fix":"Switch to SFTP. Check anonymous access with nmap --script ftp-anon"},
    22:{"service":"SSH","severity":"LOW","desc":"SSH encrypted remote access. Safe if properly hardened.","fix":"Disable root login. Use key-based auth. Keep updated."},
    23:{"service":"TELNET","severity":"CRITICAL","desc":"Telnet sends ALL data including passwords in plain text!","fix":"Disable Telnet immediately. Replace with SSH port 22."},
    25:{"service":"SMTP","severity":"MEDIUM","desc":"Mail server. Open relay risk if misconfigured.","fix":"Require SMTP auth. Use TLS. Restrict relay."},
    53:{"service":"DNS","severity":"MEDIUM","desc":"DNS service. Zone transfer attacks possible.","fix":"Disable zone transfers. Use DNSSEC."},
    80:{"service":"HTTP","severity":"MEDIUM","desc":"Web server without HTTPS encryption.","fix":"Redirect HTTP to HTTPS. Install SSL certificate."},
    110:{"service":"POP3","severity":"MEDIUM","desc":"Email retrieval in plain text.","fix":"Use POP3S port 995 with TLS."},
    111:{"service":"RPCBIND","severity":"HIGH","desc":"RPC portmapper. NFS attack vector.","fix":"Block port 111. Disable unused RPC services."},
    135:{"service":"MSRPC","severity":"HIGH","desc":"Microsoft RPC. Common Windows attack target.","fix":"Block from internet. Apply all Windows patches."},
    137:{"service":"NETBIOS-NS","severity":"HIGH","desc":"NetBIOS Name Service. Leaks system info.","fix":"Disable NetBIOS. Block 137-139 externally."},
    139:{"service":"NETBIOS","severity":"HIGH","desc":"NetBIOS Session. Legacy SMB protocol.","fix":"Use SMB over TCP port 445 only."},
    143:{"service":"IMAP","severity":"MEDIUM","desc":"Email access in plain text.","fix":"Use IMAPS port 993 with TLS."},
    161:{"service":"SNMP","severity":"HIGH","desc":"SNMP default community string public causes info leak.","fix":"Use SNMPv3 with auth. Change community strings."},
    389:{"service":"LDAP","severity":"MEDIUM","desc":"LDAP directory. Can leak user info unauthenticated.","fix":"Use LDAPS port 636. Require authentication."},
    443:{"service":"HTTPS","severity":"LOW","desc":"HTTPS web server. Encrypted. Check SSL config.","fix":"Run ssl scan. Check for weak ciphers."},
    445:{"service":"SMB","severity":"CRITICAL","desc":"SMB target of EternalBlue WannaCry ransomware!","fix":"Disable SMBv1. Block 445 from internet. Patch MS17-010."},
    512:{"service":"REXEC","severity":"CRITICAL","desc":"Remote exec no encryption no auth.","fix":"Disable immediately. Replace with SSH."},
    513:{"service":"RLOGIN","severity":"CRITICAL","desc":"Remote login legacy no encryption.","fix":"Disable rlogin. Use SSH instead."},
    514:{"service":"RSH","severity":"HIGH","desc":"Remote shell with no authentication.","fix":"Disable RSH. Use SSH."},
    873:{"service":"RSYNC","severity":"HIGH","desc":"Rsync may allow unauthenticated file access.","fix":"Require auth. Restrict by IP."},
    1433:{"service":"MSSQL","severity":"HIGH","desc":"MS SQL Server exposed. Brute force risk.","fix":"Block from internet. Strong SA password."},
    1521:{"service":"ORACLE","severity":"HIGH","desc":"Oracle database exposed.","fix":"Block from internet. Apply Oracle patches."},
    2049:{"service":"NFS","severity":"HIGH","desc":"NFS can allow remote file access without auth.","fix":"Restrict exports. Use Kerberos."},
    2375:{"service":"DOCKER","severity":"CRITICAL","desc":"Docker API exposed! Full container/host compromise possible!","fix":"Never expose Docker API. Use TLS auth if needed."},
    2376:{"service":"DOCKER-TLS","severity":"HIGH","desc":"Docker API with TLS. Verify certs are strict.","fix":"Verify client cert required. Restrict by IP."},
    3000:{"service":"DEV-SERVER","severity":"MEDIUM","desc":"Development server exposed. May have debug mode enabled.","fix":"Block from internet. Never run dev servers in production."},
    3306:{"service":"MYSQL","severity":"HIGH","desc":"MySQL database exposed. Brute force risk.","fix":"Bind to 127.0.0.1. Block externally."},
    3389:{"service":"RDP","severity":"CRITICAL","desc":"RDP exposed! BlueKeep brute force ransomware risk!","fix":"Enable NLA. Block from internet. Use VPN."},
    4444:{"service":"BACKDOOR","severity":"CRITICAL","desc":"Port 4444 common Metasploit malware backdoor!","fix":"Investigate immediately. Check for compromise."},
    5432:{"service":"POSTGRESQL","severity":"HIGH","desc":"PostgreSQL exposed. Data breach risk.","fix":"Bind to localhost. Block externally."},
    5555:{"service":"ADB","severity":"CRITICAL","desc":"Android Debug Bridge exposed. Full device control!","fix":"Disable ADB over network. USB only."},
    5900:{"service":"VNC","severity":"HIGH","desc":"VNC remote desktop exposed.","fix":"Add VNC password. Restrict by IP. Use SSH tunnel."},
    5985:{"service":"WINRM-HTTP","severity":"HIGH","desc":"Windows Remote Management over HTTP.","fix":"Use HTTPS WinRM. Restrict by IP. Require auth."},
    5986:{"service":"WINRM-HTTPS","severity":"MEDIUM","desc":"Windows Remote Management over HTTPS.","fix":"Restrict by IP. Require strong credentials."},
    6379:{"service":"REDIS","severity":"CRITICAL","desc":"Redis no auth by default! Full RCE possible!","fix":"Add Redis password. Bind to 127.0.0.1."},
    7001:{"service":"WEBLOGIC","severity":"HIGH","desc":"Oracle WebLogic server. Multiple critical CVEs.","fix":"Apply all patches. Restrict admin console access."},
    8080:{"service":"HTTP-ALT","severity":"MEDIUM","desc":"Alternate HTTP. Check for admin panels.","fix":"Secure web app. Use HTTPS."},
    8443:{"service":"HTTPS-ALT","severity":"LOW","desc":"Alternate HTTPS port.","fix":"Ensure strong TLS config."},
    8888:{"service":"JUPYTER","severity":"HIGH","desc":"Jupyter Notebook often on this port. RCE if exposed!","fix":"Add auth. Never expose Jupyter publicly."},
    9000:{"service":"PHP-FPM","severity":"HIGH","desc":"PHP-FPM exposed. Remote code execution risk.","fix":"Bind to Unix socket or 127.0.0.1 only."},
    9090:{"service":"PROMETHEUS","severity":"MEDIUM","desc":"Prometheus metrics exposed. Leaks internal info.","fix":"Restrict access. Add auth to Prometheus."},
    9200:{"service":"ELASTICSEARCH","severity":"CRITICAL","desc":"Elasticsearch no auth by default! All data readable!","fix":"Enable security. Bind to localhost."},
    10250:{"service":"KUBELET","severity":"CRITICAL","desc":"Kubernetes Kubelet API exposed! Cluster compromise!","fix":"Restrict kubelet API. Enable auth. Use firewall."},
    27017:{"service":"MONGODB","severity":"CRITICAL","desc":"MongoDB no auth by default! Full DB access!","fix":"Enable MongoDB auth. Bind to 127.0.0.1."},
}

VULN_DB = {
    "ms17-010":{"name":"EternalBlue MS17-010","severity":"CRITICAL","desc":"RCE via SMBv1 used by WannaCry ransomware.","fix":"Apply MS17-010 patch. Disable SMBv1. Block ports 445 and 139."},
    "eternalblue":{"name":"EternalBlue","severity":"CRITICAL","desc":"NSA exploit unauthenticated RCE via SMB.","fix":"Patch MS17-010. Disable SMBv1. Block inbound SMB."},
    "ms08-067":{"name":"MS08-067 NetAPI","severity":"CRITICAL","desc":"RCE in Windows Server exploited by Conficker worm.","fix":"Apply MS08-067 patch. Block port 445. Upgrade Windows."},
    "bluekeep":{"name":"BlueKeep CVE-2019-0708","severity":"CRITICAL","desc":"Wormable RDP RCE on Windows 7 and 2008.","fix":"Patch immediately. Enable NLA. Block RDP from internet."},
    "heartbleed":{"name":"Heartbleed CVE-2014-0160","severity":"CRITICAL","desc":"OpenSSL bug leaking server memory keys and passwords.","fix":"Upgrade OpenSSL. Reissue certificates. Reset passwords."},
    "shellshock":{"name":"Shellshock CVE-2014-6271","severity":"CRITICAL","desc":"Bash RCE via HTTP headers or CGI scripts.","fix":"Update Bash. Disable CGI. Use WAF."},
    "log4shell":{"name":"Log4Shell CVE-2021-44228","severity":"CRITICAL","desc":"Log4j RCE via JNDI injection in log messages.","fix":"Update Log4j to 2.17.1+. Disable JNDI lookup. Apply patches."},
    "printnightmare":{"name":"PrintNightmare CVE-2021-34527","severity":"CRITICAL","desc":"Windows Print Spooler RCE and local privilege escalation.","fix":"Disable Print Spooler on servers. Apply KB5004945 patch."},
    "zerologon":{"name":"ZeroLogon CVE-2020-1472","severity":"CRITICAL","desc":"Netlogon allows domain admin takeover with empty password.","fix":"Apply August 2020 Windows patches. Enable secure channel."},
    "ftp-anon":{"name":"FTP Anonymous Login","severity":"HIGH","desc":"FTP allows anonymous access without credentials.","fix":"Disable anonymous FTP. Use SFTP. Restrict by IP."},
    "ssl-poodle":{"name":"POODLE CVE-2014-3566","severity":"HIGH","desc":"SSLv3 CBC allows MITM traffic decryption.","fix":"Disable SSLv3. Use TLS 1.2 and 1.3 only."},
    "http-slowloris":{"name":"Slowloris DoS","severity":"HIGH","desc":"Server vulnerable to slow partial HTTP request DoS.","fix":"Set connection timeouts. Use Nginx. Deploy WAF."},
    "smb-vuln":{"name":"SMB Vulnerability","severity":"HIGH","desc":"SMB service has known vulnerabilities detected.","fix":"Disable SMBv1. Enable SMB signing. Apply patches."},
    "ssl-drown":{"name":"DROWN CVE-2016-0800","severity":"HIGH","desc":"SSLv2 support allows decryption of modern TLS.","fix":"Disable SSLv2. Upgrade OpenSSL."},
    "self-signed":{"name":"Self-Signed Certificate","severity":"MEDIUM","desc":"Self-signed cert means users cannot verify server identity.","fix":"Use free certificate from Lets Encrypt with certbot."},
    "ssl-beast":{"name":"BEAST Attack","severity":"MEDIUM","desc":"TLS 1.0 CBC allows HTTPS cookie decryption.","fix":"Upgrade to TLS 1.2 or 1.3. Use AEAD ciphers."},
    "x-frame-options":{"name":"Missing X-Frame-Options","severity":"MEDIUM","desc":"Clickjacking attacks possible without this header.","fix":"Add header: X-Frame-Options: SAMEORIGIN"},
    "content-security-policy":{"name":"Missing CSP Header","severity":"MEDIUM","desc":"No Content-Security-Policy header. XSS attacks enabled.","fix":"Add header: Content-Security-Policy: default-src self"},
    "strict-transport-security":{"name":"Missing HSTS","severity":"MEDIUM","desc":"No HSTS header. HTTP downgrade attacks possible.","fix":"Add header: Strict-Transport-Security: max-age=31536000"},
    "x-xss-protection":{"name":"Missing X-XSS-Protection","severity":"LOW","desc":"XSS protection header not configured.","fix":"Add header: X-XSS-Protection: 1; mode=block"},
    "x-content-type-options":{"name":"Missing X-Content-Type-Options","severity":"LOW","desc":"MIME sniffing not disabled.","fix":"Add header: X-Content-Type-Options: nosniff"},
}

def parse_open_ports(output):
    ports = []
    for m in re.finditer(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?", output):
        pnum = int(m.group(1)); proto = m.group(2)
        service = m.group(3); version = (m.group(4) or "").strip()
        info = PORT_DB.get(pnum, {"service":service.upper(),"severity":"MEDIUM",
            "desc":"Port "+str(pnum)+" is open and accessible.",
            "fix":"Verify if port "+str(pnum)+" needs to be publicly accessible."})
        ports.append({"port":pnum,"proto":proto,"service":info["service"],
                      "severity":info["severity"],"desc":info["desc"],
                      "fix":info["fix"],"version":version})
    return ports

def parse_vuln_threats(output, tool_type="nmap"):
    threats, out_lower = [], output.lower()
    for key, t in VULN_DB.items():
        if key in out_lower: threats.append(dict(t))
    if "anonymous" in out_lower and "ftp" in out_lower:
        t = dict(VULN_DB["ftp-anon"])
        if not any(x["name"]==t["name"] for x in threats): threats.append(t)
    if tool_type == "headers":
        for hk in ["x-frame-options","content-security-policy","x-xss-protection","strict-transport-security","x-content-type-options"]:
            if hk not in out_lower:
                t = dict(VULN_DB[hk])
                if not any(x["name"]==t["name"] for x in threats): threats.append(t)
    if tool_type == "ssl" and ("self signed" in out_lower or "self-signed" in out_lower):
        t = dict(VULN_DB["self-signed"])
        if not any(x["name"]==t["name"] for x in threats): threats.append(t)
    order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    threats.sort(key=lambda x: order.get(x["severity"],3))
    seen, unique = set(), []
    for t in threats:
        if t["name"] not in seen: seen.add(t["name"]); unique.append(t)
    return unique

import random as _random

def _mock_scan(executable, cmd, target):
    """Return realistic simulated output when tool is not installed."""
    t = target.strip() if target else "target"
    # Extract target from command
    parts = cmd.split()
    for p in reversed(parts):
        if not p.startswith('-') and p not in (executable,):
            t = p; break

    if executable == "nmap":
        ports_pool = [
            ("21","tcp","open","ftp","vsftpd 3.0.3"),
            ("22","tcp","open","ssh","OpenSSH 8.4p1"),
            ("25","tcp","open","smtp","Postfix smtpd"),
            ("53","tcp","open","domain","ISC BIND 9.16"),
            ("80","tcp","open","http","nginx 1.18.0"),
            ("110","tcp","filtered","pop3",""),
            ("143","tcp","filtered","imap",""),
            ("443","tcp","open","https","nginx 1.18.0"),
            ("445","tcp","filtered","microsoft-ds",""),
            ("3306","tcp","open","mysql","MySQL 8.0.27"),
            ("3389","tcp","filtered","ms-wbt-server",""),
            ("5432","tcp","open","postgresql","PostgreSQL 13.4"),
            ("6379","tcp","open","redis","Redis key-value store"),
            ("8080","tcp","open","http-proxy","Apache Tomcat 9.0"),
            ("8443","tcp","open","https-alt",""),
        ]
        if "--top-ports 50" in cmd or "-sU" in cmd:
            subset = _random.sample(ports_pool, _random.randint(3,6))
            proto = "udp" if "-sU" in cmd else "tcp"
            rows = ""
            for p in subset:
                rows += f"\n{p[0]}/{proto}   {p[2]:8s} {p[3]}"
            return (f"Starting Nmap 7.92 ( https://nmap.org ) — SIMULATION MODE\n"
                    f"Nmap scan report for {t}\nHost is up (0.045s latency).\n"
                    f"PORT      STATE    SERVICE{rows}\n"
                    f"\nNmap done: 1 IP address (1 host up) scanned in {_random.uniform(2,8):.2f} seconds")
        # quick or full scan
        n = _random.randint(4, 8)
        subset = _random.sample(ports_pool, n)
        rows = ""
        for p in subset:
            svc = p[4] if p[4] else p[3]
            rows += f"\n{p[0]}/tcp   {p[2]:8s} {p[3]:20s} {svc}"
        os_guess = _random.choice(["Linux 4.15 - 5.6","Linux 5.4 (Ubuntu)","Windows Server 2019"])
        return (f"Starting Nmap 7.92 ( https://nmap.org ) — SIMULATION MODE\n"
                f"Nmap scan report for {t}\nHost is up (0.028s latency).\n"
                f"Not shown: {1000-n} closed ports\n"
                f"PORT      STATE    SERVICE              VERSION{rows}\n"
                f"\nOS details: {os_guess}\n"
                f"Nmap done: 1 IP address (1 host up) scanned in {_random.uniform(5,25):.2f} seconds")

    if executable in ("nikto",):
        return (f"- Nikto v2.1.6 — SIMULATION MODE\n"
                f"+ Target IP: 93.184.216.34\n+ Target Hostname: {t}\n+ Target Port: 80\n"
                f"+ Server: nginx/1.18.0\n"
                f"+ /: Retrieved x-powered-by header: PHP/7.4.3\n"
                f"+ /: The anti-clickjacking X-Frame-Options header is not present.\n"
                f"+ /: The X-Content-Type-Options header is not set.\n"
                f"+ /login: Cookie session created without the httponly flag.\n"
                f"+ /admin/: Admin login page found.\n"
                f"+ 7889 requests: 0 error(s) and 5 item(s) reported")

    if executable in ("sqlmap",):
        return (f"sqlmap 1.6 — SIMULATION MODE\n"
                f"[INFO] testing connection to the target URL\n"
                f"[INFO] testing if the target URL content is stable\n"
                f"[INFO] GET parameter 'id' is dynamic\n"
                f"[WARNING] GET parameter 'id' does not seem to be injectable\n"
                f"[INFO] heuristic (basic) test shows that GET parameter 'q' might be injectable (possible DBMS: MySQL)\n"
                f"[INFO] testing for SQL injection on GET parameter 'q'\n"
                f"[INFO] GET parameter 'q' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable\n"
                f"[CRITICAL] SIMULATION: possible SQL injection found on parameter 'q'")

    if executable in ("sslscan","openssl"):
        return (f"sslscan 2.0 — SIMULATION MODE\nTesting {t}:443\n"
                f"  TLSv1.0   disabled\n  TLSv1.1   disabled\n  TLSv1.2   enabled\n  TLSv1.3   enabled\n"
                f"  Certificate: CN={t}, O=Example Corp\n"
                f"  Not valid before: 2024-01-01\n  Not valid after:  2026-01-01\n"
                f"  Signature Algorithm: sha256WithRSAEncryption\n"
                f"  Subject Alt Names: {t}, www.{t}")

    if executable in ("ssh-audit","ssh"):
        return (f"ssh-audit 2.5 — SIMULATION MODE\n# {t}:22\n"
                f"(gen) banner: SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1\n"
                f"(kex) curve25519-sha256 -- [info] available since OpenSSH 6.4\n"
                f"(key) ecdsa-sha2-nistp256 -- [warn] using a 256-bit elliptic curve key\n"
                f"(enc) chacha20-poly1305@openssh.com -- [info] available since OpenSSH 6.5\n"
                f"(mac) hmac-sha2-256 -- [warn] using encrypt-and-MAC mode")

    if executable in ("whatweb","curl","wget"):
        return (f"SIMULATION MODE — HTTP Headers for {t}\n"
                f"Server: nginx/1.18.0\nX-Powered-By: PHP/7.4.3\n"
                f"Content-Type: text/html; charset=UTF-8\n"
                f"X-Frame-Options: SAMEORIGIN\n"
                f"X-XSS-Protection: 1; mode=block\n"
                f"Strict-Transport-Security: max-age=31536000\n"
                f"[WARN] Missing Content-Security-Policy header\n"
                f"[WARN] Missing X-Content-Type-Options header")

    # Generic fallback
    return (f"[SIMULATION MODE] Tool '{executable}' not found.\n"
            f"Simulated scan of {t} completed.\n"
            f"No real data returned — install {executable} for live results.")


def run_cmd(cmd, timeout=90):
    is_windows = os.name == "nt"
    if is_windows:
        linux_only_markers = ["2>/dev/null", "| head", "| grep", "||", "&&", "which ", "hostname -I", "tracepath", "traceroute -m", "/usr/share/"]
        if any(marker in cmd for marker in linux_only_markers):
            return (
                "This scan command is written for Kali/Linux shell tools and is not supported in native Windows.\n"
                "Recommended: run this project in Kali Linux or WSL, or install equivalent Windows tools and adapt the command.\n\n"
                "Command:\n" + cmd
            )

        match = re.match(r'\s*["\']?([A-Za-z0-9_.-]+)', cmd)
        executable = match.group(1).lower() if match else ""
        shell_builtins = {"echo"}
        if executable and executable not in shell_builtins and shutil.which(executable) is None:
            return (
                "[SIMULATION MODE] " + executable + " not installed — showing simulated output.\n\n"
                + _mock_scan(executable, cmd, "")
            )

    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired: return "Scan timed out."
    except Exception as e: return "Error: " + str(e)

def clean(t):
    return t.strip().replace("https://","").replace("http://","").split("/")[0]

# ═══════════════════════════════════════════════════════
#  NETWORK VAPT TOOLS
# ═══════════════════════════════════════════════════════
def nmap_quick(t):      return run_cmd("nmap -Pn -T4 -F --open " + clean(t), 60)
def nmap_full(t):       return run_cmd("nmap -Pn -T4 -sV -sC -A " + clean(t), 180)
def nmap_vuln(t):       return run_cmd("nmap -Pn --script vuln -sV -T4 " + clean(t), 180)
def nmap_os(t):         return run_cmd("nmap -Pn -O -sV " + clean(t), 90)
def nmap_udp(t):        return run_cmd("nmap -Pn -sU -T4 --top-ports 50 " + clean(t), 120)
def nmap_firewall(t):   return run_cmd("nmap -Pn -sA -T4 " + clean(t) + " && nmap -Pn --script firewall-bypass " + clean(t), 90)
def nmap_banner(t):     return run_cmd("nmap -Pn --script banner -sV " + clean(t), 90)
def nmap_arp():
    local = run_cmd("hostname -I").strip().split()[0]
    subnet = ".".join(local.split(".")[:3]) + ".0/24"
    return run_cmd("nmap -sn " + subnet + " --send-eth 2>/dev/null || nmap -sn " + subnet, 60)

def smb_enum(t):
    out = run_cmd("nmap -Pn --script smb-enum-shares,smb-enum-users,smb-security-mode,smb-vuln-ms17-010,smb2-security-mode " + clean(t), 90)
    out += "\n\n" + run_cmd("enum4linux -a " + clean(t) + " 2>/dev/null | head -100", 60)
    return out

def snmp_enum(t):
    out = run_cmd("nmap -Pn -sU -p 161 --script snmp-info,snmp-sysdescr,snmp-interfaces " + clean(t), 60)
    out += "\n\n" + run_cmd("snmpwalk -v2c -c public " + clean(t) + " 2>/dev/null | head -50", 30)
    return out

def dns_zone_transfer(t):
    domain = clean(t)
    ns_out = run_cmd("dig " + domain + " NS +short", 10)
    result = "NS Records:\n" + ns_out + "\n\nZone Transfer Attempts:\n"
    for ns in ns_out.strip().split("\n"):
        ns = ns.strip().rstrip(".")
        if ns: result += run_cmd("dig axfr " + domain + " @" + ns, 15) + "\n"
    result += "\n" + run_cmd("nmap -Pn --script dns-zone-transfer --script-args dns-zone-transfer.domain=" + domain + " " + clean(t), 30)
    return result

# ═══════════════════════════════════════════════════════
#  WEB VAPT TOOLS
# ═══════════════════════════════════════════════════════
def web_headers(t):
    url = t if t.startswith("http") else "https://" + t
    res = run_cmd("curl -sI --max-time 10 " + url, 15)
    missing = [h for h in ["X-Frame-Options","X-XSS-Protection","Strict-Transport-Security","Content-Security-Policy","X-Content-Type-Options"] if h.lower() not in res.lower()]
    if missing: res += "\n\nMISSING SECURITY HEADERS:\n" + "\n".join("  MISSING: " + h for h in missing)
    else: res += "\n\nAll security headers present!"
    return res

def web_ssl(t):
    c = clean(t)
    r = run_cmd("echo | openssl s_client -connect " + c + ":443 -servername " + c + " 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null", 15)
    r += "\n\n" + run_cmd("nmap -Pn --script ssl-enum-ciphers,ssl-poodle,ssl-dh-params,ssl-heartbleed -p 443 " + c, 60)
    return r or "No SSL certificate found."

def web_waf(t):
    url = t if t.startswith("http") else "https://" + t
    r = run_cmd("wafw00f " + url + " 2>/dev/null", 30)
    if "not installed" in r.lower() or not r:
        r = run_cmd("nmap -Pn --script http-waf-detect,http-waf-fingerprint " + clean(t), 60)
    return r or "WAF detection requires wafw00f: pip install wafw00f"

def web_nikto(t):
    url = t if t.startswith("http") else "https://" + t
    return run_cmd("nikto -h " + url + " -maxtime 120 2>/dev/null", 130)

def web_dirscan(t):
    url = t if t.startswith("http") else "https://" + t
    if run_cmd("which gobuster").strip():
        return run_cmd("gobuster dir -u " + url + " -w /usr/share/wordlists/dirb/common.txt -t 30 -q 2>/dev/null", 120)
    return run_cmd("dirb " + url + " /usr/share/wordlists/dirb/common.txt -S 2>/dev/null", 120)

def web_admin_finder(t):
    url = t if t.startswith("http") else "https://" + t
    admin_paths = ["/admin","/admin/login","/administrator","/wp-admin","/wp-login.php",
                   "/phpmyadmin","/pma","/cpanel","/webmin","/manager/html",
                   "/admin.php","/login.php","/dashboard","/panel","/control",
                   "/backend","/cms","/portal","/system","/manage"]
    found = []
    for path in admin_paths:
        code = run_cmd("curl -so /dev/null -w '%{http_code}' --max-time 5 " + url + path, 8)
        if code in ["200","301","302","403"]: found.append("[" + code + "] " + url + path)
    return "\n".join(found) if found else "No admin panels found at common paths."

def web_cms(t):
    url = t if t.startswith("http") else "https://" + t
    r = run_cmd("whatweb -v " + url + " 2>/dev/null", 30)
    wpscan = run_cmd("which wpscan", 5)
    if wpscan.strip() and ("wordpress" in r.lower() or "wp-" in r.lower()):
        r += "\n\nWordPress Detected - Running WPScan:\n"
        r += run_cmd("wpscan --url " + url + " --no-update 2>/dev/null | head -60", 60)
    return r or "WhatWeb not installed: sudo apt install whatweb"

def web_cors(t):
    url = t if t.startswith("http") else "https://" + t
    r = run_cmd("curl -sI -H 'Origin: https://evil.com' --max-time 10 " + url, 15)
    r += "\n\n" + run_cmd("nmap -Pn --script http-cors " + clean(t), 30)
    issues = []
    if "access-control-allow-origin: *" in r.lower(): issues.append("CRITICAL: CORS allows ALL origins (*) - Any website can read responses!")
    if "access-control-allow-credentials: true" in r.lower(): issues.append("HIGH: CORS allows credentials - Session hijacking possible!")
    if "evil.com" in r.lower(): issues.append("HIGH: Server reflects attacker origin - CORS misconfiguration!")
    if issues: r += "\n\nCORS VULNERABILITIES FOUND:\n" + "\n".join("  " + i for i in issues)
    else: r += "\n\nNo obvious CORS misconfigurations detected."
    return r

def web_sqli(t):
    url = t if t.startswith("http") else "https://" + t
    r = run_cmd("which sqlmap", 5)
    if r.strip():
        return run_cmd("sqlmap -u " + url + " --batch --level=1 --risk=1 --forms --crawl=1 --random-agent 2>/dev/null | tail -40", 120)
    return "SQLMap not installed. Install: sudo apt install sqlmap\nManual test: Add \' to URL parameters and check for SQL errors."

def web_xss(t):
    url = t if t.startswith("http") else "https://" + t
    r = run_cmd("nmap -Pn --script http-stored-xss,http-dombased-xss,http-xssed " + clean(t), 60)
    r += "\n\n" + run_cmd("curl -sk --max-time 10 '" + url + "?q=<script>alert(1)</script>' | grep -i 'script' | head -5", 15)
    r += "\n\nManual XSS Test Payloads:\n"
    r += "  Basic: <script>alert('XSS')</script>\n"
    r += "  Image: <img src=x onerror=alert(1)>\n"
    r += "  SVG: <svg onload=alert(1)>\n"
    r += "  URL Encode: %3Cscript%3Ealert(1)%3C/script%3E"
    return r

def web_methods(t):
    url = t if t.startswith("http") else "https://" + t
    methods = ["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD","TRACE","CONNECT"]
    results = []
    for m in methods:
        code = run_cmd("curl -so /dev/null -w '%{http_code}' -X " + m + " --max-time 5 " + url, 8)
        danger = " [DANGEROUS!]" if m in ["PUT","DELETE","TRACE","CONNECT"] and code not in ["404","405","403"] else ""
        results.append("[" + code + "] " + m + danger)
    return "HTTP Methods Test for " + url + ":\n" + "\n".join(results)

def web_subdomain(t):
    subs = ["www","mail","ftp","api","admin","test","dev","staging","blog","shop","vpn","remote","portal","app","beta","cdn","login","secure","dashboard","support","docs","auth","api2","m","mobile","static","assets","media","files","old","new","backup","db","database"]
    found = []
    for s in subs:
        full = s + "." + clean(t)
        try:
            ip = socket.gethostbyname(full)
            found.append("FOUND: " + full + " -> " + ip)
        except: pass
    return "\n".join(found) or "No common subdomains found."

# ═══════════════════════════════════════════════════════
#  INFRASTRUCTURE VAPT TOOLS
# ═══════════════════════════════════════════════════════
def infra_ssh_audit(t):
    r = run_cmd("nmap -Pn --script ssh-auth-methods,ssh-hostkey,ssh2-enum-algos -p 22 " + clean(t), 60)
    r += "\n\n" + run_cmd("ssh-audit " + clean(t) + " 2>/dev/null | head -50", 30)
    return r

def infra_ftp(t):
    r = run_cmd("nmap -Pn --script ftp-anon,ftp-bounce,ftp-syst,ftp-vuln-cve2010-4221 -p 21 " + clean(t), 60)
    anon_test = run_cmd("curl -sk --max-time 5 ftp://" + clean(t) + "/ 2>&1", 8)
    if "Permission denied" not in anon_test and anon_test.strip():
        r += "\n\nANONYMOUS FTP ACCESS CONFIRMED:\n" + anon_test[:500]
    return r

def infra_rdp(t):
    r = run_cmd("nmap -Pn --script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-vuln-ms16-068 -p 3389 " + clean(t), 60)
    r += "\n\n" + run_cmd("nmap -Pn --script rdp-enum-encryption -p 3389 " + clean(t), 30)
    return r

def infra_db_check(t):
    results = []
    mysql_r = run_cmd("nmap -Pn --script mysql-info,mysql-databases,mysql-empty-password -p 3306 " + clean(t), 30)
    if "open" in mysql_r: results.append("=== MYSQL (3306) ===\n" + mysql_r)
    pg_r = run_cmd("nmap -Pn --script pgsql-brute -p 5432 " + clean(t), 30)
    if "open" in pg_r: results.append("=== POSTGRESQL (5432) ===\n" + pg_r)
    mongo_r = run_cmd("nmap -Pn --script mongodb-info,mongodb-databases -p 27017 " + clean(t), 30)
    if "open" in mongo_r: results.append("=== MONGODB (27017) ===\n" + mongo_r)
    redis_r = run_cmd("nmap -Pn --script redis-info -p 6379 " + clean(t), 30)
    if "open" in redis_r: results.append("=== REDIS (6379) ===\n" + redis_r)
    es_r = run_cmd("curl -sk --max-time 5 http://" + clean(t) + ":9200/_cluster/health 2>/dev/null", 8)
    if es_r.strip(): results.append("=== ELASTICSEARCH (9200) OPEN ===\n" + es_r[:300])
    return "\n\n".join(results) if results else "No exposed databases found on common ports."

def infra_docker(t):
    results = []
    docker_r = run_cmd("curl -sk --max-time 5 http://" + clean(t) + ":2375/version 2>/dev/null", 8)
    if docker_r.strip(): results.append("CRITICAL: Docker API EXPOSED on port 2375!\n" + docker_r[:300])
    kube_r = run_cmd("curl -sk --max-time 5 https://" + clean(t) + ":6443/version 2>/dev/null", 8)
    if kube_r.strip() and "major" in kube_r: results.append("CRITICAL: Kubernetes API EXPOSED on port 6443!\n" + kube_r[:200])
    kubelet_r = run_cmd("curl -sk --max-time 5 https://" + clean(t) + ":10250/pods 2>/dev/null | head -5", 8)
    if kubelet_r.strip(): results.append("CRITICAL: Kubernetes Kubelet EXPOSED on port 10250!\n" + kubelet_r[:200])
    meta_r = run_cmd("curl -sk --max-time 3 http://169.254.169.254/latest/meta-data/ 2>/dev/null", 5)
    if meta_r.strip(): results.append("AWS Metadata Service accessible!\n" + meta_r[:200])
    r = run_cmd("nmap -Pn -p 2375,2376,6443,10250,10255,8080,9090 " + clean(t), 30)
    results.append("Port Scan (Docker/K8s ports):\n" + r)
    return "\n\n".join(results) if results else "No exposed Docker/Kubernetes services found."

def infra_cve_scan(t):
    r = run_cmd("nmap -Pn --script vuln -sV -T4 " + clean(t), 180)
    r += "\n\n" + run_cmd("nmap -Pn --script exploit " + clean(t), 60)
    return r

def infra_winrm(t):
    r = run_cmd("nmap -Pn --script http-auth-finder -p 5985,5986 " + clean(t), 30)
    r += "\n\n" + run_cmd("curl -sk --max-time 5 http://" + clean(t) + ":5985/wsman 2>/dev/null | head -5", 8)
    return r

def infra_snmp(t):
    return run_cmd("nmap -Pn -sU -p 161 --script snmp-brute,snmp-info,snmp-interfaces,snmp-netstat,snmp-processes " + clean(t), 60)

# ═══════════════════════════════════════════════════════
#  NUCLEI SCANNER
# ═══════════════════════════════════════════════════════
def nuclei_full(t):
    """Full Nuclei scan with all templates."""
    r = "═══ NUCLEI FULL SCAN — " + t + " ═══\n\n"
    out = run_cmd("nuclei -u " + clean(t) + " -silent -nc -timeout 15 -retries 1 -rl 50 2>&1", 300)
    if out.strip():
        r += out
    else:
        r += "No vulnerabilities found by Nuclei, or Nuclei is not installed.\n"
        r += "Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
        r += "Or: apt install nuclei\n"
    return r

def nuclei_cve(t):
    """Nuclei CVE-specific scan."""
    r = "═══ NUCLEI CVE SCAN — " + t + " ═══\n\n"
    out = run_cmd("nuclei -u " + clean(t) + " -t cves/ -silent -nc -timeout 15 -severity critical,high -rl 50 2>&1", 300)
    if out.strip():
        r += out
    else:
        r += "No CVEs detected.\n"
        r += "Tip: Make sure Nuclei templates are updated: nuclei -update-templates\n"
    return r

def nuclei_misconfig(t):
    """Nuclei misconfiguration scan."""
    r = "═══ NUCLEI MISCONFIGURATION SCAN — " + t + " ═══\n\n"
    out = run_cmd("nuclei -u " + clean(t) + " -t misconfiguration/ -t exposed-panels/ -t exposures/ -silent -nc -timeout 15 -rl 50 2>&1", 240)
    if out.strip():
        r += out
    else:
        r += "No misconfigurations found.\n"
    return r

def nuclei_tech(t):
    """Nuclei technology detection."""
    r = "═══ NUCLEI TECHNOLOGY DETECTION — " + t + " ═══\n\n"
    out = run_cmd("nuclei -u " + clean(t) + " -t technologies/ -silent -nc -timeout 10 -rl 50 2>&1", 120)
    if out.strip():
        r += out
    else:
        r += "No technologies detected via Nuclei.\n"
    return r

def nuclei_critical(t):
    """Nuclei critical and high severity only."""
    r = "═══ NUCLEI CRITICAL/HIGH SCAN — " + t + " ═══\n\n"
    out = run_cmd("nuclei -u " + clean(t) + " -severity critical,high -silent -nc -timeout 15 -rl 50 2>&1", 300)
    if out.strip():
        r += out
    else:
        r += "No critical/high severity issues found.\n"
    return r

def nuclei_network(t):
    """Nuclei network-level scan."""
    r = "═══ NUCLEI NETWORK SCAN — " + t + " ═══\n\n"
    out = run_cmd("nuclei -u " + clean(t) + " -t network/ -silent -nc -timeout 15 -rl 30 2>&1", 240)
    if out.strip():
        r += out
    else:
        r += "No network-level issues found.\n"
    return r

def parse_nuclei_threats(output):
    """Parse Nuclei output into threat objects."""
    threats = []
    lines = output.split("\n")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("═") or line.startswith("Tip:") or line.startswith("Install:") or line.startswith("No "):
            continue
        # Nuclei output format: [template-id] [protocol] [severity] target
        sev = "MEDIUM"
        if "[critical]" in line.lower(): sev = "CRITICAL"
        elif "[high]" in line.lower(): sev = "HIGH"
        elif "[medium]" in line.lower(): sev = "MEDIUM"
        elif "[low]" in line.lower(): sev = "LOW"
        elif "[info]" in line.lower(): sev = "LOW"

        # Extract template name
        name = line
        if "] " in line:
            parts = line.split("] ")
            if parts:
                name = parts[0].replace("[", "").strip()

        if len(name) > 3 and name != output[:20]:
            threats.append({
                "name": "Nuclei: " + name[:80],
                "severity": sev,
                "desc": line[:200],
                "fix": "Review finding and apply vendor-recommended patch or configuration fix."
            })
    return threats

# ═══════════════════════════════════════════════════════
#  RECON TOOLS
# ═══════════════════════════════════════════════════════
def do_whois(t):    return run_cmd("whois " + clean(t), 30)[:4000]
def do_dns(t):
    out = []
    for r in ["A","MX","NS","TXT","CNAME","SOA","AAAA"]:
        res = run_cmd("dig " + clean(t) + " " + r + " +short", 10)
        if res.strip(): out.append("-- " + r + " --\n" + res)
    return "\n\n".join(out) or "No DNS records found."
def do_ip_info(ip):
    try:
        import requests
        d = requests.get("http://ip-api.com/json/" + ip, timeout=5).json()
        if d.get("status") == "success":
            return "IP: "+str(d.get("query"))+"\nCountry: "+str(d.get("country"))+"\nCity: "+str(d.get("city"))+"\nISP: "+str(d.get("isp"))+"\nOrg: "+str(d.get("org"))+"\nTimezone: "+str(d.get("timezone"))+"\nAS: "+str(d.get("as"))
        return "IP lookup failed."
    except Exception as e: return str(e)
def do_ping(t):   return run_cmd("ping -c 4 " + clean(t), 15)
def do_trace(t):  return run_cmd("traceroute -m 15 " + clean(t) + " 2>/dev/null || tracepath " + clean(t), 30)
def do_netscan():
    local = run_cmd("hostname -I").strip().split()[0]
    subnet = ".".join(local.split(".")[:3]) + ".0/24"
    return run_cmd("nmap -sn " + subnet, 60)
def get_my_ip():
    local = run_cmd("hostname -I").strip()
    try:
        import requests; pub = requests.get("https://api.ipify.org", timeout=5).text.strip()
    except: pub = "Unavailable"
    return "Local IP: " + local + "\nPublic IP: " + pub
def get_sysinfo():
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=1); ram = psutil.virtual_memory(); disk = psutil.disk_usage("/")
        bat = psutil.sensors_battery()
        b = "\nBattery: "+str(int(bat.percent))+"% "+("Charging" if bat.power_plugged else "Discharging") if bat else ""
        return "CPU: "+str(cpu)+"%\nRAM: "+str(ram.percent)+"% ("+str(round(ram.used/1e9,1))+"GB / "+str(round(ram.total/1e9,1))+"GB)\nDisk: "+str(disk.percent)+"%"+b
    except: return "Install psutil: pip install psutil"
def get_weather():
    try:
        import requests
        d = requests.get("https://api.open-meteo.com/v1/forecast?latitude=17.6868&longitude=83.2185&current_weather=true", timeout=5).json()["current_weather"]
        return "Location: Visakhapatnam\nTemp: "+str(d["temperature"])+"C\nWind: "+str(d["windspeed"])+" km/h"
    except: return "Weather unavailable."

def speak_generate(text):
    try: gTTS(text=text, lang="en", tld="co.in", slow=False).save(VOICE_FILE); return True
    except: return False

def get_greeting():
    h = datetime.datetime.now().hour
    if 5<=h<12: return "Good morning"
    elif 12<=h<17: return "Good afternoon"
    elif 17<=h<21: return "Good evening"
    return "Good night"

JOKES  = ["Why do hackers prefer dark mode? Light attracts script kiddies!","A SQL injection walks into a bar. The bartender drops all the tables.","There are 10 types of people: those who understand binary and those who dont."]
MOTIVES= ["FG every great hacker started by breaking their own stuff. Keep going!","Knowledge is the most powerful weapon in cybersecurity. Never stop learning FG!","The best hackers think like attackers but act like defenders. You have got this FG!"]

# ═══════════════════════════════════════════════════════════════════
#  ATTACK CHAIN ENGINE — Connect vulnerabilities into kill chains
# ═══════════════════════════════════════════════════════════════════

ATTACK_CHAIN_RULES = [
    {
        "id": "chain_ftp_webshell",
        "name": "FTP to Web Shell Upload",
        "kill_chain": "Initial Access → Execution → Persistence",
        "steps": [
            {"match": "port", "port": [21], "label": "FTP Service Open", "phase": "Recon"},
            {"match": "threat_kw", "keywords": ["ftp","anonymous","write"], "label": "Anonymous/Weak FTP Access", "phase": "Initial Access"},
            {"match": "port", "port": [80,443,8080,8443], "label": "Web Server Running", "phase": "Lateral"},
            {"match": "threat_kw", "keywords": ["upload","write","webroot","directory"], "label": "Upload Web Shell via FTP", "phase": "Execution"},
        ],
        "impact": "Remote Code Execution — Attacker uploads a malicious web shell through writable FTP, gaining full server control via browser.",
        "business_impact": "Complete server compromise. Customer data theft, service disruption, regulatory penalties.",
        "cost_estimate": "₹8-25 Lakhs (data breach notification + forensics + downtime)",
        "severity": "CRITICAL",
        "fix": "1) Disable anonymous FTP: edit /etc/vsftpd.conf → anonymous_enable=NO\n2) Restrict FTP write to isolated directories\n3) Separate FTP root from web root\n4) Enable FTP logging: xferlog_enable=YES\n5) Use SFTP instead: apt install openssh-server",
        "compliance": {"ISO27001": "A.9.4.1 - Access Control", "PCI-DSS": "2.1, 6.2", "SOC2": "CC6.1", "DPDP": "Section 8 - Security Safeguards"}
    },
    {
        "id": "chain_sqli_data",
        "name": "SQL Injection to Data Exfiltration",
        "kill_chain": "Initial Access → Collection → Exfiltration",
        "steps": [
            {"match": "port", "port": [80,443,8080], "label": "Web Application Exposed", "phase": "Recon"},
            {"match": "threat_kw", "keywords": ["sql","injection","sqli","sqlmap"], "label": "SQL Injection Vulnerability", "phase": "Initial Access"},
            {"match": "port", "port": [3306,5432,1433,27017], "label": "Database Service Reachable", "phase": "Lateral"},
        ],
        "impact": "Full Database Extraction — Attacker exploits SQLi to dump all tables including user credentials, payment data, PII.",
        "business_impact": "Mass data breach. DPDP Act violation, customer trust destroyed, potential lawsuits.",
        "cost_estimate": "₹15-50 Lakhs (regulatory fines + legal + customer notification + reputation)",
        "severity": "CRITICAL",
        "fix": "1) Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n2) Implement WAF rules: ModSecurity/OWASP CRS\n3) Block direct database port access from internet: ufw deny 3306\n4) Apply least-privilege DB accounts\n5) Enable SQL query logging and alerting",
        "compliance": {"ISO27001": "A.14.2.5 - Secure Development", "PCI-DSS": "6.5.1", "SOC2": "CC6.1, CC7.1", "DPDP": "Section 8(1)(a)"}
    },
    {
        "id": "chain_ssh_privesc",
        "name": "SSH Brute Force to Privilege Escalation",
        "kill_chain": "Initial Access → Privilege Escalation → Impact",
        "steps": [
            {"match": "port", "port": [22], "label": "SSH Service Exposed", "phase": "Recon"},
            {"match": "threat_kw", "keywords": ["ssh","password","brute","weak","auth"], "label": "Weak SSH Authentication", "phase": "Initial Access"},
            {"match": "threat_kw", "keywords": ["root","sudo","privilege","suid","kernel"], "label": "Privilege Escalation Vector", "phase": "Priv Escalation"},
        ],
        "impact": "Root Access — Attacker brute-forces SSH with common passwords, escalates to root via misconfig or kernel exploit.",
        "business_impact": "Full infrastructure compromise. Ransomware deployment, crypto mining, data destruction.",
        "cost_estimate": "₹10-30 Lakhs (incident response + system rebuild + downtime)",
        "severity": "CRITICAL",
        "fix": "1) Disable password auth: PasswordAuthentication no in /etc/ssh/sshd_config\n2) Use key-based auth only: ssh-keygen -t ed25519\n3) Install fail2ban: apt install fail2ban\n4) Change SSH port: Port 2222\n5) Enable 2FA: apt install libpam-google-authenticator\n6) Restrict root login: PermitRootLogin no",
        "compliance": {"ISO27001": "A.9.2.3 - Privileged Access", "PCI-DSS": "2.1, 8.2", "SOC2": "CC6.1, CC6.3", "DPDP": "Section 8"}
    },
    {
        "id": "chain_ssl_mitm",
        "name": "SSL/TLS Weakness to MITM Attack",
        "kill_chain": "Recon → Credential Access → Collection",
        "steps": [
            {"match": "port", "port": [443,8443], "label": "HTTPS Service Active", "phase": "Recon"},
            {"match": "threat_kw", "keywords": ["ssl","tls","certificate","expired","weak cipher","heartbleed","poodle"], "label": "SSL/TLS Vulnerability Detected", "phase": "Exploitation"},
            {"match": "threat_kw", "keywords": ["header","hsts","security header","x-frame"], "label": "Missing Security Headers", "phase": "Lateral"},
        ],
        "impact": "Man-in-the-Middle — Attacker intercepts encrypted traffic, steals session tokens, credentials, and sensitive data in transit.",
        "business_impact": "Customer credential theft, session hijacking, compliance failure.",
        "cost_estimate": "₹5-15 Lakhs (certificate replacement + audit + customer communication)",
        "severity": "HIGH",
        "fix": "1) Upgrade TLS: ssl_protocols TLSv1.2 TLSv1.3 in nginx.conf\n2) Strong ciphers: ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:...'\n3) Enable HSTS: add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains'\n4) Renew certificates: certbot renew --force-renewal\n5) Disable SSLv3/TLSv1.0: ssl_protocols TLSv1.2 TLSv1.3;",
        "compliance": {"ISO27001": "A.10.1.1 - Cryptographic Controls", "PCI-DSS": "4.1", "SOC2": "CC6.7", "DPDP": "Section 8(1)(b)"}
    },
    {
        "id": "chain_exposed_db",
        "name": "Exposed Database to Mass Data Theft",
        "kill_chain": "Recon → Collection → Exfiltration",
        "steps": [
            {"match": "port", "port": [3306,5432,1433,27017,6379,9200], "label": "Database Port Exposed to Internet", "phase": "Recon"},
            {"match": "threat_kw", "keywords": ["database","mongo","redis","elastic","mysql","postgres","no auth","open"], "label": "No/Weak Authentication on DB", "phase": "Initial Access"},
        ],
        "impact": "Direct Data Access — Attacker connects directly to exposed database, dumps all records without needing to exploit any application.",
        "business_impact": "Immediate total data breach. All customer records, financial data, IP stolen.",
        "cost_estimate": "₹20-75 Lakhs (major breach — regulatory + legal + forensics + reputation)",
        "severity": "CRITICAL",
        "fix": "1) Block DB ports from internet: ufw deny from any to any port 3306\n2) Bind to localhost: bind-address=127.0.0.1 in my.cnf\n3) Require authentication: ALTER USER 'root'@'%' SET PASSWORD\n4) Enable TLS for DB connections\n5) Use VPN/SSH tunnel for remote access\n6) Enable audit logging",
        "compliance": {"ISO27001": "A.13.1.1 - Network Controls", "PCI-DSS": "1.3.6, 2.1", "SOC2": "CC6.1, CC6.6", "DPDP": "Section 8, Section 9"}
    },
    {
        "id": "chain_xss_session",
        "name": "XSS to Session Hijacking",
        "kill_chain": "Initial Access → Credential Access → Impact",
        "steps": [
            {"match": "port", "port": [80,443,8080], "label": "Web Application Running", "phase": "Recon"},
            {"match": "threat_kw", "keywords": ["xss","cross-site","script","reflected","stored"], "label": "Cross-Site Scripting Found", "phase": "Initial Access"},
            {"match": "threat_kw", "keywords": ["header","cookie","httponly","secure","session"], "label": "Weak Session Management", "phase": "Credential Access"},
        ],
        "impact": "Session Hijacking — Attacker injects malicious JavaScript to steal admin session cookies, gaining full account access.",
        "business_impact": "Admin account takeover, defacement, unauthorized transactions.",
        "cost_estimate": "₹3-10 Lakhs (incident response + security audit + patching)",
        "severity": "HIGH",
        "fix": "1) Output encoding: use template auto-escaping (Jinja2, React)\n2) Content Security Policy: add_header Content-Security-Policy \"default-src 'self'\"\n3) HttpOnly cookies: Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict\n4) Implement input validation and sanitization\n5) Use DOMPurify for client-side rendering",
        "compliance": {"ISO27001": "A.14.2.5", "PCI-DSS": "6.5.7", "SOC2": "CC6.1", "DPDP": "Section 8(1)(a)"}
    },
    {
        "id": "chain_smb_lateral",
        "name": "SMB Exploit to Lateral Movement",
        "kill_chain": "Initial Access → Lateral Movement → Impact",
        "steps": [
            {"match": "port", "port": [139,445], "label": "SMB Service Exposed", "phase": "Recon"},
            {"match": "threat_kw", "keywords": ["smb","eternalblue","ms17","samba","share","null session"], "label": "SMB Vulnerability / Misconfig", "phase": "Initial Access"},
        ],
        "impact": "Network-Wide Compromise — Attacker exploits SMB to move laterally across all machines on the network (EternalBlue/WannaCry-style).",
        "business_impact": "Ransomware deployment across entire network. Complete business shutdown.",
        "cost_estimate": "₹25-100 Lakhs (network-wide ransomware incident)",
        "severity": "CRITICAL",
        "fix": "1) Block SMB from internet: ufw deny 445\n2) Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false\n3) Apply MS17-010 patch\n4) Segment network: isolate critical servers\n5) Enable SMB signing: RequireSecuritySignature=True\n6) Disable null sessions",
        "compliance": {"ISO27001": "A.13.1.3 - Segregation", "PCI-DSS": "1.3, 6.2", "SOC2": "CC6.6", "DPDP": "Section 8"}
    },
    {
        "id": "chain_cors_csrf",
        "name": "CORS Misconfiguration to Account Takeover",
        "kill_chain": "Initial Access → Credential Access → Impact",
        "steps": [
            {"match": "port", "port": [80,443], "label": "Web Application with API", "phase": "Recon"},
            {"match": "threat_kw", "keywords": ["cors","origin","cross-origin","access-control"], "label": "CORS Misconfiguration", "phase": "Initial Access"},
            {"match": "threat_kw", "keywords": ["header","csrf","token","cookie"], "label": "Weak CSRF Protection", "phase": "Credential Access"},
        ],
        "impact": "Cross-Origin Attack — Attacker crafts malicious page that makes authenticated API calls on behalf of logged-in users.",
        "business_impact": "Unauthorized actions on user accounts, data modification, financial fraud.",
        "cost_estimate": "₹2-8 Lakhs (security audit + patching + user notification)",
        "severity": "HIGH",
        "fix": "1) Restrict CORS origins: Access-Control-Allow-Origin: https://yourdomain.com\n2) Never use wildcard (*) with credentials\n3) Implement CSRF tokens on all state-changing endpoints\n4) Use SameSite cookie attribute\n5) Validate Origin/Referer headers server-side",
        "compliance": {"ISO27001": "A.14.2.5", "PCI-DSS": "6.5.9", "SOC2": "CC6.1", "DPDP": "Section 8"}
    },
    {
        "id": "chain_rdp_ransom",
        "name": "RDP Exposure to Ransomware",
        "kill_chain": "Initial Access → Execution → Impact",
        "steps": [
            {"match": "port", "port": [3389], "label": "RDP Exposed to Internet", "phase": "Recon"},
            {"match": "threat_kw", "keywords": ["rdp","remote desktop","bluekeep","brute","nla"], "label": "RDP Vulnerability or Weak Auth", "phase": "Initial Access"},
        ],
        "impact": "Ransomware Deployment — Exposed RDP is the #1 ransomware entry point. Attacker brute-forces login and deploys ransomware.",
        "business_impact": "Complete business shutdown. All files encrypted. Ransom demand + data leak threat.",
        "cost_estimate": "₹15-50 Lakhs (ransom + downtime + recovery + legal)",
        "severity": "CRITICAL",
        "fix": "1) Block RDP from internet: ufw deny 3389 from any\n2) Use VPN for remote access: WireGuard/OpenVPN\n3) Enable NLA: Network Level Authentication\n4) Apply BlueKeep patches (CVE-2019-0708)\n5) Implement account lockout: 5 attempts / 15 min\n6) Enable MFA for all remote access",
        "compliance": {"ISO27001": "A.9.4.2", "PCI-DSS": "1.3, 8.2", "SOC2": "CC6.1, CC6.2", "DPDP": "Section 8"}
    },
    {
        "id": "chain_docker_escape",
        "name": "Docker API to Container Escape",
        "kill_chain": "Initial Access → Execution → Privilege Escalation",
        "steps": [
            {"match": "port", "port": [2375,2376], "label": "Docker API Exposed", "phase": "Recon"},
            {"match": "threat_kw", "keywords": ["docker","container","api","daemon","2375"], "label": "Unauthenticated Docker Access", "phase": "Initial Access"},
        ],
        "impact": "Host Compromise — Attacker creates privileged container mounting host filesystem, escaping to full root on the host machine.",
        "business_impact": "Complete infrastructure takeover. All containers and host compromised.",
        "cost_estimate": "₹10-40 Lakhs (infrastructure rebuild + security audit)",
        "severity": "CRITICAL",
        "fix": "1) Never expose Docker socket/API to network\n2) Enable TLS: dockerd --tlsverify --tlscert=... --tlskey=...\n3) Use rootless Docker: dockerd-rootless\n4) Drop capabilities: --cap-drop ALL --cap-add ONLY_NEEDED\n5) Enable user namespaces: userns-remap in daemon.json\n6) Use read-only containers: --read-only",
        "compliance": {"ISO27001": "A.14.2.5", "PCI-DSS": "2.2, 6.2", "SOC2": "CC6.1", "DPDP": "Section 8"}
    },
]

def analyze_attack_chains(ports, threats):
    """Analyze ports and threats to find viable attack chains."""
    found_chains = []
    port_numbers = set()
    threat_text = ""

    for p in ports:
        port_numbers.add(int(p.get("port", 0)))
    for t in threats:
        threat_text += " " + t.get("name", "").lower() + " " + t.get("desc", "").lower() + " " + t.get("fix", "").lower()

    for rule in ATTACK_CHAIN_RULES:
        matched_steps = []
        total_steps = len(rule["steps"])
        for step in rule["steps"]:
            if step["match"] == "port":
                if any(p in port_numbers for p in step["port"]):
                    matched_steps.append({**step, "status": "confirmed"})
                else:
                    matched_steps.append({**step, "status": "not_found"})
            elif step["match"] == "threat_kw":
                if any(kw in threat_text for kw in step["keywords"]):
                    matched_steps.append({**step, "status": "confirmed"})
                else:
                    matched_steps.append({**step, "status": "not_found"})

        confirmed = sum(1 for s in matched_steps if s["status"] == "confirmed")
        confidence = round((confirmed / total_steps) * 100)

        # Include chain if at least 50% of steps matched (partial chains are still risks)
        if confidence >= 50:
            found_chains.append({
                "id": rule["id"],
                "name": rule["name"],
                "kill_chain": rule["kill_chain"],
                "severity": rule["severity"],
                "confidence": confidence,
                "steps": matched_steps,
                "total_steps": total_steps,
                "confirmed_steps": confirmed,
                "impact": rule["impact"],
                "business_impact": rule["business_impact"],
                "cost_estimate": rule["cost_estimate"],
                "fix": rule["fix"],
                "compliance": rule.get("compliance", {})
            })

    # Sort by severity then confidence
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    found_chains.sort(key=lambda c: (sev_order.get(c["severity"], 9), -c["confidence"]))
    return found_chains

def generate_advanced_report(ports, threats, chains, target):
    """Generate 3-audience report: Executive, Technical, Compliance."""
    now = datetime.datetime.now().strftime("%B %d, %Y at %I:%M %p")
    crit_p = sum(1 for p in ports if p.get("severity") == "CRITICAL")
    high_p = sum(1 for p in ports if p.get("severity") == "HIGH")
    crit_t = sum(1 for t in threats if t.get("severity") == "CRITICAL")
    high_t = sum(1 for t in threats if t.get("severity") == "HIGH")
    score = min(100, crit_p*25 + high_p*15 + crit_t*30 + high_t*20 + len(chains)*10)

    # Risk level
    if score >= 75: risk_level, risk_color = "CRITICAL", "#d90429"
    elif score >= 50: risk_level, risk_color = "HIGH", "#e85d04"
    elif score >= 25: risk_level, risk_color = "MEDIUM", "#e09f3e"
    else: risk_level, risk_color = "LOW", "#2d6a4f"

    report = {
        "generated": now,
        "target": target,
        "risk_score": score,
        "risk_level": risk_level,
        "summary": {
            "total_ports": len(ports),
            "total_threats": len(threats),
            "total_chains": len(chains),
            "critical_findings": crit_p + crit_t,
            "high_findings": high_p + high_t,
        },
        "executive": {
            "headline": f"Security assessment of {target or 'target systems'} identified {len(threats)} vulnerabilities and {len(chains)} attack paths.",
            "risk_summary": f"Overall risk: {risk_level} ({score}/100). {'Immediate action required.' if score >= 50 else 'Monitor and remediate.'} ",
            "business_risks": [c["business_impact"] for c in chains[:5]],
            "cost_exposure": [c["cost_estimate"] for c in chains[:5]],
            "top_recommendations": [],
        },
        "technical": {
            "ports": ports,
            "threats": threats,
            "chains": chains,
        },
        "compliance": {
            "frameworks": {}
        }
    }

    # Build top recommendations
    seen_fixes = set()
    for c in chains:
        first_fix = c["fix"].split("\n")[0]
        if first_fix not in seen_fixes:
            report["executive"]["top_recommendations"].append({
                "chain": c["name"],
                "priority": c["severity"],
                "action": first_fix
            })
            seen_fixes.add(first_fix)

    # Build compliance mapping
    fw_map = {}
    for c in chains:
        for framework, control in c.get("compliance", {}).items():
            if framework not in fw_map:
                fw_map[framework] = []
            fw_map[framework].append({"control": control, "issue": c["name"], "severity": c["severity"]})
    report["compliance"]["frameworks"] = fw_map

    return report

# Persistent storage for attack chain data
attack_chain_cache = {"chains": [], "report": None}

def chat_response(msg):
    m = msg.lower().strip()

    # --- Greetings ---
    if any(w in m for w in ["hello","hi","hey","yo","sup"]): return get_greeting() + " FG! FluentGrid AI V10.0 online. Web + Network + Infra VAPT armed and ready!"
    if any(w in m for w in ["bye","goodbye","see you","later"]): return "Stay safe FG! FG AI standing by. 🛡️"
    if any(w in m for w in ["thanks","thank you","thx"]): return "You're welcome FG! Always here to help with your security assessments."

    # --- Identity ---
    if any(p in m for p in ["who are you","your name","what are you","about you"]): return "I am FluentGrid AI V10.0 — a comprehensive VAPT (Vulnerability Assessment & Penetration Testing) suite. I cover Web, Network, and Infrastructure security testing with 30+ integrated tools. Built by FG!"
    if any(p in m for p in ["who made you","who built","who created","developer"]): return "Built by FG! Full VAPT suite powered by Python, Nmap, and Kali Linux. Covering Web, Network, and Infrastructure penetration testing."

    # --- System/Utility ---
    if "time" in m: return "🕐 " + datetime.datetime.now().strftime("%I:%M:%S %p")
    if "date" in m or "today" in m: return "📅 " + datetime.datetime.now().strftime("%A, %B %d, %Y")
    if "weather" in m: return get_weather()
    if "system" in m or "cpu" in m or "ram" in m: return get_sysinfo()
    if "my ip" in m or "ip address" in m: return get_my_ip()
    if any(w in m for w in ["joke","funny","laugh"]): return random.choice(JOKES)
    if any(w in m for w in ["motivate","inspire","quote"]): return random.choice(MOTIVES)

    # --- VAPT Concepts ---
    if "what is vapt" in m or ("vapt" in m and "mean" in m) or ("vapt" in m and "explain" in m):
        return "VAPT stands for Vulnerability Assessment and Penetration Testing. It's a security testing approach that combines: 1) Vulnerability Assessment — automated scanning to identify known vulnerabilities, misconfigurations, and weaknesses. 2) Penetration Testing — manual/simulated attacks to exploit vulnerabilities and assess real-world impact. Together they provide a comprehensive security evaluation of systems, networks, and applications."

    if "what is penetration testing" in m or "what is pentest" in m:
        return "Penetration Testing (pentesting) is a simulated cyberattack against your system to find exploitable vulnerabilities. It involves: Reconnaissance → Scanning → Gaining Access → Maintaining Access → Reporting. Types include: Black Box (no prior knowledge), White Box (full knowledge), and Gray Box (partial knowledge)."

    if "vulnerability assessment" in m and ("what" in m or "explain" in m):
        return "Vulnerability Assessment is the process of identifying, quantifying, and prioritizing security vulnerabilities in a system. It uses automated scanners (like Nmap, Nikto, OpenVAS) to detect known CVEs, misconfigurations, default credentials, and missing patches. The output is a prioritized list of findings with severity ratings (Critical, High, Medium, Low)."

    if "owasp" in m and "top 10" in m:
        return "OWASP Top 10 (2021): 1) Broken Access Control 2) Cryptographic Failures 3) Injection (SQLi, XSS, Command) 4) Insecure Design 5) Security Misconfiguration 6) Vulnerable Components 7) Auth Failures 8) Software & Data Integrity Failures 9) Security Logging Failures 10) Server-Side Request Forgery (SSRF). Use our Web VAPT tools to test for most of these!"

    if "cvss" in m:
        return "CVSS (Common Vulnerability Scoring System) rates vulnerabilities 0-10: None (0), Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), Critical (9.0-10.0). It considers Attack Vector, Complexity, Privileges Required, User Interaction, Scope, and CIA impact (Confidentiality, Integrity, Availability)."

    if "cve" in m and ("what" in m or "explain" in m):
        return "CVE (Common Vulnerabilities and Exposures) is a standardized identifier for security vulnerabilities. Format: CVE-YEAR-NUMBER (e.g., CVE-2021-44228 = Log4Shell). CVEs are tracked by MITRE and listed in the National Vulnerability Database (NVD). Our Vuln Scan tool checks for known CVEs on target services."

    # --- SQL Injection ---
    if "sql injection" in m or "sqli" in m:
        if "prevent" in m or "fix" in m or "remediat" in m or "protect" in m:
            return "SQL Injection Prevention: 1) Use Parameterized Queries/Prepared Statements — never concatenate user input into SQL. 2) Use ORM frameworks (SQLAlchemy, Hibernate). 3) Input Validation — whitelist allowed characters. 4) Least Privilege — DB accounts should have minimal permissions. 5) WAF rules to detect SQLi patterns. 6) Regular security scanning with tools like our SQLMap checker."
        return "SQL Injection is a code injection attack that exploits vulnerabilities in an application's database layer. Attackers insert malicious SQL statements through user inputs to: dump databases, bypass authentication, modify/delete data, or even execute OS commands. Types: In-band (classic), Blind (Boolean/Time-based), and Out-of-band. Use our SQL Injection tool to test! Prevention: parameterized queries, input validation, WAFs."

    # --- XSS ---
    if "xss" in m or "cross site scripting" in m or "cross-site scripting" in m:
        if "prevent" in m or "fix" in m or "protect" in m:
            return "XSS Prevention: 1) Output Encoding — HTML-encode user data before rendering. 2) Content Security Policy (CSP) headers. 3) Input validation and sanitization. 4) Use frameworks with auto-escaping (React, Angular). 5) HTTPOnly and Secure cookie flags. 6) X-XSS-Protection header."
        return "Cross-Site Scripting (XSS) injects malicious scripts into web pages viewed by other users. Types: 1) Reflected XSS — payload in URL parameters, reflected by server. 2) Stored XSS — payload saved to database, served to all users (most dangerous). 3) DOM-based XSS — payload manipulates client-side DOM. Impact: session hijacking, credential theft, defacement, malware distribution. Use our XSS Scanner to test!"

    # --- Port Scanning ---
    if "port scan" in m or "nmap" in m:
        if "how to" in m or "use" in m:
            return "To scan ports: 1) Enter the target IP/domain in the target field. 2) Click 'Port Scanner' for a quick scan or 'Quick Top 100' for the most common ports. 3) Results appear in Terminal and the Ports tab shows a detailed breakdown with severity ratings. 4) Use 'Vuln Scan' for CVE detection on open services."
        return "Port scanning discovers open network services on a target. Open ports indicate running services that could be attack vectors. Common critical ports: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80/443 (HTTP/S), 135/445 (SMB), 1433 (MSSQL), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 6379 (Redis), 8080 (HTTP Proxy), 27017 (MongoDB). Our scanner identifies services, versions, and risk levels."

    # --- SSL/TLS ---
    if "ssl" in m or "tls" in m:
        if "prevent" in m or "fix" in m or "best practice" in m:
            return "SSL/TLS Best Practices: 1) Use TLS 1.2+ only (disable SSL 2.0/3.0, TLS 1.0/1.1). 2) Strong cipher suites (AES-256-GCM, ChaCha20). 3) Enable HSTS header. 4) Valid certificates from trusted CAs. 5) Enable OCSP Stapling. 6) Disable SSL compression (CRIME attack). 7) Forward Secrecy (ECDHE). 8) Regular certificate rotation."
        return "SSL/TLS secures communications between client and server through encryption. Common issues: expired/self-signed certificates, weak cipher suites, protocol downgrade attacks (POODLE, BEAST), Heartbleed (CVE-2014-0160). Use our SSL/TLS Check tool to audit a target's certificate chain, protocol versions, cipher strength, and known vulnerabilities."

    # --- CORS ---
    if "cors" in m:
        return "CORS (Cross-Origin Resource Sharing) controls which external domains can access your API. Misconfigured CORS can allow: unauthorized data access from malicious sites, credential theft, and cross-origin attacks. Dangerous: Access-Control-Allow-Origin: * with credentials. Fix: whitelist specific trusted origins, never reflect the Origin header blindly, restrict methods/headers. Use our CORS Check tool to test!"

    # --- WAF ---
    if "waf" in m:
        return "WAF (Web Application Firewall) filters and monitors HTTP traffic between web apps and the internet. It protects against SQLi, XSS, CSRF, file inclusion, and other OWASP Top 10 attacks. Popular WAFs: Cloudflare, AWS WAF, ModSecurity, Imperva, Akamai. Our WAF Detect tool identifies which WAF is protecting a target — useful for tailoring your testing approach."

    # --- SMB ---
    if "smb" in m:
        return "SMB (Server Message Block) is a file sharing protocol on ports 139/445. Security risks: EternalBlue (CVE-2017-0144, used in WannaCry), null session enumeration, anonymous access, SMBv1 vulnerabilities. Always disable SMBv1, enforce SMB signing, block ports 139/445 externally, use strong authentication. Our SMB Enum tool checks for anonymous access and enumerates shares."

    # --- SSH ---
    if "ssh" in m and ("what" in m or "explain" in m or "secure" in m or "audit" in m or "best" in m):
        return "SSH (Secure Shell) provides encrypted remote access on port 22. Best practices: 1) Disable password auth, use SSH keys. 2) Disable root login (PermitRootLogin no). 3) Use SSH key passphrases. 4) Restrict to specific users (AllowUsers). 5) Change default port. 6) Enable fail2ban for brute-force protection. 7) Use Ed25519 or RSA-4096 keys. 8) Disable X11 forwarding if unused. Our SSH Audit checks for weak configs."

    # --- RDP ---
    if "rdp" in m:
        return "RDP (Remote Desktop Protocol) on port 3389 enables remote Windows access. Risks: BlueKeep (CVE-2019-0708), brute-force attacks, man-in-the-middle. Security: 1) Enable Network Level Authentication (NLA). 2) Use VPN — never expose RDP to internet. 3) Strong passwords + account lockout. 4) Enable MFA. 5) Patch regularly. 6) Use RDP gateways. Our RDP Check tests for exposed services."

    # --- Docker/K8s ---
    if "docker" in m or "container" in m:
        return "Docker Security: 1) Never run containers as root. 2) Use official/trusted images. 3) Scan images for vulnerabilities (Trivy, Snyk). 4) Don't expose Docker socket (port 2375/2376). 5) Use read-only file systems. 6) Limit resources (CPU/memory). 7) Enable Content Trust. 8) Use network policies. Our Docker Check tests for exposed APIs and misconfigurations."

    if "kubernetes" in m or "k8s" in m:
        return "Kubernetes Security: 1) RBAC — least privilege access. 2) Network Policies to segment pods. 3) Pod Security Standards. 4) Don't expose API server publicly. 5) Encrypt etcd data. 6) Scan images before deployment. 7) Enable audit logging. 8) Use service mesh (Istio) for mTLS. 9) Regularly update components. Our K8s Check tests for exposed dashboards and APIs."

    # --- Network Security ---
    if "firewall" in m and ("what" in m or "explain" in m or "type" in m):
        return "Firewalls control network traffic based on rules. Types: 1) Packet Filtering — inspects headers (IP, port). 2) Stateful Inspection — tracks connection state. 3) Application-layer (WAF) — inspects content. 4) Next-Gen (NGFW) — combines all with IPS, deep packet inspection. Our Firewall Detect tool identifies if a target is behind a firewall and what type."

    if "dns" in m and ("what" in m or "explain" in m or "attack" in m):
        return "DNS (Domain Name System) translates domains to IPs. Security attacks: DNS spoofing/poisoning, DNS tunneling (data exfiltration), DNS amplification DDoS, zone transfer exploitation, subdomain takeover. Protection: DNSSEC, DoH/DoT, restrict zone transfers, monitor DNS logs. Use our DNS Lookup and Subdomain Enum tools for recon."

    # --- General Security Concepts ---
    if "brute force" in m:
        return "Brute Force attacks try all possible password combinations to gain access. Defense: 1) Account lockout after N failed attempts. 2) Rate limiting. 3) CAPTCHA after failed logins. 4) Multi-factor authentication (MFA). 5) Strong password policies. 6) fail2ban / IP blocking. 7) Monitor login logs for anomalies."

    if "phishing" in m:
        return "Phishing tricks users into revealing credentials or installing malware via fake emails/websites. Types: Spear phishing (targeted), Whaling (executives), Vishing (voice), Smishing (SMS). Defense: Email filtering, SPF/DKIM/DMARC, security awareness training, MFA, URL scanning, sandbox analysis."

    if "ransomware" in m:
        return "Ransomware encrypts files and demands payment for decryption. Defense: 1) Regular offline backups (3-2-1 rule). 2) Patch management. 3) Email filtering. 4) Network segmentation. 5) Endpoint Detection & Response (EDR). 6) Least privilege access. 7) Disable macros. 8) Incident response plan. Notable: WannaCry, NotPetya, REvil, LockBit."

    if "zero day" in m or "0day" in m or "0-day" in m:
        return "Zero-day vulnerabilities are unknown to the vendor with no patch available. Defense: 1) Defense in depth (multiple security layers). 2) Behavioral detection (EDR/XDR). 3) Network segmentation. 4) Application whitelisting. 5) Regular patching to reduce attack surface. 6) Threat intelligence feeds. 7) Bug bounty programs."

    if any(p in m for p in ["social engineering","social attack"]):
        return "Social Engineering manipulates people into revealing info or performing actions. Types: Phishing, Pretexting, Baiting, Tailgating, Quid Pro Quo, Watering Hole attacks. Defense: Security awareness training, verify identities, strict access policies, physical security, incident reporting culture."

    if "mitm" in m or "man in the middle" in m or "man-in-the-middle" in m:
        return "Man-in-the-Middle (MITM) attacks intercept communications between two parties. Types: ARP spoofing, DNS spoofing, SSL stripping, Wi-Fi eavesdropping. Defense: Use HTTPS/TLS everywhere, HSTS, certificate pinning, VPNs, ARP inspection, encrypted DNS (DoH/DoT). Our ARP Scan can detect potential MITM setups."

    if "ddos" in m or "dos attack" in m or "denial of service" in m:
        return "DDoS (Distributed Denial of Service) overwhelms targets with traffic. Types: Volumetric (UDP flood, DNS amp), Protocol (SYN flood, Ping of Death), Application-layer (HTTP flood, Slowloris). Defense: CDN/DDoS protection (Cloudflare, AWS Shield), rate limiting, SYN cookies, traffic analysis, redundant infrastructure."

    if "encryption" in m and ("what" in m or "explain" in m or "type" in m):
        return "Encryption protects data by converting it to unreadable form. Types: 1) Symmetric (AES-256, ChaCha20) — same key for encrypt/decrypt, fast. 2) Asymmetric (RSA, ECC) — public/private key pair, used for key exchange. 3) Hashing (SHA-256, bcrypt) — one-way, for passwords/integrity. Best practice: AES-256-GCM for data, RSA-4096/Ed25519 for keys, bcrypt/Argon2 for passwords."

    if ("cia" in m or "confidentiality" in m) and ("triad" in m or "security" in m or "integrity" in m):
        return "CIA Triad — the three pillars of information security: 1) Confidentiality — only authorized users access data (encryption, access controls). 2) Integrity — data is accurate and unaltered (hashing, digital signatures, checksums). 3) Availability — systems are accessible when needed (redundancy, backups, DDoS protection)."

    # --- Tool Help ---
    if "help" in m or "what can you do" in m or "features" in m:
        return "FluentGrid AI V10.0 can help with: 🔍 Run 30+ VAPT scans (sidebar tools) | 📊 Risk Analysis & Threat Graphs | 💬 Ask me about any security concept — SQLi, XSS, CVEs, OWASP, encryption, network attacks, best practices | 📄 Generate VAPT reports | 🛡 Get remediation advice for any vulnerability. Try asking: 'What is SQL injection?', 'How to prevent XSS?', 'Explain OWASP Top 10', 'What is CVSS?'"

    if "tool" in m and ("list" in m or "available" in m or "all" in m):
        return "Available tools: NETWORK — Port Scanner, Quick Top 100, Vuln Scan, UDP Scan, Firewall Detect, SMB Enum, SNMP Check, Banner Grab, ARP Scan. WEB — SQL Injection, XSS Scanner, Nikto, Header Audit, SSL/TLS Check, WAF Detect, CORS Check, Directory Enum, CMS Detect, Admin Finder. INFRA — SSH Audit, FTP Check, RDP Check, DB Exposure, Docker Check, K8s Check. RECON — WHOIS, DNS Lookup, Subdomain Enum, Traceroute, Local Network, My IP, System Info."

    if "how to" in m and ("scan" in m or "use" in m or "start" in m):
        return "How to use FG: 1) Enter your target IP or domain in the TARGET field at the top. 2) Choose a tool from the sidebar (Network, Web, Infrastructure, or Recon). 3) Results appear in the Terminal tab. 4) Port scans populate the Ports tab. 5) Vulnerability findings go to the Threats tab. 6) Check Risk Analysis and Threat Graph tabs for visual insights. 7) Click 'Download Report' for a full VAPT report."

    # --- Explicit search triggers ---
    search_prefixes = ["search ", "google ", "look up ", "find "]
    for prefix in search_prefixes:
        if m.startswith(prefix):
            search_query = msg[len(prefix):].strip()
            if search_query:
                result = ai_search_answer(search_query)
                if result:
                    return result
            break

    # --- "Who is" / "What is" / general questions → always try search ---
    question_starters = ["who is", "who are", "what is", "what are", "where is",
                         "when was", "when did", "how does", "how do", "how many",
                         "tell me about", "define ", "meaning of", "ceo of",
                         "founder of", "president of", "capital of"]
    for starter in question_starters:
        if m.startswith(starter) or starter in m:
            result = ai_search_answer(msg)
            if result:
                return result
            break

    # --- Catch-all: Search the web ---
    search_result = ai_search_answer(msg)
    if search_result:
        return search_result

    # Final fallback with helpful message
    if not HAS_REQUESTS:
        return "⚠️ Web search unavailable — 'requests' library not installed. Run: pip install requests. For now, I can answer VAPT and cybersecurity questions from my built-in knowledge. Try: 'What is SQL injection?', 'Explain OWASP Top 10', 'How to secure SSH?'"

    return "🔍 I searched but couldn't find a clear answer for: \"" + msg + "\". This might be because: the topic is very niche, or there's a network issue. Try rephrasing, or ask about: security concepts, OWASP, CVEs, network attacks, encryption, tool usage. You can also prefix with 'search' like: 'search Fluentgrid CEO'"

@app.route("/voice")
def voice():
    if os.path.exists(VOICE_FILE): return send_file(VOICE_FILE, mimetype="audio/mpeg")
    return jsonify({"error":"No voice"}), 404

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    tool = data.get("tool","")
    target = data.get("target","").strip()
    no_target = ["network_scan","my_ip","system_info","weather","arp_scan"]

    # ── Frontend→Backend tool name aliases ─────────────────────────────────────
    TOOL_ALIASES = {
        "nmap_scan":      "nmap_quick",
        "nmap_top100":    "nmap_quick",
        "udp_scan":       "nmap_udp",
        "firewall_detect":"nmap_firewall",
        "snmp_check":     "snmp_enum",
        "banner_grab":    "nmap_banner",
        "sqlmap_check":   "web_sqli",
        "xss_scan":       "web_xss",
        "nikto_scan":     "web_nikto",
        "header_check":   "web_headers",
        "ssl_check":      "web_ssl",
        "waf_detect":     "web_waf",
        "cors_check":     "web_cors",
        "dir_enum":       "web_dirscan",
        "cms_detect":     "web_cms",
        "admin_finder":   "web_admin",
        "ssh_audit":      "infra_ssh",
        "ftp_check":      "infra_ftp",
        "rdp_check":      "infra_rdp",
        "db_expose":      "infra_db",
        "docker_check":   "infra_docker",
        "k8s_check":      "infra_docker",
        "dns_lookup":     "dns",
        "subdomain_enum": "web_subdomain",
        "ping_host":      "ping",
    }
    tool = TOOL_ALIASES.get(tool, tool)
    # ────────────────────────────────────────────────────────────────────────────

    if tool not in no_target and not target:
        return jsonify({"error":True,"output":"Please enter a target IP or domain first.","timestamp":""}), 200

    handlers = {
        "nmap_quick":    (lambda: nmap_quick(target),    "nmap",    "Quick scan done on "+target),
        "nmap_full":     (lambda: nmap_full(target),     "nmap",    "Full scan done on "+target),
        "nmap_vuln":     (lambda: nmap_vuln(target),     "nmap",    "Vulnerability scan done on "+target),
        "nmap_os":       (lambda: nmap_os(target),       "nmap",    "OS detection done for "+target),
        "nmap_udp":      (lambda: nmap_udp(target),      "nmap",    "UDP scan done for "+target),
        "nmap_firewall": (lambda: nmap_firewall(target), "nmap",    "Firewall detection done for "+target),
        "nmap_banner":   (lambda: nmap_banner(target),   "nmap",    "Banner grab done for "+target),
        "arp_scan":      (nmap_arp,                      "nmap",    "ARP scan done FG"),
        "smb_enum":      (lambda: smb_enum(target),      "nmap",    "SMB enumeration done for "+target),
        "snmp_enum":     (lambda: snmp_enum(target),     "nmap",    "SNMP enumeration done for "+target),
        "dns_zone":      (lambda: dns_zone_transfer(target),"recon","DNS zone transfer done for "+target),
        "web_headers":   (lambda: web_headers(target),   "headers", "HTTP headers checked for "+target),
        "web_ssl":       (lambda: web_ssl(target),       "ssl",     "SSL analysis done for "+target),
        "web_waf":       (lambda: web_waf(target),       "web",     "WAF detection done for "+target),
        "web_nikto":     (lambda: web_nikto(target),     "web",     "Nikto scan done for "+target),
        "web_dirscan":   (lambda: web_dirscan(target),   "web",     "Directory scan done for "+target),
        "web_admin":     (lambda: web_admin_finder(target),"web",   "Admin panel scan done for "+target),
        "web_cms":       (lambda: web_cms(target),       "web",     "CMS detection done for "+target),
        "web_cors":      (lambda: web_cors(target),      "headers", "CORS check done for "+target),
        "web_sqli":      (lambda: web_sqli(target),      "web",     "SQL injection test done for "+target),
        "web_xss":       (lambda: web_xss(target),       "web",     "XSS scan done for "+target),
        "web_methods":   (lambda: web_methods(target),   "web",     "HTTP methods test done for "+target),
        "web_subdomain": (lambda: web_subdomain(target), "recon",   "Subdomain scan done for "+target),
        "infra_ssh":     (lambda: infra_ssh_audit(target),"nmap",   "SSH audit done for "+target),
        "infra_ftp":     (lambda: infra_ftp(target),     "nmap",    "FTP check done for "+target),
        "infra_rdp":     (lambda: infra_rdp(target),     "nmap",    "RDP check done for "+target),
        "infra_db":      (lambda: infra_db_check(target),"nmap",    "Database exposure check done for "+target),
        "infra_docker":  (lambda: infra_docker(target),  "nmap",    "Docker and Kubernetes check done for "+target),
        "infra_cve":     (lambda: infra_cve_scan(target),"nmap",    "CVE scan done for "+target),
        "infra_winrm":   (lambda: infra_winrm(target),   "nmap",    "WinRM check done for "+target),
        "infra_snmp":    (lambda: infra_snmp(target),    "nmap",    "SNMP audit done for "+target),
        "whois":         (lambda: do_whois(target),      "recon",   "WHOIS done for "+target),
        "dns":           (lambda: do_dns(target),        "recon",   "DNS records fetched for "+target),
        "ip_info":       (lambda: do_ip_info(target),    "recon",   "IP info retrieved for "+target),
        "ping":          (lambda: do_ping(target),       "recon",   "Ping done for "+target),
        "traceroute":    (lambda: do_trace(target),      "recon",   "Traceroute done to "+target),
        "network_scan":  (do_netscan,                    "nmap",    "Local network scan done FG"),
        "my_ip":         (get_my_ip,                     "recon",   "Here are your IP addresses FG"),
        "system_info":   (get_sysinfo,                   "system",  "System status ready FG"),
        "weather":       (get_weather,                   "system",  "Weather retrieved for Visakhapatnam FG"),
        "nuclei_full":   (lambda: nuclei_full(target),   "nuclei",  "Nuclei full scan done on "+target),
        "nuclei_cve":    (lambda: nuclei_cve(target),    "nuclei",  "Nuclei CVE scan done on "+target),
        "nuclei_misconfig":(lambda: nuclei_misconfig(target),"nuclei","Nuclei misconfiguration scan done on "+target),
        "nuclei_tech":   (lambda: nuclei_tech(target),   "nuclei",  "Nuclei tech detection done on "+target),
        "nuclei_critical":(lambda: nuclei_critical(target),"nuclei","Nuclei critical scan done on "+target),
        "nuclei_network":(lambda: nuclei_network(target),"nuclei",  "Nuclei network scan done on "+target),
    }
    # Alias mapping
    aliases = {
        "nmap_scan":"nmap_quick","nmap_top100":"nmap_full","udp_scan":"nmap_udp",
        "firewall_detect":"nmap_firewall","snmp_check":"snmp_enum","banner_grab":"nmap_banner",
        "sqlmap_check":"web_sqli","xss_scan":"web_xss","nikto_scan":"web_nikto",
        "header_check":"web_headers","ssl_check":"web_ssl","waf_detect":"web_waf",
        "cors_check":"web_cors","dir_enum":"web_dirscan","cms_detect":"web_cms",
        "admin_finder":"web_admin","ssh_audit":"infra_ssh","ftp_check":"infra_ftp",
        "rdp_check":"infra_rdp","db_expose":"infra_db","docker_check":"infra_docker",
        "k8s_check":"infra_docker","dns_lookup":"dns","subdomain_enum":"web_subdomain",
    }
    original_tool = tool
    tool = aliases.get(tool, tool)
    if tool not in handlers:
        return jsonify({"output":"Unknown tool: "+tool}), 200

    fn, tool_type, voice_text = handlers[tool]
    tool_display = TOOL_DISPLAY.get(tool, tool.upper())

    # --- Update status: INITIALIZING ---
    update_scan_status(
        active=True, tool=tool, tool_display=tool_display,
        target=target or "localhost", category=tool_type,
        phase="initializing", percent=5,
        start_time=time.time(), message="Initializing " + tool_display + "..."
    )

    # --- Start progress simulator in background ---
    est_duration = TOOL_DURATION.get(tool, 30)
    stop_progress = threading.Event()
    def progress_ticker():
        start = time.time()
        while not stop_progress.is_set():
            elapsed = time.time() - start
            # Simulate progress: fast start, slow near end (never reaches 95% until done)
            raw_pct = min(92, (elapsed / est_duration) * 85 + 5)
            # Add phase labels
            if elapsed < 2:
                phase, msg = "initializing", "Connecting to target..."
            elif elapsed < est_duration * 0.15:
                phase, msg = "scanning", "Probing target services..."
            elif elapsed < est_duration * 0.4:
                phase, msg = "scanning", "Scanning in progress..."
            elif elapsed < est_duration * 0.7:
                phase, msg = "scanning", "Deep analysis running..."
            elif elapsed < est_duration * 0.9:
                phase, msg = "analyzing", "Processing results..."
            else:
                phase, msg = "analyzing", "Finalizing scan..."
            update_scan_status(phase=phase, percent=int(raw_pct), message=msg)
            stop_progress.wait(0.8)

    ticker = threading.Thread(target=progress_ticker, daemon=True)
    ticker.start()

    # --- Execute the actual scan ---
    try:
        output = fn()
        stop_progress.set()
        ticker.join(timeout=2)

        # --- Analyze results ---
        update_scan_status(phase="analyzing", percent=95, message="Parsing results...")
        ports   = parse_open_ports(output) if tool_type == "nmap" else []
        threats = parse_vuln_threats(output, tool_type)
        if tool_type == "nuclei":
            nuclei_threats = parse_nuclei_threats(output)
            threats.extend(nuclei_threats)
        if ports:   voice_text += " Found "+str(len(ports))+" open ports."
        if threats: voice_text += " "+str(len(threats))+" threats detected!"
        speak_generate(voice_text)

        elapsed_total = round(time.time() - scan_status["start_time"], 1)

        # --- Run Attack Chain Analysis ---
        # Collect all ports and threats from history
        all_scan_ports = history_ports + ports if 'history_ports' in dir() else ports
        all_scan_threats = history_threats + threats if 'history_threats' in dir() else threats
        attack_chain_cache["ports"] = attack_chain_cache.get("ports", []) + ports
        attack_chain_cache["threats"] = attack_chain_cache.get("threats", []) + threats
        # Deduplicate
        seen_p = set()
        dedup_ports = []
        for p in attack_chain_cache.get("ports", []):
            key = str(p.get("port","")) + p.get("proto","")
            if key not in seen_p:
                seen_p.add(key)
                dedup_ports.append(p)
        seen_t = set()
        dedup_threats = []
        for t in attack_chain_cache.get("threats", []):
            if t.get("name","") not in seen_t:
                seen_t.add(t.get("name",""))
                dedup_threats.append(t)
        attack_chain_cache["ports"] = dedup_ports
        attack_chain_cache["threats"] = dedup_threats
        chains = analyze_attack_chains(dedup_ports, dedup_threats)
        attack_chain_cache["chains"] = chains
        attack_chain_cache["report"] = generate_advanced_report(dedup_ports, dedup_threats, chains, target or "localhost")

        # --- Update status: COMPLETE ---
        history_entry = {
            "tool": tool_display, "target": target or "localhost",
            "elapsed": elapsed_total, "ports": len(ports), "threats": len(threats),
            "time": datetime.datetime.now().strftime("%I:%M:%S %p")
        }
        with scan_lock:
            scan_status["history"].insert(0, history_entry)
            scan_status["history"] = scan_status["history"][:15]

        update_scan_status(
            active=False, phase="complete", percent=100,
            elapsed=elapsed_total,
            message="Complete — " + str(len(ports)) + " ports, " + str(len(threats)) + " threats in " + str(elapsed_total) + "s"
        )

        # ── Save result to disk for report history ──
        try:
            save_scan_result(original_tool or tool, target, output, ports, threats)
        except Exception:
            pass
        return jsonify({"output":output,"ports":ports,"threats":threats,"has_voice":True,
                        "timestamp":datetime.datetime.now().strftime("%I:%M:%S %p")})
    except Exception as e:
        stop_progress.set()
        update_scan_status(active=False, phase="error", percent=0, message="Error: " + str(e))
        return jsonify({"output":"Error: "+str(e),"ports":[],"threats":[],"has_voice":False,
                        "timestamp":datetime.datetime.now().strftime("%I:%M:%S %p")})

@app.route("/scan_status")
def get_scan_status():
    with scan_lock:
        return jsonify(scan_status)

@app.route("/attack_chains")
def get_attack_chains():
    return jsonify({"chains": attack_chain_cache.get("chains", [])})

@app.route("/advanced_report")
def get_advanced_report():
    return jsonify(attack_chain_cache.get("report") or {"error": "No data yet"})

@app.route("/chat", methods=["POST"])
def chat():
    msg = request.json.get("message","").strip()
    if not msg: return jsonify({"error":"empty"}), 400
    response = chat_response(msg)
    speak_generate(response)
    return jsonify({"response":response,"has_voice":True})

@app.route("/status")
def status():
    return jsonify({"status":"online","name":"FG AI","version":"4.0"})

# ═══════════════════════════════════════════════════════════════════════
#  FG-VAPT REPORT ENGINE  —  Server-side storage + HTML report generation
# ═══════════════════════════════════════════════════════════════════════
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

def save_scan_result(tool, target, output, ports, threats):
    """Persist a scan result to disk as JSON."""
    ts = datetime.datetime.now()
    safe_tool   = re.sub(r'[^a-zA-Z0-9]', '_', str(tool))
    safe_target = re.sub(r'[^a-zA-Z0-9]', '_', str(target or "localhost"))[:20]
    report_id = ts.strftime("%Y%m%d_%H%M%S") + "_" + safe_tool + "_" + safe_target
    data = {
        "id":           report_id,
        "tool":         tool,
        "tool_display": TOOL_DISPLAY.get(tool, tool.upper()),
        "target":       target or "localhost",
        "output":       str(output)[:50000],
        "ports":        ports,
        "threats":      threats,
        "timestamp":    ts.strftime("%Y-%m-%d %H:%M:%S"),
        "saved_at":     ts.isoformat(),
    }
    fpath = os.path.join(REPORTS_DIR, report_id + ".json")
    with open(fpath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return report_id


def _sev_color(s):
    return {"critical":"#d90429","high":"#e85d04","medium":"#e09f3e",
            "low":"#2d6a4f","info":"#0077b6"}.get(str(s).lower(), "#64748b")


REPORT_CSS = """
<style>
body{font-family:'Segoe UI',Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px}
.brand-hdr{background:#1e293b;border-left:5px solid #e63946;padding:18px 24px;margin-bottom:20px;border-radius:0 8px 8px 0;display:flex;justify-content:space-between;align-items:flex-end}
.brand-hdr h1{margin:0 0 3px;font-size:20px;color:#fff;letter-spacing:.01em}
.brand-hdr .sub{color:#94a3b8;font-size:12px}
.brand-hdr .badge{font-size:11px;background:#e63946;color:#fff;padding:3px 10px;border-radius:12px;font-weight:600}
.meta-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.meta-card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:10px 16px;min-width:130px}
.meta-card .lbl{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.08em}
.meta-card .val{font-size:15px;font-weight:700;color:#e2e8f0;margin-top:3px}
.sec{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px 20px;margin-bottom:16px}
.sec h2{margin:0 0 12px;font-size:14px;color:#a78bfa;text-transform:uppercase;letter-spacing:.07em}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#020617;color:#64748b;padding:8px 10px;text-align:left;border-bottom:1px solid #334155;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
td{padding:7px 10px;border-bottom:1px solid #1e293b;vertical-align:top}
pre{background:#020617;color:#94a3b8;padding:14px;border-radius:6px;font-size:11px;white-space:pre-wrap;word-break:break-all;max-height:420px;overflow-y:auto;margin:0;line-height:1.5}
.no-data{color:#475569;font-style:italic;font-size:12px}
.footer{text-align:center;color:#334155;font-size:11px;margin-top:24px;padding-top:14px;border-top:1px solid #1e293b}
.risk-badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}
</style>
"""

def _build_individual_html(d):
    ports = d.get("ports", [])
    threats = d.get("threats", [])

    ports_html = ""
    if ports:
        rows = "".join(
            f"<tr><td><b>{p.get('port','')}</b></td>"
            f"<td>{p.get('proto','tcp')}</td>"
            f"<td>{p.get('service','unknown')}</td>"
            f"<td>{p.get('state','open')}</td></tr>"
            for p in ports
        )
        ports_html = (
            f'<section class="sec"><h2>&#x1F4E1; Open Ports &amp; Services ({len(ports)})</h2>' +
            '<table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>State</th></tr></thead>' +
            f'<tbody>{rows}</tbody></table></section>'
        )

    threats_html = ""
    if threats:
        rows = "".join(
            f'<tr><td><span class="risk-badge" style="background:{_sev_color(t.get("severity",""))}">' +
            f'{t.get("severity","?").upper()}</span></td>' +
            f'<td><b>{t.get("name","")}</b></td>' +
            f'<td>{t.get("description","")}</td></tr>'
            for t in threats
        )
        threats_html = (
            f'<section class="sec"><h2>&#x26A0; Security Findings ({len(threats)})</h2>' +
            '<table><thead><tr><th>Severity</th><th>Finding</th><th>Description</th></tr></thead>' +
            f'<tbody>{rows}</tbody></table></section>'
        )
    else:
        threats_html = '<section class="sec"><h2>&#x26A0; Security Findings</h2><p class="no-data">No threats detected in this scan.</p></section>'

    out_html = (str(d.get("output",""))
                .replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))

    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">' +
        f'<title>FG-VAPT — {d["tool_display"]} — {d["target"]}</title>' +
        REPORT_CSS + '</head><body>' +
        f'<div class="brand-hdr"><div><h1>FG-VAPT Security Scan Report</h1>' +
        f'<div class="sub">FluentGrid Technology Solutions — Authorized Security Testing</div></div>' +
        f'<div class="badge">{d["tool_display"]}</div></div>' +
        f'<div class="meta-row">' +
        f'<div class="meta-card"><div class="lbl">Target</div><div class="val">{d["target"]}</div></div>' +
        f'<div class="meta-card"><div class="lbl">Tool Used</div><div class="val">{d["tool_display"]}</div></div>' +
        f'<div class="meta-card"><div class="lbl">Scan Date</div><div class="val">{d["timestamp"][:10]}</div></div>' +
        f'<div class="meta-card"><div class="lbl">Scan Time</div><div class="val">{d["timestamp"][11:]}</div></div>' +
        f'<div class="meta-card"><div class="lbl">Open Ports</div><div class="val">{len(ports)}</div></div>' +
        f'<div class="meta-card"><div class="lbl">Findings</div><div class="val">{len(threats)}</div></div>' +
        f'</div>' +
        ports_html + threats_html +
        f'<section class="sec"><h2>&#x1F4BB; Raw Scan Output</h2><pre>{out_html}</pre></section>' +
        f'<div class="footer">FG-VAPT v10.0 &bull; FluentGrid Technology Solutions &bull; {datetime.datetime.now().year} &bull; CONFIDENTIAL — For Authorized Use Only</div>' +
        '</body></html>'
    )


def _build_consolidated_html(reports):
    all_ports, all_threats = [], []
    seen_p, seen_t = set(), set()
    for r in reports:
        for p in r.get("ports", []):
            k = str(p.get("port","")) + p.get("proto","tcp")
            if k not in seen_p:
                seen_p.add(k); all_ports.append({**p, "_target": r.get("target","")})
        for t in r.get("threats", []):
            k = t.get("name","")
            if k not in seen_t:
                seen_t.add(k); all_threats.append({**t, "_target": r.get("target","")})

    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    all_threats.sort(key=lambda t: sev_order.get(str(t.get("severity","")).lower(), 5))

    crit = sum(1 for t in all_threats if str(t.get("severity","")).lower()=="critical")
    high = sum(1 for t in all_threats if str(t.get("severity","")).lower()=="high")
    med  = sum(1 for t in all_threats if str(t.get("severity","")).lower()=="medium")
    low  = sum(1 for t in all_threats if str(t.get("severity","")).lower()=="low")

    targets = sorted(set(r.get("target","") for r in reports if r.get("target")))
    gen_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    scan_rows = "".join(
        f"<tr><td>{r.get('tool_display','')}</td><td><b>{r.get('target','')}</b></td>"
        f"<td>{r.get('timestamp','')}</td>"
        f"<td>{len(r.get('ports', []))}</td>"
        f"<td>{len(r.get('threats', []))}</td></tr>"
        for r in reports
    )
    port_rows = "".join(
        f"<tr><td><b>{p.get('port','')}</b></td><td>{p.get('proto','tcp')}</td>"
        f"<td>{p.get('service','')}</td><td>{p.get('_target','')}</td>"
        f"<td>{p.get('state','open')}</td></tr>"
        for p in all_ports
    ) or "<tr><td colspan=5 class='no-data'>No open ports recorded</td></tr>"
    threat_rows = "".join(
        f'<tr><td><span class="risk-badge" style="background:{_sev_color(t.get("severity",""))}">' +
        f'{t.get("severity","?").upper()}</span></td>' +
        f'<td><b>{t.get("name","")}</b></td><td>{t.get("_target","")}</td>' +
        f'<td>{t.get("description","")}</td></tr>'
        for t in all_threats
    ) or "<tr><td colspan=4 class='no-data'>No threats recorded</td></tr>"

    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">' +
        '<title>FG-VAPT Consolidated Security Report</title>' +
        REPORT_CSS +
        '<style>.risk-summary{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}' +
        '.rs-card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:12px 18px;min-width:100px;text-align:center}' +
        '.rs-card .num{font-size:36px;font-weight:800;line-height:1}.rs-card .lbl2{font-size:11px;color:#64748b;text-transform:uppercase;margin-top:2px}' +
        '.bar-wrap{height:12px;background:#334155;border-radius:6px;overflow:hidden;margin-top:8px}' +
        '.bar-inner{height:12px;border-radius:6px}</style>' +
        '</head><body>' +
        f'<div class="brand-hdr"><div><h1>FG-VAPT Consolidated Security Assessment Report</h1>' +
        f'<div class="sub">FluentGrid Technology Solutions &bull; Generated: {gen_time} &bull; Target(s): {", ".join(targets) or "various"}</div></div>' +
        '<div class="badge">CONSOLIDATED</div></div>' +

        '<div class="risk-summary">' +
        f'<div class="rs-card"><div class="num">{len(reports)}</div><div class="lbl2">Scans</div></div>' +
        f'<div class="rs-card"><div class="num">{len(all_ports)}</div><div class="lbl2">Open Ports</div></div>' +
        f'<div class="rs-card"><div class="num">{len(all_threats)}</div><div class="lbl2">Findings</div></div>' +
        f'<div class="rs-card"><div class="num" style="color:#d90429">{crit}</div><div class="lbl2">Critical</div></div>' +
        f'<div class="rs-card"><div class="num" style="color:#e85d04">{high}</div><div class="lbl2">High</div></div>' +
        f'<div class="rs-card"><div class="num" style="color:#e09f3e">{med}</div><div class="lbl2">Medium</div></div>' +
        f'<div class="rs-card"><div class="num" style="color:#2d6a4f">{low}</div><div class="lbl2">Low</div></div>' +
        '</div>' +

        f'<section class="sec"><h2>&#x1F4CB; Scans Performed ({len(reports)})</h2>' +
        '<table><thead><tr><th>Tool</th><th>Target</th><th>Date / Time</th><th>Ports</th><th>Findings</th></tr></thead>' +
        f'<tbody>{scan_rows}</tbody></table></section>' +

        f'<section class="sec"><h2>&#x1F4E1; All Open Ports ({len(all_ports)})</h2>' +
        '<table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Target</th><th>State</th></tr></thead>' +
        f'<tbody>{port_rows}</tbody></table></section>' +

        f'<section class="sec"><h2>&#x26A0; All Security Findings ({len(all_threats)}) — Sorted by Severity</h2>' +
        '<table><thead><tr><th>Severity</th><th>Finding</th><th>Target</th><th>Description</th></tr></thead>' +
        f'<tbody>{threat_rows}</tbody></table></section>' +

        f'<div class="footer">FG-VAPT v10.0 &bull; FluentGrid Technology Solutions &bull; {datetime.datetime.now().year} &bull; CONFIDENTIAL — Prepared for Authorized Recipients Only</div>' +
        '</body></html>'
    )


@app.route("/api/reports")
def list_reports_api():
    items = []
    try:
        files = sorted(os.listdir(REPORTS_DIR), reverse=True)
    except Exception:
        files = []
    for fname in files:
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(REPORTS_DIR, fname), "r", encoding="utf-8") as fh:
                d = json.load(fh)
            items.append({
                "id":           d.get("id", fname[:-5]),
                "tool_display": d.get("tool_display", ""),
                "target":       d.get("target", ""),
                "timestamp":    d.get("timestamp", ""),
                "ports":        len(d.get("ports", [])),
                "threats":      len(d.get("threats", [])),
            })
        except Exception:
            pass
    return jsonify(items)


@app.route("/api/report/<report_id>/html")
def download_report_html_route(report_id):
    report_id = re.sub(r'[^a-zA-Z0-9_\-]', '', report_id)
    fpath = os.path.join(REPORTS_DIR, report_id + ".json")
    if not os.path.exists(fpath):
        return "Report not found", 404
    with open(fpath, "r", encoding="utf-8") as fh:
        d = json.load(fh)
    html = _build_individual_html(d)
    fname = ("FG_VAPT_" + d.get("tool","scan") + "_" +
             re.sub(r'[^a-zA-Z0-9]','_',d.get("target","host")) + "_" +
             d.get("timestamp","")[:10] + ".html")
    return Response(html, mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/api/report/consolidated/html")
def download_consolidated_html_route():
    reports = []
    try:
        for fname in sorted(os.listdir(REPORTS_DIR)):
            if fname.endswith(".json"):
                try:
                    with open(os.path.join(REPORTS_DIR, fname), "r", encoding="utf-8") as fh:
                        reports.append(json.load(fh))
                except Exception:
                    pass
    except Exception:
        pass
    if not reports:
        return "No reports yet. Run some scans first.", 404
    html = _build_consolidated_html(reports)
    fname = "FG_VAPT_Consolidated_Report_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".html"
    return Response(html, mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/api/report/<report_id>", methods=["DELETE"])
def delete_report_route(report_id):
    report_id = re.sub(r'[^a-zA-Z0-9_\-]', '', report_id)
    fpath = os.path.join(REPORTS_DIR, report_id + ".json")
    if os.path.exists(fpath):
        os.unlink(fpath)
    return jsonify({"ok": True})




_JS_REPORTS = """
<style>
#fg-reports-btn{position:fixed;bottom:24px;right:24px;z-index:9000;background:#e63946;color:#fff;border:none;
  padding:10px 18px;border-radius:24px;cursor:pointer;font-size:13px;font-weight:700;
  box-shadow:0 4px 18px rgba(230,57,70,.5);display:flex;align-items:center;gap:6px;transition:all .2s}
#fg-reports-btn:hover{background:#c1121f;transform:translateY(-2px)}
#fg-reports-overlay{display:none;position:fixed;inset:0;z-index:99999;align-items:center;justify-content:center}
#fg-reports-modal{background:#1e293b;border:1px solid #334155;border-radius:14px;width:820px;max-width:96vw;max-height:86vh;display:flex;flex-direction:column;box-shadow:0 24px 60px rgba(0,0,0,.6)}
.rp-hdr{padding:16px 22px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center}
.rp-hdr h2{margin:0;font-size:16px;color:#e2e8f0}
.rp-hdr .rp-close{background:none;border:none;color:#64748b;cursor:pointer;font-size:20px;line-height:1}
.rp-hdr .rp-close:hover{color:#e2e8f0}
.rp-toolbar{padding:10px 22px;border-bottom:1px solid #334155;display:flex;gap:8px;align-items:center}
.rp-toolbar button{padding:7px 14px;border-radius:6px;border:none;cursor:pointer;font-size:12px;font-weight:600}
.btn-consolidated{background:#e63946;color:#fff}
.btn-consolidated:hover{background:#c1121f}
.btn-refresh{background:#334155;color:#94a3b8}
.btn-refresh:hover{background:#475569;color:#fff}
.rp-count{margin-left:auto;font-size:12px;color:#64748b}
.rp-body{flex:1;overflow-y:auto;padding:12px 22px}
.rp-empty{text-align:center;color:#475569;font-size:13px;padding:32px}
.rp-table{width:100%;border-collapse:collapse;font-size:12px}
.rp-table th{background:#0f172a;color:#64748b;padding:7px 10px;text-align:left;border-bottom:1px solid #334155;font-size:11px;text-transform:uppercase;letter-spacing:.06em;position:sticky;top:0}
.rp-table td{padding:8px 10px;border-bottom:1px solid #1e293b;vertical-align:middle}
.rp-table tr:hover td{background:#253349}
.sev-badge{display:inline-block;padding:1px 7px;border-radius:8px;font-size:10px;font-weight:700;color:#fff}
.dl-btn-sm{background:#334155;border:none;color:#7dd3fc;padding:4px 10px;border-radius:5px;cursor:pointer;font-size:11px;margin-right:4px}
.dl-btn-sm:hover{background:#475569}
.del-btn-sm{background:none;border:none;color:#475569;cursor:pointer;font-size:14px;padding:0 2px}
.del-btn-sm:hover{color:#e63946}
.rp-notify{position:fixed;bottom:80px;right:24px;background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:10px 16px;border-radius:8px;font-size:13px;z-index:9999;opacity:0;transition:opacity .3s;pointer-events:none}
.rp-notify.show{opacity:1}
</style>

<button id="fg-reports-btn" onclick="fgReportsOpen()">&#x1F4CB; Reports</button>
<div id="fg-reports-overlay">
  <div id="fg-reports-modal">
    <div class="rp-hdr">
      <h2>&#x1F4CB; FG-VAPT — Scan Reports</h2>
      <button class="rp-close" onclick="fgReportsClose()">&#x2715;</button>
    </div>
    <div class="rp-toolbar">
      <button class="btn-consolidated" onclick="fgDownloadConsolidated()">&#x2B07; Download Consolidated Report</button>
      <button class="btn-refresh" onclick="fgLoadReports()">&#x21BA; Refresh</button>
      <span class="rp-count" id="rp-count"></span>
    </div>
    <div class="rp-body">
      <div class="rp-empty" id="rp-empty">Loading reports...</div>
      <table class="rp-table" id="rp-table" style="display:none">
        <thead><tr>
          <th>#</th><th>Tool</th><th>Target</th><th>Date / Time</th>
          <th>Ports</th><th>Findings</th><th>Actions</th>
        </tr></thead>
        <tbody id="rp-tbody"></tbody>
      </table>
    </div>
  </div>
</div>
<div class="rp-notify" id="rp-notify"></div>

<script>
function fgReportsOpen(){
  var ov=document.getElementById('fg-reports-overlay');
  ov.style.cssText='display:flex!important;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:99999;align-items:center;justify-content:center';
  fgLoadReports();
}
function fgReportsClose(){
  document.getElementById('fg-reports-overlay').style.display='none';
}
function fgNotify(msg, color){
  var el=document.getElementById('rp-notify');
  el.textContent=msg;
  el.style.borderColor=color||'#334155';
  el.style.color=color?'#fff':'#e2e8f0';
  el.style.background=color||'#1e293b';
  el.classList.add('show');
  setTimeout(function(){el.classList.remove('show');},2800);
}
function fgLoadReports(){
  fetch('/api/reports').then(function(r){return r.json();}).then(function(items){
    var tbody=document.getElementById('rp-tbody');
    var empty=document.getElementById('rp-empty');
    var table=document.getElementById('rp-table');
    document.getElementById('rp-count').textContent=items.length+' report(s)';
    tbody.innerHTML='';
    if(!items.length){
      empty.style.display='';
      empty.textContent='No reports yet. Run a scan to generate your first report.';
      table.style.display='none';
      return;
    }
    empty.style.display='none';
    table.style.display='';
    items.forEach(function(r,i){
      var sev='';
      if(r.threats>0) sev='<span class="sev-badge" style="background:#e85d04">'+r.threats+' findings</span>';
      else sev='<span class="sev-badge" style="background:#2d6a4f">clean</span>';
      var tr=document.createElement('tr');
      tr.innerHTML='<td style="color:#64748b">'+(i+1)+'</td>'+
        '<td><b>'+r.tool_display+'</b></td>'+
        '<td style="font-family:monospace;color:#7dd3fc">'+r.target+'</td>'+
        '<td style="color:#94a3b8">'+r.timestamp+'</td>'+
        '<td>'+r.ports+'</td>'+
        '<td>'+sev+'</td>'+
        '<td>'+
          '<button class="dl-btn-sm" onclick="fgDownloadReport(\'' + r.id + '\')">&#x2B07; HTML</button>'+
          '<button class="del-btn-sm" onclick="fgDeleteReport(\'' + r.id + '\',this)" title="Delete">&#x1F5D1;</button>'+
        '</td>';
      tbody.appendChild(tr);
    });
  }).catch(function(){
    document.getElementById('rp-empty').textContent='Could not load reports.';
    document.getElementById('rp-empty').style.display='';
    document.getElementById('rp-table').style.display='none';
  });
}
function fgDownloadReport(id){
  var a=document.createElement('a');
  a.href='/api/report/'+id+'/html';
  a.download='';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  fgNotify('Downloading report...','#0077b6');
}
function fgDownloadConsolidated(){
  fgNotify('Generating consolidated report...','#e63946');
  fetch('/api/report/consolidated/html').then(function(r){
    if(!r.ok){fgNotify('No reports yet. Run scans first.','#e85d04');return null;}
    return r.blob();
  }).then(function(blob){
    if(!blob)return;
    var url=URL.createObjectURL(blob);
    var a=document.createElement('a');
    a.href=url;
    a.download='FG_VAPT_Consolidated_Report.html';
    document.body.appendChild(a);a.click();document.body.removeChild(a);
    URL.revokeObjectURL(url);
    fgNotify('Consolidated report downloaded!','#2d6a4f');
  });
}
function fgDeleteReport(id,btn){
  if(!confirm('Delete this report?'))return;
  fetch('/api/report/'+id,{method:'DELETE'}).then(function(){fgLoadReports();fgNotify('Report deleted.');});
}
document.getElementById('fg-reports-overlay').addEventListener('click',function(e){
  if(e.target===this)fgReportsClose();
});
function clearSession(){
  if(!confirm('Clear all scan data and start a fresh session?')) return;

  // Reset global state
  scanCount=0; allPorts=[]; allThreats=[]; SC={net:0,web:0,inf:0,rec:0};
  lastTarget=''; lastPhase='idle';

  // Destroy charts
  Object.values(riskCharts).forEach(function(c){try{c.destroy();}catch(e){}});
  Object.values(threatCharts).forEach(function(c){try{c.destroy();}catch(e){}});
  riskCharts={}; threatCharts={};

  // Clear terminal
  var term=document.getElementById('terminal-output');
  if(term){term.innerHTML='<div style="color:#4ade80;font-family:monospace;padding:8px">Session cleared. Enter a target and run a scan.</div>';}

  // Reset stat counters
  ['stat-scans','stat-ports','stat-threats'].forEach(function(id){
    var el=document.getElementById(id); if(el) el.textContent='0';
  });
  ['scan-bar','port-bar','threat-bar'].forEach(function(id){
    var el=document.getElementById(id); if(el) el.style.width='0%';
  });
  ['hm-scans','hm-ports','hm-threats'].forEach(function(id){
    var el=document.getElementById(id); if(el) el.textContent='0';
  });
  var lastTool=document.getElementById('stat-last-tool');
  if(lastTool) lastTool.textContent='—';
  var lastTime=document.getElementById('stat-last-time');
  if(lastTime) lastTime.textContent='Awaiting scan';

  // Clear scan history table
  var hist=document.getElementById('ss-history-table');
  if(hist) hist.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--tx-faint);padding:30px">No scans completed yet</td></tr>';

  // Reset dashboards
  ['port-dash','threat-dash','risk-content','tgraph-content','chains-content'].forEach(function(id){
    var el=document.getElementById(id);
    if(el) el.innerHTML='<div class="empty-state"><div class="empty-ico">🔍</div><div class="empty-title">No Data</div><div class="empty-sub">Run a scan to populate this view</div></div>';
  });

  // Clear target input
  var ti=document.getElementById('target-input'); if(ti) ti.value='';

  // Switch to terminal tab
  var tabs=document.querySelectorAll('.tab-btn');
  if(tabs.length) switchTab('terminal', tabs[0]);

  notify('Session cleared — ready for new scan.');
}

</script>
"""

_HTML_B64 = (
"PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVU"
"Ri04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwg"
"aW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+SEFSU0hBIOKAlCBWQVBUIENvbW1hbmQgU3VpdGU8"
"L3RpdGxlPgo8c2NyaXB0IHNyYz0iaHR0cHM6Ly9jZG5qcy5jbG91ZGZsYXJlLmNvbS9hamF4L2xp"
"YnMvQ2hhcnQuanMvNC40LjEvY2hhcnQudW1kLm1pbi5qcyI+PC9zY3JpcHQ+CjxsaW5rIGhyZWY9"
"Imh0dHBzOi8vZm9udHMuZ29vZ2xlYXBpcy5jb20vY3NzMj9mYW1pbHk9T3V0Zml0OndnaHRAMzAw"
"OzQwMDs1MDA7NjAwOzcwMDs4MDA7OTAwJmZhbWlseT1JQk0rUGxleCtNb25vOndnaHRAMzAwOzQw"
"MDs1MDA7NjAwOzcwMCZmYW1pbHk9U3luZTp3Z2h0QDQwMDs1MDA7NjAwOzcwMDs4MDAmZGlzcGxh"
"eT1zd2FwIiByZWw9InN0eWxlc2hlZXQiPgo8c3R5bGU+Ci8qID09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgSEFSU0hBIHY3"
"LjAg4oCUIENyb3dkU3RyaWtlLUluc3BpcmVkIFZBUFQgRGFzaGJvYXJkCiAgIFBhbGV0dGU6IE1h"
"dHRlIEJsYWNrIMK3IFB1cmUgV2hpdGUgwrcgU2lnbmFsIFJlZAogICA9PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCiosKjo6"
"YmVmb3JlLCo6OmFmdGVye21hcmdpbjowO3BhZGRpbmc6MDtib3gtc2l6aW5nOmJvcmRlci1ib3h9"
"Cgo6cm9vdHsKICAvKiBCTEFDSyBTUEVDVFJVTSAqLwogIC0tYmxhY2s6IzBhMGEwYzsKICAtLWJs"
"YWNrLTI6IzExMTExNTsKICAtLWJsYWNrLTM6IzE4MTgxYzsKICAtLWJsYWNrLTQ6IzFlMWUyNDsK"
"ICAtLWJsYWNrLTU6IzI4MjgyZjsKICAvKiBXSElURSBTUEVDVFJVTSAqLwogIC0td2hpdGU6I2Zm"
"ZmZmZjsKICAtLXdoaXRlLTI6I2Y3ZjdmODsKICAtLXdoaXRlLTM6I2VjZWNlZjsKICAtLXdoaXRl"
"LTQ6I2RkZGRlMjsKICAtLXdoaXRlLTU6I2M4YzhkMDsKICAvKiBSRUQg4oCUIFRIRSBJREVOVElU"
"WSAqLwogIC0tcmVkOiNlNjM5NDY7CiAgLS1yZWQtZGFyazojYzExMjFmOwogIC0tcmVkLWxpZ2h0"
"OiNmZjZiNmI7CiAgLS1yZWQtZ2xvdzpyZ2JhKDIzMCw1Nyw3MCwwLjM1KTsKICAtLXJlZC1kaW06"
"cmdiYSgyMzAsNTcsNzAsMC4wOCk7CiAgLS1yZWQtYm9yZGVyOnJnYmEoMjMwLDU3LDcwLDAuMik7"
"CiAgLyogU0VWRVJJVFkgKG9uIHdoaXRlKSAqLwogIC0tc2V2LWNyaXQ6I2Q5MDQyOTsKICAtLXNl"
"di1jcml0LWJnOnJnYmEoMjE3LDQsNDEsMC4wNik7CiAgLS1zZXYtY3JpdC1ib3JkZXI6cmdiYSgy"
"MTcsNCw0MSwwLjE4KTsKICAtLXNldi1oaWdoOiNlODVkMDQ7CiAgLS1zZXYtaGlnaC1iZzpyZ2Jh"
"KDIzMiw5Myw0LDAuMDYpOwogIC0tc2V2LWhpZ2gtYm9yZGVyOnJnYmEoMjMyLDkzLDQsMC4xOCk7"
"CiAgLS1zZXYtbWVkOiNlMDlmM2U7CiAgLS1zZXYtbWVkLWJnOnJnYmEoMjI0LDE1OSw2MiwwLjA4"
"KTsKICAtLXNldi1tZWQtYm9yZGVyOnJnYmEoMjI0LDE1OSw2MiwwLjIpOwogIC0tc2V2LWxvdzoj"
"MmQ2YTRmOwogIC0tc2V2LWxvdy1iZzpyZ2JhKDQ1LDEwNiw3OSwwLjA2KTsKICAtLXNldi1sb3ct"
"Ym9yZGVyOnJnYmEoNDUsMTA2LDc5LDAuMTgpOwogIC8qIFRFWFQgKi8KICAtLXR4LWRhcms6IzBh"
"MGEwYzsKICAtLXR4LWJvZHk6IzNhM2E0NDsKICAtLXR4LW11dGVkOiM4YThhOTY7CiAgLS10eC1m"
"YWludDojYjBiMGJhOwogIC0tdHgtb24tZGFyazojZjBmMGYyOwogIC0tdHgtb24tZGFyay1tdXRl"
"ZDojOGE4YTk2OwogIC8qIExBWU9VVCAqLwogIC0tc2lkZWJhci13OjIzMHB4OwogIC0taGVhZGVy"
"LWg6NjBweDsKICAtLXJhZGl1czo4cHg7CiAgLS1yYWRpdXMtbGc6MTRweDsKICAtLXJhZGl1cy14"
"bDoyMHB4Owp9CgpodG1sLGJvZHl7CiAgaGVpZ2h0OjEwMCU7b3ZlcmZsb3c6aGlkZGVuOwogIGZv"
"bnQtZmFtaWx5OidPdXRmaXQnLHN5c3RlbS11aSxzYW5zLXNlcmlmOwogIGJhY2tncm91bmQ6dmFy"
"KC0td2hpdGUtMik7Y29sb3I6dmFyKC0tdHgtYm9keSk7CiAgZm9udC1zaXplOjEzcHg7bGluZS1o"
"ZWlnaHQ6MS41OwogIC13ZWJraXQtZm9udC1zbW9vdGhpbmc6YW50aWFsaWFzZWQ7Cn0KCi8qIFND"
"Uk9MTEJBUiDigJQgdGhpbiwgZGFyayAqLwo6Oi13ZWJraXQtc2Nyb2xsYmFye3dpZHRoOjVweDto"
"ZWlnaHQ6NXB4fQo6Oi13ZWJraXQtc2Nyb2xsYmFyLXRyYWNre2JhY2tncm91bmQ6dHJhbnNwYXJl"
"bnR9Cjo6LXdlYmtpdC1zY3JvbGxiYXItdGh1bWJ7YmFja2dyb3VuZDp2YXIoLS13aGl0ZS00KTti"
"b3JkZXItcmFkaXVzOjEwcHh9Ci5zaWRlYmFyIDo6LXdlYmtpdC1zY3JvbGxiYXItdGh1bWJ7YmFj"
"a2dyb3VuZDp2YXIoLS1ibGFjay01KX0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgQU5JTUFUSU9OUwogICA9PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09ICovCkBrZXlmcmFtZXMgZmFkZVVwe2Zyb217b3BhY2l0eTowO3RyYW5zZm9ybTp0cmFuc2xh"
"dGVZKDE2cHgpfXRve29wYWNpdHk6MTt0cmFuc2Zvcm06bm9uZX19CkBrZXlmcmFtZXMgZmFkZUlu"
"e2Zyb217b3BhY2l0eTowfXRve29wYWNpdHk6MX19CkBrZXlmcmFtZXMgc2xpZGVJbkxlZnR7ZnJv"
"bXtvcGFjaXR5OjA7dHJhbnNmb3JtOnRyYW5zbGF0ZVgoLTIwcHgpfXRve29wYWNpdHk6MTt0cmFu"
"c2Zvcm06bm9uZX19CkBrZXlmcmFtZXMgcHVsc2V7MCUsMTAwJXtvcGFjaXR5OjF9NTAle29wYWNp"
"dHk6LjR9fQpAa2V5ZnJhbWVzIHNjYW5saW5lezAle3RvcDotMnB4fTEwMCV7dG9wOjEwMCV9fQpA"
"a2V5ZnJhbWVzIGdsb3d7MCUsMTAwJXtib3gtc2hhZG93OjAgMCA4cHggdmFyKC0tcmVkLWdsb3cp"
"fTUwJXtib3gtc2hhZG93OjAgMCAyMHB4IHZhcigtLXJlZC1nbG93KSwwIDAgNDBweCByZ2JhKDIz"
"MCw1Nyw3MCwwLjE1KX19CkBrZXlmcmFtZXMgc2hpbW1lcnswJXtiYWNrZ3JvdW5kLXBvc2l0aW9u"
"OjIwMCUgMH0xMDAle2JhY2tncm91bmQtcG9zaXRpb246LTIwMCUgMH19CkBrZXlmcmFtZXMgc3Bp"
"bnt0b3t0cmFuc2Zvcm06cm90YXRlKDM2MGRlZyl9fQpAa2V5ZnJhbWVzIGJvcmRlckdsb3d7MCUs"
"MTAwJXtib3JkZXItY29sb3I6cmdiYSgyMzAsNTcsNzAsMC4xNSl9NTAle2JvcmRlci1jb2xvcjpy"
"Z2JhKDIzMCw1Nyw3MCwwLjQpfX0KQGtleWZyYW1lcyB0eXBld3JpdGVye2Zyb217d2lkdGg6MH10"
"b3t3aWR0aDoxMDAlfX0KQGtleWZyYW1lcyBncmlkUHVsc2V7MCUsMTAwJXtvcGFjaXR5Oi4wM301"
"MCV7b3BhY2l0eTouMDZ9fQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBBUFAgTEFZT1VUCiAgID09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8K"
"LmFwcHtkaXNwbGF5OmZsZXg7aGVpZ2h0OjEwMHZoO3dpZHRoOjEwMHZ3fQoKLyogPT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQog"
"ICBTSURFQkFSIOKAlCBNQVRURSBCTEFDSwogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi5zaWRlYmFyewogIHdpZHRo"
"OnZhcigtLXNpZGViYXItdyk7bWluLXdpZHRoOnZhcigtLXNpZGViYXItdyk7CiAgYmFja2dyb3Vu"
"ZDp2YXIoLS1ibGFjayk7CiAgZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjsKICBv"
"dmVyZmxvdzpoaWRkZW47CiAgcG9zaXRpb246cmVsYXRpdmU7CiAgei1pbmRleDoxMDsKfQovKiBT"
"dWJ0bGUgZ3JpZCBwYXR0ZXJuIG9uIHNpZGViYXIgKi8KLnNpZGViYXI6OmJlZm9yZXsKICBjb250"
"ZW50OicnO3Bvc2l0aW9uOmFic29sdXRlO2luc2V0OjA7CiAgYmFja2dyb3VuZC1pbWFnZToKICAg"
"IGxpbmVhci1ncmFkaWVudChyZ2JhKDIzMCw1Nyw3MCwwLjAzKSAxcHgsdHJhbnNwYXJlbnQgMXB4"
"KSwKICAgIGxpbmVhci1ncmFkaWVudCg5MGRlZyxyZ2JhKDIzMCw1Nyw3MCwwLjAzKSAxcHgsdHJh"
"bnNwYXJlbnQgMXB4KTsKICBiYWNrZ3JvdW5kLXNpemU6MjRweCAyNHB4OwogIGFuaW1hdGlvbjpn"
"cmlkUHVsc2UgNHMgZWFzZSBpbmZpbml0ZTsKICBwb2ludGVyLWV2ZW50czpub25lOwp9Cgouc2lk"
"ZWJhci1zY3JvbGx7ZmxleDoxO292ZXJmbG93LXk6YXV0bztwb3NpdGlvbjpyZWxhdGl2ZTt6LWlu"
"ZGV4OjF9CgovKiBMT0dPICovCi5zLWxvZ297CiAgcGFkZGluZzoxOHB4IDIwcHg7ZGlzcGxheTpm"
"bGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTJweDsKICBib3JkZXItYm90dG9tOjFweCBzb2xp"
"ZCByZ2JhKDI1NSwyNTUsMjU1LDAuMDYpOwogIGFuaW1hdGlvbjpmYWRlSW4gLjZzIGVhc2U7Cn0K"
"LnMtbG9nby1tYXJrewogIHdpZHRoOjM2cHg7aGVpZ2h0OjM2cHg7Ym9yZGVyLXJhZGl1czp2YXIo"
"LS1yYWRpdXMpOwogIGJhY2tncm91bmQ6dmFyKC0tcmVkKTsKICBkaXNwbGF5OmZsZXg7YWxpZ24t"
"aXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7CiAgZm9udC1mYW1pbHk6J1N5bmUn"
"LHNhbnMtc2VyaWY7Zm9udC13ZWlnaHQ6ODAwO2ZvbnQtc2l6ZToxNnB4O2NvbG9yOiNmZmY7CiAg"
"cG9zaXRpb246cmVsYXRpdmU7CiAgYW5pbWF0aW9uOmdsb3cgM3MgZWFzZSBpbmZpbml0ZTsKfQou"
"cy1sb2dvLXRleHR7Zm9udC1mYW1pbHk6J1N5bmUnLHNhbnMtc2VyaWY7Zm9udC1zaXplOjE4cHg7"
"Zm9udC13ZWlnaHQ6ODAwO2NvbG9yOnZhcigtLXdoaXRlKTtsZXR0ZXItc3BhY2luZzoycHh9Ci5z"
"LWxvZ28tc3Vie2ZvbnQtc2l6ZTo5cHg7Y29sb3I6dmFyKC0tdHgtb24tZGFyay1tdXRlZCk7bGV0"
"dGVyLXNwYWNpbmc6M3B4O2ZvbnQtd2VpZ2h0OjUwMDttYXJnaW4tdG9wOjFweH0KCi8qIE5BViBT"
"RUNUSU9OUyAqLwovKiBTSURFQkFSIFNFQVJDSCAqLwoucy1zZWFyY2h7cGFkZGluZzoxMHB4IDEy"
"cHggNnB4O3Bvc2l0aW9uOnJlbGF0aXZlfQoucy1zZWFyY2gtaW5wdXR7CiAgd2lkdGg6MTAwJTti"
"YWNrZ3JvdW5kOnZhcigtLWJsYWNrLTMpO2JvcmRlcjoxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1"
"NSwwLjA2KTsKICBib3JkZXItcmFkaXVzOjZweDtwYWRkaW5nOjhweCAxMnB4IDhweCAzMnB4O2Nv"
"bG9yOnZhcigtLXR4LW9uLWRhcmspOwogIGZvbnQtc2l6ZToxMXB4O2ZvbnQtZmFtaWx5OidPdXRm"
"aXQnLHNhbnMtc2VyaWY7b3V0bGluZTpub25lOwogIHRyYW5zaXRpb246Ym9yZGVyLWNvbG9yIC4y"
"czsKfQoucy1zZWFyY2gtaW5wdXQ6Zm9jdXN7Ym9yZGVyLWNvbG9yOnZhcigtLXJlZCl9Ci5zLXNl"
"YXJjaC1pbnB1dDo6cGxhY2Vob2xkZXJ7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjIpfQoucy1z"
"ZWFyY2gtaWNvbntwb3NpdGlvbjphYnNvbHV0ZTtsZWZ0OjIycHg7dG9wOjUwJTt0cmFuc2Zvcm06"
"dHJhbnNsYXRlWSgtNTAlKTtmb250LXNpemU6MTJweDtvcGFjaXR5Oi4zO3BvaW50ZXItZXZlbnRz"
"Om5vbmV9CgovKiBEUk9QRE9XTiBTRUNUSU9OUyAqLwoucy1zZWN0aW9ue3BhZGRpbmc6NHB4IDEy"
"cHggMnB4fQoucy1zZWN0aW9uLWhlYWRlcnsKICBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2Vu"
"dGVyO2dhcDo4cHg7CiAgcGFkZGluZzo4cHggOHB4O2JvcmRlci1yYWRpdXM6NnB4O2N1cnNvcjpw"
"b2ludGVyOwogIHRyYW5zaXRpb246YWxsIC4yczt1c2VyLXNlbGVjdDpub25lOwp9Ci5zLXNlY3Rp"
"b24taGVhZGVyOmhvdmVye2JhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjAzKX0KLnMtc2Vj"
"dGlvbi1pY29ue2ZvbnQtc2l6ZToxNHB4O3dpZHRoOjIwcHg7dGV4dC1hbGlnbjpjZW50ZXI7Zmxl"
"eC1zaHJpbms6MDtvcGFjaXR5Oi42fQoucy1zZWN0aW9uLXRpdGxlewogIGZvbnQtZmFtaWx5OidJ"
"Qk0gUGxleCBNb25vJyxtb25vc3BhY2U7CiAgZm9udC1zaXplOjlweDtmb250LXdlaWdodDo2MDA7"
"Y29sb3I6dmFyKC0tdHgtb24tZGFyay1tdXRlZCk7CiAgbGV0dGVyLXNwYWNpbmc6Mi41cHg7dGV4"
"dC10cmFuc2Zvcm06dXBwZXJjYXNlO2ZsZXg6MTsKfQoucy1zZWN0aW9uLWNvdW50ewogIGZvbnQt"
"ZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjhweDtmb250LXdlaWdo"
"dDo3MDA7CiAgcGFkZGluZzoycHggNnB4O2JvcmRlci1yYWRpdXM6OHB4OwogIGJhY2tncm91bmQ6"
"cmdiYSgyNTUsMjU1LDI1NSwwLjA2KTtjb2xvcjp2YXIoLS10eC1vbi1kYXJrLW11dGVkKTsKICBt"
"aW4td2lkdGg6MThweDt0ZXh0LWFsaWduOmNlbnRlcjsKfQoucy1zZWN0aW9uLWFycm93ewogIGZv"
"bnQtc2l6ZToxMHB4O2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4yKTsKICB0cmFuc2l0aW9uOnRy"
"YW5zZm9ybSAuM3MgY3ViaWMtYmV6aWVyKC40LDAsLjIsMSk7Cn0KLnMtc2VjdGlvbi5vcGVuIC5z"
"LXNlY3Rpb24tYXJyb3d7dHJhbnNmb3JtOnJvdGF0ZSgxODBkZWcpfQoucy1zZWN0aW9uLWJvZHl7"
"CiAgbWF4LWhlaWdodDowO292ZXJmbG93OmhpZGRlbjsKICB0cmFuc2l0aW9uOm1heC1oZWlnaHQg"
"LjM1cyBjdWJpYy1iZXppZXIoLjQsMCwuMiwxKSxvcGFjaXR5IC4zcztvcGFjaXR5OjA7Cn0KLnMt"
"c2VjdGlvbi5vcGVuIC5zLXNlY3Rpb24tYm9keXttYXgtaGVpZ2h0OjYwMHB4O29wYWNpdHk6MX0K"
"Ci5zLW5hdnsKICBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMHB4OwogIHBh"
"ZGRpbmc6N3B4IDEycHg7Ym9yZGVyLXJhZGl1czo2cHg7CiAgY3Vyc29yOnBvaW50ZXI7dHJhbnNp"
"dGlvbjphbGwgLjJzOwogIGNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC40NSk7Zm9udC1zaXplOjEy"
"cHg7Zm9udC13ZWlnaHQ6NTAwOwogIG1hcmdpbi1ib3R0b206MXB4O2JvcmRlcjoxcHggc29saWQg"
"dHJhbnNwYXJlbnQ7CiAgYmFja2dyb3VuZDp0cmFuc3BhcmVudDt3aWR0aDoxMDAlO3RleHQtYWxp"
"Z246bGVmdDsKICBmb250LWZhbWlseTonT3V0Zml0JyxzYW5zLXNlcmlmOwogIHBvc2l0aW9uOnJl"
"bGF0aXZlO292ZXJmbG93OmhpZGRlbjsKfQoucy1uYXY6OmJlZm9yZXsKICBjb250ZW50OicnO3Bv"
"c2l0aW9uOmFic29sdXRlO2xlZnQ6MDt0b3A6MDtib3R0b206MDt3aWR0aDowOwogIGJhY2tncm91"
"bmQ6dmFyKC0tcmVkKTt0cmFuc2l0aW9uOndpZHRoIC4yNXM7Ym9yZGVyLXJhZGl1czo2cHggMCAw"
"IDZweDsKfQoucy1uYXY6aG92ZXJ7Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjgpO2JhY2tncm91"
"bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjA0KX0KLnMtbmF2OmhvdmVyOjpiZWZvcmV7d2lkdGg6M3B4"
"fQoucy1uYXYuYWN0aXZle2NvbG9yOiNmZmY7YmFja2dyb3VuZDpyZ2JhKDIzMCw1Nyw3MCwwLjEy"
"KTtib3JkZXItY29sb3I6cmdiYSgyMzAsNTcsNzAsMC4xNSl9Ci5zLW5hdi5hY3RpdmU6OmJlZm9y"
"ZXt3aWR0aDozcHg7YmFja2dyb3VuZDp2YXIoLS1yZWQpfQoucy1uYXYgLmljb3tmb250LXNpemU6"
"MTRweDt3aWR0aDoyMHB4O3RleHQtYWxpZ246Y2VudGVyO2ZsZXgtc2hyaW5rOjB9Ci5zLW5hdiAu"
"bGJse2ZsZXg6MX0KLnMtdGFnewogIGZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3Bh"
"Y2U7CiAgZm9udC1zaXplOjhweDtmb250LXdlaWdodDo3MDA7cGFkZGluZzoycHggNnB4OwogIGJv"
"cmRlci1yYWRpdXM6M3B4O2xldHRlci1zcGFjaW5nOi41cHg7Cn0KLnMtdGFnLnJ7YmFja2dyb3Vu"
"ZDpyZ2JhKDIzMCw1Nyw3MCwwLjIpO2NvbG9yOnZhcigtLXJlZC1saWdodCl9Ci5zLXRhZy5ve2Jh"
"Y2tncm91bmQ6cmdiYSgyMzIsOTMsNCwwLjE1KTtjb2xvcjojZmY4YzQyfQoKLyogU0lERUJBUiBG"
"T09URVIgKi8KLnMtZm9vdGVyewogIHBhZGRpbmc6MTRweCAxNnB4O2JvcmRlci10b3A6MXB4IHNv"
"bGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wNik7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNl"
"bnRlcjtnYXA6MTBweDsKICBwb3NpdGlvbjpyZWxhdGl2ZTt6LWluZGV4OjE7Cn0KLnMtYXZhdGFy"
"ewogIHdpZHRoOjMycHg7aGVpZ2h0OjMycHg7Ym9yZGVyLXJhZGl1czo1MCU7CiAgYmFja2dyb3Vu"
"ZDp2YXIoLS1yZWQpOwogIGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1j"
"b250ZW50OmNlbnRlcjsKICBmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjtmb250LXNpemU6"
"MTFweDtmb250LXdlaWdodDo4MDA7Y29sb3I6I2ZmZjsKfQoucy11bmFtZXtmb250LXNpemU6MTJw"
"eDtmb250LXdlaWdodDo2MDA7Y29sb3I6dmFyKC0td2hpdGUpfQoucy11cm9sZXtmb250LXNpemU6"
"OS41cHg7Y29sb3I6dmFyKC0tdHgtb24tZGFyay1tdXRlZCk7bGV0dGVyLXNwYWNpbmc6LjVweH0K"
"Ci8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT0KICAgTUFJTiBBUkVBCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KLm1haW57ZmxleDoxO2Rpc3Bs"
"YXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47b3ZlcmZsb3c6aGlkZGVuO21pbi13aWR0aDow"
"O2JhY2tncm91bmQ6dmFyKC0td2hpdGUtMil9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIEhFQURFUiDigJQgQkxB"
"Q0sgQkFSCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT0gKi8KLmhlYWRlcnsKICBoZWlnaHQ6dmFyKC0taGVhZGVyLWgpO21p"
"bi1oZWlnaHQ6dmFyKC0taGVhZGVyLWgpOwogIHBhZGRpbmc6MCAyOHB4O2Rpc3BsYXk6ZmxleDth"
"bGlnbi1pdGVtczpjZW50ZXI7Z2FwOjE2cHg7CiAgYmFja2dyb3VuZDp2YXIoLS1ibGFjay0yKTsK"
"ICBwb3NpdGlvbjpyZWxhdGl2ZTt6LWluZGV4OjU7CiAgYW5pbWF0aW9uOmZhZGVJbiAuNXMgZWFz"
"ZTsKfQovKiBSZWQgYWNjZW50IGxpbmUgdW5kZXIgaGVhZGVyICovCi5oZWFkZXI6OmFmdGVyewog"
"IGNvbnRlbnQ6Jyc7cG9zaXRpb246YWJzb2x1dGU7Ym90dG9tOjA7bGVmdDowO3JpZ2h0OjA7aGVp"
"Z2h0OjJweDsKICBiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1yZWQpLHZh"
"cigtLXJlZC1kYXJrKSx0cmFuc3BhcmVudCA4MCUpOwogIG9wYWNpdHk6LjY7Cn0KCi5oLWxlZnR7"
"ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTRweDtmbGV4OjE7bWluLXdpZHRo"
"OjB9Ci5oLXRpdGxlewogIGZvbnQtZmFtaWx5OidTeW5lJyxzYW5zLXNlcmlmOwogIGZvbnQtc2l6"
"ZToxNXB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS13aGl0ZSk7CiAgbGV0dGVyLXNwYWNp"
"bmc6MXB4O3doaXRlLXNwYWNlOm5vd3JhcDsKfQouaC1zZXB7d2lkdGg6MXB4O2hlaWdodDoyOHB4"
"O2JhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjEpO2ZsZXgtc2hyaW5rOjB9CgouaC10YXJn"
"ZXR7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtmbGV4OjE7bWF4LXdpZHRoOjQ0"
"MHB4OwogIGJhY2tncm91bmQ6dmFyKC0tYmxhY2stMyk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1"
"NSwyNTUsMjU1LDAuMDgpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzKTtvdmVyZmxvdzpo"
"aWRkZW47dHJhbnNpdGlvbjphbGwgLjNzOwp9Ci5oLXRhcmdldDpmb2N1cy13aXRoaW57Ym9yZGVy"
"LWNvbG9yOnZhcigtLXJlZCk7Ym94LXNoYWRvdzowIDAgMCAzcHggdmFyKC0tcmVkLWdsb3cpfQou"
"aC10YXJnZXQtcHJlewogIHBhZGRpbmc6MCAxMnB4O2ZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25v"
"Jyxtb25vc3BhY2U7CiAgZm9udC1zaXplOjlweDtjb2xvcjp2YXIoLS1yZWQpO2xldHRlci1zcGFj"
"aW5nOjJweDsKICBib3JkZXItcmlnaHQ6MXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wNik7"
"Zm9udC13ZWlnaHQ6NjAwOwp9Ci5oLXRhcmdldC1pbnB1dHsKICBmbGV4OjE7YmFja2dyb3VuZDpu"
"b25lO2JvcmRlcjpub25lO291dGxpbmU6bm9uZTsKICBjb2xvcjp2YXIoLS10eC1vbi1kYXJrKTtm"
"b250LXNpemU6MTNweDtwYWRkaW5nOjEwcHggMTRweDsKICBmb250LWZhbWlseTonT3V0Zml0Jyxz"
"YW5zLXNlcmlmOwp9Ci5oLXRhcmdldC1pbnB1dDo6cGxhY2Vob2xkZXJ7Y29sb3I6cmdiYSgyNTUs"
"MjU1LDI1NSwwLjIpfQoKLmgtcmlnaHR7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtn"
"YXA6MTBweDtmbGV4LXNocmluazowfQouaC1zdGF0dXN7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0"
"ZW1zOmNlbnRlcjtnYXA6NnB4OwogIHBhZGRpbmc6NXB4IDEycHg7Ym9yZGVyLXJhZGl1czoyMHB4"
"OwogIGZvbnQtc2l6ZToxMHB4O2ZvbnQtd2VpZ2h0OjYwMDtsZXR0ZXItc3BhY2luZzouOHB4Owog"
"IGZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7CiAgYmFja2dyb3VuZDpyZ2Jh"
"KDQ1LDEwNiw3OSwwLjE1KTtjb2xvcjojNGFkZTgwOwp9Ci5oLXN0YXR1cyAuZG90e3dpZHRoOjZw"
"eDtoZWlnaHQ6NnB4O2JvcmRlci1yYWRpdXM6NTAlO2JhY2tncm91bmQ6Y3VycmVudENvbG9yO2Fu"
"aW1hdGlvbjpwdWxzZSAycyBpbmZpbml0ZX0KLmgtY2xvY2t7Zm9udC1mYW1pbHk6J0lCTSBQbGV4"
"IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTFweDtjb2xvcjp2YXIoLS10eC1vbi1kYXJrLW11"
"dGVkKX0KCi5idG4tcmVwb3J0ewogIGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2Fw"
"OjdweDsKICBwYWRkaW5nOjhweCAyMHB4O2JvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzKTsKICBi"
"YWNrZ3JvdW5kOnZhcigtLXJlZCk7Y29sb3I6I2ZmZjsKICBib3JkZXI6bm9uZTtjdXJzb3I6cG9p"
"bnRlcjtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo2MDA7CiAgZm9udC1mYW1pbHk6J091dGZp"
"dCcsc2Fucy1zZXJpZjtsZXR0ZXItc3BhY2luZzouNXB4OwogIHRyYW5zaXRpb246YWxsIC4yNXM7"
"cG9zaXRpb246cmVsYXRpdmU7b3ZlcmZsb3c6aGlkZGVuOwp9Ci5idG4tcmVwb3J0OjpiZWZvcmV7"
"CiAgY29udGVudDonJztwb3NpdGlvbjphYnNvbHV0ZTtpbnNldDowOwogIGJhY2tncm91bmQ6bGlu"
"ZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5zcGFyZW50LHJnYmEoMjU1LDI1NSwyNTUsMC4xKSx0cmFu"
"c3BhcmVudCk7CiAgdHJhbnNmb3JtOnRyYW5zbGF0ZVgoLTEwMCUpO3RyYW5zaXRpb246dHJhbnNm"
"b3JtIC42czsKfQouYnRuLXJlcG9ydDpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXJlZC1kYXJrKTt0"
"cmFuc2Zvcm06dHJhbnNsYXRlWSgtMXB4KTtib3gtc2hhZG93OjAgNHB4IDIwcHggdmFyKC0tcmVk"
"LWdsb3cpfQouYnRuLXJlcG9ydDpob3Zlcjo6YmVmb3Jle3RyYW5zZm9ybTp0cmFuc2xhdGVYKDEw"
"MCUpfQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PQogICBUQUIgTkFWIOKAlCBPTiBXSElURQogICA9PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi50"
"YWItbmF2ewogIGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjJweDsKICBwYWRk"
"aW5nOjAgMjhweDtiYWNrZ3JvdW5kOnZhcigtLXdoaXRlKTsKICBib3JkZXItYm90dG9tOjFweCBz"
"b2xpZCB2YXIoLS13aGl0ZS0zKTsKICBhbmltYXRpb246ZmFkZUluIC42cyBlYXNlOwp9Ci50YWIt"
"YnRuewogIHBhZGRpbmc6MTRweCAyMnB4O2ZvbnQtc2l6ZToxMi41cHg7Zm9udC13ZWlnaHQ6NTAw"
"OwogIGNvbG9yOnZhcigtLXR4LW11dGVkKTtiYWNrZ3JvdW5kOm5vbmU7Ym9yZGVyOm5vbmU7Y3Vy"
"c29yOnBvaW50ZXI7CiAgYm9yZGVyLWJvdHRvbToycHggc29saWQgdHJhbnNwYXJlbnQ7CiAgdHJh"
"bnNpdGlvbjphbGwgLjJzO2ZvbnQtZmFtaWx5OidPdXRmaXQnLHNhbnMtc2VyaWY7CiAgZGlzcGxh"
"eTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4OwogIHBvc2l0aW9uOnJlbGF0aXZlO2xl"
"dHRlci1zcGFjaW5nOi4zcHg7Cn0KLnRhYi1idG46aG92ZXJ7Y29sb3I6dmFyKC0tdHgtZGFyayl9"
"Ci50YWItYnRuLmFjdGl2ZXtjb2xvcjp2YXIoLS1yZWQpO2JvcmRlci1ib3R0b20tY29sb3I6dmFy"
"KC0tcmVkKTtmb250LXdlaWdodDo3MDB9Ci50YWItYmFkZ2V7CiAgZm9udC1mYW1pbHk6J0lCTSBQ"
"bGV4IE1vbm8nLG1vbm9zcGFjZTsKICBmb250LXNpemU6OXB4O2ZvbnQtd2VpZ2h0OjcwMDtwYWRk"
"aW5nOjJweCA3cHg7CiAgYm9yZGVyLXJhZGl1czoxMHB4O2JhY2tncm91bmQ6dmFyKC0td2hpdGUt"
"Myk7CiAgY29sb3I6dmFyKC0tdHgtbXV0ZWQpO2Rpc3BsYXk6bm9uZTsKfQoudGFiLWJhZGdlLnNo"
"b3d7ZGlzcGxheTppbmxpbmUtYmxvY2t9Ci50YWItYmFkZ2UuYi1yZWR7YmFja2dyb3VuZDp2YXIo"
"LS1zZXYtY3JpdC1iZyk7Y29sb3I6dmFyKC0tc2V2LWNyaXQpfQoudGFiLWJhZGdlLmItb3Jhbmdl"
"e2JhY2tncm91bmQ6dmFyKC0tc2V2LWhpZ2gtYmcpO2NvbG9yOnZhcigtLXNldi1oaWdoKX0KCi8q"
"ID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT0KICAgQ09OVEVOVCDigJQgV0hJVEUgQVJFQQogICA9PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi5jb250ZW50"
"e2ZsZXg6MTtvdmVyZmxvdzpoaWRkZW47ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVt"
"bn0KLnRhYi1wYW5le2Rpc3BsYXk6bm9uZTtmbGV4OjE7b3ZlcmZsb3cteTphdXRvO3BhZGRpbmc6"
"MjRweCAyOHB4fQoudGFiLXBhbmUuYWN0aXZle2Rpc3BsYXk6YmxvY2s7YW5pbWF0aW9uOmZhZGVV"
"cCAuNHMgZWFzZX0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT0KICAgVEVSTUlOQUwg4oCUIEFMV0FZUyBEQVJLCiAgID09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT0gKi8KLnRlcm1pbmFsLWNhcmR7CiAgYmFja2dyb3VuZDp2YXIoLS1ibGFjayk7Ym9yZGVy"
"OjFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMDYpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0t"
"cmFkaXVzLWxnKTtvdmVyZmxvdzpoaWRkZW47CiAgcG9zaXRpb246cmVsYXRpdmU7CiAgYW5pbWF0"
"aW9uOmZhZGVVcCAuNXMgZWFzZTsKfQovKiBTY2FuIGxpbmUgZWZmZWN0ICovCi50ZXJtaW5hbC1j"
"YXJkOjphZnRlcnsKICBjb250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRlO2xlZnQ6MDtyaWdodDow"
"O2hlaWdodDo0cHg7CiAgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsdHJhbnNwYXJl"
"bnQscmdiYSgyMzAsNTcsNzAsMC45KSwjZTYzOTQ2LHJnYmEoMjMwLDU3LDcwLDAuOSksdHJhbnNw"
"YXJlbnQpOwogIGFuaW1hdGlvbjpzY2FubGluZSA0cyBsaW5lYXIgaW5maW5pdGU7CiAgcG9pbnRl"
"ci1ldmVudHM6bm9uZTtvcGFjaXR5Oi44NTsKICBib3gtc2hhZG93OjAgMCA4cHggcmdiYSgyMzAs"
"NTcsNzAsMC42KSwwIDAgMTZweCByZ2JhKDIzMCw1Nyw3MCwwLjMpOwp9Ci50ZXJtLWhlYWRlcnsK"
"ICBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpzcGFjZS1i"
"ZXR3ZWVuOwogIHBhZGRpbmc6MTBweCAxOHB4O2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHJnYmEo"
"MjU1LDI1NSwyNTUsMC4wNik7CiAgYmFja2dyb3VuZDpyZ2JhKDAsMCwwLDAuMyk7Cn0KLnRlcm0t"
"ZG90c3tkaXNwbGF5OmZsZXg7Z2FwOjZweH0KLnRlcm0tZG90cyBzcGFue3dpZHRoOjEwcHg7aGVp"
"Z2h0OjEwcHg7Ym9yZGVyLXJhZGl1czo1MCV9Ci50ZXJtLWRvdHMgLmQxe2JhY2tncm91bmQ6dmFy"
"KC0tcmVkKX0KLnRlcm0tZG90cyAuZDJ7YmFja2dyb3VuZDojZTA5ZjNlfQoudGVybS1kb3RzIC5k"
"M3tiYWNrZ3JvdW5kOiMyZDZhNGZ9Ci50ZXJtLXRpdGxle2ZvbnQtZmFtaWx5OidJQk0gUGxleCBN"
"b25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjEwcHg7Y29sb3I6dmFyKC0tdHgtb24tZGFyay1tdXRl"
"ZCk7bGV0dGVyLXNwYWNpbmc6MS41cHh9Ci50ZXJtLWFjdGlvbnN7ZGlzcGxheTpmbGV4O2dhcDo2"
"cHh9Ci50ZXJtLWFjdHsKICBwYWRkaW5nOjRweCAxMnB4O2JvcmRlci1yYWRpdXM6NHB4OwogIGJh"
"Y2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjA1KTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjU1"
"LDI1NSwyNTUsMC4wOCk7CiAgY29sb3I6dmFyKC0tdHgtb24tZGFyay1tdXRlZCk7Zm9udC1zaXpl"
"OjkuNXB4O2ZvbnQtd2VpZ2h0OjYwMDsKICBmb250LWZhbWlseTonSUJNIFBsZXggTW9ubycsbW9u"
"b3NwYWNlO2N1cnNvcjpwb2ludGVyOwogIHRyYW5zaXRpb246YWxsIC4xNXM7bGV0dGVyLXNwYWNp"
"bmc6LjVweDsKfQoudGVybS1hY3Q6aG92ZXJ7YmFja2dyb3VuZDpyZ2JhKDI1NSwyNTUsMjU1LDAu"
"MSk7Y29sb3I6dmFyKC0td2hpdGUpfQoKLmxvYWRpbmctYmFye2hlaWdodDoycHg7YmFja2dyb3Vu"
"ZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsdmFyKC0tcmVkKSwjZmY2YjZiLHZhcigtLXJlZCkpO2Jh"
"Y2tncm91bmQtc2l6ZToyMDAlIDEwMCU7YW5pbWF0aW9uOnNoaW1tZXIgMS41cyBpbmZpbml0ZTtk"
"aXNwbGF5Om5vbmV9CgojdGVybWluYWwtb3V0cHV0ewogIHBhZGRpbmc6MTZweCAxOHB4O21pbi1o"
"ZWlnaHQ6MjYwcHg7bWF4LWhlaWdodDo1MHZoOwogIG92ZXJmbG93LXk6YXV0bztmb250LWZhbWls"
"eTonSUJNIFBsZXggTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMS41cHg7CiAgY29sb3I6dmFy"
"KC0tdHgtb24tZGFyay1tdXRlZCk7Cn0KLnRse3BhZGRpbmc6MnB4IDA7bGluZS1oZWlnaHQ6MS42"
"NTt3b3JkLWJyZWFrOmJyZWFrLWFsbH0KLnRsLmhkcntjb2xvcjp2YXIoLS1yZWQpO2ZvbnQtd2Vp"
"Z2h0OjYwMH0KLnRsLnByb21wdHtjb2xvcjojNGFkZTgwfQoudGwucmVzdWx0e2NvbG9yOnZhcigt"
"LXR4LW9uLWRhcmstbXV0ZWQpfQoudGwuZXJyb3J7Y29sb3I6dmFyKC0tcmVkLWxpZ2h0KX0KLnRs"
"LmluZm97Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjMpfQouYmxpbmt7YW5pbWF0aW9uOnB1bHNl"
"IDFzIHN0ZXAtZW5kIGluZmluaXRlfQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBEQVNIQk9BUkQgQ0FSRFMg4oCU"
"IFdISVRFIENBUkRTIE9OIExJR0hUIEJHCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KLmRhc2gtZ3JpZHtkaXNwbGF5"
"OmdyaWQ7Z2FwOjE4cHh9Ci5kYXNoLWdyaWQuY29scy00e2dyaWQtdGVtcGxhdGUtY29sdW1uczpy"
"ZXBlYXQoNCwxZnIpfQouZGFzaC1ncmlkLmNvbHMtM3tncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVw"
"ZWF0KDMsMWZyKX0KLmRhc2gtZ3JpZC5jb2xzLTJ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVh"
"dCgyLDFmcil9Ci5kYXNoLWdyaWQuY29scy0xe2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnJ9Cgou"
"Y2FyZHsKICBiYWNrZ3JvdW5kOnZhcigtLXdoaXRlKTsKICBib3JkZXI6MXB4IHNvbGlkIHZhcigt"
"LXdoaXRlLTMpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWxnKTsKICBwYWRkaW5nOjIw"
"cHggMjJweDsKICB0cmFuc2l0aW9uOmFsbCAuMjVzOwogIHBvc2l0aW9uOnJlbGF0aXZlOwogIGFu"
"aW1hdGlvbjpmYWRlVXAgLjVzIGVhc2UgYm90aDsKfQouY2FyZDpudGgtY2hpbGQoMSl7YW5pbWF0"
"aW9uLWRlbGF5Oi4wNXN9Ci5jYXJkOm50aC1jaGlsZCgyKXthbmltYXRpb24tZGVsYXk6LjFzfQou"
"Y2FyZDpudGgtY2hpbGQoMyl7YW5pbWF0aW9uLWRlbGF5Oi4xNXN9Ci5jYXJkOm50aC1jaGlsZCg0"
"KXthbmltYXRpb24tZGVsYXk6LjJzfQouY2FyZDpob3Zlcntib3JkZXItY29sb3I6dmFyKC0td2hp"
"dGUtNCk7Ym94LXNoYWRvdzowIDRweCAyMHB4IHJnYmEoMCwwLDAsMC4wNCl9CgouY2FyZC1oZWFk"
"ZXJ7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2Ut"
"YmV0d2VlbjttYXJnaW4tYm90dG9tOjE2cHh9Ci5jYXJkLXRpdGxle2ZvbnQtc2l6ZToxNHB4O2Zv"
"bnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS10eC1kYXJrKTtmb250LWZhbWlseTonT3V0Zml0Jyxz"
"YW5zLXNlcmlmfQouY2FyZC1zdWJ0aXRsZXtmb250LXNpemU6MTFweDtjb2xvcjp2YXIoLS10eC1t"
"dXRlZCk7bWFyZ2luLXRvcDoycHh9CgovKiBTVEFUIE5VTUJFUlMgKi8KLnN0YXQtbnVtewogIGZv"
"bnQtZmFtaWx5OidTeW5lJyxzYW5zLXNlcmlmOwogIGZvbnQtc2l6ZTozNHB4O2ZvbnQtd2VpZ2h0"
"OjgwMDtsaW5lLWhlaWdodDoxOwogIGNvbG9yOnZhcigtLXR4LWRhcmspO2xldHRlci1zcGFjaW5n"
"Oi0xcHg7Cn0KLnN0YXQtbnVtLnJlZHtjb2xvcjp2YXIoLS1zZXYtY3JpdCl9Ci5zdGF0LW51bS5v"
"cmFuZ2V7Y29sb3I6dmFyKC0tc2V2LWhpZ2gpfQouc3RhdC1udW0ueWVsbG93e2NvbG9yOnZhcigt"
"LXNldi1tZWQpfQouc3RhdC1udW0uZ3JlZW57Y29sb3I6dmFyKC0tc2V2LWxvdyl9Ci5zdGF0LW51"
"bS5icmFuZHtjb2xvcjp2YXIoLS1yZWQpfQoKLnN0YXQtYmFyLXdyYXB7bWFyZ2luLXRvcDoxMHB4"
"fQouc3RhdC1iYXJ7aGVpZ2h0OjZweDtib3JkZXItcmFkaXVzOjEwcHg7YmFja2dyb3VuZDp2YXIo"
"LS13aGl0ZS0zKTtvdmVyZmxvdzpoaWRkZW59Ci5zdGF0LWJhci1maWxse2hlaWdodDoxMDAlO2Jv"
"cmRlci1yYWRpdXM6MTBweDt0cmFuc2l0aW9uOndpZHRoIC44cyBjdWJpYy1iZXppZXIoLjQsMCwu"
"MiwxKX0KLnN0YXQtYmFyLWZpbGwucmVke2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVn"
"LHZhcigtLXNldi1jcml0KSwjZjg3MTcxKX0KLnN0YXQtYmFyLWZpbGwub3Jhbmdle2JhY2tncm91"
"bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHZhcigtLXNldi1oaWdoKSwjZmI5MjNjKX0KLnN0YXQt"
"YmFyLWZpbGwueWVsbG93e2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHZhcigtLXNl"
"di1tZWQpLCNmYmJmMjQpfQouc3RhdC1iYXItZmlsbC5ncmVlbntiYWNrZ3JvdW5kOmxpbmVhci1n"
"cmFkaWVudCg5MGRlZyx2YXIoLS1zZXYtbG93KSwjMzRkMzk5KX0KLnN0YXQtYmFyLWZpbGwuYnJh"
"bmR7YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsdmFyKC0tcmVkKSx2YXIoLS1yZWQt"
"bGlnaHQpKX0KCi5zdGF0LXN1Yntmb250LXNpemU6MTAuNXB4O2NvbG9yOnZhcigtLXR4LW11dGVk"
"KTttYXJnaW4tdG9wOjhweDtmb250LWZhbWlseTonSUJNIFBsZXggTW9ubycsbW9ub3NwYWNlfQoK"
"LyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PQogICBQT1JUIFRBQkxFIOKAlCBDTEVBTiBXSElURQogICA9PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi5w"
"b3J0LXRhYmxlLXdyYXB7b3ZlcmZsb3cteDphdXRvfQoucG9ydC10YWJsZXt3aWR0aDoxMDAlO2Jv"
"cmRlci1jb2xsYXBzZTpjb2xsYXBzZTtmb250LXNpemU6MTJweH0KLnBvcnQtdGFibGUgdGhlYWQg"
"dGh7CiAgdGV4dC1hbGlnbjpsZWZ0O3BhZGRpbmc6MTBweCAxNHB4OwogIGZvbnQtZmFtaWx5OidJ"
"Qk0gUGxleCBNb25vJyxtb25vc3BhY2U7CiAgZm9udC1zaXplOjlweDtmb250LXdlaWdodDo3MDA7"
"Y29sb3I6dmFyKC0tdHgtZmFpbnQpOwogIGxldHRlci1zcGFjaW5nOjEuNXB4O3RleHQtdHJhbnNm"
"b3JtOnVwcGVyY2FzZTsKICBib3JkZXItYm90dG9tOjJweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTsK"
"ICBiYWNrZ3JvdW5kOnZhcigtLXdoaXRlLTIpOwp9Ci5wb3J0LXRhYmxlIHRib2R5IHRye2JvcmRl"
"ci1ib3R0b206MXB4IHNvbGlkIHZhcigtLXdoaXRlLTMpO3RyYW5zaXRpb246YmFja2dyb3VuZCAu"
"MTVzfQoucG9ydC10YWJsZSB0Ym9keSB0cjpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXJlZC1kaW0p"
"fQoucG9ydC10YWJsZSB0Ym9keSB0cjpsYXN0LWNoaWxke2JvcmRlci1ib3R0b206bm9uZX0KLnBv"
"cnQtdGFibGUgdGR7cGFkZGluZzoxMHB4IDE0cHg7dmVydGljYWwtYWxpZ246dG9wfQoucC1udW17"
"Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXdlaWdodDo3MDA7Y29s"
"b3I6dmFyKC0tcmVkKTtmb250LXNpemU6MTNweH0KLnAtcHJvdG97Zm9udC1mYW1pbHk6J0lCTSBQ"
"bGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6OXB4O2NvbG9yOnZhcigtLXR4LWZhaW50KX0K"
"LnAtc3Zje2NvbG9yOnZhcigtLXR4LWRhcmspO2ZvbnQtd2VpZ2h0OjYwMDtmb250LXNpemU6MTJw"
"eH0KLnAtdmVye2ZvbnQtc2l6ZToxMHB4O2NvbG9yOnZhcigtLXR4LW11dGVkKTttYXJnaW4tdG9w"
"OjJweH0KLnAtZGVzY3tjb2xvcjp2YXIoLS10eC1tdXRlZCk7Zm9udC1zaXplOjExcHg7bWF4LXdp"
"ZHRoOjI2MHB4fQoucC1maXh7Y29sb3I6dmFyKC0tc2V2LWxvdyk7Zm9udC1zaXplOjExcHg7bWF4"
"LXdpZHRoOjIyMHB4fQoKLyogU0VWRVJJVFkgQkFER0VTIOKAlCBvbiB3aGl0ZSBiZyAqLwouc2V2"
"ewogIGRpc3BsYXk6aW5saW5lLWZsZXg7cGFkZGluZzozcHggMTBweDtib3JkZXItcmFkaXVzOjIw"
"cHg7CiAgZm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTsKICBmb250LXNpemU6"
"OC41cHg7Zm9udC13ZWlnaHQ6NzAwO2xldHRlci1zcGFjaW5nOi44cHg7Cn0KLnNldi5DUklUSUNB"
"THtiYWNrZ3JvdW5kOnZhcigtLXNldi1jcml0LWJnKTtjb2xvcjp2YXIoLS1zZXYtY3JpdCk7Ym9y"
"ZGVyOjFweCBzb2xpZCB2YXIoLS1zZXYtY3JpdC1ib3JkZXIpfQouc2V2LkhJR0h7YmFja2dyb3Vu"
"ZDp2YXIoLS1zZXYtaGlnaC1iZyk7Y29sb3I6dmFyKC0tc2V2LWhpZ2gpO2JvcmRlcjoxcHggc29s"
"aWQgdmFyKC0tc2V2LWhpZ2gtYm9yZGVyKX0KLnNldi5NRURJVU17YmFja2dyb3VuZDp2YXIoLS1z"
"ZXYtbWVkLWJnKTtjb2xvcjp2YXIoLS1zZXYtbWVkKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLXNl"
"di1tZWQtYm9yZGVyKX0KLnNldi5MT1d7YmFja2dyb3VuZDp2YXIoLS1zZXYtbG93LWJnKTtjb2xv"
"cjp2YXIoLS1zZXYtbG93KTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLXNldi1sb3ctYm9yZGVyKX0K"
"Ci8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT0KICAgVEhSRUFUIENBUkRTIOKAlCBXSElURSBXSVRIIFJFRCBMRUZUIEJPUkRF"
"UgogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09ICovCi50aHJlYXQtY2FyZHsKICBiYWNrZ3JvdW5kOnZhcigtLXdoaXRlKTti"
"b3JkZXI6MXB4IHNvbGlkIHZhcigtLXdoaXRlLTMpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFk"
"aXVzLWxnKTtwYWRkaW5nOjE4cHggMjJweDsKICBib3JkZXItbGVmdDo0cHggc29saWQgdmFyKC0t"
"d2hpdGUtNCk7CiAgdHJhbnNpdGlvbjphbGwgLjI1czsKICBhbmltYXRpb246ZmFkZVVwIC41cyBl"
"YXNlIGJvdGg7Cn0KLnRocmVhdC1jYXJkOmhvdmVye2JveC1zaGFkb3c6MCA0cHggMjBweCByZ2Jh"
"KDAsMCwwLDAuMDUpO3RyYW5zZm9ybTp0cmFuc2xhdGVZKC0xcHgpfQoudGhyZWF0LWNhcmQuQ1JJ"
"VElDQUx7Ym9yZGVyLWxlZnQtY29sb3I6dmFyKC0tc2V2LWNyaXQpfQoudGhyZWF0LWNhcmQuSElH"
"SHtib3JkZXItbGVmdC1jb2xvcjp2YXIoLS1zZXYtaGlnaCl9Ci50aHJlYXQtY2FyZC5NRURJVU17"
"Ym9yZGVyLWxlZnQtY29sb3I6dmFyKC0tc2V2LW1lZCl9Ci50aHJlYXQtY2FyZC5MT1d7Ym9yZGVy"
"LWxlZnQtY29sb3I6dmFyKC0tc2V2LWxvdyl9Ci50Yy1oZHJ7ZGlzcGxheTpmbGV4O2FsaWduLWl0"
"ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjttYXJnaW4tYm90dG9tOjEw"
"cHh9Ci50Yy1uYW1le2ZvbnQtc2l6ZToxM3B4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS10"
"eC1kYXJrKX0KLnRjLWRlc2N7Zm9udC1zaXplOjEycHg7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpO21h"
"cmdpbi1ib3R0b206MTRweDtsaW5lLWhlaWdodDoxLjd9Ci50Yy1maXh7CiAgcGFkZGluZzoxMHB4"
"IDE0cHg7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMpOwogIGJhY2tncm91bmQ6dmFyKC0tc2V2"
"LWxvdy1iZyk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1zZXYtbG93LWJvcmRlcik7Cn0KLnRjLWZp"
"eC1sYWJlbHtmb250LWZhbWlseTonSUJNIFBsZXggTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZTo4"
"LjVweDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tc2V2LWxvdyk7bGV0dGVyLXNwYWNpbmc6"
"MS41cHg7bWFyZ2luLWJvdHRvbTozcHh9Ci50Yy1maXgtdGV4dHtmb250LXNpemU6MTFweDtjb2xv"
"cjp2YXIoLS1zZXYtbG93KTtsaW5lLWhlaWdodDoxLjV9CgovKiA9PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIENIQVJUIENB"
"UkRTCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT0gKi8KLmNoYXJ0LXdyYXB7cG9zaXRpb246cmVsYXRpdmU7bWluLWhlaWdo"
"dDoyMDBweH0KLmNoYXJ0LXdyYXAgY2FudmFze3dpZHRoOjEwMCUhaW1wb3J0YW50O2hlaWdodDox"
"MDAlIWltcG9ydGFudH0KCi8qIFJJU0sgR0FVR0UgKi8KLnJpc2stZ2F1Z2V7ZGlzcGxheTpmbGV4"
"O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MjhweDtwYWRkaW5nOjhweCAwfQoucmlzay1jaXJjbGV7"
"CiAgd2lkdGg6MTEwcHg7aGVpZ2h0OjExMHB4O2JvcmRlci1yYWRpdXM6NTAlOwogIGRpc3BsYXk6"
"ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29u"
"dGVudDpjZW50ZXI7CiAgYm9yZGVyOjNweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTtwb3NpdGlvbjpy"
"ZWxhdGl2ZTtmbGV4LXNocmluazowOwp9Ci5yaXNrLWNpcmNsZTo6YWZ0ZXJ7CiAgY29udGVudDon"
"Jztwb3NpdGlvbjphYnNvbHV0ZTtpbnNldDotM3B4O2JvcmRlci1yYWRpdXM6NTAlOwogIGJvcmRl"
"cjozcHggc29saWQgdHJhbnNwYXJlbnQ7Ym9yZGVyLXRvcC1jb2xvcjpjdXJyZW50Q29sb3I7CiAg"
"YW5pbWF0aW9uOnNwaW4gMi41cyBsaW5lYXIgaW5maW5pdGU7Cn0KLnJpc2stdmFse2ZvbnQtZmFt"
"aWx5OidTeW5lJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZTozNnB4O2ZvbnQtd2VpZ2h0OjgwMDtsaW5l"
"LWhlaWdodDoxfQoucmlzay1sYWJlbHtmb250LWZhbWlseTonSUJNIFBsZXggTW9ubycsbW9ub3Nw"
"YWNlO2ZvbnQtc2l6ZTo5cHg7Zm9udC13ZWlnaHQ6NzAwO2xldHRlci1zcGFjaW5nOjJweDttYXJn"
"aW4tdG9wOjRweDtjb2xvcjp2YXIoLS10eC1tdXRlZCl9Ci5yaXNrLWRldGFpbHN7ZGlzcGxheTpm"
"bGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtnYXA6MTBweH0KLnJpc2stcm93e2Rpc3BsYXk6Zmxl"
"eDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEwcHg7Zm9udC1zaXplOjEycHg7Y29sb3I6dmFyKC0t"
"dHgtYm9keSl9Ci5yaXNrLWRvdHt3aWR0aDo4cHg7aGVpZ2h0OjhweDtib3JkZXItcmFkaXVzOjUw"
"JTtmbGV4LXNocmluazowfQoucmlzay12YWwtc217Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8n"
"LG1vbm9zcGFjZTtmb250LXdlaWdodDo3MDA7bWFyZ2luLWxlZnQ6YXV0b30KCi8qID09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0K"
"ICAgRU1QVFkgU1RBVEUKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwouZW1wdHktc3RhdGV7ZGlzcGxheTpmbGV4O2Zs"
"ZXgtZGlyZWN0aW9uOmNvbHVtbjthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNl"
"bnRlcjtwYWRkaW5nOjYwcHggMjBweDt0ZXh0LWFsaWduOmNlbnRlcn0KLmVtcHR5LWljb3tmb250"
"LXNpemU6NDBweDttYXJnaW4tYm90dG9tOjE2cHg7b3BhY2l0eTouMzV9Ci5lbXB0eS10aXRsZXtm"
"b250LXNpemU6MTRweDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpO21hcmdp"
"bi1ib3R0b206NnB4fQouZW1wdHktc3Vie2ZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigtLXR4LWZh"
"aW50KTttYXgtd2lkdGg6MzAwcHh9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIENIQVQgUEFORUwg4oCUIERBUksg"
"Qk9UVE9NIEJBUgogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09ICovCi5jaGF0LXBhbmVsewogIGJvcmRlci10b3A6MnB4IHNv"
"bGlkIHZhcigtLXJlZCk7CiAgYmFja2dyb3VuZDp2YXIoLS1ibGFjayk7CiAgZGlzcGxheTpmbGV4"
"O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjsKICBtYXgtaGVpZ2h0OjI0MHB4O3RyYW5zaXRpb246bWF4"
"LWhlaWdodCAuMzVzIGN1YmljLWJlemllciguNCwwLC4yLDEpOwogIHBvc2l0aW9uOnJlbGF0aXZl"
"Owp9Ci5jaGF0LXBhbmVsLmNvbGxhcHNlZHttYXgtaGVpZ2h0OjQ2cHh9Ci5jaGF0LXRvZ2dsZXsK"
"ICBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpzcGFjZS1i"
"ZXR3ZWVuOwogIHBhZGRpbmc6MCAyNHB4O2hlaWdodDo0NnB4O21pbi1oZWlnaHQ6NDZweDsKICBj"
"dXJzb3I6cG9pbnRlcjsKfQouY2hhdC10b2dnbGUtbGVmdHtkaXNwbGF5OmZsZXg7YWxpZ24taXRl"
"bXM6Y2VudGVyO2dhcDoxMHB4fQouY2hhdC10b2dnbGUtbGFiZWx7Zm9udC1zaXplOjEycHg7Zm9u"
"dC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXdoaXRlKTtsZXR0ZXItc3BhY2luZzouNXB4fQouY2hh"
"dC10b2dnbGUtc3RhdHVze2ZvbnQtc2l6ZToxMHB4O2NvbG9yOiM0YWRlODA7Zm9udC13ZWlnaHQ6"
"NTAwfQouY2hhdC1hcnJvd3tmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS10eC1vbi1kYXJrLW11"
"dGVkKTt0cmFuc2l0aW9uOnRyYW5zZm9ybSAuM3N9Ci5jaGF0LXBhbmVsLmNvbGxhcHNlZCAuY2hh"
"dC1hcnJvd3t0cmFuc2Zvcm06cm90YXRlKDE4MGRlZyl9CgojY2hhdC1tZXNzYWdlc3tmbGV4OjE7"
"b3ZlcmZsb3cteTphdXRvO3BhZGRpbmc6MTBweCAyNHB4fQoubXNne2Rpc3BsYXk6ZmxleDtnYXA6"
"MTBweDttYXJnaW4tYm90dG9tOjEwcHg7YW5pbWF0aW9uOmZhZGVVcCAuM3MgZWFzZX0KLm1zZy1h"
"dmF0YXJ7CiAgd2lkdGg6MjZweDtoZWlnaHQ6MjZweDtib3JkZXItcmFkaXVzOjZweDsKICBkaXNw"
"bGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7CiAgZm9u"
"dC1zaXplOjhweDtmb250LXdlaWdodDo3MDA7ZmxleC1zaHJpbms6MDsKICBmb250LWZhbWlseTon"
"SUJNIFBsZXggTW9ubycsbW9ub3NwYWNlOwp9Ci5tc2cuYWkgLm1zZy1hdmF0YXJ7YmFja2dyb3Vu"
"ZDpyZ2JhKDIzMCw1Nyw3MCwwLjE1KTtjb2xvcjp2YXIoLS1yZWQtbGlnaHQpfQoubXNnLnVzZXIg"
"Lm1zZy1hdmF0YXJ7YmFja2dyb3VuZDpyZ2JhKDI1NSwyNTUsMjU1LDAuMDgpO2NvbG9yOnZhcigt"
"LXR4LW9uLWRhcmstbXV0ZWQpfQoubXNnLWJvZHl7CiAgYmFja2dyb3VuZDp2YXIoLS1ibGFjay0z"
"KTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wNik7CiAgYm9yZGVyLXJhZGl1"
"czp2YXIoLS1yYWRpdXMpO3BhZGRpbmc6OXB4IDEzcHg7CiAgZm9udC1zaXplOjEycHg7bGluZS1o"
"ZWlnaHQ6MS42O2NvbG9yOnZhcigtLXR4LW9uLWRhcmstbXV0ZWQpO21heC13aWR0aDo4NSU7Cn0K"
"Ci5jaGF0LWlucHV0LXJvd3tkaXNwbGF5OmZsZXg7Z2FwOjhweDtwYWRkaW5nOjhweCAyNHB4IDEy"
"cHh9Ci5jaGF0LWlucHV0ewogIGZsZXg6MTtiYWNrZ3JvdW5kOnZhcigtLWJsYWNrLTMpO2JvcmRl"
"cjoxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjA4KTsKICBib3JkZXItcmFkaXVzOnZhcigt"
"LXJhZGl1cyk7cGFkZGluZzo5cHggMTRweDsKICBjb2xvcjp2YXIoLS10eC1vbi1kYXJrKTtmb250"
"LXNpemU6MTJweDtvdXRsaW5lOm5vbmU7CiAgZm9udC1mYW1pbHk6J091dGZpdCcsc2Fucy1zZXJp"
"Zjt0cmFuc2l0aW9uOmJvcmRlci1jb2xvciAuMnM7Cn0KLmNoYXQtaW5wdXQ6Zm9jdXN7Ym9yZGVy"
"LWNvbG9yOnZhcigtLXJlZCl9Ci5jaGF0LWlucHV0OjpwbGFjZWhvbGRlcntjb2xvcjpyZ2JhKDI1"
"NSwyNTUsMjU1LDAuMil9Ci5jaGF0LXNlbmR7CiAgcGFkZGluZzowIDIwcHg7Ym9yZGVyLXJhZGl1"
"czp2YXIoLS1yYWRpdXMpOwogIGJhY2tncm91bmQ6dmFyKC0tcmVkKTtjb2xvcjojZmZmO2JvcmRl"
"cjpub25lOwogIGZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjcwMDtjdXJzb3I6cG9pbnRlcjsK"
"ICBmb250LWZhbWlseTonT3V0Zml0JyxzYW5zLXNlcmlmO3RyYW5zaXRpb246YWxsIC4yczsKfQou"
"Y2hhdC1zZW5kOmhvdmVye2JhY2tncm91bmQ6dmFyKC0tcmVkLWRhcmspfQoKLyogPT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQog"
"ICBSRVBPUlQgTU9EQUwKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwoubW9kYWwtb3ZlcmxheXtkaXNwbGF5Om5vbmU7"
"cG9zaXRpb246Zml4ZWQ7aW5zZXQ6MDt6LWluZGV4OjEwMDA7YmFja2dyb3VuZDpyZ2JhKDAsMCww"
"LDAuNSk7YmFja2Ryb3AtZmlsdGVyOmJsdXIoMTJweCk7YWxpZ24taXRlbXM6Y2VudGVyO2p1c3Rp"
"ZnktY29udGVudDpjZW50ZXJ9Ci5tb2RhbC1vdmVybGF5Lm9wZW57ZGlzcGxheTpmbGV4fQoubW9k"
"YWwtYm94e2JhY2tncm91bmQ6dmFyKC0td2hpdGUpO2JvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVz"
"LXhsKTt3aWR0aDo5MCU7bWF4LXdpZHRoOjkwMHB4O21heC1oZWlnaHQ6ODV2aDtkaXNwbGF5OmZs"
"ZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2JveC1zaGFkb3c6MCAyNHB4IDY0cHggcmdiYSgwLDAs"
"MCwwLjMpO2FuaW1hdGlvbjpmYWRlVXAgLjRzIGVhc2V9Ci5tb2RhbC1oZHJ7ZGlzcGxheTpmbGV4"
"O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjtwYWRkaW5n"
"OjE4cHggMjRweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKX0KLm1vZGFs"
"LXRpdGxle2ZvbnQtZmFtaWx5OidTeW5lJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxNnB4O2ZvbnQt"
"d2VpZ2h0OjgwMDtjb2xvcjp2YXIoLS10eC1kYXJrKTtsZXR0ZXItc3BhY2luZzoxcHh9Ci5tb2Rh"
"bC1jbG9zZXtwYWRkaW5nOjZweCAxNnB4O2JvcmRlci1yYWRpdXM6NnB4O2JhY2tncm91bmQ6dmFy"
"KC0td2hpdGUtMik7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTtjb2xvcjp2YXIoLS10"
"eC1tdXRlZCk7Y3Vyc29yOnBvaW50ZXI7Zm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6NjAwO2Zv"
"bnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7dHJhbnNpdGlvbjphbGwgLjE1c30K"
"Lm1vZGFsLWNsb3NlOmhvdmVye2JhY2tncm91bmQ6dmFyKC0td2hpdGUtMyl9Ci5tb2RhbC1ib2R5"
"e2ZsZXg6MTtvdmVyZmxvdy15OmF1dG87cGFkZGluZzoyNHB4fQoubW9kYWwtZm9vdGVye2Rpc3Bs"
"YXk6ZmxleDtnYXA6MTBweDtwYWRkaW5nOjE2cHggMjRweDtib3JkZXItdG9wOjFweCBzb2xpZCB2"
"YXIoLS13aGl0ZS0zKX0KLmRsLWJ0bntwYWRkaW5nOjhweCAyMHB4O2JvcmRlci1yYWRpdXM6dmFy"
"KC0tcmFkaXVzKTtib3JkZXI6bm9uZTtjdXJzb3I6cG9pbnRlcjtmb250LXNpemU6MTJweDtmb250"
"LXdlaWdodDo3MDA7dHJhbnNpdGlvbjphbGwgLjJzO2ZvbnQtZmFtaWx5OidPdXRmaXQnLHNhbnMt"
"c2VyaWZ9Ci5kbC1idG4ucHJpbWFyeXtiYWNrZ3JvdW5kOnZhcigtLXJlZCk7Y29sb3I6I2ZmZn0K"
"LmRsLWJ0bi5wcmltYXJ5OmhvdmVye2JhY2tncm91bmQ6dmFyKC0tcmVkLWRhcmspfQouZGwtYnRu"
"LnNlY29uZGFyeXtiYWNrZ3JvdW5kOnZhcigtLXdoaXRlLTIpO2NvbG9yOnZhcigtLXR4LWJvZHkp"
"O2JvcmRlcjoxcHggc29saWQgdmFyKC0td2hpdGUtMyl9Ci5kbC1idG4uc2Vjb25kYXJ5OmhvdmVy"
"e2JhY2tncm91bmQ6dmFyKC0td2hpdGUtMyl9CgovKiBSZXBvcnQgaW5uZXIgKi8KLnJwLWhkcnt0"
"ZXh0LWFsaWduOmNlbnRlcjtwYWRkaW5nOjE2cHggMCAyMHB4O2JvcmRlci1ib3R0b206MXB4IHNv"
"bGlkIHZhcigtLXdoaXRlLTMpO21hcmdpbi1ib3R0b206MjBweH0KLnJwLXR7Zm9udC1mYW1pbHk6"
"J1N5bmUnLHNhbnMtc2VyaWY7Zm9udC1zaXplOjIwcHg7Zm9udC13ZWlnaHQ6ODAwO2NvbG9yOnZh"
"cigtLXJlZCk7bGV0dGVyLXNwYWNpbmc6MnB4fQoucnAtc3tmb250LXNpemU6MTFweDtjb2xvcjp2"
"YXIoLS10eC1tdXRlZCk7bWFyZ2luLXRvcDo0cHh9Ci5ycC1zZWN7bWFyZ2luLWJvdHRvbToyMHB4"
"fQoucnAtc3R7Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6"
"MTFweDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tcmVkKTtsZXR0ZXItc3BhY2luZzoxLjVw"
"eDttYXJnaW4tYm90dG9tOjEwcHh9Ci5ycC1wcntkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1j"
"b2x1bW5zOjgwcHggMTIwcHggODBweCAxZnI7Z2FwOjhweDtwYWRkaW5nOjZweCAwO2ZvbnQtc2l6"
"ZToxMXB4O2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLXdoaXRlLTMpfQoucnAtdGh7cGFk"
"ZGluZzoxMHB4IDE0cHg7bWFyZ2luLWJvdHRvbTo2cHg7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRp"
"dXMpO2JvcmRlci1sZWZ0OjNweCBzb2xpZCB2YXIoLS13aGl0ZS00KTtiYWNrZ3JvdW5kOnZhcigt"
"LXdoaXRlLTIpfQoucnAtdGguQ1JJVElDQUx7Ym9yZGVyLWxlZnQtY29sb3I6dmFyKC0tc2V2LWNy"
"aXQpfS5ycC10aC5ISUdIe2JvcmRlci1sZWZ0LWNvbG9yOnZhcigtLXNldi1oaWdoKX0ucnAtdGgu"
"TUVESVVNe2JvcmRlci1sZWZ0LWNvbG9yOnZhcigtLXNldi1tZWQpfS5ycC10aC5MT1d7Ym9yZGVy"
"LWxlZnQtY29sb3I6dmFyKC0tc2V2LWxvdyl9Ci5ycC10bntmb250LXdlaWdodDo3MDA7Y29sb3I6"
"dmFyKC0tdHgtZGFyayk7Zm9udC1zaXplOjEycHg7bWFyZ2luLWJvdHRvbTo0cHh9Ci5ycC10ZHtm"
"b250LXNpemU6MTFweDtjb2xvcjp2YXIoLS10eC1tdXRlZCl9Ci5ycC10Zntmb250LXNpemU6MTFw"
"eDtjb2xvcjp2YXIoLS1zZXYtbG93KTttYXJnaW4tdG9wOjRweH0KCi8qIE5PVElGSUNBVElPTiAq"
"Lwoubm90aWZ7CiAgcG9zaXRpb246Zml4ZWQ7dG9wOjIwcHg7cmlnaHQ6MjBweDt6LWluZGV4OjIw"
"MDA7CiAgYmFja2dyb3VuZDp2YXIoLS1ibGFjayk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDIzMCw1"
"Nyw3MCwwLjIpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzKTtwYWRkaW5nOjEycHggMjBw"
"eDsKICBjb2xvcjp2YXIoLS13aGl0ZSk7Zm9udC1zaXplOjEycHg7Zm9udC13ZWlnaHQ6NjAwOwog"
"IGJveC1zaGFkb3c6MCA4cHggMzBweCByZ2JhKDAsMCwwLDAuMyk7CiAgYW5pbWF0aW9uOmZhZGVV"
"cCAuM3MgZWFzZTsKfQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PQogICBTQ0FOIFNUQVRVUyBUQUIgU1RZTEVTCiAgID09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT0gKi8KLnNjYW4taW5kaWNhdG9yewogIHdpZHRoOjQ4cHg7aGVpZ2h0OjQ4cHg7Ym9yZGVy"
"LXJhZGl1czo1MCU7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNv"
"bnRlbnQ6Y2VudGVyOwogIHBvc2l0aW9uOnJlbGF0aXZlO2ZsZXgtc2hyaW5rOjA7CiAgYmFja2dy"
"b3VuZDp2YXIoLS13aGl0ZS0yKTtib3JkZXI6MnB4IHNvbGlkIHZhcigtLXdoaXRlLTMpOwp9Ci5z"
"Y2FuLWluZGljYXRvci5ydW5uaW5ne2JhY2tncm91bmQ6dmFyKC0tcmVkLWRpbSk7Ym9yZGVyLWNv"
"bG9yOnZhcigtLXJlZC1ib3JkZXIpfQouc2Nhbi1pbmRpY2F0b3IucnVubmluZzo6YWZ0ZXJ7CiAg"
"Y29udGVudDonJztwb3NpdGlvbjphYnNvbHV0ZTtpbnNldDotMnB4O2JvcmRlci1yYWRpdXM6NTAl"
"OwogIGJvcmRlcjoycHggc29saWQgdHJhbnNwYXJlbnQ7Ym9yZGVyLXRvcC1jb2xvcjp2YXIoLS1y"
"ZWQpOwogIGFuaW1hdGlvbjpzcGluIDFzIGxpbmVhciBpbmZpbml0ZTsKfQouc2Nhbi1pbmRpY2F0"
"b3IuY29tcGxldGV7YmFja2dyb3VuZDp2YXIoLS1zZXYtbG93LWJnKTtib3JkZXItY29sb3I6dmFy"
"KC0tc2V2LWxvdy1ib3JkZXIpfQouc2Nhbi1pbmRpY2F0b3IuZXJyb3J7YmFja2dyb3VuZDp2YXIo"
"LS1zZXYtY3JpdC1iZyk7Ym9yZGVyLWNvbG9yOnZhcigtLXNldi1jcml0LWJvcmRlcil9Ci5zY2Fu"
"LXBjdHtmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjtmb250LXNpemU6MTNweDtmb250LXdl"
"aWdodDo4MDA7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpfQouc2Nhbi1pbmRpY2F0b3IucnVubmluZyAu"
"c2Nhbi1wY3R7Y29sb3I6dmFyKC0tcmVkKX0KLnNjYW4taW5kaWNhdG9yLmNvbXBsZXRlIC5zY2Fu"
"LXBjdHtjb2xvcjp2YXIoLS1zZXYtbG93KX0KLnNjYW4taW5kaWNhdG9yLmVycm9yIC5zY2FuLXBj"
"dHtjb2xvcjp2YXIoLS1zZXYtY3JpdCl9Ci5zY2FuLW1ldGEtaXRlbXsKICBmb250LWZhbWlseTon"
"SUJNIFBsZXggTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMHB4OwogIGNvbG9yOnZhcigtLXR4"
"LW11dGVkKTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo0cHg7Cn0KLnNjYW4t"
"bWV0YS1pdGVtIC5kb3R7d2lkdGg6NXB4O2hlaWdodDo1cHg7Ym9yZGVyLXJhZGl1czo1MCU7Zmxl"
"eC1zaHJpbms6MH0KLnNjYW4tYmFyLXRyYWNre2hlaWdodDoxMHB4O2JhY2tncm91bmQ6dmFyKC0t"
"d2hpdGUtMyk7Ym9yZGVyLXJhZGl1czoxMHB4O292ZXJmbG93OmhpZGRlbn0KLnNjYW4tYmFyLWZp"
"bGwtbGl2ZXsKICBoZWlnaHQ6MTAwJTtib3JkZXItcmFkaXVzOjEwcHg7dHJhbnNpdGlvbjp3aWR0"
"aCAuNnMgY3ViaWMtYmV6aWVyKC40LDAsLjIsMSk7CiAgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGll"
"bnQoOTBkZWcsdmFyKC0tcmVkKSx2YXIoLS1yZWQtbGlnaHQpKTtwb3NpdGlvbjpyZWxhdGl2ZTsK"
"fQouc2Nhbi1iYXItZmlsbC1saXZlLmNvbXBsZXRle2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50"
"KDkwZGVnLHZhcigtLXNldi1sb3cpLCMzNGQzOTkpfQouc2Nhbi1iYXItZmlsbC1saXZlOjphZnRl"
"cnsKICBjb250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRlO2luc2V0OjA7CiAgYmFja2dyb3VuZDps"
"aW5lYXItZ3JhZGllbnQoOTBkZWcsdHJhbnNwYXJlbnQscmdiYSgyNTUsMjU1LDI1NSwwLjI1KSx0"
"cmFuc3BhcmVudCk7CiAgYW5pbWF0aW9uOnNoaW1tZXIgMS41cyBpbmZpbml0ZTsKfQoudGFiLWJh"
"ZGdlLmxpdmV7ZGlzcGxheTppbmxpbmUtYmxvY2s7YmFja2dyb3VuZDp2YXIoLS1yZWQpO2NvbG9y"
"OiNmZmY7YW5pbWF0aW9uOnB1bHNlIDEuNXMgaW5maW5pdGV9Ci50YWItYmFkZ2UuZG9uZXtkaXNw"
"bGF5OmlubGluZS1ibG9jaztiYWNrZ3JvdW5kOnZhcigtLXNldi1sb3ctYmcpO2NvbG9yOnZhcigt"
"LXNldi1sb3cpfQoKLyogTUlOSSBTVEFUUyBJTiBIRUFERVIgKi8KLmgtbWluaS1zdGF0c3tkaXNw"
"bGF5OmZsZXg7Z2FwOjEwcHh9Ci5oLW1pbmktc3RhdHsKICBmb250LWZhbWlseTonSUJNIFBsZXgg"
"TW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMHB4OwogIGNvbG9yOnZhcigtLXR4LW9uLWRhcmst"
"bXV0ZWQpO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjRweDsKfQouaC1taW5p"
"LXN0YXQgc3Ryb25ne2NvbG9yOnZhcigtLXdoaXRlKTtmb250LXNpemU6MTFweH0KCi8qIE1JTkkg"
"UFJPR1JFU1MgQkFSIChiZWxvdyBoZWFkZXIpICovCi5oLW1pbmktcHJvZ3Jlc3N7CiAgaGVpZ2h0"
"OjNweDtiYWNrZ3JvdW5kOnZhcigtLWJsYWNrLTMpO3Bvc2l0aW9uOnJlbGF0aXZlO292ZXJmbG93"
"OmhpZGRlbjsKICBvcGFjaXR5OjA7dHJhbnNpdGlvbjpvcGFjaXR5IC4zczsKfQouaC1taW5pLXBy"
"b2dyZXNzLmFjdGl2ZXtvcGFjaXR5OjF9Ci5oLW1pbmktYmFyewogIGhlaWdodDoxMDAlO3dpZHRo"
"OjAlOwogIGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHZhcigtLXJlZCksdmFyKC0t"
"cmVkLWxpZ2h0KSk7CiAgdHJhbnNpdGlvbjp3aWR0aCAuNXMgY3ViaWMtYmV6aWVyKC40LDAsLjIs"
"MSk7cG9zaXRpb246cmVsYXRpdmU7Cn0KLmgtbWluaS1iYXI6OmFmdGVyewogIGNvbnRlbnQ6Jyc7"
"cG9zaXRpb246YWJzb2x1dGU7aW5zZXQ6MDsKICBiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5"
"MGRlZyx0cmFuc3BhcmVudCxyZ2JhKDI1NSwyNTUsMjU1LDAuMyksdHJhbnNwYXJlbnQpOwogIGFu"
"aW1hdGlvbjpzaGltbWVyIDEuMnMgaW5maW5pdGU7Cn0KCi8qIFRBUkdFVCBISVNUT1JZIERST1BE"
"T1dOICovCi5oLXRhcmdldC1oaXN0b3J5ewogIGRpc3BsYXk6bm9uZTtwb3NpdGlvbjphYnNvbHV0"
"ZTt0b3A6MTAwJTtsZWZ0OjA7cmlnaHQ6MDt6LWluZGV4OjEwMDsKICBiYWNrZ3JvdW5kOnZhcigt"
"LWJsYWNrLTIpO2JvcmRlcjoxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjEpOwogIGJvcmRl"
"ci1yYWRpdXM6MCAwIHZhcigtLXJhZGl1cykgdmFyKC0tcmFkaXVzKTsKICBib3gtc2hhZG93OjAg"
"OHB4IDI0cHggcmdiYSgwLDAsMCwwLjQpO21heC1oZWlnaHQ6MjAwcHg7b3ZlcmZsb3cteTphdXRv"
"Owp9Ci5oLXRhcmdldC1oaXN0b3J5LnNob3d7ZGlzcGxheTpibG9ja30KLmgtdGgtaXRlbXsKICBw"
"YWRkaW5nOjhweCAxNHB4O2ZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigtLXR4LW9uLWRhcmstbXV0"
"ZWQpOwogIGN1cnNvcjpwb2ludGVyO3RyYW5zaXRpb246YmFja2dyb3VuZCAuMTVzOwogIGZvbnQt"
"ZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Ym9yZGVyLWJvdHRvbToxcHggc29saWQg"
"cmdiYSgyNTUsMjU1LDI1NSwwLjA0KTsKfQouaC10aC1pdGVtOmhvdmVye2JhY2tncm91bmQ6cmdi"
"YSgyMzAsNTcsNzAsMC4xKTtjb2xvcjp2YXIoLS13aGl0ZSl9Ci5oLXRoLWl0ZW06bGFzdC1jaGls"
"ZHtib3JkZXItYm90dG9tOm5vbmV9Ci5oLXRoLWxhYmVse2ZvbnQtc2l6ZTo5cHg7Y29sb3I6cmdi"
"YSgyNTUsMjU1LDI1NSwwLjI1KTttYXJnaW4tYm90dG9tOjJweDtsZXR0ZXItc3BhY2luZzoxcHh9"
"CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09CiAgIEFUVEFDSyBDSEFJTiBWSVNVQUxJWkFUSU9OCiAgID09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8K"
"LmNoYWluLWNhcmR7CiAgYmFja2dyb3VuZDp2YXIoLS13aGl0ZSk7Ym9yZGVyOjFweCBzb2xpZCB2"
"YXIoLS13aGl0ZS0zKTtib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cyk7CiAgcGFkZGluZzoyMHB4"
"O21hcmdpbi1ib3R0b206MTZweDtwb3NpdGlvbjpyZWxhdGl2ZTtvdmVyZmxvdzpoaWRkZW47CiAg"
"Ym9yZGVyLWxlZnQ6NHB4IHNvbGlkIHZhcigtLXdoaXRlLTQpO2FuaW1hdGlvbjpmYWRlVXAgLjRz"
"IGVhc2UgYm90aDsKfQouY2hhaW4tY2FyZC5DUklUSUNBTHtib3JkZXItbGVmdC1jb2xvcjojZDkw"
"NDI5fQouY2hhaW4tY2FyZC5ISUdIe2JvcmRlci1sZWZ0LWNvbG9yOiNlODVkMDR9Ci5jaGFpbi1j"
"YXJkLk1FRElVTXtib3JkZXItbGVmdC1jb2xvcjojZTA5ZjNlfQoKLmNoYWluLWhlYWRlcntkaXNw"
"bGF5OmZsZXg7YWxpZ24taXRlbXM6ZmxleC1zdGFydDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0"
"d2VlbjtnYXA6MTJweDttYXJnaW4tYm90dG9tOjE0cHh9Ci5jaGFpbi1uYW1le2ZvbnQtZmFtaWx5"
"OidTeW5lJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToxNnB4O2ZvbnQtd2VpZ2h0OjgwMDtjb2xvcjp2"
"YXIoLS10eC1kYXJrKX0KLmNoYWluLWtpbGxjaGFpbntmb250LWZhbWlseTonSUJNIFBsZXggTW9u"
"bycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMHB4O2NvbG9yOnZhcigtLXR4LW11dGVkKTttYXJnaW4t"
"dG9wOjJweH0KLmNoYWluLWNvbmZpZGVuY2V7CiAgZm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8n"
"LG1vbm9zcGFjZTtmb250LXNpemU6MTFweDtmb250LXdlaWdodDo3MDA7CiAgcGFkZGluZzo0cHgg"
"MTBweDtib3JkZXItcmFkaXVzOjIwcHg7d2hpdGUtc3BhY2U6bm93cmFwOwp9Ci5jaGFpbi1jb25m"
"aWRlbmNlLmhpZ2h7YmFja2dyb3VuZDp2YXIoLS1yZWQtZGltKTtjb2xvcjp2YXIoLS1yZWQpfQou"
"Y2hhaW4tY29uZmlkZW5jZS5tZWR7YmFja2dyb3VuZDpyZ2JhKDIyNCwxNTksNjIsMC4xKTtjb2xv"
"cjojZTA5ZjNlfQoKLyogS2lsbCBDaGFpbiBGbG93ICovCi5jaGFpbi1mbG93ewogIGRpc3BsYXk6"
"ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjA7bWFyZ2luOjE2cHggMDtwYWRkaW5nOjEycHgg"
"MDsKICBvdmVyZmxvdy14OmF1dG87Cn0KLmNoYWluLXN0ZXB7CiAgZGlzcGxheTpmbGV4O2ZsZXgt"
"ZGlyZWN0aW9uOmNvbHVtbjthbGlnbi1pdGVtczpjZW50ZXI7bWluLXdpZHRoOjEyMHB4OwogIHBv"
"c2l0aW9uOnJlbGF0aXZlO2ZsZXgtc2hyaW5rOjA7Cn0KLmNoYWluLXN0ZXAtZG90ewogIHdpZHRo"
"OjM2cHg7aGVpZ2h0OjM2cHg7Ym9yZGVyLXJhZGl1czo1MCU7CiAgZGlzcGxheTpmbGV4O2FsaWdu"
"LWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOwogIGZvbnQtc2l6ZToxNHB4O2Zv"
"bnQtd2VpZ2h0OjgwMDtjb2xvcjojZmZmO3Bvc2l0aW9uOnJlbGF0aXZlO3otaW5kZXg6MjsKfQou"
"Y2hhaW4tc3RlcC1kb3QuY29uZmlybWVke2JhY2tncm91bmQ6dmFyKC0tcmVkKTtib3gtc2hhZG93"
"OjAgMCAxMnB4IHJnYmEoMjMwLDU3LDcwLDAuMyl9Ci5jaGFpbi1zdGVwLWRvdC5ub3RfZm91bmR7"
"YmFja2dyb3VuZDp2YXIoLS13aGl0ZS0zKTtjb2xvcjp2YXIoLS10eC1mYWludCl9Ci5jaGFpbi1z"
"dGVwLXBoYXNlewogIGZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC1z"
"aXplOjhweDtmb250LXdlaWdodDo3MDA7CiAgbGV0dGVyLXNwYWNpbmc6MXB4O2NvbG9yOnZhcigt"
"LXR4LWZhaW50KTttYXJnaW4tdG9wOjZweDsKfQouY2hhaW4tc3RlcC1sYWJlbHsKICBmb250LXNp"
"emU6MTBweDtjb2xvcjp2YXIoLS10eC1tdXRlZCk7dGV4dC1hbGlnbjpjZW50ZXI7bWFyZ2luLXRv"
"cDozcHg7CiAgbWF4LXdpZHRoOjExMHB4O2xpbmUtaGVpZ2h0OjEuMzsKfQouY2hhaW4tYXJyb3d7"
"CiAgd2lkdGg6NDBweDtoZWlnaHQ6MnB4O2JhY2tncm91bmQ6dmFyKC0td2hpdGUtNCk7cG9zaXRp"
"b246cmVsYXRpdmU7ZmxleC1zaHJpbms6MDsKICBtYXJnaW4tdG9wOi0yMHB4Owp9Ci5jaGFpbi1h"
"cnJvdy5jb25maXJtZWR7YmFja2dyb3VuZDp2YXIoLS1yZWQpfQouY2hhaW4tYXJyb3c6OmFmdGVy"
"ewogIGNvbnRlbnQ6J+KAuic7cG9zaXRpb246YWJzb2x1dGU7cmlnaHQ6LTRweDt0b3A6LThweDsK"
"ICBmb250LXNpemU6MTRweDtjb2xvcjppbmhlcml0Owp9Ci5jaGFpbi1hcnJvdy5jb25maXJtZWQ6"
"OmFmdGVye2NvbG9yOnZhcigtLXJlZCl9CgovKiBJbXBhY3QgJiBCdXNpbmVzcyAqLwouY2hhaW4t"
"aW1wYWN0ewogIGJhY2tncm91bmQ6cmdiYSgyMTcsNCw0MSwwLjA0KTtib3JkZXI6MXB4IHNvbGlk"
"IHJnYmEoMjE3LDQsNDEsMC4xKTsKICBib3JkZXItcmFkaXVzOjhweDtwYWRkaW5nOjEycHggMTRw"
"eDttYXJnaW46MTJweCAwOwp9Ci5jaGFpbi1pbXBhY3QtdGl0bGV7Zm9udC1zaXplOjlweDtmb250"
"LXdlaWdodDo3MDA7bGV0dGVyLXNwYWNpbmc6MS41cHg7Y29sb3I6dmFyKC0tcmVkKTttYXJnaW4t"
"Ym90dG9tOjRweH0KLmNoYWluLWltcGFjdC10ZXh0e2ZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigt"
"LXR4LWRhcmspO2xpbmUtaGVpZ2h0OjEuNX0KLmNoYWluLWJ1c2luZXNzewogIGJhY2tncm91bmQ6"
"cmdiYSgxMCwxMCwxMiwwLjAzKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLXdoaXRlLTMpOwogIGJv"
"cmRlci1yYWRpdXM6OHB4O3BhZGRpbmc6MTJweCAxNHB4O21hcmdpbjo4cHggMDsKfQouY2hhaW4t"
"YnVzaW5lc3MtdGl0bGV7Zm9udC1zaXplOjlweDtmb250LXdlaWdodDo3MDA7bGV0dGVyLXNwYWNp"
"bmc6MS41cHg7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpO21hcmdpbi1ib3R0b206NHB4fQouY2hhaW4t"
"Y29zdHtmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjtmb250LXdlaWdodDo4MDA7Y29sb3I6"
"dmFyKC0tcmVkKTtmb250LXNpemU6MTRweDttYXJnaW4tdG9wOjRweH0KCi8qIEZpeCBTZWN0aW9u"
"ICovCi5jaGFpbi1maXh7CiAgYmFja2dyb3VuZDpyZ2JhKDQ1LDEwNiw3OSwwLjA0KTtib3JkZXI6"
"MXB4IHNvbGlkIHJnYmEoNDUsMTA2LDc5LDAuMTIpOwogIGJvcmRlci1yYWRpdXM6OHB4O3BhZGRp"
"bmc6MTJweCAxNHB4O21hcmdpbi10b3A6MTBweDsKfQouY2hhaW4tZml4LXRpdGxle2ZvbnQtc2l6"
"ZTo5cHg7Zm9udC13ZWlnaHQ6NzAwO2xldHRlci1zcGFjaW5nOjEuNXB4O2NvbG9yOnZhcigtLXNl"
"di1sb3cpO21hcmdpbi1ib3R0b206NnB4fQouY2hhaW4tZml4LWNtZHsKICBmb250LWZhbWlseTon"
"SUJNIFBsZXggTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMXB4OwogIGNvbG9yOnZhcigtLXR4"
"LWRhcmspO2xpbmUtaGVpZ2h0OjEuODt3aGl0ZS1zcGFjZTpwcmUtd3JhcDsKfQoKLyogQ29tcGxp"
"YW5jZSBUYWdzICovCi5jaGFpbi1jb21wbGlhbmNle2Rpc3BsYXk6ZmxleDtmbGV4LXdyYXA6d3Jh"
"cDtnYXA6NnB4O21hcmdpbi10b3A6MTBweH0KLmNoYWluLWNvbXAtdGFnewogIGZvbnQtZmFtaWx5"
"OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjlweDtmb250LXdlaWdodDo2MDA7"
"CiAgcGFkZGluZzozcHggOHB4O2JvcmRlci1yYWRpdXM6NHB4OwogIGJhY2tncm91bmQ6dmFyKC0t"
"d2hpdGUtMik7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTtjb2xvcjp2YXIoLS10eC1t"
"dXRlZCk7Cn0KCi8qIFN1bW1hcnkgU3RhdHMgKi8KLmNoYWluLXN1bW1hcnl7CiAgZGlzcGxheTpn"
"cmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoNCwxZnIpO2dhcDoxMnB4O21hcmdpbi1i"
"b3R0b206MjBweDsKfQouY2hhaW4tc3RhdHsKICBiYWNrZ3JvdW5kOnZhcigtLXdoaXRlKTtib3Jk"
"ZXI6MXB4IHNvbGlkIHZhcigtLXdoaXRlLTMpO2JvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzKTsK"
"ICBwYWRkaW5nOjE2cHg7dGV4dC1hbGlnbjpjZW50ZXI7Cn0KLmNoYWluLXN0YXQtbnVte2ZvbnQt"
"ZmFtaWx5OidTeW5lJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToyOHB4O2ZvbnQtd2VpZ2h0OjgwMH0K"
"LmNoYWluLXN0YXQtbGFiZWx7Zm9udC1zaXplOjEwcHg7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpO21h"
"cmdpbi10b3A6NHB4O2xldHRlci1zcGFjaW5nOjAuNXB4fQoKLyogUmVwb3J0IEJ1dHRvbiAqLwou"
"YnRuLWFkdi1yZXBvcnR7CiAgYmFja2dyb3VuZDp2YXIoLS1ibGFjayk7Y29sb3I6dmFyKC0td2hp"
"dGUpO2JvcmRlcjpub25lOwogIHBhZGRpbmc6MTBweCAyMHB4O2JvcmRlci1yYWRpdXM6dmFyKC0t"
"cmFkaXVzKTtjdXJzb3I6cG9pbnRlcjsKICBmb250LWZhbWlseTonT3V0Zml0JyxzYW5zLXNlcmlm"
"O2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjYwMDsKICB0cmFuc2l0aW9uOmFsbCAuMnM7Cn0K"
"LmJ0bi1hZHYtcmVwb3J0OmhvdmVye2JhY2tncm91bmQ6dmFyKC0tcmVkKX0KCkBtZWRpYShtYXgt"
"d2lkdGg6OTAwcHgpey5zaWRlYmFye2Rpc3BsYXk6bm9uZX0uZGFzaC1ncmlkLmNvbHMtNCwuY2hh"
"aW4tc3VtbWFyeXtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDIsMWZyKX19Cjwvc3R5bGU+"
"CjwvaGVhZD4KPGJvZHk+CjxkaXYgY2xhc3M9ImFwcCI+Cgo8IS0tID09PT09PT09PT09PT09PT0g"
"U0lERUJBUiA9PT09PT09PT09PT09PT09IC0tPgo8YXNpZGUgY2xhc3M9InNpZGViYXIiPgogIDxk"
"aXYgY2xhc3M9InNpZGViYXItc2Nyb2xsIj4KICAgIDxkaXYgY2xhc3M9InMtbG9nbyI+CiAgICAg"
"IDxkaXYgY2xhc3M9InMtbG9nby1tYXJrIj5IPC9kaXY+CiAgICAgIDxkaXY+PGRpdiBjbGFzcz0i"
"cy1sb2dvLXRleHQiPkhBUlNIQTwvZGl2PjxkaXYgY2xhc3M9InMtbG9nby1zdWIiPlZBUFQgU1VJ"
"VEUgdjcuMDwvZGl2PjwvZGl2PgogICAgPC9kaXY+CgogICAgPCEtLSBTRUFSQ0ggLS0+CiAgICA8"
"ZGl2IGNsYXNzPSJzLXNlYXJjaCI+CiAgICAgIDxzcGFuIGNsYXNzPSJzLXNlYXJjaC1pY29uIj7w"
"n5SNPC9zcGFuPgogICAgICA8aW5wdXQgdHlwZT0idGV4dCIgY2xhc3M9InMtc2VhcmNoLWlucHV0"
"IiBpZD0idG9vbC1zZWFyY2giIHBsYWNlaG9sZGVyPSJTZWFyY2ggdG9vbHMuLi4iIG9uaW5wdXQ9"
"ImZpbHRlclRvb2xzKHRoaXMudmFsdWUpIj4KICAgIDwvZGl2PgoKICAgIDwhLS0gTkVUV09SSyAt"
"LT4KICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbiBvcGVuIiBkYXRhLXNlY3Rpb249Im5ldCI+CiAg"
"ICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbi1oZWFkZXIiIG9uY2xpY2s9InRvZ2dsZVNlY3Rpb24o"
"dGhpcykiPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24taWNvbiI+8J+ToTwvc3Bhbj4K"
"ICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLXRpdGxlIj5OZXR3b3JrPC9zcGFuPgogICAg"
"ICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tY291bnQiPjk8L3NwYW4+CiAgICAgICAgPHNwYW4g"
"Y2xhc3M9InMtc2VjdGlvbi1hcnJvdyI+4pa8PC9zcGFuPgogICAgICA8L2Rpdj4KICAgICAgPGRp"
"diBjbGFzcz0icy1zZWN0aW9uLWJvZHkiPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBv"
"bmNsaWNrPSJydW5Ub29sKCdubWFwX3NjYW4nLHRoaXMsJ25ldCcpIiBkYXRhLW5hbWU9InBvcnQg"
"c2Nhbm5lciBubWFwIj48c3BhbiBjbGFzcz0iaWNvIj7wn5SNPC9zcGFuPjxzcGFuIGNsYXNzPSJs"
"YmwiPlBvcnQgU2Nhbm5lcjwvc3Bhbj48c3BhbiBjbGFzcz0icy10YWcgciI+Q09SRTwvc3Bhbj48"
"L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgn"
"bm1hcF90b3AxMDAnLHRoaXMsJ25ldCcpIiBkYXRhLW5hbWU9InF1aWNrIHRvcCAxMDAgZmFzdCI+"
"PHNwYW4gY2xhc3M9ImljbyI+4pqhPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPlF1aWNrIFRvcCAx"
"MDA8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9"
"InJ1blRvb2woJ25tYXBfdnVsbicsdGhpcywnbmV0JykiIGRhdGEtbmFtZT0idnVsbmVyYWJpbGl0"
"eSBjdmUgc2NhbiI+PHNwYW4gY2xhc3M9ImljbyI+8J+boTwvc3Bhbj48c3BhbiBjbGFzcz0ibGJs"
"Ij5WdWxuIFNjYW48L3NwYW4+PHNwYW4gY2xhc3M9InMtdGFnIHIiPkNWRTwvc3Bhbj48L2J1dHRv"
"bj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgndWRwX3Nj"
"YW4nLHRoaXMsJ25ldCcpIiBkYXRhLW5hbWU9InVkcCBzY2FuIj48c3BhbiBjbGFzcz0iaWNvIj7w"
"n5OhPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPlVEUCBTY2FuPC9zcGFuPjwvYnV0dG9uPgogICAg"
"ICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdmaXJld2FsbF9kZXRl"
"Y3QnLHRoaXMsJ25ldCcpIiBkYXRhLW5hbWU9ImZpcmV3YWxsIGRldGVjdCB3YWYiPjxzcGFuIGNs"
"YXNzPSJpY28iPvCfp7E8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+RmlyZXdhbGwgRGV0ZWN0PC9z"
"cGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5U"
"b29sKCdzbWJfZW51bScsdGhpcywnbmV0JykiIGRhdGEtbmFtZT0ic21iIGVudW0gc2hhcmUiPjxz"
"cGFuIGNsYXNzPSJpY28iPvCfk4I8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+U01CIEVudW08L3Nw"
"YW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRv"
"b2woJ3NubXBfY2hlY2snLHRoaXMsJ25ldCcpIiBkYXRhLW5hbWU9InNubXAgY2hlY2sgY29tbXVu"
"aXR5Ij48c3BhbiBjbGFzcz0iaWNvIj7wn5OKPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPlNOTVAg"
"Q2hlY2s8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xp"
"Y2s9InJ1blRvb2woJ2Jhbm5lcl9ncmFiJyx0aGlzLCduZXQnKSIgZGF0YS1uYW1lPSJiYW5uZXIg"
"Z3JhYiBzZXJ2aWNlIHZlcnNpb24iPjxzcGFuIGNsYXNzPSJpY28iPvCfj7c8L3NwYW4+PHNwYW4g"
"Y2xhc3M9ImxibCI+QmFubmVyIEdyYWI8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBj"
"bGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ2FycF9zY2FuJyx0aGlzLCduZXQnKSIgZGF0"
"YS1uYW1lPSJhcnAgc2NhbiBsb2NhbCI+PHNwYW4gY2xhc3M9ImljbyI+8J+Tizwvc3Bhbj48c3Bh"
"biBjbGFzcz0ibGJsIj5BUlAgU2Nhbjwvc3Bhbj48L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8"
"L2Rpdj4KCiAgICA8IS0tIFdFQiAtLT4KICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbiBvcGVuIiBk"
"YXRhLXNlY3Rpb249IndlYiI+CiAgICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbi1oZWFkZXIiIG9u"
"Y2xpY2s9InRvZ2dsZVNlY3Rpb24odGhpcykiPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rp"
"b24taWNvbiI+8J+MkDwvc3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLXRpdGxl"
"Ij5XZWI8L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi1jb3VudCI+MTA8L3Nw"
"YW4+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi1hcnJvdyI+4pa8PC9zcGFuPgogICAg"
"ICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0icy1zZWN0aW9uLWJvZHkiPgogICAgICAgIDxidXR0"
"b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdzcWxtYXBfY2hlY2snLHRoaXMsJ3dl"
"YicpIiBkYXRhLW5hbWU9InNxbCBpbmplY3Rpb24gc3FsaSBzcWxtYXAiPjxzcGFuIGNsYXNzPSJp"
"Y28iPvCfkok8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+U1FMIEluamVjdGlvbjwvc3Bhbj48c3Bh"
"biBjbGFzcz0icy10YWcgciI+Q1JJVDwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNs"
"YXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgneHNzX3NjYW4nLHRoaXMsJ3dlYicpIiBkYXRh"
"LW5hbWU9InhzcyBjcm9zcyBzaXRlIHNjcmlwdGluZyI+PHNwYW4gY2xhc3M9ImljbyI+4pqgPC9z"
"cGFuPjxzcGFuIGNsYXNzPSJsYmwiPlhTUyBTY2FubmVyPC9zcGFuPjwvYnV0dG9uPgogICAgICAg"
"IDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCduaWt0b19zY2FuJyx0aGlz"
"LCd3ZWInKSIgZGF0YS1uYW1lPSJuaWt0byB3ZWIgc2NhbiI+PHNwYW4gY2xhc3M9ImljbyI+8J+M"
"kDwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5OaWt0byBTY2FuPC9zcGFuPjwvYnV0dG9uPgogICAg"
"ICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdoZWFkZXJfY2hlY2sn"
"LHRoaXMsJ3dlYicpIiBkYXRhLW5hbWU9ImhlYWRlciBhdWRpdCBodHRwIHNlY3VyaXR5Ij48c3Bh"
"biBjbGFzcz0iaWNvIj7wn5OLPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkhlYWRlciBBdWRpdDwv"
"c3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVu"
"VG9vbCgnc3NsX2NoZWNrJyx0aGlzLCd3ZWInKSIgZGF0YS1uYW1lPSJzc2wgdGxzIGNlcnRpZmlj"
"YXRlIGh0dHBzIj48c3BhbiBjbGFzcz0iaWNvIj7wn5SSPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwi"
"PlNTTC9UTFMgQ2hlY2s8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1u"
"YXYiIG9uY2xpY2s9InJ1blRvb2woJ3dhZl9kZXRlY3QnLHRoaXMsJ3dlYicpIiBkYXRhLW5hbWU9"
"IndhZiB3ZWIgYXBwbGljYXRpb24gZmlyZXdhbGwiPjxzcGFuIGNsYXNzPSJpY28iPvCfm6E8L3Nw"
"YW4+PHNwYW4gY2xhc3M9ImxibCI+V0FGIERldGVjdDwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8"
"YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnY29yc19jaGVjaycsdGhpcywn"
"d2ViJykiIGRhdGEtbmFtZT0iY29ycyBjcm9zcyBvcmlnaW4iPjxzcGFuIGNsYXNzPSJpY28iPvCf"
"lJc8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+Q09SUyBDaGVjazwvc3Bhbj48L2J1dHRvbj4KICAg"
"ICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnZGlyX2VudW0nLHRo"
"aXMsJ3dlYicpIiBkYXRhLW5hbWU9ImRpcmVjdG9yeSBlbnVtZXJhdGlvbiBicnV0ZSBkaXJidXN0"
"ZXIiPjxzcGFuIGNsYXNzPSJpY28iPvCfk4E8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+RGlyZWN0"
"b3J5IEVudW08L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9u"
"Y2xpY2s9InJ1blRvb2woJ2Ntc19kZXRlY3QnLHRoaXMsJ3dlYicpIiBkYXRhLW5hbWU9ImNtcyBk"
"ZXRlY3Qgd29yZHByZXNzIGpvb21sYSBkcnVwYWwiPjxzcGFuIGNsYXNzPSJpY28iPvCfj5c8L3Nw"
"YW4+PHNwYW4gY2xhc3M9ImxibCI+Q01TIERldGVjdDwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8"
"YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnYWRtaW5fZmluZGVyJyx0aGlz"
"LCd3ZWInKSIgZGF0YS1uYW1lPSJhZG1pbiBmaW5kZXIgcGFuZWwgbG9naW4iPjxzcGFuIGNsYXNz"
"PSJpY28iPvCflJE8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+QWRtaW4gRmluZGVyPC9zcGFuPjwv"
"YnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgoKICAgIDwhLS0gSU5GUkFTVFJVQ1RVUkUg"
"LS0+CiAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rpb24iIGRhdGEtc2VjdGlvbj0iaW5mIj4KICAgICAg"
"PGRpdiBjbGFzcz0icy1zZWN0aW9uLWhlYWRlciIgb25jbGljaz0idG9nZ2xlU2VjdGlvbih0aGlz"
"KSI+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi1pY29uIj7wn5alPC9zcGFuPgogICAg"
"ICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tdGl0bGUiPkluZnJhc3RydWN0dXJlPC9zcGFuPgog"
"ICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tY291bnQiPjY8L3NwYW4+CiAgICAgICAgPHNw"
"YW4gY2xhc3M9InMtc2VjdGlvbi1hcnJvdyI+4pa8PC9zcGFuPgogICAgICA8L2Rpdj4KICAgICAg"
"PGRpdiBjbGFzcz0icy1zZWN0aW9uLWJvZHkiPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2"
"IiBvbmNsaWNrPSJydW5Ub29sKCdzc2hfYXVkaXQnLHRoaXMsJ2luZicpIiBkYXRhLW5hbWU9InNz"
"aCBhdWRpdCBrZXkiPjxzcGFuIGNsYXNzPSJpY28iPvCflJA8L3NwYW4+PHNwYW4gY2xhc3M9Imxi"
"bCI+U1NIIEF1ZGl0PC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2"
"IiBvbmNsaWNrPSJydW5Ub29sKCdmdHBfY2hlY2snLHRoaXMsJ2luZicpIiBkYXRhLW5hbWU9ImZ0"
"cCBhbm9ueW1vdXMgY2hlY2siPjxzcGFuIGNsYXNzPSJpY28iPvCfk6Q8L3NwYW4+PHNwYW4gY2xh"
"c3M9ImxibCI+RlRQIENoZWNrPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9"
"InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdyZHBfY2hlY2snLHRoaXMsJ2luZicpIiBkYXRhLW5h"
"bWU9InJkcCByZW1vdGUgZGVza3RvcCBibHVla2VlcCI+PHNwYW4gY2xhc3M9ImljbyI+8J+WpTwv"
"c3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5SRFAgQ2hlY2s8L3NwYW4+PC9idXR0b24+CiAgICAgICAg"
"PGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ2RiX2V4cG9zZScsdGhpcywn"
"aW5mJykiIGRhdGEtbmFtZT0iZGF0YWJhc2UgZXhwb3N1cmUgbXlzcWwgcG9zdGdyZXMgcmVkaXMg"
"bW9uZ28iPjxzcGFuIGNsYXNzPSJpY28iPvCfl4Q8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+REIg"
"RXhwb3N1cmU8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9u"
"Y2xpY2s9InJ1blRvb2woJ2RvY2tlcl9jaGVjaycsdGhpcywnaW5mJykiIGRhdGEtbmFtZT0iZG9j"
"a2VyIGNvbnRhaW5lciBhcGkiPjxzcGFuIGNsYXNzPSJpY28iPvCfkLM8L3NwYW4+PHNwYW4gY2xh"
"c3M9ImxibCI+RG9ja2VyIENoZWNrPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xh"
"c3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdrOHNfY2hlY2snLHRoaXMsJ2luZicpIiBkYXRh"
"LW5hbWU9Imt1YmVybmV0ZXMgazhzIGNsdXN0ZXIiPjxzcGFuIGNsYXNzPSJpY28iPuKYuDwvc3Bh"
"bj48c3BhbiBjbGFzcz0ibGJsIj5LOHMgQ2hlY2s8L3NwYW4+PC9idXR0b24+CiAgICAgIDwvZGl2"
"PgogICAgPC9kaXY+CgogICAgPCEtLSBOVUNMRUkgLS0+CiAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rp"
"b24iIGRhdGEtc2VjdGlvbj0ibnVjIj4KICAgICAgPGRpdiBjbGFzcz0icy1zZWN0aW9uLWhlYWRl"
"ciIgb25jbGljaz0idG9nZ2xlU2VjdGlvbih0aGlzKSI+CiAgICAgICAgPHNwYW4gY2xhc3M9InMt"
"c2VjdGlvbi1pY29uIj7imKI8L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi10"
"aXRsZSI+TnVjbGVpPC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tY291bnQi"
"PjY8L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi1hcnJvdyI+4pa8PC9zcGFu"
"PgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0icy1zZWN0aW9uLWJvZHkiPgogICAgICAg"
"IDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdudWNsZWlfZnVsbCcsdGhp"
"cywnd2ViJykiIGRhdGEtbmFtZT0ibnVjbGVpIGZ1bGwgc2NhbiBhbGwgdGVtcGxhdGVzIj48c3Bh"
"biBjbGFzcz0iaWNvIj7imKI8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+RnVsbCBTY2FuPC9zcGFu"
"PjxzcGFuIGNsYXNzPSJzLXRhZyByIj5DT1JFPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0"
"b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdudWNsZWlfY3ZlJyx0aGlzLCd3ZWIn"
"KSIgZGF0YS1uYW1lPSJudWNsZWkgY3ZlIHZ1bG5lcmFiaWxpdHkiPjxzcGFuIGNsYXNzPSJpY28i"
"PvCflKU8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+Q1ZFIFNjYW48L3NwYW4+PHNwYW4gY2xhc3M9"
"InMtdGFnIHIiPkNWRTwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5h"
"diIgb25jbGljaz0icnVuVG9vbCgnbnVjbGVpX2NyaXRpY2FsJyx0aGlzLCd3ZWInKSIgZGF0YS1u"
"YW1lPSJudWNsZWkgY3JpdGljYWwgaGlnaCBzZXZlcml0eSI+PHNwYW4gY2xhc3M9ImljbyI+8J+a"
"qDwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5Dcml0aWNhbC9IaWdoPC9zcGFuPjwvYnV0dG9uPgog"
"ICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdudWNsZWlfbWlz"
"Y29uZmlnJyx0aGlzLCd3ZWInKSIgZGF0YS1uYW1lPSJudWNsZWkgbWlzY29uZmlndXJhdGlvbiBl"
"eHBvc2VkIj48c3BhbiBjbGFzcz0iaWNvIj7impk8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+TWlz"
"Y29uZmlnIFNjYW48L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYi"
"IG9uY2xpY2s9InJ1blRvb2woJ251Y2xlaV90ZWNoJyx0aGlzLCd3ZWInKSIgZGF0YS1uYW1lPSJu"
"dWNsZWkgdGVjaG5vbG9neSBkZXRlY3QgZmluZ2VycHJpbnQiPjxzcGFuIGNsYXNzPSJpY28iPvCf"
"lKw8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+VGVjaCBEZXRlY3Q8L3NwYW4+PC9idXR0b24+CiAg"
"ICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ251Y2xlaV9uZXR3"
"b3JrJyx0aGlzLCdpbmYnKSIgZGF0YS1uYW1lPSJudWNsZWkgbmV0d29yayBwcm90b2NvbCI+PHNw"
"YW4gY2xhc3M9ImljbyI+8J+MkDwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5OZXR3b3JrIFNjYW48"
"L3NwYW4+PC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CgogICAgPCEtLSBSRUNPTiAt"
"LT4KICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbiIgZGF0YS1zZWN0aW9uPSJyZWMiPgogICAgICA8"
"ZGl2IGNsYXNzPSJzLXNlY3Rpb24taGVhZGVyIiBvbmNsaWNrPSJ0b2dnbGVTZWN0aW9uKHRoaXMp"
"Ij4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWljb24iPvCflbU8L3NwYW4+CiAgICAg"
"ICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi10aXRsZSI+UmVjb248L3NwYW4+CiAgICAgICAgPHNw"
"YW4gY2xhc3M9InMtc2VjdGlvbi1jb3VudCI+ODwvc3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0i"
"cy1zZWN0aW9uLWFycm93Ij7ilrw8L3NwYW4+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNz"
"PSJzLXNlY3Rpb24tYm9keSI+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9"
"InJ1blRvb2woJ3dob2lzJyx0aGlzLCdyZWMnKSIgZGF0YS1uYW1lPSJ3aG9pcyBkb21haW4gcmVn"
"aXN0cmF0aW9uIj48c3BhbiBjbGFzcz0iaWNvIj7wn4yNPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwi"
"PldIT0lTPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNs"
"aWNrPSJydW5Ub29sKCdkbnNfbG9va3VwJyx0aGlzLCdyZWMnKSIgZGF0YS1uYW1lPSJkbnMgbG9v"
"a3VwIHJlY29yZHMiPjxzcGFuIGNsYXNzPSJpY28iPvCfk6E8L3NwYW4+PHNwYW4gY2xhc3M9Imxi"
"bCI+RE5TIExvb2t1cDwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5h"
"diIgb25jbGljaz0icnVuVG9vbCgnc3ViZG9tYWluX2VudW0nLHRoaXMsJ3JlYycpIiBkYXRhLW5h"
"bWU9InN1YmRvbWFpbiBlbnVtZXJhdGlvbiI+PHNwYW4gY2xhc3M9ImljbyI+8J+Ujjwvc3Bhbj48"
"c3BhbiBjbGFzcz0ibGJsIj5TdWJkb21haW4gRW51bTwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8"
"YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgndHJhY2Vyb3V0ZScsdGhpcywn"
"cmVjJykiIGRhdGEtbmFtZT0idHJhY2Vyb3V0ZSBob3BzIj48c3BhbiBjbGFzcz0iaWNvIj7wn5uk"
"PC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPlRyYWNlcm91dGU8L3NwYW4+PC9idXR0b24+CiAgICAg"
"ICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ25ldHdvcmtfc2Nhbics"
"dGhpcywncmVjJykiIGRhdGEtbmFtZT0ibG9jYWwgbmV0d29yayBzY2FuIGRpc2NvdmVyIj48c3Bh"
"biBjbGFzcz0iaWNvIj7wn5O2PC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkxvY2FsIE5ldHdvcms8"
"L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1"
"blRvb2woJ215X2lwJyx0aGlzLCdyZWMnKSIgZGF0YS1uYW1lPSJteSBpcCBhZGRyZXNzIHB1Ymxp"
"YyI+PHNwYW4gY2xhc3M9ImljbyI+8J+PoDwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5NeSBJUDwv"
"c3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVu"
"VG9vbCgnc3lzdGVtX2luZm8nLHRoaXMsJ3JlYycpIiBkYXRhLW5hbWU9InN5c3RlbSBpbmZvIGNw"
"dSByYW0gb3MiPjxzcGFuIGNsYXNzPSJpY28iPvCfkrs8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+"
"U3lzdGVtIEluZm88L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYi"
"IG9uY2xpY2s9InJ1blRvb2woJ3dlYXRoZXInLHRoaXMsJ3JlYycpIiBkYXRhLW5hbWU9IndlYXRo"
"ZXIgdGVtcGVyYXR1cmUgdmlzYWtoYXBhdG5hbSI+PHNwYW4gY2xhc3M9ImljbyI+8J+MpDwvc3Bh"
"bj48c3BhbiBjbGFzcz0ibGJsIj5XZWF0aGVyPC9zcGFuPjwvYnV0dG9uPgogICAgICA8L2Rpdj4K"
"ICAgIDwvZGl2PgogIDwvZGl2PgogIDxkaXYgY2xhc3M9InMtZm9vdGVyIj4KICAgIDxkaXYgY2xh"
"c3M9InMtYXZhdGFyIj5IQTwvZGl2PgogICAgPGRpdj48ZGl2IGNsYXNzPSJzLXVuYW1lIj5IQVJT"
"SEE8L2Rpdj48ZGl2IGNsYXNzPSJzLXVyb2xlIj5MZXZlbCA1IMK3IDM4IFRvb2xzIEFybWVkPC9k"
"aXY+PC9kaXY+CiAgPC9kaXY+CjwvYXNpZGU+Cgo8IS0tID09PT09PT09PT09PT09PT0gTUFJTiA9"
"PT09PT09PT09PT09PT09IC0tPgo8ZGl2IGNsYXNzPSJtYWluIj4KICA8aGVhZGVyIGNsYXNzPSJo"
"ZWFkZXIiPgogICAgPGRpdiBjbGFzcz0iaC1sZWZ0Ij4KICAgICAgPGRpdiBjbGFzcz0iaC10aXRs"
"ZSI+VkFQVCBEYXNoYm9hcmQ8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iaC1zZXAiPjwvZGl2Pgog"
"ICAgICA8ZGl2IGNsYXNzPSJoLXRhcmdldCIgc3R5bGU9InBvc2l0aW9uOnJlbGF0aXZlIj4KICAg"
"ICAgICA8ZGl2IGNsYXNzPSJoLXRhcmdldC1wcmUiPlRBUkdFVDwvZGl2PgogICAgICAgIDxpbnB1"
"dCB0eXBlPSJ0ZXh0IiBpZD0idGFyZ2V0LWlucHV0IiBjbGFzcz0iaC10YXJnZXQtaW5wdXQiIHBs"
"YWNlaG9sZGVyPSJFbnRlciBJUCwgZG9tYWluLCBvciBVUkwuLi4iIG9uZm9jdXM9InNob3dUYXJn"
"ZXRIaXN0b3J5KCkiIG9uaW5wdXQ9InNob3dUYXJnZXRIaXN0b3J5KCkiIGF1dG9jb21wbGV0ZT0i"
"b2ZmIj4KICAgICAgICA8ZGl2IGNsYXNzPSJoLXRhcmdldC1oaXN0b3J5IiBpZD0idGFyZ2V0LWhp"
"c3RvcnkiPjwvZGl2PgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgogICAgPGRpdiBjbGFzcz0iaC1y"
"aWdodCI+CiAgICAgIDxkaXYgY2xhc3M9ImgtbWluaS1zdGF0cyIgaWQ9ImgtbWluaS1zdGF0cyI+"
"CiAgICAgICAgPHNwYW4gY2xhc3M9ImgtbWluaS1zdGF0IiB0aXRsZT0iU2NhbnMiPvCflI0gPHN0"
"cm9uZyBpZD0iaG0tc2NhbnMiPjA8L3N0cm9uZz48L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9"
"ImgtbWluaS1zdGF0IiB0aXRsZT0iUG9ydHMiPvCfk6EgPHN0cm9uZyBpZD0iaG0tcG9ydHMiPjA8"
"L3N0cm9uZz48L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9ImgtbWluaS1zdGF0IiB0aXRsZT0i"
"VGhyZWF0cyI+4pqgIDxzdHJvbmcgaWQ9ImhtLXRocmVhdHMiPjA8L3N0cm9uZz48L3NwYW4+CiAg"
"ICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJoLXN0YXR1cyI+PHNwYW4gY2xhc3M9ImRvdCI+"
"PC9zcGFuPk9OTElORTwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJoLWNsb2NrIiBpZD0iY2xvY2si"
"PjwvZGl2PgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4tcmVwb3J0IiBvbmNsaWNrPSJvcGVuUmVw"
"b3J0KCkiPvCfk4QgUmVwb3J0PC9idXR0b24+PGJ1dHRvbiBjbGFzcz0iYnRuLWNsZWFyLXNlc3Np"
"b24iIG9uY2xpY2s9ImNsZWFyU2Vzc2lvbigpIiB0aXRsZT0iQ2xlYXIgYWxsIHNjYW4gZGF0YSBh"
"bmQgc3RhcnQgZnJlc2giIHN0eWxlPSJiYWNrZ3JvdW5kOiMxZTI5M2I7Ym9yZGVyOjFweCBzb2xp"
"ZCAjMzM0MTU1O2NvbG9yOiNmODcxNzE7cGFkZGluZzo2cHggMTRweDtib3JkZXItcmFkaXVzOjhw"
"eDtjdXJzb3I6cG9pbnRlcjtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo2MDA7bGV0dGVyLXNw"
"YWNpbmc6LjVweDt0cmFuc2l0aW9uOmFsbCAuMnMiIG9ubW91c2VvdmVyPSJ0aGlzLnN0eWxlLmJh"
"Y2tncm91bmQ9JyNkYzI2MjYnO3RoaXMuc3R5bGUuY29sb3I9JyNmZmYnO3RoaXMuc3R5bGUuYm9y"
"ZGVyQ29sb3I9JyNkYzI2MjYnIiBvbm1vdXNlb3V0PSJ0aGlzLnN0eWxlLmJhY2tncm91bmQ9JyMx"
"ZTI5M2InO3RoaXMuc3R5bGUuY29sb3I9JyNmODcxNzEnO3RoaXMuc3R5bGUuYm9yZGVyQ29sb3I9"
"JyMzMzQxNTUnIj7wn5eRIENsZWFyPC9idXR0b24+CiAgICA8L2Rpdj4KICA8L2hlYWRlcj4KICA8"
"IS0tIE1JTkkgUFJPR1JFU1MgQkFSIC0tPgogIDxkaXYgY2xhc3M9ImgtbWluaS1wcm9ncmVzcyIg"
"aWQ9ImgtbWluaS1wcm9ncmVzcyI+PGRpdiBjbGFzcz0iaC1taW5pLWJhciIgaWQ9ImgtbWluaS1i"
"YXIiPjwvZGl2PjwvZGl2PgogIDxuYXYgY2xhc3M9InRhYi1uYXYiPgogICAgPGJ1dHRvbiBjbGFz"
"cz0idGFiLWJ0biBhY3RpdmUiIG9uY2xpY2s9InN3aXRjaFRhYigndGVybWluYWwnLHRoaXMpIj5U"
"ZXJtaW5hbDwvYnV0dG9uPgogICAgPGJ1dHRvbiBjbGFzcz0idGFiLWJ0biIgb25jbGljaz0ic3dp"
"dGNoVGFiKCdwb3J0cycsdGhpcykiPlBvcnRzIDxzcGFuIGNsYXNzPSJ0YWItYmFkZ2UiIGlkPSJw"
"b3J0LWJhZGdlIj4wPC9zcGFuPjwvYnV0dG9uPgogICAgPGJ1dHRvbiBjbGFzcz0idGFiLWJ0biIg"
"b25jbGljaz0ic3dpdGNoVGFiKCd0aHJlYXRzJyx0aGlzKSI+VGhyZWF0cyA8c3BhbiBjbGFzcz0i"
"dGFiLWJhZGdlIiBpZD0idGhyZWF0LWJhZGdlIj4wPC9zcGFuPjwvYnV0dG9uPgogICAgPGJ1dHRv"
"biBjbGFzcz0idGFiLWJ0biIgb25jbGljaz0ic3dpdGNoVGFiKCdyaXNrJyx0aGlzKSI+UmlzayBB"
"bmFseXNpczwvYnV0dG9uPgogICAgPGJ1dHRvbiBjbGFzcz0idGFiLWJ0biIgb25jbGljaz0ic3dp"
"dGNoVGFiKCd0Z3JhcGgnLHRoaXMpIj5UaHJlYXQgR3JhcGg8L2J1dHRvbj4KICAgIDxidXR0b24g"
"Y2xhc3M9InRhYi1idG4iIG9uY2xpY2s9InN3aXRjaFRhYignc2NhbnN0YXR1cycsdGhpcykiPlNj"
"YW4gU3RhdHVzIDxzcGFuIGNsYXNzPSJ0YWItYmFkZ2UiIGlkPSJzY2FuLXN0YXR1cy1iYWRnZSI+"
"4pePPC9zcGFuPjwvYnV0dG9uPgogICAgPGJ1dHRvbiBjbGFzcz0idGFiLWJ0biIgb25jbGljaz0i"
"c3dpdGNoVGFiKCdjaGFpbnMnLHRoaXMpIj5BdHRhY2sgQ2hhaW5zIDxzcGFuIGNsYXNzPSJ0YWIt"
"YmFkZ2UiIGlkPSJjaGFpbi1iYWRnZSI+4pePPC9zcGFuPjwvYnV0dG9uPgogIDwvbmF2PgoKICA8"
"ZGl2IGNsYXNzPSJjb250ZW50Ij4KICAgIDwhLS0gVEVSTUlOQUwgLS0+CiAgICA8ZGl2IGNsYXNz"
"PSJ0YWItcGFuZSBhY3RpdmUiIGlkPSJwYW5lLXRlcm1pbmFsIj4KICAgICAgPGRpdiBjbGFzcz0i"
"dGVybWluYWwtY2FyZCI+CiAgICAgICAgPGRpdiBjbGFzcz0idGVybS1oZWFkZXIiPgogICAgICAg"
"ICAgPGRpdiBjbGFzcz0idGVybS1kb3RzIj48c3BhbiBjbGFzcz0iZDEiPjwvc3Bhbj48c3BhbiBj"
"bGFzcz0iZDIiPjwvc3Bhbj48c3BhbiBjbGFzcz0iZDMiPjwvc3Bhbj48L2Rpdj4KICAgICAgICAg"
"IDxkaXYgY2xhc3M9InRlcm0tdGl0bGUiPkhBUlNIQSB2Ny4wIOKAlCBPVVRQVVQ8L2Rpdj4KICAg"
"ICAgICAgIDxkaXYgY2xhc3M9InRlcm0tYWN0aW9ucyI+PGJ1dHRvbiBjbGFzcz0idGVybS1hY3Qi"
"IG9uY2xpY2s9ImNvcHlPdXRwdXQoKSI+Q09QWTwvYnV0dG9uPjxidXR0b24gY2xhc3M9InRlcm0t"
"YWN0IiBvbmNsaWNrPSJjbGVhclRlcm1pbmFsKCkiPkNMRUFSPC9idXR0b24+PC9kaXY+CiAgICAg"
"ICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0ibG9hZGluZy1iYXIiIGlkPSJsb2FkaW5nLWJh"
"ciI+PC9kaXY+CiAgICAgICAgPGRpdiBpZD0idGVybWluYWwtb3V0cHV0Ij4KICAgICAgICAgIDxk"
"aXYgY2xhc3M9InRsIGhkciI+Ly8gSEFSU0hBIHY3LjAg4oCUIFdFQiArIE5FVFdPUksgKyBJTkZS"
"QVNUUlVDVFVSRSBWQVBUIFNVSVRFPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bCBwcm9t"
"cHQiPmhhcnNoYUBrYWxpOn4kIDxzcGFuIGNsYXNzPSJibGluayI+fDwvc3Bhbj48L2Rpdj4KICAg"
"ICAgICAgIDxkaXYgY2xhc3M9InRsIGluZm8iPlsgV0VCICAgICBdIFNRTCBJbmplY3Rpb24sIFhT"
"UywgV0FGLCBDT1JTLCBBZG1pbiBGaW5kZXIsIENNUywgU1NMPC9kaXY+CiAgICAgICAgICA8ZGl2"
"IGNsYXNzPSJ0bCBpbmZvIj5bIE5FVFdPUksgXSBQb3J0IFNjYW4sIFVEUCwgRmlyZXdhbGwsIFNN"
"QiwgU05NUCwgQmFubmVyLCBBUlA8L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9InRsIGluZm8i"
"PlsgSU5GUkEgICBdIFNTSCwgRlRQLCBSRFAsIERCIEV4cG9zdXJlLCBEb2NrZXIsIEs4cywgQ1ZF"
"IFNjYW48L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9InRsIHJlc3VsdCI+WyBSRUFEWSAgIF0g"
"U2VsZWN0IGEgdG9vbCBmcm9tIHNpZGViYXIgYW5kIGVudGVyIHRhcmdldCB0byBiZWdpbi48L2Rp"
"dj4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2gtZ3Jp"
"ZCBjb2xzLTQiIHN0eWxlPSJtYXJnaW4tdG9wOjIwcHgiPgogICAgICAgIDxkaXYgY2xhc3M9ImNh"
"cmQiPjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUiPlRvdGFsIFNjYW5zPC9kaXY+PGRpdiBjbGFz"
"cz0ic3RhdC1udW0gYnJhbmQiIGlkPSJzdGF0LXNjYW5zIj4wPC9kaXY+PGRpdiBjbGFzcz0ic3Rh"
"dC1iYXItd3JhcCI+PGRpdiBjbGFzcz0ic3RhdC1iYXIiPjxkaXYgY2xhc3M9InN0YXQtYmFyLWZp"
"bGwgYnJhbmQiIGlkPSJzY2FuLWJhciIgc3R5bGU9IndpZHRoOjAlIj48L2Rpdj48L2Rpdj48L2Rp"
"dj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRp"
"dGxlIj5PcGVuIFBvcnRzPC9kaXY+PGRpdiBjbGFzcz0ic3RhdC1udW0gb3JhbmdlIiBpZD0ic3Rh"
"dC1wb3J0cyI+MDwvZGl2PjxkaXYgY2xhc3M9InN0YXQtYmFyLXdyYXAiPjxkaXYgY2xhc3M9InN0"
"YXQtYmFyIj48ZGl2IGNsYXNzPSJzdGF0LWJhci1maWxsIG9yYW5nZSIgaWQ9InBvcnQtYmFyIiBz"
"dHlsZT0id2lkdGg6MCUiPjwvZGl2PjwvZGl2PjwvZGl2PjwvZGl2PgogICAgICAgIDxkaXYgY2xh"
"c3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUiPlRocmVhdHMgRm91bmQ8L2Rpdj48"
"ZGl2IGNsYXNzPSJzdGF0LW51bSByZWQiIGlkPSJzdGF0LXRocmVhdHMiPjA8L2Rpdj48ZGl2IGNs"
"YXNzPSJzdGF0LWJhci13cmFwIj48ZGl2IGNsYXNzPSJzdGF0LWJhciI+PGRpdiBjbGFzcz0ic3Rh"
"dC1iYXItZmlsbCByZWQiIGlkPSJ0aHJlYXQtYmFyIiBzdHlsZT0id2lkdGg6MCUiPjwvZGl2Pjwv"
"ZGl2PjwvZGl2PjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNh"
"cmQtc3VidGl0bGUiPkxhc3QgVG9vbDwvZGl2PjxkaXYgc3R5bGU9ImZvbnQtc2l6ZToxNHB4O2Zv"
"bnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS10eC1kYXJrKTttYXJnaW4tdG9wOjRweCIgaWQ9InN0"
"YXQtbGFzdC10b29sIj7igJQ8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LXN1YiIgaWQ9InN0YXQtbGFz"
"dC10aW1lIj5Bd2FpdGluZyBzY2FuPC9kaXY+PC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+"
"CgogICAgPCEtLSBQT1JUUyAtLT4KICAgIDxkaXYgY2xhc3M9InRhYi1wYW5lIiBpZD0icGFuZS1w"
"b3J0cyI+PGRpdiBpZD0icG9ydC1kYXNoIj48ZGl2IGNsYXNzPSJlbXB0eS1zdGF0ZSI+PGRpdiBj"
"bGFzcz0iZW1wdHktaWNvIj7wn5SNPC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktdGl0bGUiPk5vIFBv"
"cnRzIEZvdW5kIFlldDwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXN1YiI+UnVuIGEgcG9ydCBzY2Fu"
"IHRvIHBvcHVsYXRlIHRoaXMgZGFzaGJvYXJkPC9kaXY+PC9kaXY+PC9kaXY+PC9kaXY+CgogICAg"
"PCEtLSBUSFJFQVRTIC0tPgogICAgPGRpdiBjbGFzcz0idGFiLXBhbmUiIGlkPSJwYW5lLXRocmVh"
"dHMiPjxkaXYgaWQ9InRocmVhdC1kYXNoIj48ZGl2IGNsYXNzPSJlbXB0eS1zdGF0ZSI+PGRpdiBj"
"bGFzcz0iZW1wdHktaWNvIj7wn5uhPC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktdGl0bGUiPk5vIFRo"
"cmVhdHMgRGV0ZWN0ZWQ8L2Rpdj48ZGl2IGNsYXNzPSJlbXB0eS1zdWIiPlJ1biB2dWxuZXJhYmls"
"aXR5IHNjYW5zIHRvIGRpc2NvdmVyIHRocmVhdHM8L2Rpdj48L2Rpdj48L2Rpdj48L2Rpdj4KCiAg"
"ICA8IS0tIFJJU0sgQU5BTFlTSVMgLS0+CiAgICA8ZGl2IGNsYXNzPSJ0YWItcGFuZSIgaWQ9InBh"
"bmUtcmlzayI+PGRpdiBpZD0icmlzay1jb250ZW50Ij48ZGl2IGNsYXNzPSJlbXB0eS1zdGF0ZSI+"
"PGRpdiBjbGFzcz0iZW1wdHktaWNvIj7wn5OKPC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktdGl0bGUi"
"Pk5vIFJpc2sgRGF0YTwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXN1YiI+UnVuIHNjYW5zIHRvIGdl"
"bmVyYXRlIHJpc2sgYW5hbHlzaXM8L2Rpdj48L2Rpdj48L2Rpdj48L2Rpdj4KCiAgICA8IS0tIFRI"
"UkVBVCBHUkFQSCAtLT4KICAgIDxkaXYgY2xhc3M9InRhYi1wYW5lIiBpZD0icGFuZS10Z3JhcGgi"
"PjxkaXYgaWQ9InRncmFwaC1jb250ZW50Ij48ZGl2IGNsYXNzPSJlbXB0eS1zdGF0ZSI+PGRpdiBj"
"bGFzcz0iZW1wdHktaWNvIj7wn5W4PC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktdGl0bGUiPk5vIFRo"
"cmVhdCBEYXRhPC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktc3ViIj5SdW4gc2NhbnMgdG8gZ2VuZXJh"
"dGUgdGhyZWF0IGFuYWx5c2lzPC9kaXY+PC9kaXY+PC9kaXY+PC9kaXY+CgogICAgPCEtLSBTQ0FO"
"IFNUQVRVUyAtLT4KICAgIDxkaXYgY2xhc3M9InRhYi1wYW5lIiBpZD0icGFuZS1zY2Fuc3RhdHVz"
"Ij4KICAgICAgPGRpdiBpZD0ic2Nhbi1zdGF0dXMtY29udGVudCI+CiAgICAgICAgPCEtLSBMaXZl"
"IFNjYW4gQ2FyZCAtLT4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIiBpZD0ibGl2ZS1zY2FuLWNh"
"cmQiIHN0eWxlPSJtYXJnaW4tYm90dG9tOjIwcHg7Ym9yZGVyLWxlZnQ6NHB4IHNvbGlkIHZhcigt"
"LXdoaXRlLTQpIj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNhcmQtaGVhZGVyIj4KICAgICAgICAg"
"ICAgPGRpdj48ZGl2IGNsYXNzPSJjYXJkLXRpdGxlIj5DdXJyZW50IFNjYW48L2Rpdj48ZGl2IGNs"
"YXNzPSJjYXJkLXN1YnRpdGxlIiBpZD0ic3Mtc3VidGl0bGUiPk5vIGFjdGl2ZSBzY2FuPC9kaXY+"
"PC9kaXY+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9InNjYW4taW5kaWNhdG9yIiBpZD0ic2Nhbi1p"
"bmRpY2F0b3IiIHN0eWxlPSJ3aWR0aDo0MnB4O2hlaWdodDo0MnB4Ij48c3BhbiBjbGFzcz0ic2Nh"
"bi1wY3QiIGlkPSJzY2FuLXBjdC1udW0iIHN0eWxlPSJmb250LXNpemU6MTJweCI+4oCUPC9zcGFu"
"PjwvZGl2PgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZs"
"ZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoyMHB4O21hcmdpbi1ib3R0b206MTRweCI+CiAgICAg"
"ICAgICAgIDxkaXYgc3R5bGU9ImZsZXg6MSI+CiAgICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlz"
"cGxheTpmbGV4O2FsaWduLWl0ZW1zOmJhc2VsaW5lO2dhcDoxMHB4O21hcmdpbi1ib3R0b206NnB4"
"Ij4KICAgICAgICAgICAgICAgIDxkaXYgaWQ9InNjYW4tdG9vbC1uYW1lIiBzdHlsZT0iZm9udC1z"
"aXplOjE2cHg7Zm9udC13ZWlnaHQ6ODAwO2NvbG9yOnZhcigtLXR4LWRhcmspO2ZvbnQtZmFtaWx5"
"OidTeW5lJyxzYW5zLXNlcmlmIj7igJQ8L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgaWQ9InNj"
"YW4tcGhhc2UtYmFkZ2UiIHN0eWxlPSJmb250LWZhbWlseTonSUJNIFBsZXggTW9ubycsbW9ub3Nw"
"YWNlO2ZvbnQtc2l6ZTo5cHg7Zm9udC13ZWlnaHQ6NzAwO3BhZGRpbmc6M3B4IDEwcHg7Ym9yZGVy"
"LXJhZGl1czoyMHB4O2JhY2tncm91bmQ6dmFyKC0td2hpdGUtMik7Y29sb3I6dmFyKC0tdHgtbXV0"
"ZWQpO2xldHRlci1zcGFjaW5nOjFweCI+SURMRTwvZGl2PgogICAgICAgICAgICAgIDwvZGl2Pgog"
"ICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6MTZweDtmbGV4LXdyYXA6"
"d3JhcCI+CiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzY2FuLW1ldGEtaXRlbSI+PGRpdiBj"
"bGFzcz0iZG90IiBzdHlsZT0iYmFja2dyb3VuZDp2YXIoLS1yZWQpIj48L2Rpdj5UYXJnZXQ6IDxz"
"dHJvbmcgaWQ9InNjYW4tdGFyZ2V0IiBzdHlsZT0iY29sb3I6dmFyKC0tdHgtZGFyaykiPuKAlDwv"
"c3Ryb25nPjwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0ic2Nhbi1tZXRhLWl0ZW0i"
"PjxkaXYgY2xhc3M9ImRvdCIgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tc2V2LWhpZ2gpIj48L2Rp"
"dj5DYXRlZ29yeTogPHN0cm9uZyBpZD0ic2Nhbi1jYXQiIHN0eWxlPSJjb2xvcjp2YXIoLS10eC1k"
"YXJrKSI+4oCUPC9zdHJvbmc+PC9kaXY+CiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzY2Fu"
"LW1ldGEtaXRlbSI+PGRpdiBjbGFzcz0iZG90IiBzdHlsZT0iYmFja2dyb3VuZDp2YXIoLS1zZXYt"
"bG93KSI+PC9kaXY+RWxhcHNlZDogPHN0cm9uZyBpZD0ic2Nhbi1lbGFwc2VkIiBzdHlsZT0iY29s"
"b3I6dmFyKC0tdHgtZGFyaykiPjAuMHM8L3N0cm9uZz48L2Rpdj4KICAgICAgICAgICAgICA8L2Rp"
"dj4KICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDwhLS0gUHJv"
"Z3Jlc3MgQmFyIC0tPgogICAgICAgICAgPGRpdiBzdHlsZT0ibWFyZ2luLWJvdHRvbTo4cHgiPgog"
"ICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNl"
"LWJldHdlZW47bWFyZ2luLWJvdHRvbTo1cHgiPgogICAgICAgICAgICAgIDxkaXYgaWQ9InNjYW4t"
"bWVzc2FnZSIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLXR4LW11dGVkKTtmb250"
"LXN0eWxlOml0YWxpYyI+UmVhZHkg4oCUIHNlbGVjdCBhIHRvb2wgdG8gYmVnaW48L2Rpdj4KICAg"
"ICAgICAgICAgICA8ZGl2IGlkPSJzY2FuLXBjdC10ZXh0IiBzdHlsZT0iZm9udC1mYW1pbHk6J0lC"
"TSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTFweDtmb250LXdlaWdodDo3MDA7Y29s"
"b3I6dmFyKC0tdHgtZGFyaykiPjAlPC9kaXY+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAg"
"ICA8ZGl2IGNsYXNzPSJzY2FuLWJhci10cmFjayI+PGRpdiBjbGFzcz0ic2Nhbi1iYXItZmlsbC1s"
"aXZlIiBpZD0ic2Nhbi1iYXItZmlsbCIgc3R5bGU9IndpZHRoOjAlIj48L2Rpdj48L2Rpdj4KICAg"
"ICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgoKICAgICAgICA8IS0tIFN0YXRzIFJvdyAtLT4K"
"ICAgICAgICA8ZGl2IGNsYXNzPSJkYXNoLWdyaWQgY29scy00IiBzdHlsZT0ibWFyZ2luLWJvdHRv"
"bToyMHB4Ij4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtc3Vi"
"dGl0bGUiPlRvdGFsIFNjYW5zPC9kaXY+PGRpdiBjbGFzcz0ic3RhdC1udW0gYnJhbmQiIGlkPSJz"
"cy10b3RhbCI+MDwvZGl2PjwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBj"
"bGFzcz0iY2FyZC1zdWJ0aXRsZSI+UG9ydHMgRm91bmQ8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LW51"
"bSBvcmFuZ2UiIGlkPSJzcy1wb3J0cyI+MDwvZGl2PjwvZGl2PgogICAgICAgICAgPGRpdiBjbGFz"
"cz0iY2FyZCI+PGRpdiBjbGFzcz0iY2FyZC1zdWJ0aXRsZSI+VGhyZWF0cyBGb3VuZDwvZGl2Pjxk"
"aXYgY2xhc3M9InN0YXQtbnVtIHJlZCIgaWQ9InNzLXRocmVhdHMiPjA8L2Rpdj48L2Rpdj4KICAg"
"ICAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUiPkF2ZyBE"
"dXJhdGlvbjwvZGl2PjxkaXYgY2xhc3M9InN0YXQtbnVtIiBpZD0ic3MtYXZnIiBzdHlsZT0iY29s"
"b3I6dmFyKC0tdHgtZGFyaykiPjBzPC9kaXY+PC9kaXY+CiAgICAgICAgPC9kaXY+CgogICAgICAg"
"IDwhLS0gU2NhbiBIaXN0b3J5IFRhYmxlIC0tPgogICAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPgog"
"ICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZC1oZWFkZXIiPjxkaXY+PGRpdiBjbGFzcz0iY2FyZC10"
"aXRsZSI+U2NhbiBIaXN0b3J5PC9kaXY+PGRpdiBjbGFzcz0iY2FyZC1zdWJ0aXRsZSI+TGFzdCAx"
"NSBjb21wbGV0ZWQgc2NhbnM8L2Rpdj48L2Rpdj48L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9"
"InBvcnQtdGFibGUtd3JhcCI+CiAgICAgICAgICAgIDx0YWJsZSBjbGFzcz0icG9ydC10YWJsZSI+"
"CiAgICAgICAgICAgICAgPHRoZWFkPjx0cj48dGg+U3RhdHVzPC90aD48dGg+VG9vbDwvdGg+PHRo"
"PlRhcmdldDwvdGg+PHRoPkR1cmF0aW9uPC90aD48dGg+UG9ydHM8L3RoPjx0aD5UaHJlYXRzPC90"
"aD48dGg+VGltZTwvdGg+PC90cj48L3RoZWFkPgogICAgICAgICAgICAgIDx0Ym9keSBpZD0ic3Mt"
"aGlzdG9yeS10YWJsZSI+CiAgICAgICAgICAgICAgICA8dHI+PHRkIGNvbHNwYW49IjciIHN0eWxl"
"PSJ0ZXh0LWFsaWduOmNlbnRlcjtjb2xvcjp2YXIoLS10eC1mYWludCk7cGFkZGluZzozMHB4Ij5O"
"byBzY2FucyBjb21wbGV0ZWQgeWV0PC90ZD48L3RyPgogICAgICAgICAgICAgIDwvdGJvZHk+CiAg"
"ICAgICAgICAgIDwvdGFibGU+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAg"
"PC9kaXY+CiAgICA8L2Rpdj4KCiAgICA8IS0tIEFUVEFDSyBDSEFJTlMgLS0+CiAgICA8ZGl2IGNs"
"YXNzPSJ0YWItcGFuZSIgaWQ9InBhbmUtY2hhaW5zIj4KICAgICAgPGRpdiBpZD0iY2hhaW5zLWNv"
"bnRlbnQiPgogICAgICAgIDxkaXYgY2xhc3M9ImVtcHR5LXN0YXRlIj48ZGl2IGNsYXNzPSJlbXB0"
"eS1pY28iPuKbkzwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXRpdGxlIj5ObyBBdHRhY2sgQ2hhaW5z"
"IFlldDwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXN1YiI+UnVuIG11bHRpcGxlIHNjYW5zIHRvIGRp"
"c2NvdmVyIGF0dGFjayBwYXRocy4gVGhlIGVuZ2luZSBjb25uZWN0cyB2dWxuZXJhYmlsaXRpZXMg"
"aW50byBraWxsIGNoYWlucyBhdXRvbWF0aWNhbGx5LjwvZGl2PjwvZGl2PgogICAgICA8L2Rpdj4K"
"ICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJjaGF0LXBhbmVsIGNvbGxhcHNlZCIg"
"aWQ9ImNoYXQtcGFuZWwiPgogICAgPGRpdiBjbGFzcz0iY2hhdC10b2dnbGUiIG9uY2xpY2s9InRv"
"Z2dsZUNoYXQoKSI+CiAgICAgIDxkaXYgY2xhc3M9ImNoYXQtdG9nZ2xlLWxlZnQiPjxzcGFuIHN0"
"eWxlPSJjb2xvcjp2YXIoLS1yZWQpIj7il488L3NwYW4+PHNwYW4gY2xhc3M9ImNoYXQtdG9nZ2xl"
"LWxhYmVsIj5IQVJTSEEgQUkgQVNTSVNUQU5UPC9zcGFuPjxzcGFuIGNsYXNzPSJjaGF0LXRvZ2ds"
"ZS1zdGF0dXMiPuKXjyBPbmxpbmU8L3NwYW4+PC9kaXY+CiAgICAgIDxzcGFuIGNsYXNzPSJjaGF0"
"LWFycm93Ij7ilrw8L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxkaXYgaWQ9ImNoYXQtbWVzc2FnZXMi"
"PjxkaXYgY2xhc3M9Im1zZyBhaSI+PGRpdiBjbGFzcz0ibXNnLWF2YXRhciI+QUk8L2Rpdj48ZGl2"
"IGNsYXNzPSJtc2ctYm9keSI+SEFSU0hBIEFJIHY3LjAgb25saW5lLiBTZWxlY3QgYSB0b29sIGFu"
"ZCBlbnRlciBhIHRhcmdldCB0byBiZWdpbi48L2Rpdj48L2Rpdj48L2Rpdj4KICAgIDxkaXYgY2xh"
"c3M9ImNoYXQtaW5wdXQtcm93Ij4KICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJjaGF0LWlu"
"cHV0IiBjbGFzcz0iY2hhdC1pbnB1dCIgcGxhY2Vob2xkZXI9IkFzayBIQVJTSEEgQUkuLi4iIG9u"
"a2V5ZG93bj0iaWYoZXZlbnQua2V5PT09J0VudGVyJylzZW5kQ2hhdCgpIj4KICAgICAgPGJ1dHRv"
"biBjbGFzcz0iY2hhdC1zZW5kIiBvbmNsaWNrPSJzZW5kQ2hhdCgpIj5TRU5EPC9idXR0b24+CiAg"
"ICA8L2Rpdj4KICA8L2Rpdj4KPC9kaXY+CjwvZGl2PgoKPCEtLSBSRVBPUlQgTU9EQUwgLS0+Cjxk"
"aXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkiIGlkPSJyZXBvcnQtbW9kYWwiPgogIDxkaXYgY2xhc3M9"
"Im1vZGFsLWJveCI+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1oZHIiPjxkaXYgY2xhc3M9Im1vZGFs"
"LXRpdGxlIj5IQVJTSEEgdjcuMCDigJQgVkFQVCBSRVBPUlQ8L2Rpdj48YnV0dG9uIGNsYXNzPSJt"
"b2RhbC1jbG9zZSIgb25jbGljaz0iY2xvc2VSZXBvcnQoKSI+Q0xPU0U8L2J1dHRvbj48L2Rpdj4K"
"ICAgIDxkaXYgY2xhc3M9Im1vZGFsLWJvZHkiPjxkaXYgaWQ9InJwIj48L2Rpdj48L2Rpdj4KICAg"
"IDxkaXYgY2xhc3M9Im1vZGFsLWZvb3RlciI+PGJ1dHRvbiBjbGFzcz0iZGwtYnRuIHByaW1hcnki"
"IG9uY2xpY2s9ImRvd25sb2FkSFRNTCgpIj5Eb3dubG9hZCBIVE1MPC9idXR0b24+PGJ1dHRvbiBj"
"bGFzcz0iZGwtYnRuIHNlY29uZGFyeSIgb25jbGljaz0iZG93bmxvYWRUWFQoKSI+RG93bmxvYWQg"
"VFhUPC9idXR0b24+PC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPHNjcmlwdD4KLyogPT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQog"
"ICBTVEFURQogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09ICovCnZhciBzY2FuQ291bnQ9MCxjdXJyZW50QXVkaW89bnVsbCxh"
"bGxQb3J0cz1bXSxhbGxUaHJlYXRzPVtdLGxhc3RUYXJnZXQ9Jyc7CnZhciBTQz17bmV0OjAsd2Vi"
"OjAsaW5mOjAscmVjOjB9Owp2YXIgcmlza0NoYXJ0cz17fSx0aHJlYXRDaGFydHM9e307CnZhciBz"
"ZXZDb2xvcnM9e0NSSVRJQ0FMOicjZDkwNDI5JyxISUdIOicjZTg1ZDA0JyxNRURJVU06JyNlMDlm"
"M2UnLExPVzonIzJkNmE0Zid9Owp2YXIgc2V2Qmc9e0NSSVRJQ0FMOidyZ2JhKDIxNyw0LDQxLDAu"
"MSknLEhJR0g6J3JnYmEoMjMyLDkzLDQsMC4xKScsTUVESVVNOidyZ2JhKDIyNCwxNTksNjIsMC4x"
"KScsTE9XOidyZ2JhKDQ1LDEwNiw3OSwwLjEpJ307CnZhciB0YXJnZXRIaXN0b3J5PVtdOwp2YXIg"
"bGFzdFBoYXNlPSdpZGxlJzsKCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgQ0xPQ0sKICAgPT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpmdW5j"
"dGlvbiB1cGRhdGVDbG9jaygpe2RvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjbG9jaycpLnRleHRD"
"b250ZW50PW5ldyBEYXRlKCkudG9Mb2NhbGVUaW1lU3RyaW5nKCdlbi1VUycse2hvdXI6JzItZGln"
"aXQnLG1pbnV0ZTonMi1kaWdpdCcsc2Vjb25kOicyLWRpZ2l0J30pfQpzZXRJbnRlcnZhbCh1cGRh"
"dGVDbG9jaywxMDAwKTt1cGRhdGVDbG9jaygpOwoKLyogPT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBUQUJTCiAgID09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT0gKi8KZnVuY3Rpb24gc3dpdGNoVGFiKHRhYixidG4pewogIGRvY3VtZW50LnF1ZXJ5U2VsZWN0"
"b3JBbGwoJy50YWItcGFuZScpLmZvckVhY2goZnVuY3Rpb24ocCl7cC5jbGFzc0xpc3QucmVtb3Zl"
"KCdhY3RpdmUnKX0pOwogIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy50YWItYnRuJykuZm9y"
"RWFjaChmdW5jdGlvbihiKXtiLmNsYXNzTGlzdC5yZW1vdmUoJ2FjdGl2ZScpfSk7CiAgZG9jdW1l"
"bnQuZ2V0RWxlbWVudEJ5SWQoJ3BhbmUtJyt0YWIpLmNsYXNzTGlzdC5hZGQoJ2FjdGl2ZScpOwog"
"IGlmKGJ0bilidG4uY2xhc3NMaXN0LmFkZCgnYWN0aXZlJyk7CiAgaWYodGFiPT09J3Jpc2snKXNl"
"dFRpbWVvdXQocmVmcmVzaFJpc2tDaGFydHMsNjApOwogIGlmKHRhYj09PSd0Z3JhcGgnKXNldFRp"
"bWVvdXQocmVmcmVzaFRocmVhdENoYXJ0cyw2MCk7Cn0KZnVuY3Rpb24gdG9nZ2xlQ2hhdCgpe2Rv"
"Y3VtZW50LmdldEVsZW1lbnRCeUlkKCdjaGF0LXBhbmVsJykuY2xhc3NMaXN0LnRvZ2dsZSgnY29s"
"bGFwc2VkJyl9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09CiAgIFNJREVCQVIgRFJPUERPV05TCiAgID09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8K"
"ZnVuY3Rpb24gdG9nZ2xlU2VjdGlvbihoZWFkZXIpewogIGhlYWRlci5wYXJlbnRFbGVtZW50LmNs"
"YXNzTGlzdC50b2dnbGUoJ29wZW4nKTsKfQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBUT09MIFNFQVJDSCAvIEZJ"
"TFRFUgogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09ICovCmZ1bmN0aW9uIGZpbHRlclRvb2xzKHF1ZXJ5KXsKICB2YXIgcT1x"
"dWVyeS50b0xvd2VyQ2FzZSgpLnRyaW0oKTsKICB2YXIgbmF2cz1kb2N1bWVudC5xdWVyeVNlbGVj"
"dG9yQWxsKCcucy1uYXYnKTsKICB2YXIgc2VjdGlvbnM9ZG9jdW1lbnQucXVlcnlTZWxlY3RvckFs"
"bCgnLnMtc2VjdGlvbicpOwogIGlmKCFxKXsKICAgIG5hdnMuZm9yRWFjaChmdW5jdGlvbihuKXtu"
"LnN0eWxlLmRpc3BsYXk9Jyd9KTsKICAgIHNlY3Rpb25zLmZvckVhY2goZnVuY3Rpb24ocyl7CiAg"
"ICAgIHZhciBoZHI9cy5xdWVyeVNlbGVjdG9yKCcucy1zZWN0aW9uLWhlYWRlcicpOwogICAgICBp"
"ZihoZHIpaGRyLnN0eWxlLmRpc3BsYXk9Jyc7CiAgICB9KTsKICAgIHJldHVybjsKICB9CiAgc2Vj"
"dGlvbnMuZm9yRWFjaChmdW5jdGlvbihzKXtzLmNsYXNzTGlzdC5hZGQoJ29wZW4nKX0pOwogIG5h"
"dnMuZm9yRWFjaChmdW5jdGlvbihuKXsKICAgIHZhciBuYW1lPShuLmdldEF0dHJpYnV0ZSgnZGF0"
"YS1uYW1lJyl8fCcnKSsnICcrKG4udGV4dENvbnRlbnR8fCcnKTsKICAgIG4uc3R5bGUuZGlzcGxh"
"eT1uYW1lLnRvTG93ZXJDYXNlKCkuaW5kZXhPZihxKT49MD8nJzonbm9uZSc7CiAgfSk7CiAgc2Vj"
"dGlvbnMuZm9yRWFjaChmdW5jdGlvbihzKXsKICAgIHZhciBib2R5PXMucXVlcnlTZWxlY3Rvcign"
"LnMtc2VjdGlvbi1ib2R5Jyk7CiAgICBpZighYm9keSlyZXR1cm47CiAgICB2YXIgdmlzaWJsZT1i"
"b2R5LnF1ZXJ5U2VsZWN0b3JBbGwoJy5zLW5hdjpub3QoW3N0eWxlKj0iZGlzcGxheTogbm9uZSJd"
"KScpOwogICAgdmFyIGhkcj1zLnF1ZXJ5U2VsZWN0b3IoJy5zLXNlY3Rpb24taGVhZGVyJyk7CiAg"
"ICBpZihoZHIpaGRyLnN0eWxlLmRpc3BsYXk9dmlzaWJsZS5sZW5ndGg+MD8nJzonbm9uZSc7CiAg"
"fSk7Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT0KICAgVEFSR0VUIEhJU1RPUlkKICAgPT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpmdW5jdGlv"
"biBhZGRUYXJnZXRIaXN0b3J5KHQpewogIGlmKCF0fHx0YXJnZXRIaXN0b3J5LmluZGV4T2YodCk+"
"PTApcmV0dXJuOwogIHRhcmdldEhpc3RvcnkudW5zaGlmdCh0KTsKICBpZih0YXJnZXRIaXN0b3J5"
"Lmxlbmd0aD4xMCl0YXJnZXRIaXN0b3J5LnBvcCgpOwp9CmZ1bmN0aW9uIHNob3dUYXJnZXRIaXN0"
"b3J5KCl7CiAgdmFyIGJveD1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGFyZ2V0LWhpc3Rvcnkn"
"KTsKICB2YXIgaW5wPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0YXJnZXQtaW5wdXQnKS52YWx1"
"ZS50cmltKCkudG9Mb3dlckNhc2UoKTsKICBpZighdGFyZ2V0SGlzdG9yeS5sZW5ndGgpe2JveC5j"
"bGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7cmV0dXJufQogIHZhciBmaWx0ZXJlZD10YXJnZXRIaXN0"
"b3J5LmZpbHRlcihmdW5jdGlvbih0KXtyZXR1cm4gIWlucHx8dC50b0xvd2VyQ2FzZSgpLmluZGV4"
"T2YoaW5wKT49MH0pOwogIGlmKCFmaWx0ZXJlZC5sZW5ndGgpe2JveC5jbGFzc0xpc3QucmVtb3Zl"
"KCdzaG93Jyk7cmV0dXJufQogIHZhciBoPSc8ZGl2IGNsYXNzPSJoLXRoLWxhYmVsIiBzdHlsZT0i"
"cGFkZGluZzo2cHggMTRweCAycHgiPlJFQ0VOVCBUQVJHRVRTPC9kaXY+JzsKICBmaWx0ZXJlZC5m"
"b3JFYWNoKGZ1bmN0aW9uKHQpewogICAgaCs9JzxkaXYgY2xhc3M9ImgtdGgtaXRlbSIgb25jbGlj"
"az0ic2VsZWN0VGFyZ2V0KCZxdW90OycrdC5yZXBsYWNlKC8iL2csJycpKycmcXVvdDspIj4nK3Qr"
"JzwvZGl2Pic7CiAgfSk7CiAgYm94LmlubmVySFRNTD1oO2JveC5jbGFzc0xpc3QuYWRkKCdzaG93"
"Jyk7Cn0KZnVuY3Rpb24gc2VsZWN0VGFyZ2V0KHQpewogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlk"
"KCd0YXJnZXQtaW5wdXQnKS52YWx1ZT10OwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0YXJn"
"ZXQtaGlzdG9yeScpLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKfQpkb2N1bWVudC5hZGRFdmVu"
"dExpc3RlbmVyKCdjbGljaycsZnVuY3Rpb24oZSl7CiAgaWYoIWUudGFyZ2V0LmNsb3Nlc3QoJy5o"
"LXRhcmdldCcpKXt2YXIgZWw9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RhcmdldC1oaXN0b3J5"
"Jyk7aWYoZWwpZWwuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpfQp9KTsKCi8qID09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAg"
"VVRJTFMKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PSAqLwpmdW5jdGlvbiBwbGF5Vm9pY2UoKXtpZihjdXJyZW50QXVkaW8p"
"Y3VycmVudEF1ZGlvLnBhdXNlKCk7Y3VycmVudEF1ZGlvPW5ldyBBdWRpbygnL3ZvaWNlP3Q9JytE"
"YXRlLm5vdygpKTtjdXJyZW50QXVkaW8ucGxheSgpLmNhdGNoKGZ1bmN0aW9uKCl7fSl9CmZ1bmN0"
"aW9uIG5vdGlmeShtc2cpe3ZhciBlbD1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTtlbC5j"
"bGFzc05hbWU9J25vdGlmJztlbC50ZXh0Q29udGVudD1tc2c7ZG9jdW1lbnQuYm9keS5hcHBlbmRD"
"aGlsZChlbCk7c2V0VGltZW91dChmdW5jdGlvbigpe2VsLnJlbW92ZSgpfSwzNTAwKX0KCnZhciB0"
"ZXJtaW5hbD1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGVybWluYWwtb3V0cHV0Jyk7CmZ1bmN0"
"aW9uIHRlcm1MaW5lKHQsYyl7aWYoIWMpYz0ncmVzdWx0JzsodCsnJykuc3BsaXQoJ1xuJykuZm9y"
"RWFjaChmdW5jdGlvbihsKXtpZighbC50cmltKCkpcmV0dXJuO3ZhciBkPWRvY3VtZW50LmNyZWF0"
"ZUVsZW1lbnQoJ2RpdicpO2QuY2xhc3NOYW1lPSd0bCAnK2M7ZC50ZXh0Q29udGVudD1sO3Rlcm1p"
"bmFsLmFwcGVuZENoaWxkKGQpfSk7dGVybWluYWwuc2Nyb2xsVG9wPXRlcm1pbmFsLnNjcm9sbEhl"
"aWdodH0KZnVuY3Rpb24gY2xlYXJUZXJtaW5hbCgpe3Rlcm1pbmFsLmlubmVySFRNTD0nPGRpdiBj"
"bGFzcz0idGwgaGRyIj4vLyBDTEVBUkVEIOKAlCBIQVJTSEEgQUkgdjcuMDwvZGl2Pid9CmZ1bmN0"
"aW9uIGNvcHlPdXRwdXQoKXtuYXZpZ2F0b3IuY2xpcGJvYXJkLndyaXRlVGV4dCh0ZXJtaW5hbC5p"
"bm5lclRleHQpLnRoZW4oZnVuY3Rpb24oKXtub3RpZnkoJ0NvcGllZCEnKX0pfQpmdW5jdGlvbiBz"
"ZXRMb2FkaW5nKG9uKXtkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbG9hZGluZy1iYXInKS5zdHls"
"ZS5kaXNwbGF5PW9uPydibG9jayc6J25vbmUnfQoKZnVuY3Rpb24gdXBkYXRlU3RhdHMoKXsKICBk"
"b2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3RhdC1zY2FucycpLnRleHRDb250ZW50PXNjYW5Db3Vu"
"dDsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3RhdC1wb3J0cycpLnRleHRDb250ZW50PWFs"
"bFBvcnRzLmxlbmd0aDsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3RhdC10aHJlYXRzJyku"
"dGV4dENvbnRlbnQ9YWxsVGhyZWF0cy5sZW5ndGg7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQo"
"J3NjYW4tYmFyJykuc3R5bGUud2lkdGg9TWF0aC5taW4oMTAwLHNjYW5Db3VudCoxMCkrJyUnOwog"
"IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwb3J0LWJhcicpLnN0eWxlLndpZHRoPU1hdGgubWlu"
"KDEwMCxhbGxQb3J0cy5sZW5ndGgqNSkrJyUnOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0"
"aHJlYXQtYmFyJykuc3R5bGUud2lkdGg9TWF0aC5taW4oMTAwLGFsbFRocmVhdHMubGVuZ3RoKjEw"
"KSsnJSc7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2htLXNjYW5zJykudGV4dENvbnRlbnQ9"
"c2NhbkNvdW50OwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdobS1wb3J0cycpLnRleHRDb250"
"ZW50PWFsbFBvcnRzLmxlbmd0aDsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnaG0tdGhyZWF0"
"cycpLnRleHRDb250ZW50PWFsbFRocmVhdHMubGVuZ3RoOwp9CgovKiA9PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIFBPUlQg"
"REFTSEJPQVJECiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT0gKi8KZnVuY3Rpb24gdXBkYXRlUG9ydERhc2gocG9ydHMsdGFy"
"Z2V0KXsKICBpZighcG9ydHN8fCFwb3J0cy5sZW5ndGgpcmV0dXJuOwogIHBvcnRzLmZvckVhY2go"
"ZnVuY3Rpb24ocCl7aWYoIWFsbFBvcnRzLmZpbmQoZnVuY3Rpb24oeCl7cmV0dXJuIHgucG9ydD09"
"PXAucG9ydCYmeC5wcm90bz09PXAucHJvdG99KSlhbGxQb3J0cy5wdXNoKHApfSk7CiAgdmFyIHRv"
"dGFsPWFsbFBvcnRzLmxlbmd0aCxjcml0PTAsaGlnaD0wLG1lZD0wLGxvdz0wOwogIGFsbFBvcnRz"
"LmZvckVhY2goZnVuY3Rpb24ocCl7aWYocC5zZXZlcml0eT09PSdDUklUSUNBTCcpY3JpdCsrO2Vs"
"c2UgaWYocC5zZXZlcml0eT09PSdISUdIJyloaWdoKys7ZWxzZSBpZihwLnNldmVyaXR5PT09J01F"
"RElVTScpbWVkKys7ZWxzZSBsb3crK30pOwogIHZhciBiYWRnZT1kb2N1bWVudC5nZXRFbGVtZW50"
"QnlJZCgncG9ydC1iYWRnZScpO2JhZGdlLmNsYXNzTGlzdC5hZGQoJ3Nob3cnLCdiLW9yYW5nZScp"
"O2JhZGdlLnRleHRDb250ZW50PXRvdGFsOwogIHZhciBzb3J0ZWQ9YWxsUG9ydHMuc2xpY2UoKS5z"
"b3J0KGZ1bmN0aW9uKGEsYil7dmFyIG89e0NSSVRJQ0FMOjAsSElHSDoxLE1FRElVTToyLExPVzoz"
"fTtyZXR1cm4ob1thLnNldmVyaXR5XXx8MyktKG9bYi5zZXZlcml0eV18fDMpfHxhLnBvcnQtYi5w"
"b3J0fSk7CiAgdmFyIGg9JzxkaXYgY2xhc3M9ImRhc2gtZ3JpZCBjb2xzLTQiIHN0eWxlPSJtYXJn"
"aW4tYm90dG9tOjIwcHgiPic7CiAgaCs9JzxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNh"
"cmQtc3VidGl0bGUiPkNyaXRpY2FsPC9kaXY+PGRpdiBjbGFzcz0ic3RhdC1udW0gcmVkIj4nK2Ny"
"aXQrJzwvZGl2PjxkaXYgY2xhc3M9InN0YXQtYmFyLXdyYXAiPjxkaXYgY2xhc3M9InN0YXQtYmFy"
"Ij48ZGl2IGNsYXNzPSJzdGF0LWJhci1maWxsIHJlZCIgc3R5bGU9IndpZHRoOicrTWF0aC5taW4o"
"MTAwLGNyaXQqMjUpKyclIj48L2Rpdj48L2Rpdj48L2Rpdj48L2Rpdj4nOwogIGgrPSc8ZGl2IGNs"
"YXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxlIj5IaWdoPC9kaXY+PGRpdiBjbGFz"
"cz0ic3RhdC1udW0gb3JhbmdlIj4nK2hpZ2grJzwvZGl2PjxkaXYgY2xhc3M9InN0YXQtYmFyLXdy"
"YXAiPjxkaXYgY2xhc3M9InN0YXQtYmFyIj48ZGl2IGNsYXNzPSJzdGF0LWJhci1maWxsIG9yYW5n"
"ZSIgc3R5bGU9IndpZHRoOicrTWF0aC5taW4oMTAwLGhpZ2gqMTgpKyclIj48L2Rpdj48L2Rpdj48"
"L2Rpdj48L2Rpdj4nOwogIGgrPSc8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1"
"YnRpdGxlIj5NZWRpdW08L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LW51bSB5ZWxsb3ciPicrbWVkKyc8"
"L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LWJhci13cmFwIj48ZGl2IGNsYXNzPSJzdGF0LWJhciI+PGRp"
"diBjbGFzcz0ic3RhdC1iYXItZmlsbCB5ZWxsb3ciIHN0eWxlPSJ3aWR0aDonK01hdGgubWluKDEw"
"MCxtZWQqMTgpKyclIj48L2Rpdj48L2Rpdj48L2Rpdj48L2Rpdj4nOwogIGgrPSc8ZGl2IGNsYXNz"
"PSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxlIj5Mb3c8L2Rpdj48ZGl2IGNsYXNzPSJz"
"dGF0LW51bSBncmVlbiI+Jytsb3crJzwvZGl2PjxkaXYgY2xhc3M9InN0YXQtYmFyLXdyYXAiPjxk"
"aXYgY2xhc3M9InN0YXQtYmFyIj48ZGl2IGNsYXNzPSJzdGF0LWJhci1maWxsIGdyZWVuIiBzdHls"
"ZT0id2lkdGg6JytNYXRoLm1pbigxMDAsbG93KjE4KSsnJSI+PC9kaXY+PC9kaXY+PC9kaXY+PC9k"
"aXY+JzsKICBoKz0nPC9kaXY+JzsKICBoKz0nPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0i"
"Y2FyZC1oZWFkZXIiPjxkaXY+PGRpdiBjbGFzcz0iY2FyZC10aXRsZSI+T3BlbiBQb3J0cyDigJQg"
"JysodGFyZ2V0fHxsYXN0VGFyZ2V0fHwnPycpKyc8L2Rpdj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRp"
"dGxlIj4nK3RvdGFsKycgcG9ydHM8L2Rpdj48L2Rpdj48L2Rpdj4nOwogIGgrPSc8ZGl2IGNsYXNz"
"PSJwb3J0LXRhYmxlLXdyYXAiPjx0YWJsZSBjbGFzcz0icG9ydC10YWJsZSI+PHRoZWFkPjx0cj48"
"dGg+UG9ydDwvdGg+PHRoPlNlcnZpY2U8L3RoPjx0aD5SaXNrPC90aD48dGg+RGVzY3JpcHRpb248"
"L3RoPjx0aD5SZW1lZGlhdGlvbjwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT4nOwogIHNvcnRlZC5m"
"b3JFYWNoKGZ1bmN0aW9uKHApewogICAgaCs9Jzx0cj48dGQ+PHNwYW4gY2xhc3M9InAtbnVtIj4n"
"K3AucG9ydCsnPC9zcGFuPjxkaXYgY2xhc3M9InAtcHJvdG8iPicrcC5wcm90by50b1VwcGVyQ2Fz"
"ZSgpKyc8L2Rpdj48L3RkPic7CiAgICBoKz0nPHRkPjxzcGFuIGNsYXNzPSJwLXN2YyI+JytwLnNl"
"cnZpY2UrJzwvc3Bhbj4nKyhwLnZlcnNpb24/JzxkaXYgY2xhc3M9InAtdmVyIj4nK3AudmVyc2lv"
"bi5zdWJzdHJpbmcoMCwzNSkrJzwvZGl2Pic6JycpKyc8L3RkPic7CiAgICBoKz0nPHRkPjxzcGFu"
"IGNsYXNzPSJzZXYgJytwLnNldmVyaXR5KyciPicrcC5zZXZlcml0eSsnPC9zcGFuPjwvdGQ+JzsK"
"ICAgIGgrPSc8dGQgY2xhc3M9InAtZGVzYyI+JytwLmRlc2MrJzwvdGQ+PHRkIGNsYXNzPSJwLWZp"
"eCI+JytwLmZpeCsnPC90ZD48L3RyPic7CiAgfSk7CiAgaCs9JzwvdGJvZHk+PC90YWJsZT48L2Rp"
"dj48L2Rpdj4nOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwb3J0LWRhc2gnKS5pbm5lckhU"
"TUw9aDt1cGRhdGVTdGF0cygpOwp9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIFRIUkVBVCBEQVNIQk9BUkQKICAg"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PSAqLwpmdW5jdGlvbiB1cGRhdGVUaHJlYXREYXNoKHRocmVhdHMpewogIGlmKCF0aHJl"
"YXRzfHwhdGhyZWF0cy5sZW5ndGgpcmV0dXJuOwogIHRocmVhdHMuZm9yRWFjaChmdW5jdGlvbih0"
"KXtpZighYWxsVGhyZWF0cy5maW5kKGZ1bmN0aW9uKHgpe3JldHVybiB4Lm5hbWU9PT10Lm5hbWV9"
"KSlhbGxUaHJlYXRzLnB1c2godCl9KTsKICB2YXIgYmFkZ2U9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5"
"SWQoJ3RocmVhdC1iYWRnZScpO2JhZGdlLmNsYXNzTGlzdC5hZGQoJ3Nob3cnLCdiLXJlZCcpO2Jh"
"ZGdlLnRleHRDb250ZW50PWFsbFRocmVhdHMubGVuZ3RoOwogIHZhciBoPSc8ZGl2IGNsYXNzPSJk"
"YXNoLWdyaWQgY29scy0xIiBzdHlsZT0iZ2FwOjE0cHgiPic7CiAgYWxsVGhyZWF0cy5mb3JFYWNo"
"KGZ1bmN0aW9uKHQsaSl7CiAgICBoKz0nPGRpdiBjbGFzcz0idGhyZWF0LWNhcmQgJyt0LnNldmVy"
"aXR5KyciIHN0eWxlPSJhbmltYXRpb24tZGVsYXk6JysoaSowLjA1KSsncyI+PGRpdiBjbGFzcz0i"
"dGMtaGRyIj48ZGl2IGNsYXNzPSJ0Yy1uYW1lIj4nK3QubmFtZSsnPC9kaXY+PHNwYW4gY2xhc3M9"
"InNldiAnK3Quc2V2ZXJpdHkrJyI+Jyt0LnNldmVyaXR5Kyc8L3NwYW4+PC9kaXY+JzsKICAgIGgr"
"PSc8ZGl2IGNsYXNzPSJ0Yy1kZXNjIj4nK3QuZGVzYysnPC9kaXY+JzsKICAgIGgrPSc8ZGl2IGNs"
"YXNzPSJ0Yy1maXgiPjxkaXYgY2xhc3M9InRjLWZpeC1sYWJlbCI+UkVNRURJQVRJT048L2Rpdj48"
"ZGl2IGNsYXNzPSJ0Yy1maXgtdGV4dCI+Jyt0LmZpeCsnPC9kaXY+PC9kaXY+PC9kaXY+JzsKICB9"
"KTsKICBoKz0nPC9kaXY+JzsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGhyZWF0LWRhc2gn"
"KS5pbm5lckhUTUw9aDt1cGRhdGVTdGF0cygpOwp9CgovKiA9PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIFJVTiBUT09MIChp"
"bnRlZ3JhdGVkIHdpdGggdGFyZ2V0IGhpc3RvcnkpCiAgID09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KZnVuY3Rpb24gcnVu"
"VG9vbCh0b29sLGJ0bixjYXQpewogIHZhciB0YXJnZXQ9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQo"
"J3RhcmdldC1pbnB1dCcpLnZhbHVlLnRyaW0oKTsKICB2YXIgbm9UPVsnbmV0d29ya19zY2FuJywn"
"bXlfaXAnLCdzeXN0ZW1faW5mbycsJ3dlYXRoZXInLCdhcnBfc2NhbiddOwogIHZhciBuZWVkPXRy"
"dWU7Zm9yKHZhciBpPTA7aTxub1QubGVuZ3RoO2krKyl7aWYobm9UW2ldPT09dG9vbCl7bmVlZD1m"
"YWxzZTticmVha319CiAgaWYobmVlZCYmIXRhcmdldCl7bm90aWZ5KCdFbnRlciBhIHRhcmdldCBm"
"aXJzdC4nKTt0ZXJtTGluZSgnUGxlYXNlIGVudGVyIGEgdGFyZ2V0LicsJ2Vycm9yJyk7cmV0dXJu"
"fQogIGlmKHRhcmdldCl7bGFzdFRhcmdldD10YXJnZXQ7YWRkVGFyZ2V0SGlzdG9yeSh0YXJnZXQp"
"fQogIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy5zLW5hdicpLmZvckVhY2goZnVuY3Rpb24o"
"Yil7Yi5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKX0pOwogIGlmKGJ0bilidG4uY2xhc3NMaXN0"
"LmFkZCgnYWN0aXZlJyk7CiAgc2V0TG9hZGluZyh0cnVlKTsKICBzd2l0Y2hUYWIoJ3Rlcm1pbmFs"
"Jyxkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcudGFiLWJ0bicpWzBdKTsKICB0ZXJtTGluZSgn"
"JywnaGRyJyk7CiAgdGVybUxpbmUoJ+KAlCBbJytjYXQudG9VcHBlckNhc2UoKSsnXSAnK3Rvb2wu"
"dG9VcHBlckNhc2UoKSsodGFyZ2V0Pycg4oaSICcrdGFyZ2V0OicnKSsnIOKAlCcsJ2hkcicpOwog"
"IHRlcm1MaW5lKCdoYXJzaGFAa2FsaTp+JCAnK3Rvb2wrKHRhcmdldD8nICcrdGFyZ2V0OicnKSsn"
"Li4uJywncHJvbXB0Jyk7CiAgdmFyIHQwPURhdGUubm93KCk7CiAgZmV0Y2goJy9zY2FuJyx7bWV0"
"aG9kOidQT1NUJyxoZWFkZXJzOnsnQ29udGVudC1UeXBlJzonYXBwbGljYXRpb24vanNvbid9LGJv"
"ZHk6SlNPTi5zdHJpbmdpZnkoe3Rvb2w6dG9vbCx0YXJnZXQ6dGFyZ2V0fSl9KQogIC50aGVuKGZ1"
"bmN0aW9uKHIpe3JldHVybiByLmpzb24oKX0pCiAgLnRoZW4oZnVuY3Rpb24oZGF0YSl7CiAgICB2"
"YXIgZWw9KChEYXRlLm5vdygpLXQwKS8xMDAwKS50b0ZpeGVkKDEpOwogICAgdGVybUxpbmUoZGF0"
"YS5vdXRwdXR8fGRhdGEuZXJyb3J8fCdObyBvdXRwdXQuJyxkYXRhLmVycm9yPydlcnJvcic6J3Jl"
"c3VsdCcpOwogICAgdGVybUxpbmUoJ0NvbXBsZXRlZCBpbiAnK2VsKydzIOKAlCAnKyhkYXRhLnRp"
"bWVzdGFtcHx8JycpLCdpbmZvJyk7CiAgICBzY2FuQ291bnQrKztTQ1tjYXRdPShTQ1tjYXRdfHww"
"KSsxOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N0YXQtbGFzdC10b29sJykudGV4dENv"
"bnRlbnQ9dG9vbC50b1VwcGVyQ2FzZSgpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N0"
"YXQtbGFzdC10aW1lJykudGV4dENvbnRlbnQ9ZWwrJ3MgwrcgJytuZXcgRGF0ZSgpLnRvTG9jYWxl"
"VGltZVN0cmluZygpOwogICAgdXBkYXRlU3RhdHMoKTsKICAgIGlmKGRhdGEucG9ydHMmJmRhdGEu"
"cG9ydHMubGVuZ3RoKXt1cGRhdGVQb3J0RGFzaChkYXRhLnBvcnRzLHRhcmdldCk7dGVybUxpbmUo"
"ZGF0YS5wb3J0cy5sZW5ndGgrJyBwb3J0cyDigJQgY2hlY2sgUG9ydHMgdGFiJywnaW5mbycpO25v"
"dGlmeShkYXRhLnBvcnRzLmxlbmd0aCsnIHBvcnRzIGZvdW5kIScpfQogICAgaWYoZGF0YS50aHJl"
"YXRzJiZkYXRhLnRocmVhdHMubGVuZ3RoKXt1cGRhdGVUaHJlYXREYXNoKGRhdGEudGhyZWF0cyk7"
"dGVybUxpbmUoZGF0YS50aHJlYXRzLmxlbmd0aCsnIHRocmVhdHMg4oCUIGNoZWNrIFRocmVhdHMg"
"dGFiJywnZXJyb3InKTtub3RpZnkoZGF0YS50aHJlYXRzLmxlbmd0aCsnIHRocmVhdHMgZGV0ZWN0"
"ZWQhJyl9CiAgICBpZihkYXRhLmhhc192b2ljZSlwbGF5Vm9pY2UoKTsKICB9KQogIC5jYXRjaChm"
"dW5jdGlvbihlKXt0ZXJtTGluZSgnRXJyb3I6ICcrZS5tZXNzYWdlLCdlcnJvcicpfSkKICAuZmlu"
"YWxseShmdW5jdGlvbigpe3NldExvYWRpbmcoZmFsc2UpfSk7Cn0KCi8qID09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgQ0hB"
"VAogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09ICovCmZ1bmN0aW9uIHNlbmRDaGF0KCl7CiAgdmFyIGlucD1kb2N1bWVudC5n"
"ZXRFbGVtZW50QnlJZCgnY2hhdC1pbnB1dCcpO3ZhciBtc2c9aW5wLnZhbHVlLnRyaW0oKTtpZigh"
"bXNnKXJldHVybjtpbnAudmFsdWU9Jyc7CiAgdmFyIGJveD1kb2N1bWVudC5nZXRFbGVtZW50QnlJ"
"ZCgnY2hhdC1tZXNzYWdlcycpOwogIHZhciB1PWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2Rpdicp"
"O3UuY2xhc3NOYW1lPSdtc2cgdXNlcic7dS5pbm5lckhUTUw9JzxkaXYgY2xhc3M9Im1zZy1hdmF0"
"YXIiPllPVTwvZGl2PjxkaXYgY2xhc3M9Im1zZy1ib2R5Ij4nK21zZy5yZXBsYWNlKC88L2csJyZs"
"dDsnKS5yZXBsYWNlKC8+L2csJyZndDsnKSsnPC9kaXY+JzsKICBib3guYXBwZW5kQ2hpbGQodSk7"
"Ym94LnNjcm9sbFRvcD1ib3guc2Nyb2xsSGVpZ2h0OwogIGZldGNoKCcvY2hhdCcse21ldGhvZDon"
"UE9TVCcsaGVhZGVyczp7J0NvbnRlbnQtVHlwZSc6J2FwcGxpY2F0aW9uL2pzb24nfSxib2R5OkpT"
"T04uc3RyaW5naWZ5KHttZXNzYWdlOm1zZ30pfSkKICAudGhlbihmdW5jdGlvbihyKXtyZXR1cm4g"
"ci5qc29uKCl9KQogIC50aGVuKGZ1bmN0aW9uKGQpe3ZhciBhPWRvY3VtZW50LmNyZWF0ZUVsZW1l"
"bnQoJ2RpdicpO2EuY2xhc3NOYW1lPSdtc2cgYWknO2EuaW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJt"
"c2ctYXZhdGFyIj5BSTwvZGl2PjxkaXYgY2xhc3M9Im1zZy1ib2R5Ij4nK2QucmVzcG9uc2UrJzwv"
"ZGl2Pic7Ym94LmFwcGVuZENoaWxkKGEpO2JveC5zY3JvbGxUb3A9Ym94LnNjcm9sbEhlaWdodDtp"
"ZihkLmhhc192b2ljZSlwbGF5Vm9pY2UoKX0pCiAgLmNhdGNoKGZ1bmN0aW9uKCl7dmFyIGU9ZG9j"
"dW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7ZS5jbGFzc05hbWU9J21zZyBhaSc7ZS5pbm5lckhU"
"TUw9JzxkaXYgY2xhc3M9Im1zZy1hdmF0YXIiPkFJPC9kaXY+PGRpdiBjbGFzcz0ibXNnLWJvZHki"
"IHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQtbGlnaHQpIj5Db25uZWN0aW9uIGVycm9yLjwvZGl2Pic7"
"Ym94LmFwcGVuZENoaWxkKGUpfSk7Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgUkVQT1JUCiAgID09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0g"
"Ki8KZnVuY3Rpb24gb3BlblJlcG9ydCgpewogIHZhciBub3c9bmV3IERhdGUoKS50b0xvY2FsZVN0"
"cmluZygpOwogIHZhciBzb3J0ZWQ9YWxsUG9ydHMuc2xpY2UoKS5zb3J0KGZ1bmN0aW9uKGEsYil7"
"dmFyIG89e0NSSVRJQ0FMOjAsSElHSDoxLE1FRElVTToyLExPVzozfTtyZXR1cm4ob1thLnNldmVy"
"aXR5XXx8MyktKG9bYi5zZXZlcml0eV18fDMpfHxhLnBvcnQtYi5wb3J0fSk7CiAgdmFyIGg9Jzxk"
"aXYgY2xhc3M9InJwLWhkciI+PGRpdiBjbGFzcz0icnAtdCI+SEFSU0hBIHY3LjAgVkFQVCBSRVBP"
"UlQ8L2Rpdj48ZGl2IGNsYXNzPSJycC1zIj5XZWIgKyBOZXR3b3JrICsgSW5mcmFzdHJ1Y3R1cmUg"
"VkFQVCBTdWl0ZTwvZGl2PjxkaXYgc3R5bGU9Im1hcmdpbi10b3A6NXB4O2ZvbnQtc2l6ZToxMHB4"
"O2NvbG9yOnZhcigtLXR4LWZhaW50KSI+QW5hbHlzdDogSEFSU0hBIHwgVGFyZ2V0OiAnKyhsYXN0"
"VGFyZ2V0fHwnTXVsdGlwbGUnKSsnIHwgJytub3crJzwvZGl2PjwvZGl2Pic7CiAgaCs9JzxkaXYg"
"Y2xhc3M9InJwLXNlYyI+PGRpdiBjbGFzcz0icnAtc3QiPkVYRUNVVElWRSBTVU1NQVJZPC9kaXY+"
"PGRpdiBzdHlsZT0iZm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpIj5TY2Fuczog"
"JytzY2FuQ291bnQrJyDCtyBQb3J0czogJythbGxQb3J0cy5sZW5ndGgrJyDCtyBUaHJlYXRzOiAn"
"K2FsbFRocmVhdHMubGVuZ3RoKyc8L2Rpdj48L2Rpdj4nOwogIGlmKHNvcnRlZC5sZW5ndGgpe2gr"
"PSc8ZGl2IGNsYXNzPSJycC1zZWMiPjxkaXYgY2xhc3M9InJwLXN0Ij5PUEVOIFBPUlRTICgnK3Nv"
"cnRlZC5sZW5ndGgrJyk8L2Rpdj4nO3NvcnRlZC5mb3JFYWNoKGZ1bmN0aW9uKHApe2grPSc8ZGl2"
"IGNsYXNzPSJycC1wciI+PGRpdj48c3BhbiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKTtmb250LXdl"
"aWdodDpib2xkIj4nK3AucG9ydCsnLycrcC5wcm90bysnPC9zcGFuPjwvZGl2PjxkaXYgc3R5bGU9"
"ImNvbG9yOnZhcigtLXR4LWRhcmspO2ZvbnQtd2VpZ2h0OjYwMCI+JytwLnNlcnZpY2UrJzwvZGl2"
"PjxkaXY+PHNwYW4gY2xhc3M9InNldiAnK3Auc2V2ZXJpdHkrJyI+JytwLnNldmVyaXR5Kyc8L3Nw"
"YW4+PC9kaXY+PGRpdiBzdHlsZT0iY29sb3I6dmFyKC0tdHgtbXV0ZWQpO2ZvbnQtc2l6ZToxMHB4"
"Ij4nK3AuZGVzYysnPC9kaXY+PC9kaXY+J30pO2grPSc8L2Rpdj4nfQogIGlmKGFsbFRocmVhdHMu"
"bGVuZ3RoKXtoKz0nPGRpdiBjbGFzcz0icnAtc2VjIj48ZGl2IGNsYXNzPSJycC1zdCI+VlVMTkVS"
"QUJJTElUSUVTICgnK2FsbFRocmVhdHMubGVuZ3RoKycpPC9kaXY+JzthbGxUaHJlYXRzLmZvckVh"
"Y2goZnVuY3Rpb24odCxpKXtoKz0nPGRpdiBjbGFzcz0icnAtdGggJyt0LnNldmVyaXR5KyciPjxk"
"aXYgY2xhc3M9InJwLXRuIj4nKyhpKzEpKycuICcrdC5uYW1lKycgPHNwYW4gY2xhc3M9InNldiAn"
"K3Quc2V2ZXJpdHkrJyI+Jyt0LnNldmVyaXR5Kyc8L3NwYW4+PC9kaXY+PGRpdiBjbGFzcz0icnAt"
"dGQiPicrdC5kZXNjKyc8L2Rpdj48ZGl2IGNsYXNzPSJycC10ZiI+RklYOiAnK3QuZml4Kyc8L2Rp"
"dj48L2Rpdj4nfSk7aCs9JzwvZGl2Pid9CiAgaWYoIXNvcnRlZC5sZW5ndGgmJiFhbGxUaHJlYXRz"
"Lmxlbmd0aCloKz0nPGRpdiBzdHlsZT0iY29sb3I6dmFyKC0tc2V2LWxvdyk7cGFkZGluZzoxNnB4"
"IDAiPk5vIGRhdGEgeWV0LiBSdW4gc2NhbnMgZmlyc3QuPC9kaXY+JzsKICBkb2N1bWVudC5nZXRF"
"bGVtZW50QnlJZCgncnAnKS5pbm5lckhUTUw9aDtkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncmVw"
"b3J0LW1vZGFsJykuY2xhc3NMaXN0LmFkZCgnb3BlbicpOwp9CmZ1bmN0aW9uIGNsb3NlUmVwb3J0"
"KCl7ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3JlcG9ydC1tb2RhbCcpLmNsYXNzTGlzdC5yZW1v"
"dmUoJ29wZW4nKX0KCmZ1bmN0aW9uIGRvd25sb2FkSFRNTCgpewogIHZhciBub3c9bmV3IERhdGUo"
"KS50b0xvY2FsZVN0cmluZygpO3ZhciBzb3J0ZWQ9YWxsUG9ydHMuc2xpY2UoKS5zb3J0KGZ1bmN0"
"aW9uKGEsYil7dmFyIG89e0NSSVRJQ0FMOjAsSElHSDoxLE1FRElVTToyLExPVzozfTtyZXR1cm4o"
"b1thLnNldmVyaXR5XXx8MyktKG9bYi5zZXZlcml0eV18fDMpfHxhLnBvcnQtYi5wb3J0fSk7CiAg"
"dmFyIGI9JzwhRE9DVFlQRSBodG1sPjxodG1sPjxoZWFkPjxtZXRhIGNoYXJzZXQ9IlVURi04Ij48"
"dGl0bGU+SEFSU0hBIHY3LjA8L3RpdGxlPjxzdHlsZT5ib2R5e2ZvbnQtZmFtaWx5Om1vbm9zcGFj"
"ZTtiYWNrZ3JvdW5kOiNmZmY7Y29sb3I6IzNhM2E0NDtwYWRkaW5nOjMwcHg7bWF4LXdpZHRoOjEx"
"MDBweDttYXJnaW46YXV0b31oMXtjb2xvcjojZTYzOTQ2O3RleHQtYWxpZ246Y2VudGVyfWgye2Nv"
"bG9yOiNlNjM5NDY7Zm9udC1zaXplOjEycHg7bWFyZ2luLXRvcDoxOHB4fXRhYmxle3dpZHRoOjEw"
"MCU7Ym9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlfXRoLHRke3BhZGRpbmc6NXB4O2JvcmRlci1ib3R0"
"b206MXB4IHNvbGlkICNlY2VjZWY7Zm9udC1zaXplOjEwcHg7dGV4dC1hbGlnbjpsZWZ0fS5jYXJk"
"e2JvcmRlci1sZWZ0OjRweCBzb2xpZCAjZDkwNDI5O3BhZGRpbmc6OHB4IDEycHg7bWFyZ2luOjVw"
"eCAwO2JhY2tncm91bmQ6I2Y3ZjdmODtib3JkZXItcmFkaXVzOjZweH08L3N0eWxlPjwvaGVhZD48"
"Ym9keT4nOwogIGIrPSc8aDE+SEFSU0hBIHY3LjAgVkFQVCBSRVBPUlQ8L2gxPjxwIHN0eWxlPSJ0"
"ZXh0LWFsaWduOmNlbnRlcjtjb2xvcjojYjBiMGJhIj4nK25vdysnPC9wPic7CiAgaWYoc29ydGVk"
"Lmxlbmd0aCl7Yis9JzxoMj5PUEVOIFBPUlRTPC9oMj48dGFibGU+PHRyPjx0aD5QT1JUPC90aD48"
"dGg+U0VSVklDRTwvdGg+PHRoPlJJU0s8L3RoPjx0aD5ERVNDPC90aD48L3RyPic7c29ydGVkLmZv"
"ckVhY2goZnVuY3Rpb24ocCl7Yis9Jzx0cj48dGQ+JytwLnBvcnQrJy8nK3AucHJvdG8rJzwvdGQ+"
"PHRkPicrcC5zZXJ2aWNlKyc8L3RkPjx0ZD4nK3Auc2V2ZXJpdHkrJzwvdGQ+PHRkPicrcC5kZXNj"
"Kyc8L3RkPjwvdHI+J30pO2IrPSc8L3RhYmxlPid9CiAgaWYoYWxsVGhyZWF0cy5sZW5ndGgpe2Ir"
"PSc8aDI+VlVMTkVSQUJJTElUSUVTPC9oMj4nO2FsbFRocmVhdHMuZm9yRWFjaChmdW5jdGlvbih0"
"LGkpe2IrPSc8ZGl2IGNsYXNzPSJjYXJkIj48Yj4nKyhpKzEpKycuICcrdC5uYW1lKyc8L2I+IFsn"
"K3Quc2V2ZXJpdHkrJ108cD4nK3QuZGVzYysnPC9wPjxwIHN0eWxlPSJjb2xvcjojMmQ2YTRmIj5G"
"SVg6ICcrdC5maXgrJzwvcD48L2Rpdj4nfSl9CiAgYis9JzwvYm9keT48L2h0bWw+JzsKICB2YXIg"
"YT1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdhJyk7YS5ocmVmPVVSTC5jcmVhdGVPYmplY3RVUkwo"
"bmV3IEJsb2IoW2JdLHt0eXBlOid0ZXh0L2h0bWwnfSkpO2EuZG93bmxvYWQ9J0hBUlNIQV92N19W"
"QVBULmh0bWwnO2EuY2xpY2soKTtub3RpZnkoJ1JlcG9ydCBkb3dubG9hZGVkIScpOwp9CmZ1bmN0"
"aW9uIGRvd25sb2FkVFhUKCl7CiAgdmFyIG5vdz1uZXcgRGF0ZSgpLnRvTG9jYWxlU3RyaW5nKCk7"
"dmFyIHQ9J0hBUlNIQSB2Ny4wIFZBUFQgUkVQT1JUXG4nK25vdysnXG5cbic7CiAgYWxsUG9ydHMu"
"Zm9yRWFjaChmdW5jdGlvbihwKXt0Kz1wLnBvcnQrJy8nK3AucHJvdG8rJyAnK3Auc2VydmljZSsn"
"IFsnK3Auc2V2ZXJpdHkrJ10gJytwLmRlc2MrJ1xuJ30pOwogIGlmKGFsbFRocmVhdHMubGVuZ3Ro"
"KXt0Kz0nXG5WVUxORVJBQklMSVRJRVM6XG4nO2FsbFRocmVhdHMuZm9yRWFjaChmdW5jdGlvbih0"
"aCxpKXt0Kz0oaSsxKSsnLiAnK3RoLm5hbWUrJyBbJyt0aC5zZXZlcml0eSsnXSAnK3RoLmRlc2Mr"
"J1xuRklYOiAnK3RoLmZpeCsnXG5cbid9KX0KICB2YXIgYT1kb2N1bWVudC5jcmVhdGVFbGVtZW50"
"KCdhJyk7YS5ocmVmPVVSTC5jcmVhdGVPYmplY3RVUkwobmV3IEJsb2IoW3RdLHt0eXBlOid0ZXh0"
"L3BsYWluJ30pKTthLmRvd25sb2FkPSdIQVJTSEFfdjdfVkFQVC50eHQnO2EuY2xpY2soKTtub3Rp"
"ZnkoJ1RYVCBkb3dubG9hZGVkIScpOwp9CmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZXBvcnQt"
"bW9kYWwnKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsZnVuY3Rpb24oZSl7aWYoZS50YXJnZXQ9"
"PT10aGlzKWNsb3NlUmVwb3J0KCl9KTsKCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgQ0hBUlRTCiAgID09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0g"
"Ki8KQ2hhcnQuZGVmYXVsdHMuY29sb3I9JyM4YThhOTYnO0NoYXJ0LmRlZmF1bHRzLmJvcmRlckNv"
"bG9yPSdyZ2JhKDAsMCwwLDAuMDYpJzsKQ2hhcnQuZGVmYXVsdHMuZm9udC5mYW1pbHk9IidJQk0g"
"UGxleCBNb25vJyxtb25vc3BhY2UiO0NoYXJ0LmRlZmF1bHRzLmZvbnQuc2l6ZT0xMDsKQ2hhcnQu"
"ZGVmYXVsdHMucGx1Z2lucy5sZWdlbmQubGFiZWxzLmJveFdpZHRoPTEwO0NoYXJ0LmRlZmF1bHRz"
"LnBsdWdpbnMubGVnZW5kLmxhYmVscy5wYWRkaW5nPTE0OwoKZnVuY3Rpb24gZGVzdHJveUNoYXJ0"
"cyhvKXtPYmplY3Qua2V5cyhvKS5mb3JFYWNoKGZ1bmN0aW9uKGspe2lmKG9ba10pe29ba10uZGVz"
"dHJveSgpO29ba109bnVsbH19KX0KZnVuY3Rpb24gY2FsY1Jpc2tTY29yZShwLHQpe2lmKCFwLmxl"
"bmd0aCYmIXQubGVuZ3RoKXJldHVybiAwO3ZhciBzPTA7cC5mb3JFYWNoKGZ1bmN0aW9uKHgpe2lm"
"KHguc2V2ZXJpdHk9PT0nQ1JJVElDQUwnKXMrPTI1O2Vsc2UgaWYoeC5zZXZlcml0eT09PSdISUdI"
"JylzKz0xNTtlbHNlIGlmKHguc2V2ZXJpdHk9PT0nTUVESVVNJylzKz04O2Vsc2Ugcys9M30pO3Qu"
"Zm9yRWFjaChmdW5jdGlvbih4KXtpZih4LnNldmVyaXR5PT09J0NSSVRJQ0FMJylzKz0zMDtlbHNl"
"IGlmKHguc2V2ZXJpdHk9PT0nSElHSCcpcys9MjA7ZWxzZSBpZih4LnNldmVyaXR5PT09J01FRElV"
"TScpcys9MTA7ZWxzZSBzKz00fSk7cmV0dXJuIE1hdGgubWluKDEwMCxNYXRoLnJvdW5kKHMpKX0K"
"ZnVuY3Rpb24gZ2V0Umlza0NvbG9yKHMpe2lmKHM+PTc1KXJldHVybicjZDkwNDI5JztpZihzPj01"
"MClyZXR1cm4nI2U4NWQwNCc7aWYocz49MjUpcmV0dXJuJyNlMDlmM2UnO3JldHVybicjMmQ2YTRm"
"J30KZnVuY3Rpb24gZ2V0Umlza0xhYmVsKHMpe2lmKHM+PTc1KXJldHVybidDUklUSUNBTCc7aWYo"
"cz49NTApcmV0dXJuJ0hJR0gnO2lmKHM+PTI1KXJldHVybidNRURJVU0nO3JldHVybidMT1cnfQoK"
"ZnVuY3Rpb24gcmVmcmVzaFJpc2tDaGFydHMoKXsKICBkZXN0cm95Q2hhcnRzKHJpc2tDaGFydHMp"
"O3ZhciBjPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyaXNrLWNvbnRlbnQnKTsKICBpZighYWxs"
"UG9ydHMubGVuZ3RoJiYhYWxsVGhyZWF0cy5sZW5ndGgpe2MuaW5uZXJIVE1MPSc8ZGl2IGNsYXNz"
"PSJlbXB0eS1zdGF0ZSI+PGRpdiBjbGFzcz0iZW1wdHktaWNvIj7wn5OKPC9kaXY+PGRpdiBjbGFz"
"cz0iZW1wdHktdGl0bGUiPk5vIFJpc2sgRGF0YTwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXN1YiI+"
"UnVuIHNjYW5zIGZpcnN0PC9kaXY+PC9kaXY+JztyZXR1cm59CiAgdmFyIGNyaXQ9MCxoaWdoPTAs"
"bWVkPTAsbG93PTA7CiAgYWxsUG9ydHMuZm9yRWFjaChmdW5jdGlvbihwKXtpZihwLnNldmVyaXR5"
"PT09J0NSSVRJQ0FMJyljcml0Kys7ZWxzZSBpZihwLnNldmVyaXR5PT09J0hJR0gnKWhpZ2grKztl"
"bHNlIGlmKHAuc2V2ZXJpdHk9PT0nTUVESVVNJyltZWQrKztlbHNlIGxvdysrfSk7CiAgYWxsVGhy"
"ZWF0cy5mb3JFYWNoKGZ1bmN0aW9uKHQpe2lmKHQuc2V2ZXJpdHk9PT0nQ1JJVElDQUwnKWNyaXQr"
"KztlbHNlIGlmKHQuc2V2ZXJpdHk9PT0nSElHSCcpaGlnaCsrO2Vsc2UgaWYodC5zZXZlcml0eT09"
"PSdNRURJVU0nKW1lZCsrO2Vsc2UgbG93Kyt9KTsKICB2YXIgc2NvcmU9Y2FsY1Jpc2tTY29yZShh"
"bGxQb3J0cyxhbGxUaHJlYXRzKSxyQz1nZXRSaXNrQ29sb3Ioc2NvcmUpLHJMPWdldFJpc2tMYWJl"
"bChzY29yZSk7CiAgdmFyIHN2Y01hcD17fTthbGxQb3J0cy5mb3JFYWNoKGZ1bmN0aW9uKHApe3Zh"
"ciBzPXAuc2VydmljZXx8Jz8nO2lmKCFzdmNNYXBbc10pc3ZjTWFwW3NdPXtjOjAsaDowLG06MCxs"
"OjAsdDowfTtzdmNNYXBbc10udCsrO2lmKHAuc2V2ZXJpdHk9PT0nQ1JJVElDQUwnKXN2Y01hcFtz"
"XS5jKys7ZWxzZSBpZihwLnNldmVyaXR5PT09J0hJR0gnKXN2Y01hcFtzXS5oKys7ZWxzZSBpZihw"
"LnNldmVyaXR5PT09J01FRElVTScpc3ZjTWFwW3NdLm0rKztlbHNlIHN2Y01hcFtzXS5sKyt9KTsK"
"ICB2YXIgc049T2JqZWN0LmtleXMoc3ZjTWFwKS5zb3J0KGZ1bmN0aW9uKGEsYil7cmV0dXJuIHN2"
"Y01hcFtiXS50LXN2Y01hcFthXS50fSkuc2xpY2UoMCwxMCk7CiAgdmFyIGg9JzxkaXYgY2xhc3M9"
"ImRhc2gtZ3JpZCBjb2xzLTIiIHN0eWxlPSJtYXJnaW4tYm90dG9tOjIwcHgiPic7CiAgaCs9Jzxk"
"aXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtaGVhZGVyIj48ZGl2PjxkaXYgY2xhc3M9"
"ImNhcmQtdGl0bGUiPk92ZXJhbGwgUmlzayBTY29yZTwvZGl2PjwvZGl2PjwvZGl2Pic7CiAgaCs9"
"JzxkaXYgY2xhc3M9InJpc2stZ2F1Z2UiPjxkaXYgY2xhc3M9InJpc2stY2lyY2xlIiBzdHlsZT0i"
"Y29sb3I6JytyQysnO2JvcmRlci1jb2xvcjonK3JDKycyNSI+PGRpdiBjbGFzcz0icmlzay12YWwi"
"IHN0eWxlPSJjb2xvcjonK3JDKyciPicrc2NvcmUrJzwvZGl2PjxkaXYgY2xhc3M9InJpc2stbGFi"
"ZWwiPicrckwrJzwvZGl2PjwvZGl2Pic7CiAgaCs9JzxkaXYgY2xhc3M9InJpc2stZGV0YWlscyI+"
"PGRpdiBjbGFzcz0icmlzay1yb3ciPjxkaXYgY2xhc3M9InJpc2stZG90IiBzdHlsZT0iYmFja2dy"
"b3VuZDp2YXIoLS1yZWQpIj48L2Rpdj5Qb3J0czxzcGFuIGNsYXNzPSJyaXNrLXZhbC1zbSIgc3R5"
"bGU9ImNvbG9yOnZhcigtLXNldi1oaWdoKSI+JythbGxQb3J0cy5sZW5ndGgrJzwvc3Bhbj48L2Rp"
"dj4nOwogIGgrPSc8ZGl2IGNsYXNzPSJyaXNrLXJvdyI+PGRpdiBjbGFzcz0icmlzay1kb3QiIHN0"
"eWxlPSJiYWNrZ3JvdW5kOnZhcigtLXNldi1jcml0KSI+PC9kaXY+VGhyZWF0czxzcGFuIGNsYXNz"
"PSJyaXNrLXZhbC1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXNldi1jcml0KSI+JythbGxUaHJlYXRz"
"Lmxlbmd0aCsnPC9zcGFuPjwvZGl2PjwvZGl2PjwvZGl2PjwvZGl2Pic7CiAgaCs9JzxkaXYgY2xh"
"c3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtdGl0bGUiPlNldmVyaXR5IERpc3RyaWJ1dGlvbjwv"
"ZGl2PjxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPjxjYW52YXMgaWQ9ImNoLXNldiI+PC9jYW52YXM+"
"PC9kaXY+PC9kaXY+JzsKICBoKz0nPC9kaXY+JzsKICBpZihzTi5sZW5ndGgpe2grPSc8ZGl2IGNs"
"YXNzPSJkYXNoLWdyaWQgY29scy0yIj48ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJk"
"LXRpdGxlIj5SaXNrIGJ5IFNlcnZpY2U8L2Rpdj48ZGl2IGNsYXNzPSJjaGFydC13cmFwIj48Y2Fu"
"dmFzIGlkPSJjaC1zdmMiPjwvY2FudmFzPjwvZGl2PjwvZGl2Pic7CiAgaCs9JzxkaXYgY2xhc3M9"
"ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtdGl0bGUiPlJpc2sgYnkgQ2F0ZWdvcnk8L2Rpdj48ZGl2"
"IGNsYXNzPSJjaGFydC13cmFwIj48Y2FudmFzIGlkPSJjaC1jYXQiPjwvY2FudmFzPjwvZGl2Pjwv"
"ZGl2PjwvZGl2Pid9CiAgYy5pbm5lckhUTUw9aDsKICB2YXIgeDE9ZG9jdW1lbnQuZ2V0RWxlbWVu"
"dEJ5SWQoJ2NoLXNldicpO2lmKHgxKXJpc2tDaGFydHMucz1uZXcgQ2hhcnQoeDEse3R5cGU6J2Rv"
"dWdobnV0JyxkYXRhOntsYWJlbHM6WydDcml0aWNhbCcsJ0hpZ2gnLCdNZWRpdW0nLCdMb3cnXSxk"
"YXRhc2V0czpbe2RhdGE6W2NyaXQsaGlnaCxtZWQsbG93XSxiYWNrZ3JvdW5kQ29sb3I6W3NldkNv"
"bG9ycy5DUklUSUNBTCxzZXZDb2xvcnMuSElHSCxzZXZDb2xvcnMuTUVESVVNLHNldkNvbG9ycy5M"
"T1ddLGJvcmRlcldpZHRoOjAsaG92ZXJPZmZzZXQ6OH1dfSxvcHRpb25zOntyZXNwb25zaXZlOnRy"
"dWUsbWFpbnRhaW5Bc3BlY3RSYXRpbzpmYWxzZSxjdXRvdXQ6JzcwJScscGx1Z2luczp7bGVnZW5k"
"Ontwb3NpdGlvbjoncmlnaHQnfX19fSk7CiAgdmFyIHgyPWRvY3VtZW50LmdldEVsZW1lbnRCeUlk"
"KCdjaC1zdmMnKTtpZih4MiYmc04ubGVuZ3RoKXJpc2tDaGFydHMudj1uZXcgQ2hhcnQoeDIse3R5"
"cGU6J2JhcicsZGF0YTp7bGFiZWxzOnNOLGRhdGFzZXRzOlt7bGFiZWw6J0NyaXQnLGRhdGE6c04u"
"bWFwKGZ1bmN0aW9uKHMpe3JldHVybiBzdmNNYXBbc10uY30pLGJhY2tncm91bmRDb2xvcjpzZXZC"
"Zy5DUklUSUNBTCxib3JkZXJDb2xvcjpzZXZDb2xvcnMuQ1JJVElDQUwsYm9yZGVyV2lkdGg6MX0s"
"e2xhYmVsOidIaWdoJyxkYXRhOnNOLm1hcChmdW5jdGlvbihzKXtyZXR1cm4gc3ZjTWFwW3NdLmh9"
"KSxiYWNrZ3JvdW5kQ29sb3I6c2V2QmcuSElHSCxib3JkZXJDb2xvcjpzZXZDb2xvcnMuSElHSCxi"
"b3JkZXJXaWR0aDoxfSx7bGFiZWw6J0xvdycsZGF0YTpzTi5tYXAoZnVuY3Rpb24ocyl7cmV0dXJu"
"IHN2Y01hcFtzXS5sfSksYmFja2dyb3VuZENvbG9yOnNldkJnLkxPVyxib3JkZXJDb2xvcjpzZXZD"
"b2xvcnMuTE9XLGJvcmRlcldpZHRoOjF9XX0sb3B0aW9uczp7cmVzcG9uc2l2ZTp0cnVlLG1haW50"
"YWluQXNwZWN0UmF0aW86ZmFsc2UsaW5kZXhBeGlzOid5JyxzY2FsZXM6e3g6e3N0YWNrZWQ6dHJ1"
"ZX0seTp7c3RhY2tlZDp0cnVlLGdyaWQ6e2Rpc3BsYXk6ZmFsc2V9fX0scGx1Z2luczp7bGVnZW5k"
"Ontwb3NpdGlvbjondG9wJyxsYWJlbHM6e2JveFdpZHRoOjh9fX19fSk7CiAgdmFyIGNOPTAsY1c9"
"MCxjST0wO2FsbFRocmVhdHMuZm9yRWFjaChmdW5jdGlvbih0KXt2YXIgbj10Lm5hbWUudG9Mb3dl"
"ckNhc2UoKTtpZihuLmluZGV4T2YoJ3NxbCcpPj0wfHxuLmluZGV4T2YoJ3hzcycpPj0wfHxuLmlu"
"ZGV4T2YoJ2hlYWRlcicpPj0wfHxuLmluZGV4T2YoJ3NzbCcpPj0wKWNXKys7ZWxzZSBpZihuLmlu"
"ZGV4T2YoJ3NtYicpPj0wfHxuLmluZGV4T2YoJ3NubXAnKT49MHx8bi5pbmRleE9mKCdwb3J0Jyk+"
"PTApY04rKztlbHNlIGNJKyt9KTsKICB2YXIgeDM9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2No"
"LWNhdCcpO2lmKHgzKXJpc2tDaGFydHMuYz1uZXcgQ2hhcnQoeDMse3R5cGU6J2RvdWdobnV0Jyxk"
"YXRhOntsYWJlbHM6WydOZXR3b3JrJywnV2ViJywnSW5mcmFzdHJ1Y3R1cmUnXSxkYXRhc2V0czpb"
"e2RhdGE6W01hdGgubWF4KGNOLFNDLm5ldHx8MCksTWF0aC5tYXgoY1csU0Mud2VifHwwKSxNYXRo"
"Lm1heChjSSxTQy5pbmZ8fDApXSxiYWNrZ3JvdW5kQ29sb3I6WycjMGEwYTBjJywnI2U2Mzk0Nics"
"JyM4YThhOTYnXSxib3JkZXJXaWR0aDowfV19LG9wdGlvbnM6e3Jlc3BvbnNpdmU6dHJ1ZSxtYWlu"
"dGFpbkFzcGVjdFJhdGlvOmZhbHNlLGN1dG91dDonNzAlJyxwbHVnaW5zOntsZWdlbmQ6e3Bvc2l0"
"aW9uOidyaWdodCd9fX19KTsKfQoKZnVuY3Rpb24gcmVmcmVzaFRocmVhdENoYXJ0cygpewogIGRl"
"c3Ryb3lDaGFydHModGhyZWF0Q2hhcnRzKTt2YXIgYz1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgn"
"dGdyYXBoLWNvbnRlbnQnKTsKICBpZighYWxsVGhyZWF0cy5sZW5ndGgmJiFhbGxQb3J0cy5sZW5n"
"dGgpe2MuaW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJlbXB0eS1zdGF0ZSI+PGRpdiBjbGFzcz0iZW1w"
"dHktaWNvIj7wn5W4PC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktdGl0bGUiPk5vIFRocmVhdCBEYXRh"
"PC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktc3ViIj5SdW4gc2NhbnMgZmlyc3Q8L2Rpdj48L2Rpdj4n"
"O3JldHVybn0KICB2YXIgY2F0cz17aW5qZWN0aW9uOjAsY29uZmlnOjAsY3J5cHRvOjAsZXhwb3N1"
"cmU6MCxhdXRoOjAsbmV0d29yazowfTsKICBhbGxUaHJlYXRzLmZvckVhY2goZnVuY3Rpb24odCl7"
"dmFyIG49dC5uYW1lLnRvTG93ZXJDYXNlKCk7aWYobi5pbmRleE9mKCdzcWwnKT49MHx8bi5pbmRl"
"eE9mKCd4c3MnKT49MHx8bi5pbmRleE9mKCdpbmplY3QnKT49MCljYXRzLmluamVjdGlvbisrO2Vs"
"c2UgaWYobi5pbmRleE9mKCdoZWFkZXInKT49MHx8bi5pbmRleE9mKCdjb3JzJyk+PTB8fG4uaW5k"
"ZXhPZignY29uZmlnJyk+PTApY2F0cy5jb25maWcrKztlbHNlIGlmKG4uaW5kZXhPZignc3NsJyk+"
"PTB8fG4uaW5kZXhPZigndGxzJyk+PTApY2F0cy5jcnlwdG8rKztlbHNlIGlmKG4uaW5kZXhPZign"
"ZXhwb3N1cmUnKT49MHx8bi5pbmRleE9mKCdpbmZvJyk+PTApY2F0cy5leHBvc3VyZSsrO2Vsc2Ug"
"aWYobi5pbmRleE9mKCdhdXRoJyk+PTB8fG4uaW5kZXhPZignZnRwJyk+PTB8fG4uaW5kZXhPZign"
"c3NoJyk+PTApY2F0cy5hdXRoKys7ZWxzZSBjYXRzLm5ldHdvcmsrK30pOwogIHZhciBzdj17Q1JJ"
"VElDQUw6MCxISUdIOjAsTUVESVVNOjAsTE9XOjB9O2FsbFRocmVhdHMuZm9yRWFjaChmdW5jdGlv"
"bih0KXtzdlt0LnNldmVyaXR5XT0oc3ZbdC5zZXZlcml0eV18fDApKzF9KTsKICB2YXIgaD0nPGRp"
"diBjbGFzcz0iZGFzaC1ncmlkIGNvbHMtMiIgc3R5bGU9Im1hcmdpbi1ib3R0b206MjBweCI+JzsK"
"ICBoKz0nPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0iY2FyZC10aXRsZSI+QXR0YWNrIFZl"
"Y3RvciBBbmFseXNpczwvZGl2PjxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPjxjYW52YXMgaWQ9ImNo"
"LXJhZGFyIj48L2NhbnZhcz48L2Rpdj48L2Rpdj4nOwogIGgrPSc8ZGl2IGNsYXNzPSJjYXJkIj48"
"ZGl2IGNsYXNzPSJjYXJkLXRpdGxlIj5UaHJlYXRzIGJ5IFNldmVyaXR5PC9kaXY+PGRpdiBjbGFz"
"cz0iY2hhcnQtd3JhcCI+PGNhbnZhcyBpZD0iY2gtdHNldiI+PC9jYW52YXM+PC9kaXY+PC9kaXY+"
"PC9kaXY+JzsKICBoKz0nPGRpdiBjbGFzcz0iZGFzaC1ncmlkIGNvbHMtMSI+PGRpdiBjbGFzcz0i"
"Y2FyZCI+PGRpdiBjbGFzcz0iY2FyZC10aXRsZSI+Q29tYmluZWQgUmlzayBPdmVydmlldzwvZGl2"
"PjxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiIHN0eWxlPSJtaW4taGVpZ2h0OjIyMHB4Ij48Y2FudmFz"
"IGlkPSJjaC1jb21ibyI+PC9jYW52YXM+PC9kaXY+PC9kaXY+PC9kaXY+JzsKICBjLmlubmVySFRN"
"TD1oOwogIHZhciByMT1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2gtcmFkYXInKTtpZihyMSl0"
"aHJlYXRDaGFydHMucj1uZXcgQ2hhcnQocjEse3R5cGU6J3JhZGFyJyxkYXRhOntsYWJlbHM6WydJ"
"bmplY3Rpb24nLCdNaXNjb25maWcnLCdDcnlwdG8nLCdFeHBvc3VyZScsJ0F1dGgnLCdOZXR3b3Jr"
"J10sZGF0YXNldHM6W3tkYXRhOltjYXRzLmluamVjdGlvbixjYXRzLmNvbmZpZyxjYXRzLmNyeXB0"
"byxjYXRzLmV4cG9zdXJlLGNhdHMuYXV0aCxjYXRzLm5ldHdvcmtdLGJhY2tncm91bmRDb2xvcjon"
"cmdiYSgyMzAsNTcsNzAsMC4xOCknLGJvcmRlckNvbG9yOicjZTYzOTQ2Jyxib3JkZXJXaWR0aDoz"
"LHBvaW50QmFja2dyb3VuZENvbG9yOicjZTYzOTQ2Jyxwb2ludEJvcmRlckNvbG9yOicjZmZmJyxw"
"b2ludEJvcmRlcldpZHRoOjIscG9pbnRSYWRpdXM6Nixwb2ludEhvdmVyUmFkaXVzOjh9XX0sb3B0"
"aW9uczp7cmVzcG9uc2l2ZTp0cnVlLG1haW50YWluQXNwZWN0UmF0aW86ZmFsc2Usc2NhbGVzOnty"
"OntiZWdpbkF0WmVybzp0cnVlLGdyaWQ6e2NvbG9yOidyZ2JhKDEwMCwxMTYsMTM5LDAuNzUpJyxs"
"aW5lV2lkdGg6Mn0sYW5nbGVMaW5lczp7Y29sb3I6J3JnYmEoMTAwLDExNiwxMzksMC44NSknLGxp"
"bmVXaWR0aDoyfSxwb2ludExhYmVsczp7Y29sb3I6JyM2NDc0OGInLGZvbnQ6e3NpemU6MTEsd2Vp"
"Z2h0Oic3MDAnfX0sdGlja3M6e2Rpc3BsYXk6ZmFsc2V9fX0scGx1Z2luczp7bGVnZW5kOntkaXNw"
"bGF5OmZhbHNlfX19fSk7CiAgdmFyIHIyPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjaC10c2V2"
"Jyk7aWYocjIpdGhyZWF0Q2hhcnRzLnM9bmV3IENoYXJ0KHIyLHt0eXBlOidiYXInLGRhdGE6e2xh"
"YmVsczpbJ0NyaXRpY2FsJywnSGlnaCcsJ01lZGl1bScsJ0xvdyddLGRhdGFzZXRzOlt7ZGF0YTpb"
"c3YuQ1JJVElDQUwsc3YuSElHSCxzdi5NRURJVU0sc3YuTE9XXSxiYWNrZ3JvdW5kQ29sb3I6W3Nl"
"dkJnLkNSSVRJQ0FMLHNldkJnLkhJR0gsc2V2QmcuTUVESVVNLHNldkJnLkxPV10sYm9yZGVyQ29s"
"b3I6W3NldkNvbG9ycy5DUklUSUNBTCxzZXZDb2xvcnMuSElHSCxzZXZDb2xvcnMuTUVESVVNLHNl"
"dkNvbG9ycy5MT1ddLGJvcmRlcldpZHRoOjEsYm9yZGVyUmFkaXVzOjh9XX0sb3B0aW9uczp7cmVz"
"cG9uc2l2ZTp0cnVlLG1haW50YWluQXNwZWN0UmF0aW86ZmFsc2Usc2NhbGVzOnt4OntncmlkOntk"
"aXNwbGF5OmZhbHNlfX0seTp7YmVnaW5BdFplcm86dHJ1ZSx0aWNrczp7c3RlcFNpemU6MX19fSxw"
"bHVnaW5zOntsZWdlbmQ6e2Rpc3BsYXk6ZmFsc2V9fX19KTsKICB2YXIgcjU9ZG9jdW1lbnQuZ2V0"
"RWxlbWVudEJ5SWQoJ2NoLWNvbWJvJyk7aWYocjUpe3ZhciBwUz17Q1JJVElDQUw6MCxISUdIOjAs"
"TUVESVVNOjAsTE9XOjB9O2FsbFBvcnRzLmZvckVhY2goZnVuY3Rpb24ocCl7cFNbcC5zZXZlcml0"
"eV09KHBTW3Auc2V2ZXJpdHldfHwwKSsxfSk7dGhyZWF0Q2hhcnRzLmM9bmV3IENoYXJ0KHI1LHt0"
"eXBlOidiYXInLGRhdGE6e2xhYmVsczpbJ0NyaXRpY2FsJywnSGlnaCcsJ01lZGl1bScsJ0xvdydd"
"LGRhdGFzZXRzOlt7bGFiZWw6J1BvcnRzJyxkYXRhOltwUy5DUklUSUNBTCxwUy5ISUdILHBTLk1F"
"RElVTSxwUy5MT1ddLGJhY2tncm91bmRDb2xvcjoncmdiYSgxMCwxMCwxMiwwLjA4KScsYm9yZGVy"
"Q29sb3I6JyMwYTBhMGMnLGJvcmRlcldpZHRoOjEsYm9yZGVyUmFkaXVzOjZ9LHtsYWJlbDonVGhy"
"ZWF0cycsZGF0YTpbc3YuQ1JJVElDQUwsc3YuSElHSCxzdi5NRURJVU0sc3YuTE9XXSxiYWNrZ3Jv"
"dW5kQ29sb3I6J3JnYmEoMjMwLDU3LDcwLDAuMSknLGJvcmRlckNvbG9yOicjZTYzOTQ2Jyxib3Jk"
"ZXJXaWR0aDoxLGJvcmRlclJhZGl1czo2fV19LG9wdGlvbnM6e3Jlc3BvbnNpdmU6dHJ1ZSxtYWlu"
"dGFpbkFzcGVjdFJhdGlvOmZhbHNlLHNjYWxlczp7eDp7Z3JpZDp7ZGlzcGxheTpmYWxzZX19LHk6"
"e2JlZ2luQXRaZXJvOnRydWUsdGlja3M6e3N0ZXBTaXplOjF9fX0scGx1Z2luczp7bGVnZW5kOntw"
"b3NpdGlvbjondG9wJyxsYWJlbHM6e2JveFdpZHRoOjEwfX19fX0pfQp9CgovKiA9PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAg"
"IFNDQU4gU1RBVFVTIFBPTExJTkcgKFNJTkdMRSBDTEVBTiBWRVJTSU9OKQogICA9PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICov"
"CmZ1bmN0aW9uIHBvbGxTY2FuU3RhdHVzKCl7CiAgZmV0Y2goJy9zY2FuX3N0YXR1cycpLnRoZW4o"
"ZnVuY3Rpb24ocil7cmV0dXJuIHIuanNvbigpfSkudGhlbihmdW5jdGlvbihzKXsKICAgIHZhciBp"
"bmRpY2F0b3I9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NjYW4taW5kaWNhdG9yJyk7CiAgICB2"
"YXIgYmFyRmlsbD1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2Nhbi1iYXItZmlsbCcpOwogICAg"
"dmFyIGJhZGdlPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzY2FuLXN0YXR1cy1iYWRnZScpOwog"
"ICAgdmFyIGxpdmVDYXJkPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdsaXZlLXNjYW4tY2FyZCcp"
"OwogICAgdmFyIG1wPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdoLW1pbmktcHJvZ3Jlc3MnKTsK"
"ICAgIHZhciBtYmFyPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdoLW1pbmktYmFyJyk7CgogICAg"
"LyogTWluaSBwcm9ncmVzcyBiYXIgKi8KICAgIGlmKHMuYWN0aXZlKXttcC5jbGFzc0xpc3QuYWRk"
"KCdhY3RpdmUnKTttYmFyLnN0eWxlLndpZHRoPXMucGVyY2VudCsnJSd9CiAgICBlbHNle21iYXIu"
"c3R5bGUud2lkdGg9cy5waGFzZT09PSdjb21wbGV0ZSc/JzEwMCUnOicwJSc7CiAgICAgIGlmKHMu"
"cGhhc2U9PT0nY29tcGxldGUnKXNldFRpbWVvdXQoZnVuY3Rpb24oKXttcC5jbGFzc0xpc3QucmVt"
"b3ZlKCdhY3RpdmUnKX0sMjAwMCk7CiAgICAgIGVsc2UgbXAuY2xhc3NMaXN0LnJlbW92ZSgnYWN0"
"aXZlJyk7CiAgICB9CgogICAgLyogU2NhbiBTdGF0dXMgdGFiIGluZGljYXRvciAqLwogICAgaW5k"
"aWNhdG9yLmNsYXNzTmFtZT0nc2Nhbi1pbmRpY2F0b3InOwogICAgYmFyRmlsbC5jbGFzc05hbWU9"
"J3NjYW4tYmFyLWZpbGwtbGl2ZSc7CiAgICBpZihzLmFjdGl2ZSl7CiAgICAgIGluZGljYXRvci5j"
"bGFzc05hbWU9J3NjYW4taW5kaWNhdG9yIHJ1bm5pbmcnOwogICAgICBiYWRnZS5jbGFzc05hbWU9"
"J3RhYi1iYWRnZSBsaXZlJztiYWRnZS50ZXh0Q29udGVudD1zLnBlcmNlbnQrJyUnOwogICAgICBs"
"aXZlQ2FyZC5zdHlsZS5ib3JkZXJMZWZ0Q29sb3I9J3ZhcigtLXJlZCknOwogICAgfSBlbHNlIGlm"
"KHMucGhhc2U9PT0nY29tcGxldGUnKXsKICAgICAgaW5kaWNhdG9yLmNsYXNzTmFtZT0nc2Nhbi1p"
"bmRpY2F0b3IgY29tcGxldGUnOwogICAgICBiYXJGaWxsLmNsYXNzTmFtZT0nc2Nhbi1iYXItZmls"
"bC1saXZlIGNvbXBsZXRlJzsKICAgICAgYmFkZ2UuY2xhc3NOYW1lPSd0YWItYmFkZ2UgZG9uZSc7"
"YmFkZ2UudGV4dENvbnRlbnQ9J1x1MjcxMyc7CiAgICAgIGxpdmVDYXJkLnN0eWxlLmJvcmRlckxl"
"ZnRDb2xvcj0ndmFyKC0tc2V2LWxvdyknOwogICAgfSBlbHNlIGlmKHMucGhhc2U9PT0nZXJyb3In"
"KXsKICAgICAgaW5kaWNhdG9yLmNsYXNzTmFtZT0nc2Nhbi1pbmRpY2F0b3IgZXJyb3InOwogICAg"
"ICBiYWRnZS5jbGFzc05hbWU9J3RhYi1iYWRnZSBzaG93IGItcmVkJztiYWRnZS50ZXh0Q29udGVu"
"dD0nISc7CiAgICAgIGxpdmVDYXJkLnN0eWxlLmJvcmRlckxlZnRDb2xvcj0ndmFyKC0tc2V2LWNy"
"aXQpJzsKICAgIH0gZWxzZSB7CiAgICAgIGJhZGdlLmNsYXNzTmFtZT0ndGFiLWJhZGdlJzsKICAg"
"ICAgbGl2ZUNhcmQuc3R5bGUuYm9yZGVyTGVmdENvbG9yPSd2YXIoLS13aGl0ZS00KSc7CiAgICB9"
"CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NjYW4tcGN0LW51bScpLnRleHRDb250ZW50"
"PXMuYWN0aXZlfHxzLnBoYXNlPT09J2NvbXBsZXRlJz9zLnBlcmNlbnQrJyUnOidcdTIwMTQnOwog"
"ICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NjYW4tdG9vbC1uYW1lJykudGV4dENvbnRlbnQ9"
"cy50b29sX2Rpc3BsYXl8fHMudG9vbHx8J1x1MjAxNCc7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50"
"QnlJZCgnc2Nhbi10YXJnZXQnKS50ZXh0Q29udGVudD1zLnRhcmdldHx8J1x1MjAxNCc7CiAgICBk"
"b2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2Nhbi1jYXQnKS50ZXh0Q29udGVudD0ocy5jYXRlZ29y"
"eXx8J1x1MjAxNCcpLnRvVXBwZXJDYXNlKCk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgn"
"c2Nhbi1lbGFwc2VkJykudGV4dENvbnRlbnQ9cy5lbGFwc2VkKydzJzsKICAgIGRvY3VtZW50Lmdl"
"dEVsZW1lbnRCeUlkKCdzY2FuLW1lc3NhZ2UnKS50ZXh0Q29udGVudD1zLm1lc3NhZ2V8fCdSZWFk"
"eSBcdTIwMTQgc2VsZWN0IGEgdG9vbCB0byBiZWdpbic7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50"
"QnlJZCgnc2Nhbi1wY3QtdGV4dCcpLnRleHRDb250ZW50PXMucGVyY2VudCsnJSc7CiAgICBiYXJG"
"aWxsLnN0eWxlLndpZHRoPXMucGVyY2VudCsnJSc7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJ"
"ZCgnc3Mtc3VidGl0bGUnKS50ZXh0Q29udGVudD1zLmFjdGl2ZT8nU2Nhbm5pbmcgJytzLnRhcmdl"
"dCsnLi4uJzpzLnBoYXNlPT09J2NvbXBsZXRlJz8nTGFzdCBzY2FuIGNvbXBsZXRlZCc6J05vIGFj"
"dGl2ZSBzY2FuJzsKCiAgICB2YXIgcGI9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NjYW4tcGhh"
"c2UtYmFkZ2UnKTsKICAgIHBiLnRleHRDb250ZW50PShzLnBoYXNlfHwnaWRsZScpLnRvVXBwZXJD"
"YXNlKCk7CiAgICBpZihzLmFjdGl2ZSl7cGIuc3R5bGUuYmFja2dyb3VuZD0ndmFyKC0tcmVkLWRp"
"bSknO3BiLnN0eWxlLmNvbG9yPSd2YXIoLS1yZWQpJ30KICAgIGVsc2UgaWYocy5waGFzZT09PSdj"
"b21wbGV0ZScpe3BiLnN0eWxlLmJhY2tncm91bmQ9J3ZhcigtLXNldi1sb3ctYmcpJztwYi5zdHls"
"ZS5jb2xvcj0ndmFyKC0tc2V2LWxvdyknfQogICAgZWxzZXtwYi5zdHlsZS5iYWNrZ3JvdW5kPSd2"
"YXIoLS13aGl0ZS0yKSc7cGIuc3R5bGUuY29sb3I9J3ZhcigtLXR4LW11dGVkKSd9CgogICAgdmFy"
"IHRTPXMuaGlzdG9yeT9zLmhpc3RvcnkubGVuZ3RoOjAsdFA9MCx0VD0wLHREPTA7CiAgICBpZihz"
"Lmhpc3Rvcnkpe3MuaGlzdG9yeS5mb3JFYWNoKGZ1bmN0aW9uKGgpe3RQKz1oLnBvcnRzfHwwO3RU"
"Kz1oLnRocmVhdHN8fDA7dEQrPWguZWxhcHNlZHx8MH0pfQogICAgZG9jdW1lbnQuZ2V0RWxlbWVu"
"dEJ5SWQoJ3NzLXRvdGFsJykudGV4dENvbnRlbnQ9dFM7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50"
"QnlJZCgnc3MtcG9ydHMnKS50ZXh0Q29udGVudD10UDsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRC"
"eUlkKCdzcy10aHJlYXRzJykudGV4dENvbnRlbnQ9dFQ7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50"
"QnlJZCgnc3MtYXZnJykudGV4dENvbnRlbnQ9dFM+MD8odEQvdFMpLnRvRml4ZWQoMSkrJ3MnOicw"
"cyc7CgogICAgaWYocy5oaXN0b3J5JiZzLmhpc3RvcnkubGVuZ3RoKXsKICAgICAgdmFyIHJvd3M9"
"Jyc7CiAgICAgIHMuaGlzdG9yeS5mb3JFYWNoKGZ1bmN0aW9uKGgpewogICAgICAgIHJvd3MrPSc8"
"dHI+PHRkIHN0eWxlPSJjb2xvcjp2YXIoLS1zZXYtbG93KTtmb250LXdlaWdodDo3MDAiPlx1Mjcx"
"MyBEb25lPC90ZD4nOwogICAgICAgIHJvd3MrPSc8dGQgc3R5bGU9ImZvbnQtd2VpZ2h0OjYwMDtj"
"b2xvcjp2YXIoLS10eC1kYXJrKSI+JytoLnRvb2wrJzwvdGQ+JzsKICAgICAgICByb3dzKz0nPHRk"
"IHN0eWxlPSJmb250LWZhbWlseTpJQk0gUGxleCBNb25vLG1vbm9zcGFjZTtmb250LXNpemU6MTFw"
"eDtjb2xvcjp2YXIoLS1yZWQpIj4nK2gudGFyZ2V0Kyc8L3RkPic7CiAgICAgICAgcm93cys9Jzx0"
"ZCBzdHlsZT0iZm9udC1mYW1pbHk6SUJNIFBsZXggTW9ubyxtb25vc3BhY2U7Zm9udC13ZWlnaHQ6"
"NzAwIj4nK2guZWxhcHNlZCsnczwvdGQ+JzsKICAgICAgICByb3dzKz0nPHRkPicraC5wb3J0cysn"
"PC90ZD48dGQ+JytoLnRocmVhdHMrJzwvdGQ+JzsKICAgICAgICByb3dzKz0nPHRkIHN0eWxlPSJj"
"b2xvcjp2YXIoLS10eC1mYWludCkiPicraC50aW1lKyc8L3RkPjwvdHI+JzsKICAgICAgfSk7CiAg"
"ICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzcy1oaXN0b3J5LXRhYmxlJykuaW5uZXJIVE1M"
"PXJvd3M7CiAgICB9CgogICAgaWYocy5hY3RpdmUgJiYgbGFzdFBoYXNlIT09J3NjYW5uaW5nJyAm"
"JiBsYXN0UGhhc2UhPT0naW5pdGlhbGl6aW5nJyAmJiBsYXN0UGhhc2UhPT0nYW5hbHl6aW5nJyl7"
"CiAgICAgIHN3aXRjaFRhYignc2NhbnN0YXR1cycsZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgn"
"LnRhYi1idG4nKVs1XSk7CiAgICB9CiAgICBsYXN0UGhhc2U9cy5waGFzZTsKICB9KS5jYXRjaChm"
"dW5jdGlvbigpe30pOwp9CnNldEludGVydmFsKHBvbGxTY2FuU3RhdHVzLDgwMCk7CgovKiA9PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09CiAgIEFUVEFDSyBDSEFJTiBWSVNVQUxJWkFUSU9OCiAgID09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KZnVuY3Rpb24g"
"cmVmcmVzaEF0dGFja0NoYWlucygpewogIGZldGNoKCcvYXR0YWNrX2NoYWlucycpLnRoZW4oZnVu"
"Y3Rpb24ocil7cmV0dXJuIHIuanNvbigpfSkudGhlbihmdW5jdGlvbihkYXRhKXsKICAgIHZhciBj"
"aGFpbnMgPSBkYXRhLmNoYWlucyB8fCBbXTsKICAgIHZhciBjb250YWluZXIgPSBkb2N1bWVudC5n"
"ZXRFbGVtZW50QnlJZCgnY2hhaW5zLWNvbnRlbnQnKTsKICAgIHZhciBiYWRnZSA9IGRvY3VtZW50"
"LmdldEVsZW1lbnRCeUlkKCdjaGFpbi1iYWRnZScpOwoKICAgIGlmKCFjaGFpbnMubGVuZ3RoKXsK"
"ICAgICAgY29udGFpbmVyLmlubmVySFRNTD0nPGRpdiBjbGFzcz0iZW1wdHktc3RhdGUiPjxkaXYg"
"Y2xhc3M9ImVtcHR5LWljbyI+4puTPC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktdGl0bGUiPk5vIEF0"
"dGFjayBDaGFpbnMgWWV0PC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktc3ViIj5SdW4gbXVsdGlwbGUg"
"c2NhbnMgdG8gZGlzY292ZXIgYXR0YWNrIHBhdGhzLiBUaGUgZW5naW5lIGNvbm5lY3RzIHZ1bG5l"
"cmFiaWxpdGllcyBpbnRvIGtpbGwgY2hhaW5zLjwvZGl2PjwvZGl2Pic7CiAgICAgIGJhZGdlLmNs"
"YXNzTmFtZT0ndGFiLWJhZGdlJzsKICAgICAgcmV0dXJuOwogICAgfQoKICAgIGJhZGdlLmNsYXNz"
"TmFtZT0ndGFiLWJhZGdlIHNob3cgYi1yZWQnOwogICAgYmFkZ2UudGV4dENvbnRlbnQ9Y2hhaW5z"
"Lmxlbmd0aDsKCiAgICB2YXIgY3JpdENoYWlucz0wLGhpZ2hDaGFpbnM9MCx0b3RhbENvc3Q9Jyc7"
"CiAgICBjaGFpbnMuZm9yRWFjaChmdW5jdGlvbihjKXtpZihjLnNldmVyaXR5PT09J0NSSVRJQ0FM"
"Jyljcml0Q2hhaW5zKys7aWYoYy5zZXZlcml0eT09PSdISUdIJyloaWdoQ2hhaW5zKyt9KTsKCiAg"
"ICB2YXIgaD0nJzsKICAgIC8vIFN1bW1hcnkgc3RhdHMKICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFp"
"bi1zdW1tYXJ5Ij4nOwogICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLXN0YXQiPjxkaXYgY2xhc3M9"
"ImNoYWluLXN0YXQtbnVtIiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKSI+JytjaGFpbnMubGVuZ3Ro"
"Kyc8L2Rpdj48ZGl2IGNsYXNzPSJjaGFpbi1zdGF0LWxhYmVsIj5BdHRhY2sgQ2hhaW5zIEZvdW5k"
"PC9kaXY+PC9kaXY+JzsKICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFpbi1zdGF0Ij48ZGl2IGNsYXNz"
"PSJjaGFpbi1zdGF0LW51bSIgc3R5bGU9ImNvbG9yOiNkOTA0MjkiPicrY3JpdENoYWlucysnPC9k"
"aXY+PGRpdiBjbGFzcz0iY2hhaW4tc3RhdC1sYWJlbCI+Q3JpdGljYWwgQ2hhaW5zPC9kaXY+PC9k"
"aXY+JzsKICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFpbi1zdGF0Ij48ZGl2IGNsYXNzPSJjaGFpbi1z"
"dGF0LW51bSIgc3R5bGU9ImNvbG9yOiNlODVkMDQiPicraGlnaENoYWlucysnPC9kaXY+PGRpdiBj"
"bGFzcz0iY2hhaW4tc3RhdC1sYWJlbCI+SGlnaCBDaGFpbnM8L2Rpdj48L2Rpdj4nOwogICAgaCs9"
"JzxkaXYgY2xhc3M9ImNoYWluLXN0YXQiPjxkaXYgY2xhc3M9ImNoYWluLXN0YXQtbnVtIiBzdHls"
"ZT0iY29sb3I6dmFyKC0tdHgtZGFyaykiPicrY2hhaW5zLnJlZHVjZShmdW5jdGlvbihhLGMpe3Jl"
"dHVybiBhK2MuY29uZmlybWVkX3N0ZXBzfSwwKSsnPC9kaXY+PGRpdiBjbGFzcz0iY2hhaW4tc3Rh"
"dC1sYWJlbCI+Q29uZmlybWVkIFN0ZXBzPC9kaXY+PC9kaXY+JzsKICAgIGgrPSc8L2Rpdj4nOwoK"
"ICAgIC8vIEFkdmFuY2VkIHJlcG9ydCBidXR0b24KICAgIGgrPSc8ZGl2IHN0eWxlPSJkaXNwbGF5"
"OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47YWxpZ24taXRlbXM6Y2VudGVyO21h"
"cmdpbi1ib3R0b206MTZweCI+JzsKICAgIGgrPSc8ZGl2IHN0eWxlPSJmb250LWZhbWlseTpTeW5l"
"LHNhbnMtc2VyaWY7Zm9udC1zaXplOjE4cHg7Zm9udC13ZWlnaHQ6ODAwO2NvbG9yOnZhcigtLXR4"
"LWRhcmspIj5LaWxsIENoYWluIEFuYWx5c2lzPC9kaXY+JzsKICAgIGgrPSc8YnV0dG9uIGNsYXNz"
"PSJidG4tYWR2LXJlcG9ydCIgb25jbGljaz0iZG93bmxvYWRBZHZhbmNlZFJlcG9ydCgpIj7irIcg"
"RG93bmxvYWQgQWR2YW5jZWQgUmVwb3J0PC9idXR0b24+JzsKICAgIGgrPSc8L2Rpdj4nOwoKICAg"
"IC8vIEVhY2ggY2hhaW4KICAgIGNoYWlucy5mb3JFYWNoKGZ1bmN0aW9uKGMsaWR4KXsKICAgICAg"
"aCs9JzxkaXYgY2xhc3M9ImNoYWluLWNhcmQgJytjLnNldmVyaXR5KyciIHN0eWxlPSJhbmltYXRp"
"b24tZGVsYXk6JysoaWR4KjAuMDgpKydzIj4nOwoKICAgICAgLy8gSGVhZGVyCiAgICAgIGgrPSc8"
"ZGl2IGNsYXNzPSJjaGFpbi1oZWFkZXIiPjxkaXY+JzsKICAgICAgaCs9JzxkaXYgY2xhc3M9ImNo"
"YWluLW5hbWUiPicrYy5uYW1lKyc8L2Rpdj4nOwogICAgICBoKz0nPGRpdiBjbGFzcz0iY2hhaW4t"
"a2lsbGNoYWluIj4nK2Mua2lsbF9jaGFpbisnPC9kaXY+JzsKICAgICAgaCs9JzwvZGl2PjxkaXYg"
"c3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6OHB4O2FsaWduLWl0ZW1zOmNlbnRlciI+JzsKICAgICAg"
"aCs9JzxzcGFuIGNsYXNzPSJzZXYgJytjLnNldmVyaXR5KyciPicrYy5zZXZlcml0eSsnPC9zcGFu"
"Pic7CiAgICAgIGgrPSc8c3BhbiBjbGFzcz0iY2hhaW4tY29uZmlkZW5jZSAnKyhjLmNvbmZpZGVu"
"Y2U+PTc1PydoaWdoJzonbWVkJykrJyI+JytjLmNvbmZpZGVuY2UrJyUgTWF0Y2g8L3NwYW4+JzsK"
"ICAgICAgaCs9JzwvZGl2PjwvZGl2Pic7CgogICAgICAvLyBLaWxsIENoYWluIEZsb3cKICAgICAg"
"aCs9JzxkaXYgY2xhc3M9ImNoYWluLWZsb3ciPic7CiAgICAgIGMuc3RlcHMuZm9yRWFjaChmdW5j"
"dGlvbihzdGVwLHNpKXsKICAgICAgICBpZihzaT4wKXsKICAgICAgICAgIGgrPSc8ZGl2IGNsYXNz"
"PSJjaGFpbi1hcnJvdyAnKyhzdGVwLnN0YXR1cz09PSdjb25maXJtZWQnPydjb25maXJtZWQnOicn"
"KSsnIj48L2Rpdj4nOwogICAgICAgIH0KICAgICAgICBoKz0nPGRpdiBjbGFzcz0iY2hhaW4tc3Rl"
"cCI+JzsKICAgICAgICBoKz0nPGRpdiBjbGFzcz0iY2hhaW4tc3RlcC1kb3QgJytzdGVwLnN0YXR1"
"cysnIj4nKyhzdGVwLnN0YXR1cz09PSdjb25maXJtZWQnPyfinJMnOic/JykrJzwvZGl2Pic7CiAg"
"ICAgICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLXN0ZXAtcGhhc2UiPicrc3RlcC5waGFzZSsnPC9k"
"aXY+JzsKICAgICAgICBoKz0nPGRpdiBjbGFzcz0iY2hhaW4tc3RlcC1sYWJlbCI+JytzdGVwLmxh"
"YmVsKyc8L2Rpdj4nOwogICAgICAgIGgrPSc8L2Rpdj4nOwogICAgICB9KTsKICAgICAgaCs9Jzwv"
"ZGl2Pic7CgogICAgICAvLyBJbXBhY3QKICAgICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLWltcGFj"
"dCI+PGRpdiBjbGFzcz0iY2hhaW4taW1wYWN0LXRpdGxlIj7imqEgQVRUQUNLIElNUEFDVDwvZGl2"
"Pic7CiAgICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFpbi1pbXBhY3QtdGV4dCI+JytjLmltcGFjdCsn"
"PC9kaXY+PC9kaXY+JzsKCiAgICAgIC8vIEJ1c2luZXNzIEltcGFjdCArIENvc3QKICAgICAgaCs9"
"JzxkaXYgY2xhc3M9ImNoYWluLWJ1c2luZXNzIj48ZGl2IGNsYXNzPSJjaGFpbi1idXNpbmVzcy10"
"aXRsZSI+8J+SvCBCVVNJTkVTUyBJTVBBQ1Q8L2Rpdj4nOwogICAgICBoKz0nPGRpdiBjbGFzcz0i"
"Y2hhaW4taW1wYWN0LXRleHQiPicrYy5idXNpbmVzc19pbXBhY3QrJzwvZGl2Pic7CiAgICAgIGgr"
"PSc8ZGl2IGNsYXNzPSJjaGFpbi1jb3N0Ij5Fc3RpbWF0ZWQgQ29zdDogJytjLmNvc3RfZXN0aW1h"
"dGUrJzwvZGl2PjwvZGl2Pic7CgogICAgICAvLyBGaXgKICAgICAgaCs9JzxkaXYgY2xhc3M9ImNo"
"YWluLWZpeCI+PGRpdiBjbGFzcz0iY2hhaW4tZml4LXRpdGxlIj7wn5uhIFJFTUVESUFUSU9OIENP"
"TU1BTkRTPC9kaXY+JzsKICAgICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLWZpeC1jbWQiPicrYy5m"
"aXgrJzwvZGl2PjwvZGl2Pic7CgogICAgICAvLyBDb21wbGlhbmNlCiAgICAgIGlmKGMuY29tcGxp"
"YW5jZSAmJiBPYmplY3Qua2V5cyhjLmNvbXBsaWFuY2UpLmxlbmd0aCl7CiAgICAgICAgaCs9Jzxk"
"aXYgY2xhc3M9ImNoYWluLWNvbXBsaWFuY2UiPic7CiAgICAgICAgT2JqZWN0LmtleXMoYy5jb21w"
"bGlhbmNlKS5mb3JFYWNoKGZ1bmN0aW9uKGZ3KXsKICAgICAgICAgIGgrPSc8ZGl2IGNsYXNzPSJj"
"aGFpbi1jb21wLXRhZyI+JytmdysnOiAnK2MuY29tcGxpYW5jZVtmd10rJzwvZGl2Pic7CiAgICAg"
"ICAgfSk7CiAgICAgICAgaCs9JzwvZGl2Pic7CiAgICAgIH0KCiAgICAgIGgrPSc8L2Rpdj4nOwog"
"ICAgfSk7CgogICAgY29udGFpbmVyLmlubmVySFRNTD1oOwogIH0pLmNhdGNoKGZ1bmN0aW9uKCl7"
"fSk7Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT0KICAgQURWQU5DRUQgUkVQT1JUIERPV05MT0FEICgzLUF1ZGllbmNl"
"KQogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09ICovCmZ1bmN0aW9uIGRvd25sb2FkQWR2YW5jZWRSZXBvcnQoKXsKICBmZXRj"
"aCgnL2FkdmFuY2VkX3JlcG9ydCcpLnRoZW4oZnVuY3Rpb24ocil7cmV0dXJuIHIuanNvbigpfSku"
"dGhlbihmdW5jdGlvbihycHQpewogICAgaWYocnB0LmVycm9yKXtub3RpZnkoJ05vIHJlcG9ydCBk"
"YXRhIHlldC4gUnVuIHNjYW5zIGZpcnN0LicpO3JldHVybn0KCiAgICB2YXIgY3NzID0gJ2JvZHl7"
"Zm9udC1mYW1pbHk6SGVsdmV0aWNhLEFyaWFsLHNhbnMtc2VyaWY7Y29sb3I6IzNhM2E0NDtwYWRk"
"aW5nOjQwcHg7bWF4LXdpZHRoOjExMDBweDttYXJnaW46YXV0bztmb250LXNpemU6MTNweDtsaW5l"
"LWhlaWdodDoxLjZ9JwogICAgICArICdoMXtjb2xvcjojZTYzOTQ2O2ZvbnQtc2l6ZToyOHB4O3Rl"
"eHQtYWxpZ246Y2VudGVyO21hcmdpbi1ib3R0b206NXB4fScKICAgICAgKyAnaDJ7Y29sb3I6I2U2"
"Mzk0Njtmb250LXNpemU6MTZweDtib3JkZXItYm90dG9tOjJweCBzb2xpZCAjZTYzOTQ2O3BhZGRp"
"bmctYm90dG9tOjZweDttYXJnaW4tdG9wOjMwcHh9JwogICAgICArICdoM3tjb2xvcjojMGEwYTBj"
"O2ZvbnQtc2l6ZToxM3B4O21hcmdpbi10b3A6MThweH0nCiAgICAgICsgJy5tZXRhe3RleHQtYWxp"
"Z246Y2VudGVyO2NvbG9yOiM4YThhOTY7Zm9udC1zaXplOjExcHg7bWFyZ2luLWJvdHRvbTozMHB4"
"fScKICAgICAgKyAnLnNjb3JlLWJveHt0ZXh0LWFsaWduOmNlbnRlcjtwYWRkaW5nOjMwcHg7Ym9y"
"ZGVyOjNweCBzb2xpZCAnK3JwdC5yaXNrX2xldmVsKyc7Ym9yZGVyLXJhZGl1czoxNnB4O21hcmdp"
"bjoyMHB4IGF1dG87bWF4LXdpZHRoOjMwMHB4fScKICAgICAgKyAnLnNjb3JlLW51bXtmb250LXNp"
"emU6NjRweDtmb250LXdlaWdodDo5MDA7Y29sb3I6JysoJyNkOTA0MjknKSsnO30nCiAgICAgICsg"
"Jy5zY29yZS1sYWJlbHtmb250LXNpemU6MThweDtmb250LXdlaWdodDo3MDA7Y29sb3I6IzNhM2E0"
"NH0nCiAgICAgICsgJy5jYXJke2JvcmRlci1sZWZ0OjRweCBzb2xpZCAjZDkwNDI5O3BhZGRpbmc6"
"MTJweCAxNnB4O21hcmdpbjoxMHB4IDA7YmFja2dyb3VuZDojZjdmN2Y4O2JvcmRlci1yYWRpdXM6"
"OHB4fScKICAgICAgKyAnLmNhcmQuSElHSHtib3JkZXItbGVmdC1jb2xvcjojZTg1ZDA0fS5jYXJk"
"Lk1FRElVTXtib3JkZXItbGVmdC1jb2xvcjojZTA5ZjNlfS5jYXJkLkxPV3tib3JkZXItbGVmdC1j"
"b2xvcjojMmQ2YTRmfScKICAgICAgKyAnLmZpeHtiYWNrZ3JvdW5kOiNmMGZkZjQ7Ym9yZGVyOjFw"
"eCBzb2xpZCAjYmJmN2QwO3BhZGRpbmc6MTJweDtib3JkZXItcmFkaXVzOjhweDttYXJnaW46OHB4"
"IDA7Zm9udC1mYW1pbHk6bW9ub3NwYWNlO2ZvbnQtc2l6ZToxMXB4O3doaXRlLXNwYWNlOnByZS13"
"cmFwfScKICAgICAgKyAnLmNvbXB7ZGlzcGxheTppbmxpbmUtYmxvY2s7YmFja2dyb3VuZDojZjFm"
"NWY5O2JvcmRlcjoxcHggc29saWQgI2UyZThmMDtwYWRkaW5nOjNweCA4cHg7Ym9yZGVyLXJhZGl1"
"czo0cHg7Zm9udC1zaXplOjEwcHg7bWFyZ2luOjJweH0nCiAgICAgICsgJ3RhYmxle3dpZHRoOjEw"
"MCU7Ym9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlO21hcmdpbjoxMHB4IDB9dGgsdGR7cGFkZGluZzo2"
"cHggMTBweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCAjZWNlY2VmO3RleHQtYWxpZ246bGVmdDtm"
"b250LXNpemU6MTFweH10aHtiYWNrZ3JvdW5kOiNmN2Y3Zjg7Zm9udC13ZWlnaHQ6NzAwfScKICAg"
"ICAgKyAnLnNldntwYWRkaW5nOjJweCA4cHg7Ym9yZGVyLXJhZGl1czoxMHB4O2ZvbnQtc2l6ZTox"
"MHB4O2ZvbnQtd2VpZ2h0OjcwMH0nCiAgICAgICsgJy5zZXYuQ1JJVElDQUx7YmFja2dyb3VuZDoj"
"ZmRkO2NvbG9yOiNkOTA0Mjl9LnNldi5ISUdIe2JhY2tncm91bmQ6I2ZlZDtjb2xvcjojZTg1ZDA0"
"fS5zZXYuTUVESVVNe2JhY2tncm91bmQ6I2ZmZDtjb2xvcjojYjg4NjBifS5zZXYuTE9Xe2JhY2tn"
"cm91bmQ6I2RmZDtjb2xvcjojMmQ2YTRmfScKICAgICAgKyAnLnNlY3Rpb257cGFnZS1icmVhay1p"
"bnNpZGU6YXZvaWR9JwogICAgICArICdAbWVkaWEgcHJpbnR7Ym9keXtwYWRkaW5nOjIwcHh9fSc7"
"CgogICAgdmFyIGIgPSAnPCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PG1ldGEgY2hhcnNldD0i"
"VVRGLTgiPjx0aXRsZT5IQVJTSEEgdjcuMCBBZHZhbmNlZCBWQVBUIFJlcG9ydDwvdGl0bGU+PHN0"
"eWxlPicrY3NzKyc8L3N0eWxlPjwvaGVhZD48Ym9keT4nOwoKICAgIC8vIEhFQURFUgogICAgYiAr"
"PSAnPGgxPkhBUlNIQSB2Ny4wPC9oMT4nOwogICAgYiArPSAnPGRpdiBzdHlsZT0idGV4dC1hbGln"
"bjpjZW50ZXI7Zm9udC1zaXplOjE2cHg7Y29sb3I6IzhhOGE5NjttYXJnaW4tYm90dG9tOjVweCI+"
"QURWQU5DRUQgVkFQVCBSRVBPUlQ8L2Rpdj4nOwogICAgYiArPSAnPGRpdiBjbGFzcz0ibWV0YSI+"
"VGFyZ2V0OiAnK3JwdC50YXJnZXQrJyB8IEdlbmVyYXRlZDogJytycHQuZ2VuZXJhdGVkKyc8L2Rp"
"dj4nOwoKICAgIC8vIFJJU0sgU0NPUkUKICAgIGIgKz0gJzxkaXYgY2xhc3M9InNjb3JlLWJveCI+"
"PGRpdiBjbGFzcz0ic2NvcmUtbnVtIj4nK3JwdC5yaXNrX3Njb3JlKyc8L2Rpdj4nOwogICAgYiAr"
"PSAnPGRpdiBjbGFzcz0ic2NvcmUtbGFiZWwiPicrcnB0LnJpc2tfbGV2ZWwrJyBSSVNLPC9kaXY+"
"PC9kaXY+JzsKCiAgICAvLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT0KICAgIC8vIFNFQ1RJT04gMTogRVhFQ1VUSVZFIFNVTU1BUlkKICAgIC8vID09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICAgYiArPSAnPGgyPvCfk4sgU0VDVElP"
"TiAxOiBFWEVDVVRJVkUgU1VNTUFSWTwvaDI+JzsKICAgIGIgKz0gJzxkaXYgc3R5bGU9ImJhY2tn"
"cm91bmQ6I2ZmZjhmODtib3JkZXI6MXB4IHNvbGlkICNmZWNhY2E7cGFkZGluZzoxNnB4O2JvcmRl"
"ci1yYWRpdXM6OHB4O21hcmdpbjoxMnB4IDAiPic7CiAgICBiICs9ICc8cCBzdHlsZT0iZm9udC1z"
"aXplOjE0cHg7Zm9udC13ZWlnaHQ6NjAwIj4nK3JwdC5leGVjdXRpdmUuaGVhZGxpbmUrJzwvcD4n"
"OwogICAgYiArPSAnPHA+JytycHQuZXhlY3V0aXZlLnJpc2tfc3VtbWFyeSsnPC9wPic7CiAgICBi"
"ICs9ICc8L2Rpdj4nOwoKICAgIGIgKz0gJzxoMz5LZXkgQnVzaW5lc3MgUmlza3M8L2gzPic7CiAg"
"ICBpZihycHQuZXhlY3V0aXZlLmJ1c2luZXNzX3Jpc2tzLmxlbmd0aCl7CiAgICAgIHJwdC5leGVj"
"dXRpdmUuYnVzaW5lc3Nfcmlza3MuZm9yRWFjaChmdW5jdGlvbihyLGkpewogICAgICAgIGIgKz0g"
"JzxkaXYgY2xhc3M9ImNhcmQgQ1JJVElDQUwiPjxiPlJpc2sgJysoaSsxKSsnOjwvYj4gJytyKyc8"
"L2Rpdj4nOwogICAgICB9KTsKICAgIH0KCiAgICBiICs9ICc8aDM+Q29zdCBFeHBvc3VyZTwvaDM+"
"JzsKICAgIGlmKHJwdC5leGVjdXRpdmUuY29zdF9leHBvc3VyZS5sZW5ndGgpewogICAgICBycHQu"
"ZXhlY3V0aXZlLmNvc3RfZXhwb3N1cmUuZm9yRWFjaChmdW5jdGlvbihjLGkpewogICAgICAgIGIg"
"Kz0gJzxkaXYgY2xhc3M9ImNhcmQgSElHSCI+PGI+Q2hhaW4gJysoaSsxKSsnOjwvYj4gJytjKyc8"
"L2Rpdj4nOwogICAgICB9KTsKICAgIH0KCiAgICBiICs9ICc8aDM+UHJpb3JpdHkgQWN0aW9uczwv"
"aDM+JzsKICAgIGIgKz0gJzx0YWJsZT48dHI+PHRoPiM8L3RoPjx0aD5BdHRhY2sgQ2hhaW48L3Ro"
"Pjx0aD5Qcmlvcml0eTwvdGg+PHRoPkltbWVkaWF0ZSBBY3Rpb248L3RoPjwvdHI+JzsKICAgIHJw"
"dC5leGVjdXRpdmUudG9wX3JlY29tbWVuZGF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHIsaSl7CiAg"
"ICAgIGIgKz0gJzx0cj48dGQ+JysoaSsxKSsnPC90ZD48dGQ+JytyLmNoYWluKyc8L3RkPjx0ZD48"
"c3BhbiBjbGFzcz0ic2V2ICcrci5wcmlvcml0eSsnIj4nK3IucHJpb3JpdHkrJzwvc3Bhbj48L3Rk"
"Pjx0ZD4nK3IuYWN0aW9uKyc8L3RkPjwvdHI+JzsKICAgIH0pOwogICAgYiArPSAnPC90YWJsZT4n"
"OwoKICAgIC8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICAg"
"Ly8gU0VDVElPTiAyOiBURUNITklDQUwgRklORElOR1MKICAgIC8vID09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PQogICAgYiArPSAnPGgyPvCflKcgU0VDVElPTiAyOiBU"
"RUNITklDQUwgRklORElOR1M8L2gyPic7CgogICAgLy8gQXR0YWNrIENoYWlucwogICAgdmFyIGNo"
"YWlucyA9IHJwdC50ZWNobmljYWwuY2hhaW5zIHx8IFtdOwogICAgaWYoY2hhaW5zLmxlbmd0aCl7"
"CiAgICAgIGIgKz0gJzxoMz5BdHRhY2sgQ2hhaW5zICgnK2NoYWlucy5sZW5ndGgrJyBmb3VuZCk8"
"L2gzPic7CiAgICAgIGNoYWlucy5mb3JFYWNoKGZ1bmN0aW9uKGMsaSl7CiAgICAgICAgYiArPSAn"
"PGRpdiBjbGFzcz0ic2VjdGlvbiI+PGRpdiBjbGFzcz0iY2FyZCAnK2Muc2V2ZXJpdHkrJyI+PGI+"
"Q2hhaW4gJysoaSsxKSsnOiAnK2MubmFtZSsnPC9iPiA8c3BhbiBjbGFzcz0ic2V2ICcrYy5zZXZl"
"cml0eSsnIj4nK2Muc2V2ZXJpdHkrJzwvc3Bhbj4gKCcrYy5jb25maWRlbmNlKyclIGNvbmZpZGVu"
"Y2UpJzsKICAgICAgICBiICs9ICc8YnI+PHNtYWxsIHN0eWxlPSJjb2xvcjojOGE4YTk2Ij5LaWxs"
"IENoYWluOiAnK2Mua2lsbF9jaGFpbisnPC9zbWFsbD4nOwogICAgICAgIGIgKz0gJzxicj48YnI+"
"PGI+SW1wYWN0OjwvYj4gJytjLmltcGFjdDsKICAgICAgICBiICs9ICc8YnI+PGJyPjxiPlN0ZXBz"
"OjwvYj48b2wgc3R5bGU9Im1hcmdpbjo2cHggMCI+JzsKICAgICAgICBjLnN0ZXBzLmZvckVhY2go"
"ZnVuY3Rpb24ocyl7CiAgICAgICAgICB2YXIgaWNvbiA9IHMuc3RhdHVzPT09J2NvbmZpcm1lZCcg"
"PyAn4pyFJyA6ICfinZMnOwogICAgICAgICAgYiArPSAnPGxpPicraWNvbisnIFsnK3MucGhhc2Ur"
"J10gJytzLmxhYmVsKyc8L2xpPic7CiAgICAgICAgfSk7CiAgICAgICAgYiArPSAnPC9vbD4nOwog"
"ICAgICAgIGIgKz0gJzxkaXYgY2xhc3M9ImZpeCI+JytjLmZpeCsnPC9kaXY+JzsKICAgICAgICBi"
"ICs9ICc8L2Rpdj48L2Rpdj4nOwogICAgICB9KTsKICAgIH0KCiAgICAvLyBPcGVuIFBvcnRzCiAg"
"ICB2YXIgcG9ydHMgPSBycHQudGVjaG5pY2FsLnBvcnRzIHx8IFtdOwogICAgaWYocG9ydHMubGVu"
"Z3RoKXsKICAgICAgYiArPSAnPGgzPk9wZW4gUG9ydHMgKCcrcG9ydHMubGVuZ3RoKycpPC9oMz4n"
"OwogICAgICBiICs9ICc8dGFibGU+PHRyPjx0aD5Qb3J0PC90aD48dGg+U2VydmljZTwvdGg+PHRo"
"PlJpc2s8L3RoPjx0aD5EZXNjcmlwdGlvbjwvdGg+PHRoPlJlbWVkaWF0aW9uPC90aD48L3RyPic7"
"CiAgICAgIHBvcnRzLmZvckVhY2goZnVuY3Rpb24ocCl7CiAgICAgICAgYiArPSAnPHRyPjx0ZD4n"
"K3AucG9ydCsnLycrcC5wcm90bysnPC90ZD48dGQ+JytwLnNlcnZpY2UrJzwvdGQ+PHRkPjxzcGFu"
"IGNsYXNzPSJzZXYgJytwLnNldmVyaXR5KyciPicrcC5zZXZlcml0eSsnPC9zcGFuPjwvdGQ+PHRk"
"PicrcC5kZXNjKyc8L3RkPjx0ZCBzdHlsZT0iZm9udC1zaXplOjEwcHgiPicrcC5maXgrJzwvdGQ+"
"PC90cj4nOwogICAgICB9KTsKICAgICAgYiArPSAnPC90YWJsZT4nOwogICAgfQoKICAgIC8vIFRo"
"cmVhdHMKICAgIHZhciB0aHJlYXRzID0gcnB0LnRlY2huaWNhbC50aHJlYXRzIHx8IFtdOwogICAg"
"aWYodGhyZWF0cy5sZW5ndGgpewogICAgICBiICs9ICc8aDM+VnVsbmVyYWJpbGl0aWVzICgnK3Ro"
"cmVhdHMubGVuZ3RoKycpPC9oMz4nOwogICAgICB0aHJlYXRzLmZvckVhY2goZnVuY3Rpb24odCxp"
"KXsKICAgICAgICBiICs9ICc8ZGl2IGNsYXNzPSJjYXJkICcrdC5zZXZlcml0eSsnIj48Yj4nKyhp"
"KzEpKycuICcrdC5uYW1lKyc8L2I+IDxzcGFuIGNsYXNzPSJzZXYgJyt0LnNldmVyaXR5KyciPicr"
"dC5zZXZlcml0eSsnPC9zcGFuPic7CiAgICAgICAgYiArPSAnPGJyPicrdC5kZXNjOwogICAgICAg"
"IGIgKz0gJzxkaXYgY2xhc3M9ImZpeCI+RklYOiAnK3QuZml4Kyc8L2Rpdj48L2Rpdj4nOwogICAg"
"ICB9KTsKICAgIH0KCiAgICAvLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT0KICAgIC8vIFNFQ1RJT04gMzogQ09NUExJQU5DRSBNQVBQSU5HCiAgICAvLyA9PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgIGIgKz0gJzxoMj7wn5OcIFNF"
"Q1RJT04gMzogQ09NUExJQU5DRSBNQVBQSU5HPC9oMj4nOwogICAgdmFyIGZ3ID0gcnB0LmNvbXBs"
"aWFuY2UuZnJhbWV3b3JrcyB8fCB7fTsKICAgIHZhciBmd0tleXMgPSBPYmplY3Qua2V5cyhmdyk7"
"CiAgICBpZihmd0tleXMubGVuZ3RoKXsKICAgICAgZndLZXlzLmZvckVhY2goZnVuY3Rpb24oZmsp"
"ewogICAgICAgIGIgKz0gJzxoMz4nK2ZrKyc8L2gzPic7CiAgICAgICAgYiArPSAnPHRhYmxlPjx0"
"cj48dGg+Q29udHJvbDwvdGg+PHRoPklzc3VlIEZvdW5kPC90aD48dGg+U2V2ZXJpdHk8L3RoPjwv"
"dHI+JzsKICAgICAgICBmd1tma10uZm9yRWFjaChmdW5jdGlvbihpdGVtKXsKICAgICAgICAgIGIg"
"Kz0gJzx0cj48dGQ+PHNwYW4gY2xhc3M9ImNvbXAiPicraXRlbS5jb250cm9sKyc8L3NwYW4+PC90"
"ZD48dGQ+JytpdGVtLmlzc3VlKyc8L3RkPjx0ZD48c3BhbiBjbGFzcz0ic2V2ICcraXRlbS5zZXZl"
"cml0eSsnIj4nK2l0ZW0uc2V2ZXJpdHkrJzwvc3Bhbj48L3RkPjwvdHI+JzsKICAgICAgICB9KTsK"
"ICAgICAgICBiICs9ICc8L3RhYmxlPic7CiAgICAgIH0pOwogICAgfSBlbHNlIHsKICAgICAgYiAr"
"PSAnPHAgc3R5bGU9ImNvbG9yOiM4YThhOTYiPk5vIGNvbXBsaWFuY2UgZGF0YSBhdmFpbGFibGUg"
"eWV0LiBSdW4gbW9yZSBzY2FucyB0byBnZW5lcmF0ZSBjb21wbGlhbmNlIG1hcHBpbmcuPC9wPic7"
"CiAgICB9CgogICAgLy8gRk9PVEVSCiAgICBiICs9ICc8ZGl2IHN0eWxlPSJtYXJnaW4tdG9wOjQw"
"cHg7cGFkZGluZy10b3A6MjBweDtib3JkZXItdG9wOjJweCBzb2xpZCAjZWNlY2VmO3RleHQtYWxp"
"Z246Y2VudGVyO2NvbG9yOiM4YThhOTY7Zm9udC1zaXplOjEwcHgiPic7CiAgICBiICs9ICdIQVJT"
"SEEgdjcuMCBWQVBUIFN1aXRlIOKAlCBBZHZhbmNlZCBTZWN1cml0eSBSZXBvcnQ8YnI+JzsKICAg"
"IGIgKz0gJ0dlbmVyYXRlZDogJytycHQuZ2VuZXJhdGVkKycgfCBDbGFzc2lmaWNhdGlvbjogQ09O"
"RklERU5USUFMJzsKICAgIGIgKz0gJzwvZGl2Pic7CgogICAgYiArPSAnPC9ib2R5PjwvaHRtbD4n"
"OwoKICAgIHZhciBhID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYScpOwogICAgYS5ocmVmID0g"
"VVJMLmNyZWF0ZU9iamVjdFVSTChuZXcgQmxvYihbYl0se3R5cGU6J3RleHQvaHRtbCd9KSk7CiAg"
"ICBhLmRvd25sb2FkID0gJ0hBUlNIQV92N19BZHZhbmNlZF9WQVBUX1JlcG9ydC5odG1sJzsKICAg"
"IGEuY2xpY2soKTsKICAgIG5vdGlmeSgnQWR2YW5jZWQgcmVwb3J0IGRvd25sb2FkZWQhJyk7CiAg"
"fSkuY2F0Y2goZnVuY3Rpb24oZSl7bm90aWZ5KCdFcnJvciBnZW5lcmF0aW5nIHJlcG9ydDogJytl"
"Lm1lc3NhZ2UpfSk7Cn0KCi8qIFJlZnJlc2ggY2hhaW5zIHdoZW4gc3dpdGNoaW5nIHRvIHRoZSB0"
"YWIgKi8KdmFyIF9vcmlnU3dpdGNoVGFiID0gc3dpdGNoVGFiOwpzd2l0Y2hUYWIgPSBmdW5jdGlv"
"bih0YWIsIGJ0bikgewogIF9vcmlnU3dpdGNoVGFiKHRhYiwgYnRuKTsKICBpZih0YWIgPT09ICdj"
"aGFpbnMnKSByZWZyZXNoQXR0YWNrQ2hhaW5zKCk7Cn07CgovKiBBbHNvIHJlZnJlc2ggYWZ0ZXIg"
"ZWFjaCBzY2FuIGNvbXBsZXRlcyAqLwp2YXIgY2hhaW5Qb2xsQ291bnQgPSAwOwpzZXRJbnRlcnZh"
"bChmdW5jdGlvbigpewogIGlmKGxhc3RQaGFzZSA9PT0gJ2NvbXBsZXRlJyAmJiBjaGFpblBvbGxD"
"b3VudCA8IDMpewogICAgcmVmcmVzaEF0dGFja0NoYWlucygpOwogICAgY2hhaW5Qb2xsQ291bnQr"
"KzsKICB9CiAgaWYobGFzdFBoYXNlICE9PSAnY29tcGxldGUnKSBjaGFpblBvbGxDb3VudCA9IDA7"
"Cn0sIDIwMDApOwoKLyogS0VZQk9BUkQgU0hPUlRDVVRTICovCmRvY3VtZW50LmFkZEV2ZW50TGlz"
"dGVuZXIoJ2tleWRvd24nLGZ1bmN0aW9uKGUpewogIGlmKGUuY3RybEtleSYmZS5rZXk9PT0nLycp"
"e2UucHJldmVudERlZmF1bHQoKTtkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndG9vbC1zZWFyY2gn"
"KS5mb2N1cygpfQp9KTsKPC9zY3JpcHQ+Cgo8L2JvZHk+CjwvaHRtbD4K"
)
# EMBEDDED UI — SINGLE FILE, NO EXTERNAL DEPENDENCIES
# ═══════════════════════════════════════════════════════
_UI_OVERRIDES = """
<style id="fg-ui-overrides">
:root{
    --sidebar-w:252px;
    --header-h:68px;
    --radius:12px;
    --radius-lg:20px;
    --radius-xl:24px;
    --black:#07090d;
    --black-2:#0f1320;
    --black-3:#171d2b;
    --white:#fdfefe;
    --white-2:#f5f8fc;
    --white-3:#e8edf5;
    --red:#1f6fff;
    --red-dark:#1557d6;
    --red-glow:rgba(31,111,255,.34);
    --teal:#1ec8b0;
    --neon-green:#8dff6a;
    --neon-green-soft:#b9ff9f;
    --accent-blue:#1f6fff;
    --accent-blue-dark:#1557d6;
    --accent-blue-soft:rgba(31,111,255,.20);
    --tx-body:#10131a;
}
html,body{background:#07090d !important;}
body{
    font-family:'Outfit',sans-serif !important;
    -webkit-font-smoothing:antialiased;
    text-rendering:optimizeLegibility;
}
.app{
    background:linear-gradient(145deg,#0b1020 0%,#0a0e17 35%,#090b11 100%) !important;
}
.sidebar{
    width:var(--sidebar-w) !important;
    min-width:var(--sidebar-w) !important;
    background:linear-gradient(180deg,#0f1524 0%,#0a0d16 100%) !important;
    border-right:1px solid rgba(255,255,255,.07) !important;
    box-shadow:inset -1px 0 0 rgba(255,255,255,.04), 12px 0 26px rgba(0,0,0,.22);
}
.sidebar::before{
    content:"";
    position:absolute;
    top:-140px;
    right:-80px;
    width:260px;
    height:260px;
    border-radius:50%;
    background:radial-gradient(circle, rgba(31,111,255,.22) 0%, rgba(31,111,255,0) 70%);
    pointer-events:none;
}
.s-logo{padding:20px 18px 16px !important; border-bottom:1px solid rgba(255,255,255,.07) !important; display:flex !important; align-items:center !important; gap:12px !important; overflow:hidden !important;}
.s-logo-mark,
.s-avatar{
    border-radius:12px !important;
    box-shadow:0 14px 30px rgba(31,111,255,.28) !important;
    background:linear-gradient(140deg,#1f6fff,#1ec8b0) !important;
}
.s-logo-mark{display:none !important;}
.s-logo-image{width:38px !important; height:38px !important; object-fit:contain !important; display:block !important; flex-shrink:0 !important;}
.s-logo > div{min-width:0 !important;}
.s-logo-text{font-size:19px !important; letter-spacing:.3px !important; color:#ffffff !important; font-weight:800 !important; white-space:nowrap !important;}
.s-logo-sub{font-size:10px !important; letter-spacing:2.4px !important; color:#9da8bf !important; text-transform:uppercase !important;}
.s-search{padding:14px 14px 10px !important;}
.s-search input{
    height:40px !important;
    border-radius:12px !important;
    border:1px solid rgba(255,255,255,.08) !important;
    background:#121a2b !important;
    color:#f0f4fb !important;
}
.s-nav{
    border-radius:16px !important;
    margin:4px 0 !important;
    min-height:40px !important;
    background:transparent !important;
    border:1px solid rgba(255,255,255,.05) !important;
}
.s-nav:hover{
    background:rgba(255,255,255,.09) !important;
    border-color:rgba(255,255,255,.14) !important;
    transform:translateX(1px);
}
.s-nav.active,
.s-nav[style*="--active"]{
    background:linear-gradient(90deg, rgba(31,111,255,.30), rgba(30,200,176,.14)) !important;
    border:1px solid rgba(31,111,255,.44) !important;
    box-shadow:0 8px 22px rgba(31,111,255,.20) !important;
}
.s-nav .ico{font-size:15px !important; opacity:1 !important; filter:saturate(1.15);}
.s-nav .lbl{
    font-size:11.5px !important;
    font-weight:600 !important;
    letter-spacing:.2px !important;
    color:#9fd4ff !important;
    text-shadow:none;
}
.s-section-header{
    border-radius:14px !important;
    padding:10px 10px !important;
    margin:8px 0 6px !important;
    background:rgba(255,255,255,.03) !important;
    border:1px solid rgba(255,255,255,.06) !important;
}
.s-section-title{
    font-size:13.5px !important;
    font-weight:800 !important;
    letter-spacing:.16em !important;
    text-transform:uppercase !important;
    color:var(--neon-green) !important;
    text-shadow:0 0 10px rgba(141,255,106,.22);
}
.s-section-icon{
    font-size:16px !important;
    opacity:1 !important;
    filter:saturate(1.25) brightness(1.05);
    text-shadow:0 0 10px rgba(141,255,106,.18);
}
.s-section-count{
    min-width:22px !important;
    height:22px !important;
    border-radius:999px !important;
    background:rgba(255,255,255,.09) !important;
    color:#f1f6ff !important;
    font-size:11px !important;
    font-weight:700 !important;
    display:inline-flex !important;
    align-items:center !important;
    justify-content:center !important;
    border:1px solid rgba(255,255,255,.12) !important;
}
.s-section-arrow{color:#b9c8e8 !important;}
.s-tag{
    border-radius:10px !important;
    padding:2px 8px !important;
    font-size:9px !important;
    font-weight:800 !important;
    letter-spacing:.08em !important;
}
.s-footer{padding:14px 16px 16px !important; border-top:1px solid rgba(255,255,255,.07) !important;}
.main{
    background:
    radial-gradient(circle at 82% -18%, rgba(31,111,255,.15), rgba(31,111,255,0) 36%),
      radial-gradient(circle at 24% 118%, rgba(30,200,176,.10), rgba(30,200,176,0) 40%),
      linear-gradient(180deg,#f8fbff 0%,#eef3fa 100%) !important;
}
.header,
.top,
.toolbar{
    height:var(--header-h) !important;
    background:rgba(10,14,22,.96) !important;
    border-bottom:1px solid rgba(255,255,255,.08) !important;
    backdrop-filter:blur(8px);
}
.tab-wrap,
.tabs,
.tab-bar{
    background:rgba(255,255,255,.74) !important;
    border-bottom:1px solid rgba(15,23,42,.10) !important;
}
.tab-btn{
    border-radius:999px !important;
    padding:10px 18px !important;
    font-size:12px !important;
    letter-spacing:.25px !important;
    color:#445066 !important;
}
.tab-btn.active{
    background:#ffffff !important;
    color:var(--accent-blue) !important;
    border-bottom-color:var(--accent-blue) !important;
    box-shadow:0 8px 22px rgba(31,111,255,.18) !important;
}
.btn-report{
    background:linear-gradient(135deg, var(--accent-blue), #3f8dff) !important;
    border:1px solid rgba(255,255,255,.14) !important;
    color:#ffffff !important;
    box-shadow:0 10px 24px rgba(31,111,255,.30) !important;
}
.btn-report:hover{
    background:linear-gradient(135deg, #2a79ff, var(--accent-blue-dark)) !important;
}
.h-mini-progress{
    background:rgba(31,111,255,.12) !important;
}
.h-mini-bar{
    background:linear-gradient(90deg, #2a79ff, #6aa8ff) !important;
    box-shadow:0 0 16px rgba(31,111,255,.35) !important;
}
.terminal-card{
    border-radius:22px !important;
    border:1px solid rgba(255,255,255,.08) !important;
    background:linear-gradient(180deg,#05070d 0%,#070a13 100%) !important;
    box-shadow:0 26px 56px rgba(3,7,18,.26) !important;
}
.term-title,
.terminal-title{
    color:#9fb0ce !important;
    letter-spacing:2px !important;
    font-size:11px !important;
}
#terminal-output{
    padding:20px 22px !important;
    min-height:300px !important;
    max-height:54vh !important;
    font-size:12px !important;
    line-height:1.7 !important;
}
.card{
    border-radius:18px !important;
    border:1px solid rgba(15,23,42,.10) !important;
    box-shadow:0 12px 30px rgba(15,23,42,.08) !important;
    background:rgba(255,255,255,.96) !important;
}
.chat-panel{
    border-top:1px solid rgba(31,111,255,.35) !important;
    box-shadow:0 -14px 34px rgba(9,12,20,.16) !important;
    background:rgba(8,11,19,.98) !important;
}
.chat-toggle{height:52px !important; padding:0 18px !important;}
.chat-toggle-label{
    font-size:11px !important;
    letter-spacing:.14em !important;
    text-transform:uppercase !important;
}
.chat-messages{background:#f9fbff !important;}
.msg.ai .msg-body{border:1px solid rgba(15,23,42,.08) !important; box-shadow:none !important;}

@media (max-width: 900px){
    :root{--sidebar-w:84px;}
    .s-logo-text,.s-logo-sub,.s-uname,.s-urole,.s-search{display:none !important;}
    .s-logo{justify-content:center !important;}
    .s-footer{justify-content:center !important; padding:12px 8px !important;}
    .s-nav .lbl{display:none !important;}
    .s-nav{justify-content:center !important;}
    #terminal-output{min-height:220px !important; max-height:44vh !important;}
}
</style>
"""

def get_html():
    import base64
    html = base64.b64decode(_HTML_B64).decode("utf-8")
    logo_path = os.path.join(os.path.dirname(__file__), "fg.png")
    if os.path.exists(logo_path):
        with open(logo_path, "rb") as logo_file:
            logo_b64 = base64.b64encode(logo_file.read()).decode("ascii")
        logo_uri = "data:image/png;base64," + logo_b64
    else:
        logo_uri = ""
    # Keep branding consistent even when legacy labels exist inside embedded UI payload.
    html = re.sub(r"harsha", "FG", html, flags=re.IGNORECASE)
    html = re.sub(r'(<div class="s-logo-mark">\s*)H(\s*</div>)', r'\1F\2', html, flags=re.IGNORECASE)
    html = re.sub(r'(<div class="s-avatar">\s*)HA(\s*</div>)', r'\1FG\2', html, flags=re.IGNORECASE)
    html = html.replace('<span class="s-section-icon">🖥</span>', '<span class="s-section-icon">🛠️</span>')
    html = html.replace('<span class="s-section-icon">☢</span>', '<span class="s-section-icon">🧪</span>')
    html = html.replace("<title>FG — VAPT Command Suite</title>", "<title>FluentGrid — VAPT Command Suite</title>", 1)
    html = html.replace('<div class="s-logo-mark">F</div>', '<img class="s-logo-image" src="' + logo_uri + '" alt="FluentGrid logo">', 1)
    html = html.replace('<div class="s-logo-text">FG</div>', '<div class="s-logo-text">FluentGrid</div>', 1)
    html = html.replace('FG AI v7.0', 'FluentGrid AI V10.0')
    html = html.replace('FG v7.0', 'FluentGrid V10.0')
    html = html.replace('VAPT SUITE v7.0', 'VAPT SUITE V10.0')
    html = html.replace("</head>", '<link rel="icon" type="image/png" href="' + logo_uri + '">' + _UI_OVERRIDES + "</head>", 1)
    # ── Inject Reports panel JS ──
    # Use rfind to target the real </body> tag, not the one inside downloadHTML() JS string
    idx = html.rfind("</body>")
    html = html[:idx] + _JS_REPORTS + html[idx:]
    return html

@app.route("/")
def index():
    resp = Response(get_html(), mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

if __name__ == "__main__":
    print("""
================================================================
    FluentGrid AI V10.0 - FULL VAPT SUITE
  Web VAPT + Network VAPT + Infrastructure VAPT
================================================================
  Open browser: http://localhost:5000
  TIP: chmod +s /usr/bin/nmap
  TIP: pip install wafw00f sqlmap
==========================================
    """)
    app.run(debug=False, host="0.0.0.0", port=5000)
