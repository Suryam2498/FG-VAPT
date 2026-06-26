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
                "Required tool not installed or not available in PATH: " + executable + "\n"
                "Install it first, or run this project in Kali Linux / WSL for full tool support.\n\n"
                "Command:\n" + cmd
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
#fg-reports-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9100;align-items:center;justify-content:center}
#fg-reports-overlay.open{display:flex}
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
  document.getElementById('fg-reports-overlay').classList.add('open');
  fgLoadReports();
}
function fgReportsClose(){
  document.getElementById('fg-reports-overlay').classList.remove('open');
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
          '<button class="dl-btn-sm" onclick="fgDownloadReport(''+r.id+'')">&#x2B07; HTML</button>'+
          '<button class="del-btn-sm" onclick="fgDeleteReport(''+r.id+'',this)" title="Delete">&#x1F5D1;</button>'+
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
"O2hlaWdodDoycHg7CiAgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsdHJhbnNwYXJl"
"bnQsdmFyKC0tcmVkLWdsb3cpLHRyYW5zcGFyZW50KTsKICBhbmltYXRpb246c2NhbmxpbmUgNHMg"
"bGluZWFyIGluZmluaXRlOwogIHBvaW50ZXItZXZlbnRzOm5vbmU7b3BhY2l0eTouNTsKfQoudGVy"
"bS1oZWFkZXJ7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRl"
"bnQ6c3BhY2UtYmV0d2VlbjsKICBwYWRkaW5nOjEwcHggMThweDtib3JkZXItYm90dG9tOjFweCBz"
"b2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMDYpOwogIGJhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjMp"
"Owp9Ci50ZXJtLWRvdHN7ZGlzcGxheTpmbGV4O2dhcDo2cHh9Ci50ZXJtLWRvdHMgc3Bhbnt3aWR0"
"aDoxMHB4O2hlaWdodDoxMHB4O2JvcmRlci1yYWRpdXM6NTAlfQoudGVybS1kb3RzIC5kMXtiYWNr"
"Z3JvdW5kOnZhcigtLXJlZCl9Ci50ZXJtLWRvdHMgLmQye2JhY2tncm91bmQ6I2UwOWYzZX0KLnRl"
"cm0tZG90cyAuZDN7YmFja2dyb3VuZDojMmQ2YTRmfQoudGVybS10aXRsZXtmb250LWZhbWlseTon"
"SUJNIFBsZXggTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMHB4O2NvbG9yOnZhcigtLXR4LW9u"
"LWRhcmstbXV0ZWQpO2xldHRlci1zcGFjaW5nOjEuNXB4fQoudGVybS1hY3Rpb25ze2Rpc3BsYXk6"
"ZmxleDtnYXA6NnB4fQoudGVybS1hY3R7CiAgcGFkZGluZzo0cHggMTJweDtib3JkZXItcmFkaXVz"
"OjRweDsKICBiYWNrZ3JvdW5kOnJnYmEoMjU1LDI1NSwyNTUsMC4wNSk7Ym9yZGVyOjFweCBzb2xp"
"ZCByZ2JhKDI1NSwyNTUsMjU1LDAuMDgpOwogIGNvbG9yOnZhcigtLXR4LW9uLWRhcmstbXV0ZWQp"
"O2ZvbnQtc2l6ZTo5LjVweDtmb250LXdlaWdodDo2MDA7CiAgZm9udC1mYW1pbHk6J0lCTSBQbGV4"
"IE1vbm8nLG1vbm9zcGFjZTtjdXJzb3I6cG9pbnRlcjsKICB0cmFuc2l0aW9uOmFsbCAuMTVzO2xl"
"dHRlci1zcGFjaW5nOi41cHg7Cn0KLnRlcm0tYWN0OmhvdmVye2JhY2tncm91bmQ6cmdiYSgyNTUs"
"MjU1LDI1NSwwLjEpO2NvbG9yOnZhcigtLXdoaXRlKX0KCi5sb2FkaW5nLWJhcntoZWlnaHQ6MnB4"
"O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHZhcigtLXJlZCksI2ZmNmI2Yix2YXIo"
"LS1yZWQpKTtiYWNrZ3JvdW5kLXNpemU6MjAwJSAxMDAlO2FuaW1hdGlvbjpzaGltbWVyIDEuNXMg"
"aW5maW5pdGU7ZGlzcGxheTpub25lfQoKI3Rlcm1pbmFsLW91dHB1dHsKICBwYWRkaW5nOjE2cHgg"
"MThweDttaW4taGVpZ2h0OjI2MHB4O21heC1oZWlnaHQ6NTB2aDsKICBvdmVyZmxvdy15OmF1dG87"
"Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTEuNXB4Owog"
"IGNvbG9yOnZhcigtLXR4LW9uLWRhcmstbXV0ZWQpOwp9Ci50bHtwYWRkaW5nOjJweCAwO2xpbmUt"
"aGVpZ2h0OjEuNjU7d29yZC1icmVhazpicmVhay1hbGx9Ci50bC5oZHJ7Y29sb3I6dmFyKC0tcmVk"
"KTtmb250LXdlaWdodDo2MDB9Ci50bC5wcm9tcHR7Y29sb3I6IzRhZGU4MH0KLnRsLnJlc3VsdHtj"
"b2xvcjp2YXIoLS10eC1vbi1kYXJrLW11dGVkKX0KLnRsLmVycm9ye2NvbG9yOnZhcigtLXJlZC1s"
"aWdodCl9Ci50bC5pbmZve2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4zKX0KLmJsaW5re2FuaW1h"
"dGlvbjpwdWxzZSAxcyBzdGVwLWVuZCBpbmZpbml0ZX0KCi8qID09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgREFTSEJPQVJE"
"IENBUkRTIOKAlCBXSElURSBDQVJEUyBPTiBMSUdIVCBCRwogICA9PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi5kYXNoLWdy"
"aWR7ZGlzcGxheTpncmlkO2dhcDoxOHB4fQouZGFzaC1ncmlkLmNvbHMtNHtncmlkLXRlbXBsYXRl"
"LWNvbHVtbnM6cmVwZWF0KDQsMWZyKX0KLmRhc2gtZ3JpZC5jb2xzLTN7Z3JpZC10ZW1wbGF0ZS1j"
"b2x1bW5zOnJlcGVhdCgzLDFmcil9Ci5kYXNoLWdyaWQuY29scy0ye2dyaWQtdGVtcGxhdGUtY29s"
"dW1uczpyZXBlYXQoMiwxZnIpfQouZGFzaC1ncmlkLmNvbHMtMXtncmlkLXRlbXBsYXRlLWNvbHVt"
"bnM6MWZyfQoKLmNhcmR7CiAgYmFja2dyb3VuZDp2YXIoLS13aGl0ZSk7CiAgYm9yZGVyOjFweCBz"
"b2xpZCB2YXIoLS13aGl0ZS0zKTsKICBib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy1sZyk7CiAg"
"cGFkZGluZzoyMHB4IDIycHg7CiAgdHJhbnNpdGlvbjphbGwgLjI1czsKICBwb3NpdGlvbjpyZWxh"
"dGl2ZTsKICBhbmltYXRpb246ZmFkZVVwIC41cyBlYXNlIGJvdGg7Cn0KLmNhcmQ6bnRoLWNoaWxk"
"KDEpe2FuaW1hdGlvbi1kZWxheTouMDVzfQouY2FyZDpudGgtY2hpbGQoMil7YW5pbWF0aW9uLWRl"
"bGF5Oi4xc30KLmNhcmQ6bnRoLWNoaWxkKDMpe2FuaW1hdGlvbi1kZWxheTouMTVzfQouY2FyZDpu"
"dGgtY2hpbGQoNCl7YW5pbWF0aW9uLWRlbGF5Oi4yc30KLmNhcmQ6aG92ZXJ7Ym9yZGVyLWNvbG9y"
"OnZhcigtLXdoaXRlLTQpO2JveC1zaGFkb3c6MCA0cHggMjBweCByZ2JhKDAsMCwwLDAuMDQpfQoK"
"LmNhcmQtaGVhZGVye2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250"
"ZW50OnNwYWNlLWJldHdlZW47bWFyZ2luLWJvdHRvbToxNnB4fQouY2FyZC10aXRsZXtmb250LXNp"
"emU6MTRweDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tdHgtZGFyayk7Zm9udC1mYW1pbHk6"
"J091dGZpdCcsc2Fucy1zZXJpZn0KLmNhcmQtc3VidGl0bGV7Zm9udC1zaXplOjExcHg7Y29sb3I6"
"dmFyKC0tdHgtbXV0ZWQpO21hcmdpbi10b3A6MnB4fQoKLyogU1RBVCBOVU1CRVJTICovCi5zdGF0"
"LW51bXsKICBmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjsKICBmb250LXNpemU6MzRweDtm"
"b250LXdlaWdodDo4MDA7bGluZS1oZWlnaHQ6MTsKICBjb2xvcjp2YXIoLS10eC1kYXJrKTtsZXR0"
"ZXItc3BhY2luZzotMXB4Owp9Ci5zdGF0LW51bS5yZWR7Y29sb3I6dmFyKC0tc2V2LWNyaXQpfQou"
"c3RhdC1udW0ub3Jhbmdle2NvbG9yOnZhcigtLXNldi1oaWdoKX0KLnN0YXQtbnVtLnllbGxvd3tj"
"b2xvcjp2YXIoLS1zZXYtbWVkKX0KLnN0YXQtbnVtLmdyZWVue2NvbG9yOnZhcigtLXNldi1sb3cp"
"fQouc3RhdC1udW0uYnJhbmR7Y29sb3I6dmFyKC0tcmVkKX0KCi5zdGF0LWJhci13cmFwe21hcmdp"
"bi10b3A6MTBweH0KLnN0YXQtYmFye2hlaWdodDo2cHg7Ym9yZGVyLXJhZGl1czoxMHB4O2JhY2tn"
"cm91bmQ6dmFyKC0td2hpdGUtMyk7b3ZlcmZsb3c6aGlkZGVufQouc3RhdC1iYXItZmlsbHtoZWln"
"aHQ6MTAwJTtib3JkZXItcmFkaXVzOjEwcHg7dHJhbnNpdGlvbjp3aWR0aCAuOHMgY3ViaWMtYmV6"
"aWVyKC40LDAsLjIsMSl9Ci5zdGF0LWJhci1maWxsLnJlZHtiYWNrZ3JvdW5kOmxpbmVhci1ncmFk"
"aWVudCg5MGRlZyx2YXIoLS1zZXYtY3JpdCksI2Y4NzE3MSl9Ci5zdGF0LWJhci1maWxsLm9yYW5n"
"ZXtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1zZXYtaGlnaCksI2ZiOTIz"
"Yyl9Ci5zdGF0LWJhci1maWxsLnllbGxvd3tiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRl"
"Zyx2YXIoLS1zZXYtbWVkKSwjZmJiZjI0KX0KLnN0YXQtYmFyLWZpbGwuZ3JlZW57YmFja2dyb3Vu"
"ZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsdmFyKC0tc2V2LWxvdyksIzM0ZDM5OSl9Ci5zdGF0LWJh"
"ci1maWxsLmJyYW5ke2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHZhcigtLXJlZCks"
"dmFyKC0tcmVkLWxpZ2h0KSl9Cgouc3RhdC1zdWJ7Zm9udC1zaXplOjEwLjVweDtjb2xvcjp2YXIo"
"LS10eC1tdXRlZCk7bWFyZ2luLXRvcDo4cHg7Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1v"
"bm9zcGFjZX0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT0KICAgUE9SVCBUQUJMRSDigJQgQ0xFQU4gV0hJVEUKICAgPT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PSAqLwoucG9ydC10YWJsZS13cmFwe292ZXJmbG93LXg6YXV0b30KLnBvcnQtdGFibGV7d2lk"
"dGg6MTAwJTtib3JkZXItY29sbGFwc2U6Y29sbGFwc2U7Zm9udC1zaXplOjEycHh9Ci5wb3J0LXRh"
"YmxlIHRoZWFkIHRoewogIHRleHQtYWxpZ246bGVmdDtwYWRkaW5nOjEwcHggMTRweDsKICBmb250"
"LWZhbWlseTonSUJNIFBsZXggTW9ubycsbW9ub3NwYWNlOwogIGZvbnQtc2l6ZTo5cHg7Zm9udC13"
"ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXR4LWZhaW50KTsKICBsZXR0ZXItc3BhY2luZzoxLjVweDt0"
"ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7CiAgYm9yZGVyLWJvdHRvbToycHggc29saWQgdmFyKC0t"
"d2hpdGUtMyk7CiAgYmFja2dyb3VuZDp2YXIoLS13aGl0ZS0yKTsKfQoucG9ydC10YWJsZSB0Ym9k"
"eSB0cntib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTt0cmFuc2l0aW9uOmJh"
"Y2tncm91bmQgLjE1c30KLnBvcnQtdGFibGUgdGJvZHkgdHI6aG92ZXJ7YmFja2dyb3VuZDp2YXIo"
"LS1yZWQtZGltKX0KLnBvcnQtdGFibGUgdGJvZHkgdHI6bGFzdC1jaGlsZHtib3JkZXItYm90dG9t"
"Om5vbmV9Ci5wb3J0LXRhYmxlIHRke3BhZGRpbmc6MTBweCAxNHB4O3ZlcnRpY2FsLWFsaWduOnRv"
"cH0KLnAtbnVte2ZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC13ZWln"
"aHQ6NzAwO2NvbG9yOnZhcigtLXJlZCk7Zm9udC1zaXplOjEzcHh9Ci5wLXByb3Rve2ZvbnQtZmFt"
"aWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjlweDtjb2xvcjp2YXIoLS10"
"eC1mYWludCl9Ci5wLXN2Y3tjb2xvcjp2YXIoLS10eC1kYXJrKTtmb250LXdlaWdodDo2MDA7Zm9u"
"dC1zaXplOjEycHh9Ci5wLXZlcntmb250LXNpemU6MTBweDtjb2xvcjp2YXIoLS10eC1tdXRlZCk7"
"bWFyZ2luLXRvcDoycHh9Ci5wLWRlc2N7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpO2ZvbnQtc2l6ZTox"
"MXB4O21heC13aWR0aDoyNjBweH0KLnAtZml4e2NvbG9yOnZhcigtLXNldi1sb3cpO2ZvbnQtc2l6"
"ZToxMXB4O21heC13aWR0aDoyMjBweH0KCi8qIFNFVkVSSVRZIEJBREdFUyDigJQgb24gd2hpdGUg"
"YmcgKi8KLnNldnsKICBkaXNwbGF5OmlubGluZS1mbGV4O3BhZGRpbmc6M3B4IDEwcHg7Ym9yZGVy"
"LXJhZGl1czoyMHB4OwogIGZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7CiAg"
"Zm9udC1zaXplOjguNXB4O2ZvbnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzouOHB4Owp9Ci5z"
"ZXYuQ1JJVElDQUx7YmFja2dyb3VuZDp2YXIoLS1zZXYtY3JpdC1iZyk7Y29sb3I6dmFyKC0tc2V2"
"LWNyaXQpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tc2V2LWNyaXQtYm9yZGVyKX0KLnNldi5ISUdI"
"e2JhY2tncm91bmQ6dmFyKC0tc2V2LWhpZ2gtYmcpO2NvbG9yOnZhcigtLXNldi1oaWdoKTtib3Jk"
"ZXI6MXB4IHNvbGlkIHZhcigtLXNldi1oaWdoLWJvcmRlcil9Ci5zZXYuTUVESVVNe2JhY2tncm91"
"bmQ6dmFyKC0tc2V2LW1lZC1iZyk7Y29sb3I6dmFyKC0tc2V2LW1lZCk7Ym9yZGVyOjFweCBzb2xp"
"ZCB2YXIoLS1zZXYtbWVkLWJvcmRlcil9Ci5zZXYuTE9Xe2JhY2tncm91bmQ6dmFyKC0tc2V2LWxv"
"dy1iZyk7Y29sb3I6dmFyKC0tc2V2LWxvdyk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1zZXYtbG93"
"LWJvcmRlcil9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09CiAgIFRIUkVBVCBDQVJEUyDigJQgV0hJVEUgV0lUSCBSRUQg"
"TEVGVCBCT1JERVIKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PSAqLwoudGhyZWF0LWNhcmR7CiAgYmFja2dyb3VuZDp2YXIo"
"LS13aGl0ZSk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTsKICBib3JkZXItcmFkaXVz"
"OnZhcigtLXJhZGl1cy1sZyk7cGFkZGluZzoxOHB4IDIycHg7CiAgYm9yZGVyLWxlZnQ6NHB4IHNv"
"bGlkIHZhcigtLXdoaXRlLTQpOwogIHRyYW5zaXRpb246YWxsIC4yNXM7CiAgYW5pbWF0aW9uOmZh"
"ZGVVcCAuNXMgZWFzZSBib3RoOwp9Ci50aHJlYXQtY2FyZDpob3Zlcntib3gtc2hhZG93OjAgNHB4"
"IDIwcHggcmdiYSgwLDAsMCwwLjA1KTt0cmFuc2Zvcm06dHJhbnNsYXRlWSgtMXB4KX0KLnRocmVh"
"dC1jYXJkLkNSSVRJQ0FMe2JvcmRlci1sZWZ0LWNvbG9yOnZhcigtLXNldi1jcml0KX0KLnRocmVh"
"dC1jYXJkLkhJR0h7Ym9yZGVyLWxlZnQtY29sb3I6dmFyKC0tc2V2LWhpZ2gpfQoudGhyZWF0LWNh"
"cmQuTUVESVVNe2JvcmRlci1sZWZ0LWNvbG9yOnZhcigtLXNldi1tZWQpfQoudGhyZWF0LWNhcmQu"
"TE9Xe2JvcmRlci1sZWZ0LWNvbG9yOnZhcigtLXNldi1sb3cpfQoudGMtaGRye2Rpc3BsYXk6Zmxl"
"eDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47bWFyZ2lu"
"LWJvdHRvbToxMHB4fQoudGMtbmFtZXtmb250LXNpemU6MTNweDtmb250LXdlaWdodDo3MDA7Y29s"
"b3I6dmFyKC0tdHgtZGFyayl9Ci50Yy1kZXNje2ZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigtLXR4"
"LW11dGVkKTttYXJnaW4tYm90dG9tOjE0cHg7bGluZS1oZWlnaHQ6MS43fQoudGMtZml4ewogIHBh"
"ZGRpbmc6MTBweCAxNHB4O2JvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzKTsKICBiYWNrZ3JvdW5k"
"OnZhcigtLXNldi1sb3ctYmcpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tc2V2LWxvdy1ib3JkZXIp"
"Owp9Ci50Yy1maXgtbGFiZWx7Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtm"
"b250LXNpemU6OC41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXNldi1sb3cpO2xldHRl"
"ci1zcGFjaW5nOjEuNXB4O21hcmdpbi1ib3R0b206M3B4fQoudGMtZml4LXRleHR7Zm9udC1zaXpl"
"OjExcHg7Y29sb3I6dmFyKC0tc2V2LWxvdyk7bGluZS1oZWlnaHQ6MS41fQoKLyogPT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQog"
"ICBDSEFSVCBDQVJEUwogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09ICovCi5jaGFydC13cmFwe3Bvc2l0aW9uOnJlbGF0aXZl"
"O21pbi1oZWlnaHQ6MjAwcHh9Ci5jaGFydC13cmFwIGNhbnZhc3t3aWR0aDoxMDAlIWltcG9ydGFu"
"dDtoZWlnaHQ6MTAwJSFpbXBvcnRhbnR9CgovKiBSSVNLIEdBVUdFICovCi5yaXNrLWdhdWdle2Rp"
"c3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjI4cHg7cGFkZGluZzo4cHggMH0KLnJp"
"c2stY2lyY2xlewogIHdpZHRoOjExMHB4O2hlaWdodDoxMTBweDtib3JkZXItcmFkaXVzOjUwJTsK"
"ICBkaXNwbGF5OmZsZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2FsaWduLWl0ZW1zOmNlbnRlcjtq"
"dXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOwogIGJvcmRlcjozcHggc29saWQgdmFyKC0td2hpdGUtMyk7"
"cG9zaXRpb246cmVsYXRpdmU7ZmxleC1zaHJpbms6MDsKfQoucmlzay1jaXJjbGU6OmFmdGVyewog"
"IGNvbnRlbnQ6Jyc7cG9zaXRpb246YWJzb2x1dGU7aW5zZXQ6LTNweDtib3JkZXItcmFkaXVzOjUw"
"JTsKICBib3JkZXI6M3B4IHNvbGlkIHRyYW5zcGFyZW50O2JvcmRlci10b3AtY29sb3I6Y3VycmVu"
"dENvbG9yOwogIGFuaW1hdGlvbjpzcGluIDIuNXMgbGluZWFyIGluZmluaXRlOwp9Ci5yaXNrLXZh"
"bHtmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjtmb250LXNpemU6MzZweDtmb250LXdlaWdo"
"dDo4MDA7bGluZS1oZWlnaHQ6MX0KLnJpc2stbGFiZWx7Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1v"
"bm8nLG1vbm9zcGFjZTtmb250LXNpemU6OXB4O2ZvbnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2lu"
"ZzoycHg7bWFyZ2luLXRvcDo0cHg7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpfQoucmlzay1kZXRhaWxz"
"e2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjEwcHh9Ci5yaXNrLXJvd3tk"
"aXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMHB4O2ZvbnQtc2l6ZToxMnB4O2Nv"
"bG9yOnZhcigtLXR4LWJvZHkpfQoucmlzay1kb3R7d2lkdGg6OHB4O2hlaWdodDo4cHg7Ym9yZGVy"
"LXJhZGl1czo1MCU7ZmxleC1zaHJpbms6MH0KLnJpc2stdmFsLXNte2ZvbnQtZmFtaWx5OidJQk0g"
"UGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC13ZWlnaHQ6NzAwO21hcmdpbi1sZWZ0OmF1dG99Cgov"
"KiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09CiAgIEVNUFRZIFNUQVRFCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KLmVtcHR5LXN0YXRle2Rpc3Bs"
"YXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnkt"
"Y29udGVudDpjZW50ZXI7cGFkZGluZzo2MHB4IDIwcHg7dGV4dC1hbGlnbjpjZW50ZXJ9Ci5lbXB0"
"eS1pY297Zm9udC1zaXplOjQwcHg7bWFyZ2luLWJvdHRvbToxNnB4O29wYWNpdHk6LjM1fQouZW1w"
"dHktdGl0bGV7Zm9udC1zaXplOjE0cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXR4LW11"
"dGVkKTttYXJnaW4tYm90dG9tOjZweH0KLmVtcHR5LXN1Yntmb250LXNpemU6MTJweDtjb2xvcjp2"
"YXIoLS10eC1mYWludCk7bWF4LXdpZHRoOjMwMHB4fQoKLyogPT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBDSEFUIFBBTkVM"
"IOKAlCBEQVJLIEJPVFRPTSBCQVIKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwouY2hhdC1wYW5lbHsKICBib3JkZXIt"
"dG9wOjJweCBzb2xpZCB2YXIoLS1yZWQpOwogIGJhY2tncm91bmQ6dmFyKC0tYmxhY2spOwogIGRp"
"c3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47CiAgbWF4LWhlaWdodDoyNDBweDt0cmFu"
"c2l0aW9uOm1heC1oZWlnaHQgLjM1cyBjdWJpYy1iZXppZXIoLjQsMCwuMiwxKTsKICBwb3NpdGlv"
"bjpyZWxhdGl2ZTsKfQouY2hhdC1wYW5lbC5jb2xsYXBzZWR7bWF4LWhlaWdodDo0NnB4fQouY2hh"
"dC10b2dnbGV7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRl"
"bnQ6c3BhY2UtYmV0d2VlbjsKICBwYWRkaW5nOjAgMjRweDtoZWlnaHQ6NDZweDttaW4taGVpZ2h0"
"OjQ2cHg7CiAgY3Vyc29yOnBvaW50ZXI7Cn0KLmNoYXQtdG9nZ2xlLWxlZnR7ZGlzcGxheTpmbGV4"
"O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTBweH0KLmNoYXQtdG9nZ2xlLWxhYmVse2ZvbnQtc2l6"
"ZToxMnB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS13aGl0ZSk7bGV0dGVyLXNwYWNpbmc6"
"LjVweH0KLmNoYXQtdG9nZ2xlLXN0YXR1c3tmb250LXNpemU6MTBweDtjb2xvcjojNGFkZTgwO2Zv"
"bnQtd2VpZ2h0OjUwMH0KLmNoYXQtYXJyb3d7Zm9udC1zaXplOjEycHg7Y29sb3I6dmFyKC0tdHgt"
"b24tZGFyay1tdXRlZCk7dHJhbnNpdGlvbjp0cmFuc2Zvcm0gLjNzfQouY2hhdC1wYW5lbC5jb2xs"
"YXBzZWQgLmNoYXQtYXJyb3d7dHJhbnNmb3JtOnJvdGF0ZSgxODBkZWcpfQoKI2NoYXQtbWVzc2Fn"
"ZXN7ZmxleDoxO292ZXJmbG93LXk6YXV0bztwYWRkaW5nOjEwcHggMjRweH0KLm1zZ3tkaXNwbGF5"
"OmZsZXg7Z2FwOjEwcHg7bWFyZ2luLWJvdHRvbToxMHB4O2FuaW1hdGlvbjpmYWRlVXAgLjNzIGVh"
"c2V9Ci5tc2ctYXZhdGFyewogIHdpZHRoOjI2cHg7aGVpZ2h0OjI2cHg7Ym9yZGVyLXJhZGl1czo2"
"cHg7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2Vu"
"dGVyOwogIGZvbnQtc2l6ZTo4cHg7Zm9udC13ZWlnaHQ6NzAwO2ZsZXgtc2hyaW5rOjA7CiAgZm9u"
"dC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTsKfQoubXNnLmFpIC5tc2ctYXZhdGFy"
"e2JhY2tncm91bmQ6cmdiYSgyMzAsNTcsNzAsMC4xNSk7Y29sb3I6dmFyKC0tcmVkLWxpZ2h0KX0K"
"Lm1zZy51c2VyIC5tc2ctYXZhdGFye2JhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjA4KTtj"
"b2xvcjp2YXIoLS10eC1vbi1kYXJrLW11dGVkKX0KLm1zZy1ib2R5ewogIGJhY2tncm91bmQ6dmFy"
"KC0tYmxhY2stMyk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMDYpOwogIGJv"
"cmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzKTtwYWRkaW5nOjlweCAxM3B4OwogIGZvbnQtc2l6ZTox"
"MnB4O2xpbmUtaGVpZ2h0OjEuNjtjb2xvcjp2YXIoLS10eC1vbi1kYXJrLW11dGVkKTttYXgtd2lk"
"dGg6ODUlOwp9CgouY2hhdC1pbnB1dC1yb3d7ZGlzcGxheTpmbGV4O2dhcDo4cHg7cGFkZGluZzo4"
"cHggMjRweCAxMnB4fQouY2hhdC1pbnB1dHsKICBmbGV4OjE7YmFja2dyb3VuZDp2YXIoLS1ibGFj"
"ay0zKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wOCk7CiAgYm9yZGVyLXJh"
"ZGl1czp2YXIoLS1yYWRpdXMpO3BhZGRpbmc6OXB4IDE0cHg7CiAgY29sb3I6dmFyKC0tdHgtb24t"
"ZGFyayk7Zm9udC1zaXplOjEycHg7b3V0bGluZTpub25lOwogIGZvbnQtZmFtaWx5OidPdXRmaXQn"
"LHNhbnMtc2VyaWY7dHJhbnNpdGlvbjpib3JkZXItY29sb3IgLjJzOwp9Ci5jaGF0LWlucHV0OmZv"
"Y3Vze2JvcmRlci1jb2xvcjp2YXIoLS1yZWQpfQouY2hhdC1pbnB1dDo6cGxhY2Vob2xkZXJ7Y29s"
"b3I6cmdiYSgyNTUsMjU1LDI1NSwwLjIpfQouY2hhdC1zZW5kewogIHBhZGRpbmc6MCAyMHB4O2Jv"
"cmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzKTsKICBiYWNrZ3JvdW5kOnZhcigtLXJlZCk7Y29sb3I6"
"I2ZmZjtib3JkZXI6bm9uZTsKICBmb250LXNpemU6MTJweDtmb250LXdlaWdodDo3MDA7Y3Vyc29y"
"OnBvaW50ZXI7CiAgZm9udC1mYW1pbHk6J091dGZpdCcsc2Fucy1zZXJpZjt0cmFuc2l0aW9uOmFs"
"bCAuMnM7Cn0KLmNoYXQtc2VuZDpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXJlZC1kYXJrKX0KCi8q"
"ID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT0KICAgUkVQT1JUIE1PREFMCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KLm1vZGFsLW92ZXJsYXl7ZGlz"
"cGxheTpub25lO3Bvc2l0aW9uOmZpeGVkO2luc2V0OjA7ei1pbmRleDoxMDAwO2JhY2tncm91bmQ6"
"cmdiYSgwLDAsMCwwLjUpO2JhY2tkcm9wLWZpbHRlcjpibHVyKDEycHgpO2FsaWduLWl0ZW1zOmNl"
"bnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyfQoubW9kYWwtb3ZlcmxheS5vcGVue2Rpc3BsYXk6"
"ZmxleH0KLm1vZGFsLWJveHtiYWNrZ3JvdW5kOnZhcigtLXdoaXRlKTtib3JkZXItcmFkaXVzOnZh"
"cigtLXJhZGl1cy14bCk7d2lkdGg6OTAlO21heC13aWR0aDo5MDBweDttYXgtaGVpZ2h0Ojg1dmg7"
"ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtib3gtc2hhZG93OjAgMjRweCA2NHB4"
"IHJnYmEoMCwwLDAsMC4zKTthbmltYXRpb246ZmFkZVVwIC40cyBlYXNlfQoubW9kYWwtaGRye2Rp"
"c3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdl"
"ZW47cGFkZGluZzoxOHB4IDI0cHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0td2hpdGUt"
"Myl9Ci5tb2RhbC10aXRsZXtmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjtmb250LXNpemU6"
"MTZweDtmb250LXdlaWdodDo4MDA7Y29sb3I6dmFyKC0tdHgtZGFyayk7bGV0dGVyLXNwYWNpbmc6"
"MXB4fQoubW9kYWwtY2xvc2V7cGFkZGluZzo2cHggMTZweDtib3JkZXItcmFkaXVzOjZweDtiYWNr"
"Z3JvdW5kOnZhcigtLXdoaXRlLTIpO2JvcmRlcjoxcHggc29saWQgdmFyKC0td2hpdGUtMyk7Y29s"
"b3I6dmFyKC0tdHgtbXV0ZWQpO2N1cnNvcjpwb2ludGVyO2ZvbnQtc2l6ZToxMXB4O2ZvbnQtd2Vp"
"Z2h0OjYwMDtmb250LWZhbWlseTonSUJNIFBsZXggTW9ubycsbW9ub3NwYWNlO3RyYW5zaXRpb246"
"YWxsIC4xNXN9Ci5tb2RhbC1jbG9zZTpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXdoaXRlLTMpfQou"
"bW9kYWwtYm9keXtmbGV4OjE7b3ZlcmZsb3cteTphdXRvO3BhZGRpbmc6MjRweH0KLm1vZGFsLWZv"
"b3RlcntkaXNwbGF5OmZsZXg7Z2FwOjEwcHg7cGFkZGluZzoxNnB4IDI0cHg7Ym9yZGVyLXRvcDox"
"cHggc29saWQgdmFyKC0td2hpdGUtMyl9Ci5kbC1idG57cGFkZGluZzo4cHggMjBweDtib3JkZXIt"
"cmFkaXVzOnZhcigtLXJhZGl1cyk7Ym9yZGVyOm5vbmU7Y3Vyc29yOnBvaW50ZXI7Zm9udC1zaXpl"
"OjEycHg7Zm9udC13ZWlnaHQ6NzAwO3RyYW5zaXRpb246YWxsIC4ycztmb250LWZhbWlseTonT3V0"
"Zml0JyxzYW5zLXNlcmlmfQouZGwtYnRuLnByaW1hcnl7YmFja2dyb3VuZDp2YXIoLS1yZWQpO2Nv"
"bG9yOiNmZmZ9Ci5kbC1idG4ucHJpbWFyeTpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXJlZC1kYXJr"
"KX0KLmRsLWJ0bi5zZWNvbmRhcnl7YmFja2dyb3VuZDp2YXIoLS13aGl0ZS0yKTtjb2xvcjp2YXIo"
"LS10eC1ib2R5KTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLXdoaXRlLTMpfQouZGwtYnRuLnNlY29u"
"ZGFyeTpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXdoaXRlLTMpfQoKLyogUmVwb3J0IGlubmVyICov"
"Ci5ycC1oZHJ7dGV4dC1hbGlnbjpjZW50ZXI7cGFkZGluZzoxNnB4IDAgMjBweDtib3JkZXItYm90"
"dG9tOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTttYXJnaW4tYm90dG9tOjIwcHh9Ci5ycC10e2Zv"
"bnQtZmFtaWx5OidTeW5lJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToyMHB4O2ZvbnQtd2VpZ2h0Ojgw"
"MDtjb2xvcjp2YXIoLS1yZWQpO2xldHRlci1zcGFjaW5nOjJweH0KLnJwLXN7Zm9udC1zaXplOjEx"
"cHg7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpO21hcmdpbi10b3A6NHB4fQoucnAtc2Vje21hcmdpbi1i"
"b3R0b206MjBweH0KLnJwLXN0e2ZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7"
"Zm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXJlZCk7bGV0dGVyLXNw"
"YWNpbmc6MS41cHg7bWFyZ2luLWJvdHRvbToxMHB4fQoucnAtcHJ7ZGlzcGxheTpncmlkO2dyaWQt"
"dGVtcGxhdGUtY29sdW1uczo4MHB4IDEyMHB4IDgwcHggMWZyO2dhcDo4cHg7cGFkZGluZzo2cHgg"
"MDtmb250LXNpemU6MTFweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKX0K"
"LnJwLXRoe3BhZGRpbmc6MTBweCAxNHB4O21hcmdpbi1ib3R0b206NnB4O2JvcmRlci1yYWRpdXM6"
"dmFyKC0tcmFkaXVzKTtib3JkZXItbGVmdDozcHggc29saWQgdmFyKC0td2hpdGUtNCk7YmFja2dy"
"b3VuZDp2YXIoLS13aGl0ZS0yKX0KLnJwLXRoLkNSSVRJQ0FMe2JvcmRlci1sZWZ0LWNvbG9yOnZh"
"cigtLXNldi1jcml0KX0ucnAtdGguSElHSHtib3JkZXItbGVmdC1jb2xvcjp2YXIoLS1zZXYtaGln"
"aCl9LnJwLXRoLk1FRElVTXtib3JkZXItbGVmdC1jb2xvcjp2YXIoLS1zZXYtbWVkKX0ucnAtdGgu"
"TE9Xe2JvcmRlci1sZWZ0LWNvbG9yOnZhcigtLXNldi1sb3cpfQoucnAtdG57Zm9udC13ZWlnaHQ6"
"NzAwO2NvbG9yOnZhcigtLXR4LWRhcmspO2ZvbnQtc2l6ZToxMnB4O21hcmdpbi1ib3R0b206NHB4"
"fQoucnAtdGR7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpfQoucnAtdGZ7Zm9u"
"dC1zaXplOjExcHg7Y29sb3I6dmFyKC0tc2V2LWxvdyk7bWFyZ2luLXRvcDo0cHh9CgovKiBOT1RJ"
"RklDQVRJT04gKi8KLm5vdGlmewogIHBvc2l0aW9uOmZpeGVkO3RvcDoyMHB4O3JpZ2h0OjIwcHg7"
"ei1pbmRleDoyMDAwOwogIGJhY2tncm91bmQ6dmFyKC0tYmxhY2spO2JvcmRlcjoxcHggc29saWQg"
"cmdiYSgyMzAsNTcsNzAsMC4yKTsKICBib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cyk7cGFkZGlu"
"ZzoxMnB4IDIwcHg7CiAgY29sb3I6dmFyKC0td2hpdGUpO2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2Vp"
"Z2h0OjYwMDsKICBib3gtc2hhZG93OjAgOHB4IDMwcHggcmdiYSgwLDAsMCwwLjMpOwogIGFuaW1h"
"dGlvbjpmYWRlVXAgLjNzIGVhc2U7Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgU0NBTiBTVEFUVVMgVEFCIFNU"
"WUxFUwogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09ICovCi5zY2FuLWluZGljYXRvcnsKICB3aWR0aDo0OHB4O2hlaWdodDo0"
"OHB4O2JvcmRlci1yYWRpdXM6NTAlOwogIGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7"
"anVzdGlmeS1jb250ZW50OmNlbnRlcjsKICBwb3NpdGlvbjpyZWxhdGl2ZTtmbGV4LXNocmluazow"
"OwogIGJhY2tncm91bmQ6dmFyKC0td2hpdGUtMik7Ym9yZGVyOjJweCBzb2xpZCB2YXIoLS13aGl0"
"ZS0zKTsKfQouc2Nhbi1pbmRpY2F0b3IucnVubmluZ3tiYWNrZ3JvdW5kOnZhcigtLXJlZC1kaW0p"
"O2JvcmRlci1jb2xvcjp2YXIoLS1yZWQtYm9yZGVyKX0KLnNjYW4taW5kaWNhdG9yLnJ1bm5pbmc6"
"OmFmdGVyewogIGNvbnRlbnQ6Jyc7cG9zaXRpb246YWJzb2x1dGU7aW5zZXQ6LTJweDtib3JkZXIt"
"cmFkaXVzOjUwJTsKICBib3JkZXI6MnB4IHNvbGlkIHRyYW5zcGFyZW50O2JvcmRlci10b3AtY29s"
"b3I6dmFyKC0tcmVkKTsKICBhbmltYXRpb246c3BpbiAxcyBsaW5lYXIgaW5maW5pdGU7Cn0KLnNj"
"YW4taW5kaWNhdG9yLmNvbXBsZXRle2JhY2tncm91bmQ6dmFyKC0tc2V2LWxvdy1iZyk7Ym9yZGVy"
"LWNvbG9yOnZhcigtLXNldi1sb3ctYm9yZGVyKX0KLnNjYW4taW5kaWNhdG9yLmVycm9ye2JhY2tn"
"cm91bmQ6dmFyKC0tc2V2LWNyaXQtYmcpO2JvcmRlci1jb2xvcjp2YXIoLS1zZXYtY3JpdC1ib3Jk"
"ZXIpfQouc2Nhbi1wY3R7Zm9udC1mYW1pbHk6J1N5bmUnLHNhbnMtc2VyaWY7Zm9udC1zaXplOjEz"
"cHg7Zm9udC13ZWlnaHQ6ODAwO2NvbG9yOnZhcigtLXR4LW11dGVkKX0KLnNjYW4taW5kaWNhdG9y"
"LnJ1bm5pbmcgLnNjYW4tcGN0e2NvbG9yOnZhcigtLXJlZCl9Ci5zY2FuLWluZGljYXRvci5jb21w"
"bGV0ZSAuc2Nhbi1wY3R7Y29sb3I6dmFyKC0tc2V2LWxvdyl9Ci5zY2FuLWluZGljYXRvci5lcnJv"
"ciAuc2Nhbi1wY3R7Y29sb3I6dmFyKC0tc2V2LWNyaXQpfQouc2Nhbi1tZXRhLWl0ZW17CiAgZm9u"
"dC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTBweDsKICBjb2xv"
"cjp2YXIoLS10eC1tdXRlZCk7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NHB4"
"Owp9Ci5zY2FuLW1ldGEtaXRlbSAuZG90e3dpZHRoOjVweDtoZWlnaHQ6NXB4O2JvcmRlci1yYWRp"
"dXM6NTAlO2ZsZXgtc2hyaW5rOjB9Ci5zY2FuLWJhci10cmFja3toZWlnaHQ6MTBweDtiYWNrZ3Jv"
"dW5kOnZhcigtLXdoaXRlLTMpO2JvcmRlci1yYWRpdXM6MTBweDtvdmVyZmxvdzpoaWRkZW59Ci5z"
"Y2FuLWJhci1maWxsLWxpdmV7CiAgaGVpZ2h0OjEwMCU7Ym9yZGVyLXJhZGl1czoxMHB4O3RyYW5z"
"aXRpb246d2lkdGggLjZzIGN1YmljLWJlemllciguNCwwLC4yLDEpOwogIGJhY2tncm91bmQ6bGlu"
"ZWFyLWdyYWRpZW50KDkwZGVnLHZhcigtLXJlZCksdmFyKC0tcmVkLWxpZ2h0KSk7cG9zaXRpb246"
"cmVsYXRpdmU7Cn0KLnNjYW4tYmFyLWZpbGwtbGl2ZS5jb21wbGV0ZXtiYWNrZ3JvdW5kOmxpbmVh"
"ci1ncmFkaWVudCg5MGRlZyx2YXIoLS1zZXYtbG93KSwjMzRkMzk5KX0KLnNjYW4tYmFyLWZpbGwt"
"bGl2ZTo6YWZ0ZXJ7CiAgY29udGVudDonJztwb3NpdGlvbjphYnNvbHV0ZTtpbnNldDowOwogIGJh"
"Y2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5zcGFyZW50LHJnYmEoMjU1LDI1NSwy"
"NTUsMC4yNSksdHJhbnNwYXJlbnQpOwogIGFuaW1hdGlvbjpzaGltbWVyIDEuNXMgaW5maW5pdGU7"
"Cn0KLnRhYi1iYWRnZS5saXZle2Rpc3BsYXk6aW5saW5lLWJsb2NrO2JhY2tncm91bmQ6dmFyKC0t"
"cmVkKTtjb2xvcjojZmZmO2FuaW1hdGlvbjpwdWxzZSAxLjVzIGluZmluaXRlfQoudGFiLWJhZGdl"
"LmRvbmV7ZGlzcGxheTppbmxpbmUtYmxvY2s7YmFja2dyb3VuZDp2YXIoLS1zZXYtbG93LWJnKTtj"
"b2xvcjp2YXIoLS1zZXYtbG93KX0KCi8qIE1JTkkgU1RBVFMgSU4gSEVBREVSICovCi5oLW1pbmkt"
"c3RhdHN7ZGlzcGxheTpmbGV4O2dhcDoxMHB4fQouaC1taW5pLXN0YXR7CiAgZm9udC1mYW1pbHk6"
"J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTBweDsKICBjb2xvcjp2YXIoLS10"
"eC1vbi1kYXJrLW11dGVkKTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo0cHg7"
"Cn0KLmgtbWluaS1zdGF0IHN0cm9uZ3tjb2xvcjp2YXIoLS13aGl0ZSk7Zm9udC1zaXplOjExcHh9"
"CgovKiBNSU5JIFBST0dSRVNTIEJBUiAoYmVsb3cgaGVhZGVyKSAqLwouaC1taW5pLXByb2dyZXNz"
"ewogIGhlaWdodDozcHg7YmFja2dyb3VuZDp2YXIoLS1ibGFjay0zKTtwb3NpdGlvbjpyZWxhdGl2"
"ZTtvdmVyZmxvdzpoaWRkZW47CiAgb3BhY2l0eTowO3RyYW5zaXRpb246b3BhY2l0eSAuM3M7Cn0K"
"LmgtbWluaS1wcm9ncmVzcy5hY3RpdmV7b3BhY2l0eToxfQouaC1taW5pLWJhcnsKICBoZWlnaHQ6"
"MTAwJTt3aWR0aDowJTsKICBiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1y"
"ZWQpLHZhcigtLXJlZC1saWdodCkpOwogIHRyYW5zaXRpb246d2lkdGggLjVzIGN1YmljLWJlemll"
"ciguNCwwLC4yLDEpO3Bvc2l0aW9uOnJlbGF0aXZlOwp9Ci5oLW1pbmktYmFyOjphZnRlcnsKICBj"
"b250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRlO2luc2V0OjA7CiAgYmFja2dyb3VuZDpsaW5lYXIt"
"Z3JhZGllbnQoOTBkZWcsdHJhbnNwYXJlbnQscmdiYSgyNTUsMjU1LDI1NSwwLjMpLHRyYW5zcGFy"
"ZW50KTsKICBhbmltYXRpb246c2hpbW1lciAxLjJzIGluZmluaXRlOwp9CgovKiBUQVJHRVQgSElT"
"VE9SWSBEUk9QRE9XTiAqLwouaC10YXJnZXQtaGlzdG9yeXsKICBkaXNwbGF5Om5vbmU7cG9zaXRp"
"b246YWJzb2x1dGU7dG9wOjEwMCU7bGVmdDowO3JpZ2h0OjA7ei1pbmRleDoxMDA7CiAgYmFja2dy"
"b3VuZDp2YXIoLS1ibGFjay0yKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4x"
"KTsKICBib3JkZXItcmFkaXVzOjAgMCB2YXIoLS1yYWRpdXMpIHZhcigtLXJhZGl1cyk7CiAgYm94"
"LXNoYWRvdzowIDhweCAyNHB4IHJnYmEoMCwwLDAsMC40KTttYXgtaGVpZ2h0OjIwMHB4O292ZXJm"
"bG93LXk6YXV0bzsKfQouaC10YXJnZXQtaGlzdG9yeS5zaG93e2Rpc3BsYXk6YmxvY2t9Ci5oLXRo"
"LWl0ZW17CiAgcGFkZGluZzo4cHggMTRweDtmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS10eC1v"
"bi1kYXJrLW11dGVkKTsKICBjdXJzb3I6cG9pbnRlcjt0cmFuc2l0aW9uOmJhY2tncm91bmQgLjE1"
"czsKICBmb250LWZhbWlseTonSUJNIFBsZXggTW9ubycsbW9ub3NwYWNlO2JvcmRlci1ib3R0b206"
"MXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wNCk7Cn0KLmgtdGgtaXRlbTpob3ZlcntiYWNr"
"Z3JvdW5kOnJnYmEoMjMwLDU3LDcwLDAuMSk7Y29sb3I6dmFyKC0td2hpdGUpfQouaC10aC1pdGVt"
"Omxhc3QtY2hpbGR7Ym9yZGVyLWJvdHRvbTpub25lfQouaC10aC1sYWJlbHtmb250LXNpemU6OXB4"
"O2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4yNSk7bWFyZ2luLWJvdHRvbToycHg7bGV0dGVyLXNw"
"YWNpbmc6MXB4fQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PQogICBBVFRBQ0sgQ0hBSU4gVklTVUFMSVpBVElPTgogICA9"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09ICovCi5jaGFpbi1jYXJkewogIGJhY2tncm91bmQ6dmFyKC0td2hpdGUpO2JvcmRlcjox"
"cHggc29saWQgdmFyKC0td2hpdGUtMyk7Ym9yZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMpOwogIHBh"
"ZGRpbmc6MjBweDttYXJnaW4tYm90dG9tOjE2cHg7cG9zaXRpb246cmVsYXRpdmU7b3ZlcmZsb3c6"
"aGlkZGVuOwogIGJvcmRlci1sZWZ0OjRweCBzb2xpZCB2YXIoLS13aGl0ZS00KTthbmltYXRpb246"
"ZmFkZVVwIC40cyBlYXNlIGJvdGg7Cn0KLmNoYWluLWNhcmQuQ1JJVElDQUx7Ym9yZGVyLWxlZnQt"
"Y29sb3I6I2Q5MDQyOX0KLmNoYWluLWNhcmQuSElHSHtib3JkZXItbGVmdC1jb2xvcjojZTg1ZDA0"
"fQouY2hhaW4tY2FyZC5NRURJVU17Ym9yZGVyLWxlZnQtY29sb3I6I2UwOWYzZX0KCi5jaGFpbi1o"
"ZWFkZXJ7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmZsZXgtc3RhcnQ7anVzdGlmeS1jb250ZW50"
"OnNwYWNlLWJldHdlZW47Z2FwOjEycHg7bWFyZ2luLWJvdHRvbToxNHB4fQouY2hhaW4tbmFtZXtm"
"b250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjtmb250LXNpemU6MTZweDtmb250LXdlaWdodDo4"
"MDA7Y29sb3I6dmFyKC0tdHgtZGFyayl9Ci5jaGFpbi1raWxsY2hhaW57Zm9udC1mYW1pbHk6J0lC"
"TSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTBweDtjb2xvcjp2YXIoLS10eC1tdXRl"
"ZCk7bWFyZ2luLXRvcDoycHh9Ci5jaGFpbi1jb25maWRlbmNlewogIGZvbnQtZmFtaWx5OidJQk0g"
"UGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6NzAwOwogIHBh"
"ZGRpbmc6NHB4IDEwcHg7Ym9yZGVyLXJhZGl1czoyMHB4O3doaXRlLXNwYWNlOm5vd3JhcDsKfQou"
"Y2hhaW4tY29uZmlkZW5jZS5oaWdoe2JhY2tncm91bmQ6dmFyKC0tcmVkLWRpbSk7Y29sb3I6dmFy"
"KC0tcmVkKX0KLmNoYWluLWNvbmZpZGVuY2UubWVke2JhY2tncm91bmQ6cmdiYSgyMjQsMTU5LDYy"
"LDAuMSk7Y29sb3I6I2UwOWYzZX0KCi8qIEtpbGwgQ2hhaW4gRmxvdyAqLwouY2hhaW4tZmxvd3sK"
"ICBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDowO21hcmdpbjoxNnB4IDA7cGFk"
"ZGluZzoxMnB4IDA7CiAgb3ZlcmZsb3cteDphdXRvOwp9Ci5jaGFpbi1zdGVwewogIGRpc3BsYXk6"
"ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47YWxpZ24taXRlbXM6Y2VudGVyO21pbi13aWR0aDox"
"MjBweDsKICBwb3NpdGlvbjpyZWxhdGl2ZTtmbGV4LXNocmluazowOwp9Ci5jaGFpbi1zdGVwLWRv"
"dHsKICB3aWR0aDozNnB4O2hlaWdodDozNnB4O2JvcmRlci1yYWRpdXM6NTAlOwogIGRpc3BsYXk6"
"ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNlbnRlcjsKICBmb250LXNp"
"emU6MTRweDtmb250LXdlaWdodDo4MDA7Y29sb3I6I2ZmZjtwb3NpdGlvbjpyZWxhdGl2ZTt6LWlu"
"ZGV4OjI7Cn0KLmNoYWluLXN0ZXAtZG90LmNvbmZpcm1lZHtiYWNrZ3JvdW5kOnZhcigtLXJlZCk7"
"Ym94LXNoYWRvdzowIDAgMTJweCByZ2JhKDIzMCw1Nyw3MCwwLjMpfQouY2hhaW4tc3RlcC1kb3Qu"
"bm90X2ZvdW5ke2JhY2tncm91bmQ6dmFyKC0td2hpdGUtMyk7Y29sb3I6dmFyKC0tdHgtZmFpbnQp"
"fQouY2hhaW4tc3RlcC1waGFzZXsKICBmb250LWZhbWlseTonSUJNIFBsZXggTW9ubycsbW9ub3Nw"
"YWNlO2ZvbnQtc2l6ZTo4cHg7Zm9udC13ZWlnaHQ6NzAwOwogIGxldHRlci1zcGFjaW5nOjFweDtj"
"b2xvcjp2YXIoLS10eC1mYWludCk7bWFyZ2luLXRvcDo2cHg7Cn0KLmNoYWluLXN0ZXAtbGFiZWx7"
"CiAgZm9udC1zaXplOjEwcHg7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpO3RleHQtYWxpZ246Y2VudGVy"
"O21hcmdpbi10b3A6M3B4OwogIG1heC13aWR0aDoxMTBweDtsaW5lLWhlaWdodDoxLjM7Cn0KLmNo"
"YWluLWFycm93ewogIHdpZHRoOjQwcHg7aGVpZ2h0OjJweDtiYWNrZ3JvdW5kOnZhcigtLXdoaXRl"
"LTQpO3Bvc2l0aW9uOnJlbGF0aXZlO2ZsZXgtc2hyaW5rOjA7CiAgbWFyZ2luLXRvcDotMjBweDsK"
"fQouY2hhaW4tYXJyb3cuY29uZmlybWVke2JhY2tncm91bmQ6dmFyKC0tcmVkKX0KLmNoYWluLWFy"
"cm93OjphZnRlcnsKICBjb250ZW50OifigLonO3Bvc2l0aW9uOmFic29sdXRlO3JpZ2h0Oi00cHg7"
"dG9wOi04cHg7CiAgZm9udC1zaXplOjE0cHg7Y29sb3I6aW5oZXJpdDsKfQouY2hhaW4tYXJyb3cu"
"Y29uZmlybWVkOjphZnRlcntjb2xvcjp2YXIoLS1yZWQpfQoKLyogSW1wYWN0ICYgQnVzaW5lc3Mg"
"Ki8KLmNoYWluLWltcGFjdHsKICBiYWNrZ3JvdW5kOnJnYmEoMjE3LDQsNDEsMC4wNCk7Ym9yZGVy"
"OjFweCBzb2xpZCByZ2JhKDIxNyw0LDQxLDAuMSk7CiAgYm9yZGVyLXJhZGl1czo4cHg7cGFkZGlu"
"ZzoxMnB4IDE0cHg7bWFyZ2luOjEycHggMDsKfQouY2hhaW4taW1wYWN0LXRpdGxle2ZvbnQtc2l6"
"ZTo5cHg7Zm9udC13ZWlnaHQ6NzAwO2xldHRlci1zcGFjaW5nOjEuNXB4O2NvbG9yOnZhcigtLXJl"
"ZCk7bWFyZ2luLWJvdHRvbTo0cHh9Ci5jaGFpbi1pbXBhY3QtdGV4dHtmb250LXNpemU6MTJweDtj"
"b2xvcjp2YXIoLS10eC1kYXJrKTtsaW5lLWhlaWdodDoxLjV9Ci5jaGFpbi1idXNpbmVzc3sKICBi"
"YWNrZ3JvdW5kOnJnYmEoMTAsMTAsMTIsMC4wMyk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS13aGl0"
"ZS0zKTsKICBib3JkZXItcmFkaXVzOjhweDtwYWRkaW5nOjEycHggMTRweDttYXJnaW46OHB4IDA7"
"Cn0KLmNoYWluLWJ1c2luZXNzLXRpdGxle2ZvbnQtc2l6ZTo5cHg7Zm9udC13ZWlnaHQ6NzAwO2xl"
"dHRlci1zcGFjaW5nOjEuNXB4O2NvbG9yOnZhcigtLXR4LW11dGVkKTttYXJnaW4tYm90dG9tOjRw"
"eH0KLmNoYWluLWNvc3R7Zm9udC1mYW1pbHk6J1N5bmUnLHNhbnMtc2VyaWY7Zm9udC13ZWlnaHQ6"
"ODAwO2NvbG9yOnZhcigtLXJlZCk7Zm9udC1zaXplOjE0cHg7bWFyZ2luLXRvcDo0cHh9CgovKiBG"
"aXggU2VjdGlvbiAqLwouY2hhaW4tZml4ewogIGJhY2tncm91bmQ6cmdiYSg0NSwxMDYsNzksMC4w"
"NCk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDQ1LDEwNiw3OSwwLjEyKTsKICBib3JkZXItcmFkaXVz"
"OjhweDtwYWRkaW5nOjEycHggMTRweDttYXJnaW4tdG9wOjEwcHg7Cn0KLmNoYWluLWZpeC10aXRs"
"ZXtmb250LXNpemU6OXB4O2ZvbnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzoxLjVweDtjb2xv"
"cjp2YXIoLS1zZXYtbG93KTttYXJnaW4tYm90dG9tOjZweH0KLmNoYWluLWZpeC1jbWR7CiAgZm9u"
"dC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTFweDsKICBjb2xv"
"cjp2YXIoLS10eC1kYXJrKTtsaW5lLWhlaWdodDoxLjg7d2hpdGUtc3BhY2U6cHJlLXdyYXA7Cn0K"
"Ci8qIENvbXBsaWFuY2UgVGFncyAqLwouY2hhaW4tY29tcGxpYW5jZXtkaXNwbGF5OmZsZXg7Zmxl"
"eC13cmFwOndyYXA7Z2FwOjZweDttYXJnaW4tdG9wOjEwcHh9Ci5jaGFpbi1jb21wLXRhZ3sKICBm"
"b250LWZhbWlseTonSUJNIFBsZXggTW9ubycsbW9ub3NwYWNlO2ZvbnQtc2l6ZTo5cHg7Zm9udC13"
"ZWlnaHQ6NjAwOwogIHBhZGRpbmc6M3B4IDhweDtib3JkZXItcmFkaXVzOjRweDsKICBiYWNrZ3Jv"
"dW5kOnZhcigtLXdoaXRlLTIpO2JvcmRlcjoxcHggc29saWQgdmFyKC0td2hpdGUtMyk7Y29sb3I6"
"dmFyKC0tdHgtbXV0ZWQpOwp9CgovKiBTdW1tYXJ5IFN0YXRzICovCi5jaGFpbi1zdW1tYXJ5ewog"
"IGRpc3BsYXk6Z3JpZDtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDQsMWZyKTtnYXA6MTJw"
"eDttYXJnaW4tYm90dG9tOjIwcHg7Cn0KLmNoYWluLXN0YXR7CiAgYmFja2dyb3VuZDp2YXIoLS13"
"aGl0ZSk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTtib3JkZXItcmFkaXVzOnZhcigt"
"LXJhZGl1cyk7CiAgcGFkZGluZzoxNnB4O3RleHQtYWxpZ246Y2VudGVyOwp9Ci5jaGFpbi1zdGF0"
"LW51bXtmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjtmb250LXNpemU6MjhweDtmb250LXdl"
"aWdodDo4MDB9Ci5jaGFpbi1zdGF0LWxhYmVse2ZvbnQtc2l6ZToxMHB4O2NvbG9yOnZhcigtLXR4"
"LW11dGVkKTttYXJnaW4tdG9wOjRweDtsZXR0ZXItc3BhY2luZzowLjVweH0KCi8qIFJlcG9ydCBC"
"dXR0b24gKi8KLmJ0bi1hZHYtcmVwb3J0ewogIGJhY2tncm91bmQ6dmFyKC0tYmxhY2spO2NvbG9y"
"OnZhcigtLXdoaXRlKTtib3JkZXI6bm9uZTsKICBwYWRkaW5nOjEwcHggMjBweDtib3JkZXItcmFk"
"aXVzOnZhcigtLXJhZGl1cyk7Y3Vyc29yOnBvaW50ZXI7CiAgZm9udC1mYW1pbHk6J091dGZpdCcs"
"c2Fucy1zZXJpZjtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo2MDA7CiAgdHJhbnNpdGlvbjph"
"bGwgLjJzOwp9Ci5idG4tYWR2LXJlcG9ydDpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXJlZCl9CgpA"
"bWVkaWEobWF4LXdpZHRoOjkwMHB4KXsuc2lkZWJhcntkaXNwbGF5Om5vbmV9LmRhc2gtZ3JpZC5j"
"b2xzLTQsLmNoYWluLXN1bW1hcnl7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgyLDFmcil9"
"fQo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5Pgo8ZGl2IGNsYXNzPSJhcHAiPgoKPCEtLSA9PT09PT09"
"PT09PT09PT09IFNJREVCQVIgPT09PT09PT09PT09PT09PSAtLT4KPGFzaWRlIGNsYXNzPSJzaWRl"
"YmFyIj4KICA8ZGl2IGNsYXNzPSJzaWRlYmFyLXNjcm9sbCI+CiAgICA8ZGl2IGNsYXNzPSJzLWxv"
"Z28iPgogICAgICA8ZGl2IGNsYXNzPSJzLWxvZ28tbWFyayI+SDwvZGl2PgogICAgICA8ZGl2Pjxk"
"aXYgY2xhc3M9InMtbG9nby10ZXh0Ij5IQVJTSEE8L2Rpdj48ZGl2IGNsYXNzPSJzLWxvZ28tc3Vi"
"Ij5WQVBUIFNVSVRFIHY3LjA8L2Rpdj48L2Rpdj4KICAgIDwvZGl2PgoKICAgIDwhLS0gU0VBUkNI"
"IC0tPgogICAgPGRpdiBjbGFzcz0icy1zZWFyY2giPgogICAgICA8c3BhbiBjbGFzcz0icy1zZWFy"
"Y2gtaWNvbiI+8J+UjTwvc3Bhbj4KICAgICAgPGlucHV0IHR5cGU9InRleHQiIGNsYXNzPSJzLXNl"
"YXJjaC1pbnB1dCIgaWQ9InRvb2wtc2VhcmNoIiBwbGFjZWhvbGRlcj0iU2VhcmNoIHRvb2xzLi4u"
"IiBvbmlucHV0PSJmaWx0ZXJUb29scyh0aGlzLnZhbHVlKSI+CiAgICA8L2Rpdj4KCiAgICA8IS0t"
"IE5FVFdPUksgLS0+CiAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rpb24gb3BlbiIgZGF0YS1zZWN0aW9u"
"PSJuZXQiPgogICAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rpb24taGVhZGVyIiBvbmNsaWNrPSJ0b2dn"
"bGVTZWN0aW9uKHRoaXMpIj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWljb24iPvCf"
"k6E8L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi10aXRsZSI+TmV0d29yazwv"
"c3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWNvdW50Ij45PC9zcGFuPgogICAg"
"ICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tYXJyb3ciPuKWvDwvc3Bhbj4KICAgICAgPC9kaXY+"
"CiAgICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbi1ib2R5Ij4KICAgICAgICA8YnV0dG9uIGNsYXNz"
"PSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnbm1hcF9zY2FuJyx0aGlzLCduZXQnKSIgZGF0YS1u"
"YW1lPSJwb3J0IHNjYW5uZXIgbm1hcCI+PHNwYW4gY2xhc3M9ImljbyI+8J+UjTwvc3Bhbj48c3Bh"
"biBjbGFzcz0ibGJsIj5Qb3J0IFNjYW5uZXI8L3NwYW4+PHNwYW4gY2xhc3M9InMtdGFnIHIiPkNP"
"UkU8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9"
"InJ1blRvb2woJ25tYXBfdG9wMTAwJyx0aGlzLCduZXQnKSIgZGF0YS1uYW1lPSJxdWljayB0b3Ag"
"MTAwIGZhc3QiPjxzcGFuIGNsYXNzPSJpY28iPuKaoTwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5R"
"dWljayBUb3AgMTAwPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2"
"IiBvbmNsaWNrPSJydW5Ub29sKCdubWFwX3Z1bG4nLHRoaXMsJ25ldCcpIiBkYXRhLW5hbWU9InZ1"
"bG5lcmFiaWxpdHkgY3ZlIHNjYW4iPjxzcGFuIGNsYXNzPSJpY28iPvCfm6E8L3NwYW4+PHNwYW4g"
"Y2xhc3M9ImxibCI+VnVsbiBTY2FuPC9zcGFuPjxzcGFuIGNsYXNzPSJzLXRhZyByIj5DVkU8L3Nw"
"YW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRv"
"b2woJ3VkcF9zY2FuJyx0aGlzLCduZXQnKSIgZGF0YS1uYW1lPSJ1ZHAgc2NhbiI+PHNwYW4gY2xh"
"c3M9ImljbyI+8J+ToTwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5VRFAgU2Nhbjwvc3Bhbj48L2J1"
"dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnZmly"
"ZXdhbGxfZGV0ZWN0Jyx0aGlzLCduZXQnKSIgZGF0YS1uYW1lPSJmaXJld2FsbCBkZXRlY3Qgd2Fm"
"Ij48c3BhbiBjbGFzcz0iaWNvIj7wn6exPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkZpcmV3YWxs"
"IERldGVjdDwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25j"
"bGljaz0icnVuVG9vbCgnc21iX2VudW0nLHRoaXMsJ25ldCcpIiBkYXRhLW5hbWU9InNtYiBlbnVt"
"IHNoYXJlIj48c3BhbiBjbGFzcz0iaWNvIj7wn5OCPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPlNN"
"QiBFbnVtPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNs"
"aWNrPSJydW5Ub29sKCdzbm1wX2NoZWNrJyx0aGlzLCduZXQnKSIgZGF0YS1uYW1lPSJzbm1wIGNo"
"ZWNrIGNvbW11bml0eSI+PHNwYW4gY2xhc3M9ImljbyI+8J+Tijwvc3Bhbj48c3BhbiBjbGFzcz0i"
"bGJsIj5TTk1QIENoZWNrPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMt"
"bmF2IiBvbmNsaWNrPSJydW5Ub29sKCdiYW5uZXJfZ3JhYicsdGhpcywnbmV0JykiIGRhdGEtbmFt"
"ZT0iYmFubmVyIGdyYWIgc2VydmljZSB2ZXJzaW9uIj48c3BhbiBjbGFzcz0iaWNvIj7wn4+3PC9z"
"cGFuPjxzcGFuIGNsYXNzPSJsYmwiPkJhbm5lciBHcmFiPC9zcGFuPjwvYnV0dG9uPgogICAgICAg"
"IDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdhcnBfc2NhbicsdGhpcywn"
"bmV0JykiIGRhdGEtbmFtZT0iYXJwIHNjYW4gbG9jYWwiPjxzcGFuIGNsYXNzPSJpY28iPvCfk4s8"
"L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+QVJQIFNjYW48L3NwYW4+PC9idXR0b24+CiAgICAgIDwv"
"ZGl2PgogICAgPC9kaXY+CgogICAgPCEtLSBXRUIgLS0+CiAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rp"
"b24gb3BlbiIgZGF0YS1zZWN0aW9uPSJ3ZWIiPgogICAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rpb24t"
"aGVhZGVyIiBvbmNsaWNrPSJ0b2dnbGVTZWN0aW9uKHRoaXMpIj4KICAgICAgICA8c3BhbiBjbGFz"
"cz0icy1zZWN0aW9uLWljb24iPvCfjJA8L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2Vj"
"dGlvbi10aXRsZSI+V2ViPC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tY291"
"bnQiPjEwPC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tYXJyb3ciPuKWvDwv"
"c3Bhbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbi1ib2R5Ij4KICAg"
"ICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnc3FsbWFwX2NoZWNr"
"Jyx0aGlzLCd3ZWInKSIgZGF0YS1uYW1lPSJzcWwgaW5qZWN0aW9uIHNxbGkgc3FsbWFwIj48c3Bh"
"biBjbGFzcz0iaWNvIj7wn5KJPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPlNRTCBJbmplY3Rpb248"
"L3NwYW4+PHNwYW4gY2xhc3M9InMtdGFnIHIiPkNSSVQ8L3NwYW4+PC9idXR0b24+CiAgICAgICAg"
"PGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ3hzc19zY2FuJyx0aGlzLCd3"
"ZWInKSIgZGF0YS1uYW1lPSJ4c3MgY3Jvc3Mgc2l0ZSBzY3JpcHRpbmciPjxzcGFuIGNsYXNzPSJp"
"Y28iPuKaoDwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5YU1MgU2Nhbm5lcjwvc3Bhbj48L2J1dHRv"
"bj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnbmlrdG9f"
"c2NhbicsdGhpcywnd2ViJykiIGRhdGEtbmFtZT0ibmlrdG8gd2ViIHNjYW4iPjxzcGFuIGNsYXNz"
"PSJpY28iPvCfjJA8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+TmlrdG8gU2Nhbjwvc3Bhbj48L2J1"
"dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnaGVh"
"ZGVyX2NoZWNrJyx0aGlzLCd3ZWInKSIgZGF0YS1uYW1lPSJoZWFkZXIgYXVkaXQgaHR0cCBzZWN1"
"cml0eSI+PHNwYW4gY2xhc3M9ImljbyI+8J+Tizwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5IZWFk"
"ZXIgQXVkaXQ8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9u"
"Y2xpY2s9InJ1blRvb2woJ3NzbF9jaGVjaycsdGhpcywnd2ViJykiIGRhdGEtbmFtZT0ic3NsIHRs"
"cyBjZXJ0aWZpY2F0ZSBodHRwcyI+PHNwYW4gY2xhc3M9ImljbyI+8J+Ukjwvc3Bhbj48c3BhbiBj"
"bGFzcz0ibGJsIj5TU0wvVExTIENoZWNrPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24g"
"Y2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCd3YWZfZGV0ZWN0Jyx0aGlzLCd3ZWInKSIg"
"ZGF0YS1uYW1lPSJ3YWYgd2ViIGFwcGxpY2F0aW9uIGZpcmV3YWxsIj48c3BhbiBjbGFzcz0iaWNv"
"Ij7wn5uhPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPldBRiBEZXRlY3Q8L3NwYW4+PC9idXR0b24+"
"CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ2NvcnNfY2hl"
"Y2snLHRoaXMsJ3dlYicpIiBkYXRhLW5hbWU9ImNvcnMgY3Jvc3Mgb3JpZ2luIj48c3BhbiBjbGFz"
"cz0iaWNvIj7wn5SXPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkNPUlMgQ2hlY2s8L3NwYW4+PC9i"
"dXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ2Rp"
"cl9lbnVtJyx0aGlzLCd3ZWInKSIgZGF0YS1uYW1lPSJkaXJlY3RvcnkgZW51bWVyYXRpb24gYnJ1"
"dGUgZGlyYnVzdGVyIj48c3BhbiBjbGFzcz0iaWNvIj7wn5OBPC9zcGFuPjxzcGFuIGNsYXNzPSJs"
"YmwiPkRpcmVjdG9yeSBFbnVtPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9"
"InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdjbXNfZGV0ZWN0Jyx0aGlzLCd3ZWInKSIgZGF0YS1u"
"YW1lPSJjbXMgZGV0ZWN0IHdvcmRwcmVzcyBqb29tbGEgZHJ1cGFsIj48c3BhbiBjbGFzcz0iaWNv"
"Ij7wn4+XPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkNNUyBEZXRlY3Q8L3NwYW4+PC9idXR0b24+"
"CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ2FkbWluX2Zp"
"bmRlcicsdGhpcywnd2ViJykiIGRhdGEtbmFtZT0iYWRtaW4gZmluZGVyIHBhbmVsIGxvZ2luIj48"
"c3BhbiBjbGFzcz0iaWNvIj7wn5SRPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkFkbWluIEZpbmRl"
"cjwvc3Bhbj48L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KCiAgICA8IS0tIElORlJB"
"U1RSVUNUVVJFIC0tPgogICAgPGRpdiBjbGFzcz0icy1zZWN0aW9uIiBkYXRhLXNlY3Rpb249Imlu"
"ZiI+CiAgICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbi1oZWFkZXIiIG9uY2xpY2s9InRvZ2dsZVNl"
"Y3Rpb24odGhpcykiPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24taWNvbiI+8J+WpTwv"
"c3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLXRpdGxlIj5JbmZyYXN0cnVjdHVy"
"ZTwvc3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWNvdW50Ij42PC9zcGFuPgog"
"ICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tYXJyb3ciPuKWvDwvc3Bhbj4KICAgICAgPC9k"
"aXY+CiAgICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbi1ib2R5Ij4KICAgICAgICA8YnV0dG9uIGNs"
"YXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnc3NoX2F1ZGl0Jyx0aGlzLCdpbmYnKSIgZGF0"
"YS1uYW1lPSJzc2ggYXVkaXQga2V5Ij48c3BhbiBjbGFzcz0iaWNvIj7wn5SQPC9zcGFuPjxzcGFu"
"IGNsYXNzPSJsYmwiPlNTSCBBdWRpdDwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNs"
"YXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnZnRwX2NoZWNrJyx0aGlzLCdpbmYnKSIgZGF0"
"YS1uYW1lPSJmdHAgYW5vbnltb3VzIGNoZWNrIj48c3BhbiBjbGFzcz0iaWNvIj7wn5OkPC9zcGFu"
"PjxzcGFuIGNsYXNzPSJsYmwiPkZUUCBDaGVjazwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0"
"dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgncmRwX2NoZWNrJyx0aGlzLCdpbmYn"
"KSIgZGF0YS1uYW1lPSJyZHAgcmVtb3RlIGRlc2t0b3AgYmx1ZWtlZXAiPjxzcGFuIGNsYXNzPSJp"
"Y28iPvCflqU8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+UkRQIENoZWNrPC9zcGFuPjwvYnV0dG9u"
"PgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdkYl9leHBv"
"c2UnLHRoaXMsJ2luZicpIiBkYXRhLW5hbWU9ImRhdGFiYXNlIGV4cG9zdXJlIG15c3FsIHBvc3Rn"
"cmVzIHJlZGlzIG1vbmdvIj48c3BhbiBjbGFzcz0iaWNvIj7wn5eEPC9zcGFuPjxzcGFuIGNsYXNz"
"PSJsYmwiPkRCIEV4cG9zdXJlPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9"
"InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdkb2NrZXJfY2hlY2snLHRoaXMsJ2luZicpIiBkYXRh"
"LW5hbWU9ImRvY2tlciBjb250YWluZXIgYXBpIj48c3BhbiBjbGFzcz0iaWNvIj7wn5CzPC9zcGFu"
"PjxzcGFuIGNsYXNzPSJsYmwiPkRvY2tlciBDaGVjazwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8"
"YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnazhzX2NoZWNrJyx0aGlzLCdp"
"bmYnKSIgZGF0YS1uYW1lPSJrdWJlcm5ldGVzIGs4cyBjbHVzdGVyIj48c3BhbiBjbGFzcz0iaWNv"
"Ij7imLg8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+SzhzIENoZWNrPC9zcGFuPjwvYnV0dG9uPgog"
"ICAgICA8L2Rpdj4KICAgIDwvZGl2PgoKICAgIDwhLS0gTlVDTEVJIC0tPgogICAgPGRpdiBjbGFz"
"cz0icy1zZWN0aW9uIiBkYXRhLXNlY3Rpb249Im51YyI+CiAgICAgIDxkaXYgY2xhc3M9InMtc2Vj"
"dGlvbi1oZWFkZXIiIG9uY2xpY2s9InRvZ2dsZVNlY3Rpb24odGhpcykiPgogICAgICAgIDxzcGFu"
"IGNsYXNzPSJzLXNlY3Rpb24taWNvbiI+4piiPC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJz"
"LXNlY3Rpb24tdGl0bGUiPk51Y2xlaTwvc3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0"
"aW9uLWNvdW50Ij42PC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tYXJyb3ci"
"PuKWvDwvc3Bhbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbi1ib2R5"
"Ij4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnbnVjbGVp"
"X2Z1bGwnLHRoaXMsJ3dlYicpIiBkYXRhLW5hbWU9Im51Y2xlaSBmdWxsIHNjYW4gYWxsIHRlbXBs"
"YXRlcyI+PHNwYW4gY2xhc3M9ImljbyI+4piiPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkZ1bGwg"
"U2Nhbjwvc3Bhbj48c3BhbiBjbGFzcz0icy10YWcgciI+Q09SRTwvc3Bhbj48L2J1dHRvbj4KICAg"
"ICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnbnVjbGVpX2N2ZScs"
"dGhpcywnd2ViJykiIGRhdGEtbmFtZT0ibnVjbGVpIGN2ZSB2dWxuZXJhYmlsaXR5Ij48c3BhbiBj"
"bGFzcz0iaWNvIj7wn5SlPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkNWRSBTY2FuPC9zcGFuPjxz"
"cGFuIGNsYXNzPSJzLXRhZyByIj5DVkU8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBj"
"bGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ251Y2xlaV9jcml0aWNhbCcsdGhpcywnd2Vi"
"JykiIGRhdGEtbmFtZT0ibnVjbGVpIGNyaXRpY2FsIGhpZ2ggc2V2ZXJpdHkiPjxzcGFuIGNsYXNz"
"PSJpY28iPvCfmqg8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+Q3JpdGljYWwvSGlnaDwvc3Bhbj48"
"L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgn"
"bnVjbGVpX21pc2NvbmZpZycsdGhpcywnd2ViJykiIGRhdGEtbmFtZT0ibnVjbGVpIG1pc2NvbmZp"
"Z3VyYXRpb24gZXhwb3NlZCI+PHNwYW4gY2xhc3M9ImljbyI+4pqZPC9zcGFuPjxzcGFuIGNsYXNz"
"PSJsYmwiPk1pc2NvbmZpZyBTY2FuPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xh"
"c3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdudWNsZWlfdGVjaCcsdGhpcywnd2ViJykiIGRh"
"dGEtbmFtZT0ibnVjbGVpIHRlY2hub2xvZ3kgZGV0ZWN0IGZpbmdlcnByaW50Ij48c3BhbiBjbGFz"
"cz0iaWNvIj7wn5SsPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPlRlY2ggRGV0ZWN0PC9zcGFuPjwv"
"YnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdu"
"dWNsZWlfbmV0d29yaycsdGhpcywnaW5mJykiIGRhdGEtbmFtZT0ibnVjbGVpIG5ldHdvcmsgcHJv"
"dG9jb2wiPjxzcGFuIGNsYXNzPSJpY28iPvCfjJA8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+TmV0"
"d29yayBTY2FuPC9zcGFuPjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgoKICAgIDwh"
"LS0gUkVDT04gLS0+CiAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rpb24iIGRhdGEtc2VjdGlvbj0icmVj"
"Ij4KICAgICAgPGRpdiBjbGFzcz0icy1zZWN0aW9uLWhlYWRlciIgb25jbGljaz0idG9nZ2xlU2Vj"
"dGlvbih0aGlzKSI+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi1pY29uIj7wn5W1PC9z"
"cGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tdGl0bGUiPlJlY29uPC9zcGFuPgog"
"ICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tY291bnQiPjg8L3NwYW4+CiAgICAgICAgPHNw"
"YW4gY2xhc3M9InMtc2VjdGlvbi1hcnJvdyI+4pa8PC9zcGFuPgogICAgICA8L2Rpdj4KICAgICAg"
"PGRpdiBjbGFzcz0icy1zZWN0aW9uLWJvZHkiPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2"
"IiBvbmNsaWNrPSJydW5Ub29sKCd3aG9pcycsdGhpcywncmVjJykiIGRhdGEtbmFtZT0id2hvaXMg"
"ZG9tYWluIHJlZ2lzdHJhdGlvbiI+PHNwYW4gY2xhc3M9ImljbyI+8J+MjTwvc3Bhbj48c3BhbiBj"
"bGFzcz0ibGJsIj5XSE9JUzwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJz"
"LW5hdiIgb25jbGljaz0icnVuVG9vbCgnZG5zX2xvb2t1cCcsdGhpcywncmVjJykiIGRhdGEtbmFt"
"ZT0iZG5zIGxvb2t1cCByZWNvcmRzIj48c3BhbiBjbGFzcz0iaWNvIj7wn5OhPC9zcGFuPjxzcGFu"
"IGNsYXNzPSJsYmwiPkROUyBMb29rdXA8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBj"
"bGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ3N1YmRvbWFpbl9lbnVtJyx0aGlzLCdyZWMn"
"KSIgZGF0YS1uYW1lPSJzdWJkb21haW4gZW51bWVyYXRpb24iPjxzcGFuIGNsYXNzPSJpY28iPvCf"
"lI48L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+U3ViZG9tYWluIEVudW08L3NwYW4+PC9idXR0b24+"
"CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ3RyYWNlcm91"
"dGUnLHRoaXMsJ3JlYycpIiBkYXRhLW5hbWU9InRyYWNlcm91dGUgaG9wcyI+PHNwYW4gY2xhc3M9"
"ImljbyI+8J+bpDwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5UcmFjZXJvdXRlPC9zcGFuPjwvYnV0"
"dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCduZXR3"
"b3JrX3NjYW4nLHRoaXMsJ3JlYycpIiBkYXRhLW5hbWU9ImxvY2FsIG5ldHdvcmsgc2NhbiBkaXNj"
"b3ZlciI+PHNwYW4gY2xhc3M9ImljbyI+8J+Ttjwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5Mb2Nh"
"bCBOZXR3b3JrPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBv"
"bmNsaWNrPSJydW5Ub29sKCdteV9pcCcsdGhpcywncmVjJykiIGRhdGEtbmFtZT0ibXkgaXAgYWRk"
"cmVzcyBwdWJsaWMiPjxzcGFuIGNsYXNzPSJpY28iPvCfj6A8L3NwYW4+PHNwYW4gY2xhc3M9Imxi"
"bCI+TXkgSVA8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9u"
"Y2xpY2s9InJ1blRvb2woJ3N5c3RlbV9pbmZvJyx0aGlzLCdyZWMnKSIgZGF0YS1uYW1lPSJzeXN0"
"ZW0gaW5mbyBjcHUgcmFtIG9zIj48c3BhbiBjbGFzcz0iaWNvIj7wn5K7PC9zcGFuPjxzcGFuIGNs"
"YXNzPSJsYmwiPlN5c3RlbSBJbmZvPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xh"
"c3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCd3ZWF0aGVyJyx0aGlzLCdyZWMnKSIgZGF0YS1u"
"YW1lPSJ3ZWF0aGVyIHRlbXBlcmF0dXJlIHZpc2FraGFwYXRuYW0iPjxzcGFuIGNsYXNzPSJpY28i"
"PvCfjKQ8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+V2VhdGhlcjwvc3Bhbj48L2J1dHRvbj4KICAg"
"ICAgPC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KICA8ZGl2IGNsYXNzPSJzLWZvb3RlciI+CiAg"
"ICA8ZGl2IGNsYXNzPSJzLWF2YXRhciI+SEE8L2Rpdj4KICAgIDxkaXY+PGRpdiBjbGFzcz0icy11"
"bmFtZSI+SEFSU0hBPC9kaXY+PGRpdiBjbGFzcz0icy11cm9sZSI+TGV2ZWwgNSDCtyAzOCBUb29s"
"cyBBcm1lZDwvZGl2PjwvZGl2PgogIDwvZGl2Pgo8L2FzaWRlPgoKPCEtLSA9PT09PT09PT09PT09"
"PT09IE1BSU4gPT09PT09PT09PT09PT09PSAtLT4KPGRpdiBjbGFzcz0ibWFpbiI+CiAgPGhlYWRl"
"ciBjbGFzcz0iaGVhZGVyIj4KICAgIDxkaXYgY2xhc3M9ImgtbGVmdCI+CiAgICAgIDxkaXYgY2xh"
"c3M9ImgtdGl0bGUiPlZBUFQgRGFzaGJvYXJkPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Imgtc2Vw"
"Ij48L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iaC10YXJnZXQiIHN0eWxlPSJwb3NpdGlvbjpyZWxh"
"dGl2ZSI+CiAgICAgICAgPGRpdiBjbGFzcz0iaC10YXJnZXQtcHJlIj5UQVJHRVQ8L2Rpdj4KICAg"
"ICAgICA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9InRhcmdldC1pbnB1dCIgY2xhc3M9ImgtdGFyZ2V0"
"LWlucHV0IiBwbGFjZWhvbGRlcj0iRW50ZXIgSVAsIGRvbWFpbiwgb3IgVVJMLi4uIiBvbmZvY3Vz"
"PSJzaG93VGFyZ2V0SGlzdG9yeSgpIiBvbmlucHV0PSJzaG93VGFyZ2V0SGlzdG9yeSgpIiBhdXRv"
"Y29tcGxldGU9Im9mZiI+CiAgICAgICAgPGRpdiBjbGFzcz0iaC10YXJnZXQtaGlzdG9yeSIgaWQ9"
"InRhcmdldC1oaXN0b3J5Ij48L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYg"
"Y2xhc3M9ImgtcmlnaHQiPgogICAgICA8ZGl2IGNsYXNzPSJoLW1pbmktc3RhdHMiIGlkPSJoLW1p"
"bmktc3RhdHMiPgogICAgICAgIDxzcGFuIGNsYXNzPSJoLW1pbmktc3RhdCIgdGl0bGU9IlNjYW5z"
"Ij7wn5SNIDxzdHJvbmcgaWQ9ImhtLXNjYW5zIj4wPC9zdHJvbmc+PC9zcGFuPgogICAgICAgIDxz"
"cGFuIGNsYXNzPSJoLW1pbmktc3RhdCIgdGl0bGU9IlBvcnRzIj7wn5OhIDxzdHJvbmcgaWQ9Imht"
"LXBvcnRzIj4wPC9zdHJvbmc+PC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJoLW1pbmktc3Rh"
"dCIgdGl0bGU9IlRocmVhdHMiPuKaoCA8c3Ryb25nIGlkPSJobS10aHJlYXRzIj4wPC9zdHJvbmc+"
"PC9zcGFuPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iaC1zdGF0dXMiPjxzcGFuIGNs"
"YXNzPSJkb3QiPjwvc3Bhbj5PTkxJTkU8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iaC1jbG9jayIg"
"aWQ9ImNsb2NrIj48L2Rpdj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuLXJlcG9ydCIgb25jbGlj"
"az0ib3BlblJlcG9ydCgpIj7wn5OEIFJlcG9ydDwvYnV0dG9uPgogICAgPC9kaXY+CiAgPC9oZWFk"
"ZXI+CiAgPCEtLSBNSU5JIFBST0dSRVNTIEJBUiAtLT4KICA8ZGl2IGNsYXNzPSJoLW1pbmktcHJv"
"Z3Jlc3MiIGlkPSJoLW1pbmktcHJvZ3Jlc3MiPjxkaXYgY2xhc3M9ImgtbWluaS1iYXIiIGlkPSJo"
"LW1pbmktYmFyIj48L2Rpdj48L2Rpdj4KICA8bmF2IGNsYXNzPSJ0YWItbmF2Ij4KICAgIDxidXR0"
"b24gY2xhc3M9InRhYi1idG4gYWN0aXZlIiBvbmNsaWNrPSJzd2l0Y2hUYWIoJ3Rlcm1pbmFsJyx0"
"aGlzKSI+VGVybWluYWw8L2J1dHRvbj4KICAgIDxidXR0b24gY2xhc3M9InRhYi1idG4iIG9uY2xp"
"Y2s9InN3aXRjaFRhYigncG9ydHMnLHRoaXMpIj5Qb3J0cyA8c3BhbiBjbGFzcz0idGFiLWJhZGdl"
"IiBpZD0icG9ydC1iYWRnZSI+MDwvc3Bhbj48L2J1dHRvbj4KICAgIDxidXR0b24gY2xhc3M9InRh"
"Yi1idG4iIG9uY2xpY2s9InN3aXRjaFRhYigndGhyZWF0cycsdGhpcykiPlRocmVhdHMgPHNwYW4g"
"Y2xhc3M9InRhYi1iYWRnZSIgaWQ9InRocmVhdC1iYWRnZSI+MDwvc3Bhbj48L2J1dHRvbj4KICAg"
"IDxidXR0b24gY2xhc3M9InRhYi1idG4iIG9uY2xpY2s9InN3aXRjaFRhYigncmlzaycsdGhpcyki"
"PlJpc2sgQW5hbHlzaXM8L2J1dHRvbj4KICAgIDxidXR0b24gY2xhc3M9InRhYi1idG4iIG9uY2xp"
"Y2s9InN3aXRjaFRhYigndGdyYXBoJyx0aGlzKSI+VGhyZWF0IEdyYXBoPC9idXR0b24+CiAgICA8"
"YnV0dG9uIGNsYXNzPSJ0YWItYnRuIiBvbmNsaWNrPSJzd2l0Y2hUYWIoJ3NjYW5zdGF0dXMnLHRo"
"aXMpIj5TY2FuIFN0YXR1cyA8c3BhbiBjbGFzcz0idGFiLWJhZGdlIiBpZD0ic2Nhbi1zdGF0dXMt"
"YmFkZ2UiPuKXjzwvc3Bhbj48L2J1dHRvbj4KICAgIDxidXR0b24gY2xhc3M9InRhYi1idG4iIG9u"
"Y2xpY2s9InN3aXRjaFRhYignY2hhaW5zJyx0aGlzKSI+QXR0YWNrIENoYWlucyA8c3BhbiBjbGFz"
"cz0idGFiLWJhZGdlIiBpZD0iY2hhaW4tYmFkZ2UiPuKXjzwvc3Bhbj48L2J1dHRvbj4KICA8L25h"
"dj4KCiAgPGRpdiBjbGFzcz0iY29udGVudCI+CiAgICA8IS0tIFRFUk1JTkFMIC0tPgogICAgPGRp"
"diBjbGFzcz0idGFiLXBhbmUgYWN0aXZlIiBpZD0icGFuZS10ZXJtaW5hbCI+CiAgICAgIDxkaXYg"
"Y2xhc3M9InRlcm1pbmFsLWNhcmQiPgogICAgICAgIDxkaXYgY2xhc3M9InRlcm0taGVhZGVyIj4K"
"ICAgICAgICAgIDxkaXYgY2xhc3M9InRlcm0tZG90cyI+PHNwYW4gY2xhc3M9ImQxIj48L3NwYW4+"
"PHNwYW4gY2xhc3M9ImQyIj48L3NwYW4+PHNwYW4gY2xhc3M9ImQzIj48L3NwYW4+PC9kaXY+CiAg"
"ICAgICAgICA8ZGl2IGNsYXNzPSJ0ZXJtLXRpdGxlIj5IQVJTSEEgdjcuMCDigJQgT1VUUFVUPC9k"
"aXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ0ZXJtLWFjdGlvbnMiPjxidXR0b24gY2xhc3M9InRl"
"cm0tYWN0IiBvbmNsaWNrPSJjb3B5T3V0cHV0KCkiPkNPUFk8L2J1dHRvbj48YnV0dG9uIGNsYXNz"
"PSJ0ZXJtLWFjdCIgb25jbGljaz0iY2xlYXJUZXJtaW5hbCgpIj5DTEVBUjwvYnV0dG9uPjwvZGl2"
"PgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImxvYWRpbmctYmFyIiBpZD0ibG9h"
"ZGluZy1iYXIiPjwvZGl2PgogICAgICAgIDxkaXYgaWQ9InRlcm1pbmFsLW91dHB1dCI+CiAgICAg"
"ICAgICA8ZGl2IGNsYXNzPSJ0bCBoZHIiPi8vIEhBUlNIQSB2Ny4wIOKAlCBXRUIgKyBORVRXT1JL"
"ICsgSU5GUkFTVFJVQ1RVUkUgVkFQVCBTVUlURTwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0i"
"dGwgcHJvbXB0Ij5oYXJzaGFAa2FsaTp+JCA8c3BhbiBjbGFzcz0iYmxpbmsiPnw8L3NwYW4+PC9k"
"aXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bCBpbmZvIj5bIFdFQiAgICAgXSBTUUwgSW5qZWN0"
"aW9uLCBYU1MsIFdBRiwgQ09SUywgQWRtaW4gRmluZGVyLCBDTVMsIFNTTDwvZGl2PgogICAgICAg"
"ICAgPGRpdiBjbGFzcz0idGwgaW5mbyI+WyBORVRXT1JLIF0gUG9ydCBTY2FuLCBVRFAsIEZpcmV3"
"YWxsLCBTTUIsIFNOTVAsIEJhbm5lciwgQVJQPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ0"
"bCBpbmZvIj5bIElORlJBICAgXSBTU0gsIEZUUCwgUkRQLCBEQiBFeHBvc3VyZSwgRG9ja2VyLCBL"
"OHMsIENWRSBTY2FuPC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJ0bCByZXN1bHQiPlsgUkVB"
"RFkgICBdIFNlbGVjdCBhIHRvb2wgZnJvbSBzaWRlYmFyIGFuZCBlbnRlciB0YXJnZXQgdG8gYmVn"
"aW4uPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJk"
"YXNoLWdyaWQgY29scy00IiBzdHlsZT0ibWFyZ2luLXRvcDoyMHB4Ij4KICAgICAgICA8ZGl2IGNs"
"YXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxlIj5Ub3RhbCBTY2FuczwvZGl2Pjxk"
"aXYgY2xhc3M9InN0YXQtbnVtIGJyYW5kIiBpZD0ic3RhdC1zY2FucyI+MDwvZGl2PjxkaXYgY2xh"
"c3M9InN0YXQtYmFyLXdyYXAiPjxkaXYgY2xhc3M9InN0YXQtYmFyIj48ZGl2IGNsYXNzPSJzdGF0"
"LWJhci1maWxsIGJyYW5kIiBpZD0ic2Nhbi1iYXIiIHN0eWxlPSJ3aWR0aDowJSI+PC9kaXY+PC9k"
"aXY+PC9kaXY+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0iY2Fy"
"ZC1zdWJ0aXRsZSI+T3BlbiBQb3J0czwvZGl2PjxkaXYgY2xhc3M9InN0YXQtbnVtIG9yYW5nZSIg"
"aWQ9InN0YXQtcG9ydHMiPjA8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LWJhci13cmFwIj48ZGl2IGNs"
"YXNzPSJzdGF0LWJhciI+PGRpdiBjbGFzcz0ic3RhdC1iYXItZmlsbCBvcmFuZ2UiIGlkPSJwb3J0"
"LWJhciIgc3R5bGU9IndpZHRoOjAlIj48L2Rpdj48L2Rpdj48L2Rpdj48L2Rpdj4KICAgICAgICA8"
"ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxlIj5UaHJlYXRzIEZvdW5k"
"PC9kaXY+PGRpdiBjbGFzcz0ic3RhdC1udW0gcmVkIiBpZD0ic3RhdC10aHJlYXRzIj4wPC9kaXY+"
"PGRpdiBjbGFzcz0ic3RhdC1iYXItd3JhcCI+PGRpdiBjbGFzcz0ic3RhdC1iYXIiPjxkaXYgY2xh"
"c3M9InN0YXQtYmFyLWZpbGwgcmVkIiBpZD0idGhyZWF0LWJhciIgc3R5bGU9IndpZHRoOjAlIj48"
"L2Rpdj48L2Rpdj48L2Rpdj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNs"
"YXNzPSJjYXJkLXN1YnRpdGxlIj5MYXN0IFRvb2w8L2Rpdj48ZGl2IHN0eWxlPSJmb250LXNpemU6"
"MTRweDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tdHgtZGFyayk7bWFyZ2luLXRvcDo0cHgi"
"IGlkPSJzdGF0LWxhc3QtdG9vbCI+4oCUPC9kaXY+PGRpdiBjbGFzcz0ic3RhdC1zdWIiIGlkPSJz"
"dGF0LWxhc3QtdGltZSI+QXdhaXRpbmcgc2NhbjwvZGl2PjwvZGl2PgogICAgICA8L2Rpdj4KICAg"
"IDwvZGl2PgoKICAgIDwhLS0gUE9SVFMgLS0+CiAgICA8ZGl2IGNsYXNzPSJ0YWItcGFuZSIgaWQ9"
"InBhbmUtcG9ydHMiPjxkaXYgaWQ9InBvcnQtZGFzaCI+PGRpdiBjbGFzcz0iZW1wdHktc3RhdGUi"
"PjxkaXYgY2xhc3M9ImVtcHR5LWljbyI+8J+UjTwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXRpdGxl"
"Ij5ObyBQb3J0cyBGb3VuZCBZZXQ8L2Rpdj48ZGl2IGNsYXNzPSJlbXB0eS1zdWIiPlJ1biBhIHBv"
"cnQgc2NhbiB0byBwb3B1bGF0ZSB0aGlzIGRhc2hib2FyZDwvZGl2PjwvZGl2PjwvZGl2PjwvZGl2"
"PgoKICAgIDwhLS0gVEhSRUFUUyAtLT4KICAgIDxkaXYgY2xhc3M9InRhYi1wYW5lIiBpZD0icGFu"
"ZS10aHJlYXRzIj48ZGl2IGlkPSJ0aHJlYXQtZGFzaCI+PGRpdiBjbGFzcz0iZW1wdHktc3RhdGUi"
"PjxkaXYgY2xhc3M9ImVtcHR5LWljbyI+8J+boTwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXRpdGxl"
"Ij5ObyBUaHJlYXRzIERldGVjdGVkPC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktc3ViIj5SdW4gdnVs"
"bmVyYWJpbGl0eSBzY2FucyB0byBkaXNjb3ZlciB0aHJlYXRzPC9kaXY+PC9kaXY+PC9kaXY+PC9k"
"aXY+CgogICAgPCEtLSBSSVNLIEFOQUxZU0lTIC0tPgogICAgPGRpdiBjbGFzcz0idGFiLXBhbmUi"
"IGlkPSJwYW5lLXJpc2siPjxkaXYgaWQ9InJpc2stY29udGVudCI+PGRpdiBjbGFzcz0iZW1wdHkt"
"c3RhdGUiPjxkaXYgY2xhc3M9ImVtcHR5LWljbyI+8J+TijwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5"
"LXRpdGxlIj5ObyBSaXNrIERhdGE8L2Rpdj48ZGl2IGNsYXNzPSJlbXB0eS1zdWIiPlJ1biBzY2Fu"
"cyB0byBnZW5lcmF0ZSByaXNrIGFuYWx5c2lzPC9kaXY+PC9kaXY+PC9kaXY+PC9kaXY+CgogICAg"
"PCEtLSBUSFJFQVQgR1JBUEggLS0+CiAgICA8ZGl2IGNsYXNzPSJ0YWItcGFuZSIgaWQ9InBhbmUt"
"dGdyYXBoIj48ZGl2IGlkPSJ0Z3JhcGgtY29udGVudCI+PGRpdiBjbGFzcz0iZW1wdHktc3RhdGUi"
"PjxkaXYgY2xhc3M9ImVtcHR5LWljbyI+8J+VuDwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXRpdGxl"
"Ij5ObyBUaHJlYXQgRGF0YTwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXN1YiI+UnVuIHNjYW5zIHRv"
"IGdlbmVyYXRlIHRocmVhdCBhbmFseXNpczwvZGl2PjwvZGl2PjwvZGl2PjwvZGl2PgoKICAgIDwh"
"LS0gU0NBTiBTVEFUVVMgLS0+CiAgICA8ZGl2IGNsYXNzPSJ0YWItcGFuZSIgaWQ9InBhbmUtc2Nh"
"bnN0YXR1cyI+CiAgICAgIDxkaXYgaWQ9InNjYW4tc3RhdHVzLWNvbnRlbnQiPgogICAgICAgIDwh"
"LS0gTGl2ZSBTY2FuIENhcmQgLS0+CiAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCIgaWQ9ImxpdmUt"
"c2Nhbi1jYXJkIiBzdHlsZT0ibWFyZ2luLWJvdHRvbToyMHB4O2JvcmRlci1sZWZ0OjRweCBzb2xp"
"ZCB2YXIoLS13aGl0ZS00KSI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkLWhlYWRlciI+CiAg"
"ICAgICAgICAgIDxkaXY+PGRpdiBjbGFzcz0iY2FyZC10aXRsZSI+Q3VycmVudCBTY2FuPC9kaXY+"
"PGRpdiBjbGFzcz0iY2FyZC1zdWJ0aXRsZSIgaWQ9InNzLXN1YnRpdGxlIj5ObyBhY3RpdmUgc2Nh"
"bjwvZGl2PjwvZGl2PgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJzY2FuLWluZGljYXRvciIgaWQ9"
"InNjYW4taW5kaWNhdG9yIiBzdHlsZT0id2lkdGg6NDJweDtoZWlnaHQ6NDJweCI+PHNwYW4gY2xh"
"c3M9InNjYW4tcGN0IiBpZD0ic2Nhbi1wY3QtbnVtIiBzdHlsZT0iZm9udC1zaXplOjEycHgiPuKA"
"lDwvc3Bhbj48L2Rpdj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBzdHlsZT0iZGlz"
"cGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MjBweDttYXJnaW4tYm90dG9tOjE0cHgi"
"PgogICAgICAgICAgICA8ZGl2IHN0eWxlPSJmbGV4OjEiPgogICAgICAgICAgICAgIDxkaXYgc3R5"
"bGU9ImRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpiYXNlbGluZTtnYXA6MTBweDttYXJnaW4tYm90"
"dG9tOjZweCI+CiAgICAgICAgICAgICAgICA8ZGl2IGlkPSJzY2FuLXRvb2wtbmFtZSIgc3R5bGU9"
"ImZvbnQtc2l6ZToxNnB4O2ZvbnQtd2VpZ2h0OjgwMDtjb2xvcjp2YXIoLS10eC1kYXJrKTtmb250"
"LWZhbWlseTonU3luZScsc2Fucy1zZXJpZiI+4oCUPC9kaXY+CiAgICAgICAgICAgICAgICA8ZGl2"
"IGlkPSJzY2FuLXBoYXNlLWJhZGdlIiBzdHlsZT0iZm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8n"
"LG1vbm9zcGFjZTtmb250LXNpemU6OXB4O2ZvbnQtd2VpZ2h0OjcwMDtwYWRkaW5nOjNweCAxMHB4"
"O2JvcmRlci1yYWRpdXM6MjBweDtiYWNrZ3JvdW5kOnZhcigtLXdoaXRlLTIpO2NvbG9yOnZhcigt"
"LXR4LW11dGVkKTtsZXR0ZXItc3BhY2luZzoxcHgiPklETEU8L2Rpdj4KICAgICAgICAgICAgICA8"
"L2Rpdj4KICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7Z2FwOjE2cHg7Zmxl"
"eC13cmFwOndyYXAiPgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0ic2Nhbi1tZXRhLWl0ZW0i"
"PjxkaXYgY2xhc3M9ImRvdCIgc3R5bGU9ImJhY2tncm91bmQ6dmFyKC0tcmVkKSI+PC9kaXY+VGFy"
"Z2V0OiA8c3Ryb25nIGlkPSJzY2FuLXRhcmdldCIgc3R5bGU9ImNvbG9yOnZhcigtLXR4LWRhcmsp"
"Ij7igJQ8L3N0cm9uZz48L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InNjYW4tbWV0"
"YS1pdGVtIj48ZGl2IGNsYXNzPSJkb3QiIHN0eWxlPSJiYWNrZ3JvdW5kOnZhcigtLXNldi1oaWdo"
"KSI+PC9kaXY+Q2F0ZWdvcnk6IDxzdHJvbmcgaWQ9InNjYW4tY2F0IiBzdHlsZT0iY29sb3I6dmFy"
"KC0tdHgtZGFyaykiPuKAlDwvc3Ryb25nPjwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFz"
"cz0ic2Nhbi1tZXRhLWl0ZW0iPjxkaXYgY2xhc3M9ImRvdCIgc3R5bGU9ImJhY2tncm91bmQ6dmFy"
"KC0tc2V2LWxvdykiPjwvZGl2PkVsYXBzZWQ6IDxzdHJvbmcgaWQ9InNjYW4tZWxhcHNlZCIgc3R5"
"bGU9ImNvbG9yOnZhcigtLXR4LWRhcmspIj4wLjBzPC9zdHJvbmc+PC9kaXY+CiAgICAgICAgICAg"
"ICAgPC9kaXY+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8"
"IS0tIFByb2dyZXNzIEJhciAtLT4KICAgICAgICAgIDxkaXYgc3R5bGU9Im1hcmdpbi1ib3R0b206"
"OHB4Ij4KICAgICAgICAgICAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2p1c3RpZnktY29udGVu"
"dDpzcGFjZS1iZXR3ZWVuO21hcmdpbi1ib3R0b206NXB4Ij4KICAgICAgICAgICAgICA8ZGl2IGlk"
"PSJzY2FuLW1lc3NhZ2UiIHN0eWxlPSJmb250LXNpemU6MTFweDtjb2xvcjp2YXIoLS10eC1tdXRl"
"ZCk7Zm9udC1zdHlsZTppdGFsaWMiPlJlYWR5IOKAlCBzZWxlY3QgYSB0b29sIHRvIGJlZ2luPC9k"
"aXY+CiAgICAgICAgICAgICAgPGRpdiBpZD0ic2Nhbi1wY3QtdGV4dCIgc3R5bGU9ImZvbnQtZmFt"
"aWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6"
"NzAwO2NvbG9yOnZhcigtLXR4LWRhcmspIj4wJTwvZGl2PgogICAgICAgICAgICA8L2Rpdj4KICAg"
"ICAgICAgICAgPGRpdiBjbGFzcz0ic2Nhbi1iYXItdHJhY2siPjxkaXYgY2xhc3M9InNjYW4tYmFy"
"LWZpbGwtbGl2ZSIgaWQ9InNjYW4tYmFyLWZpbGwiIHN0eWxlPSJ3aWR0aDowJSI+PC9kaXY+PC9k"
"aXY+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KCiAgICAgICAgPCEtLSBTdGF0cyBS"
"b3cgLS0+CiAgICAgICAgPGRpdiBjbGFzcz0iZGFzaC1ncmlkIGNvbHMtNCIgc3R5bGU9Im1hcmdp"
"bi1ib3R0b206MjBweCI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJj"
"YXJkLXN1YnRpdGxlIj5Ub3RhbCBTY2FuczwvZGl2PjxkaXYgY2xhc3M9InN0YXQtbnVtIGJyYW5k"
"IiBpZD0ic3MtdG90YWwiPjA8L2Rpdj48L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNhcmQi"
"PjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUiPlBvcnRzIEZvdW5kPC9kaXY+PGRpdiBjbGFzcz0i"
"c3RhdC1udW0gb3JhbmdlIiBpZD0ic3MtcG9ydHMiPjA8L2Rpdj48L2Rpdj4KICAgICAgICAgIDxk"
"aXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUiPlRocmVhdHMgRm91bmQ8"
"L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LW51bSByZWQiIGlkPSJzcy10aHJlYXRzIj4wPC9kaXY+PC9k"
"aXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxl"
"Ij5BdmcgRHVyYXRpb248L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LW51bSIgaWQ9InNzLWF2ZyIgc3R5"
"bGU9ImNvbG9yOnZhcigtLXR4LWRhcmspIj4wczwvZGl2PjwvZGl2PgogICAgICAgIDwvZGl2PgoK"
"ICAgICAgICA8IS0tIFNjYW4gSGlzdG9yeSBUYWJsZSAtLT4KICAgICAgICA8ZGl2IGNsYXNzPSJj"
"YXJkIj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNhcmQtaGVhZGVyIj48ZGl2PjxkaXYgY2xhc3M9"
"ImNhcmQtdGl0bGUiPlNjYW4gSGlzdG9yeTwvZGl2PjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUi"
"Pkxhc3QgMTUgY29tcGxldGVkIHNjYW5zPC9kaXY+PC9kaXY+PC9kaXY+CiAgICAgICAgICA8ZGl2"
"IGNsYXNzPSJwb3J0LXRhYmxlLXdyYXAiPgogICAgICAgICAgICA8dGFibGUgY2xhc3M9InBvcnQt"
"dGFibGUiPgogICAgICAgICAgICAgIDx0aGVhZD48dHI+PHRoPlN0YXR1czwvdGg+PHRoPlRvb2w8"
"L3RoPjx0aD5UYXJnZXQ8L3RoPjx0aD5EdXJhdGlvbjwvdGg+PHRoPlBvcnRzPC90aD48dGg+VGhy"
"ZWF0czwvdGg+PHRoPlRpbWU8L3RoPjwvdHI+PC90aGVhZD4KICAgICAgICAgICAgICA8dGJvZHkg"
"aWQ9InNzLWhpc3RvcnktdGFibGUiPgogICAgICAgICAgICAgICAgPHRyPjx0ZCBjb2xzcGFuPSI3"
"IiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXI7Y29sb3I6dmFyKC0tdHgtZmFpbnQpO3BhZGRpbmc6"
"MzBweCI+Tm8gc2NhbnMgY29tcGxldGVkIHlldDwvdGQ+PC90cj4KICAgICAgICAgICAgICA8L3Ri"
"b2R5PgogICAgICAgICAgICA8L3RhYmxlPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+"
"CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CgogICAgPCEtLSBBVFRBQ0sgQ0hBSU5TIC0tPgogICAg"
"PGRpdiBjbGFzcz0idGFiLXBhbmUiIGlkPSJwYW5lLWNoYWlucyI+CiAgICAgIDxkaXYgaWQ9ImNo"
"YWlucy1jb250ZW50Ij4KICAgICAgICA8ZGl2IGNsYXNzPSJlbXB0eS1zdGF0ZSI+PGRpdiBjbGFz"
"cz0iZW1wdHktaWNvIj7im5M8L2Rpdj48ZGl2IGNsYXNzPSJlbXB0eS10aXRsZSI+Tm8gQXR0YWNr"
"IENoYWlucyBZZXQ8L2Rpdj48ZGl2IGNsYXNzPSJlbXB0eS1zdWIiPlJ1biBtdWx0aXBsZSBzY2Fu"
"cyB0byBkaXNjb3ZlciBhdHRhY2sgcGF0aHMuIFRoZSBlbmdpbmUgY29ubmVjdHMgdnVsbmVyYWJp"
"bGl0aWVzIGludG8ga2lsbCBjaGFpbnMgYXV0b21hdGljYWxseS48L2Rpdj48L2Rpdj4KICAgICAg"
"PC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0iY2hhdC1wYW5lbCBjb2xs"
"YXBzZWQiIGlkPSJjaGF0LXBhbmVsIj4KICAgIDxkaXYgY2xhc3M9ImNoYXQtdG9nZ2xlIiBvbmNs"
"aWNrPSJ0b2dnbGVDaGF0KCkiPgogICAgICA8ZGl2IGNsYXNzPSJjaGF0LXRvZ2dsZS1sZWZ0Ij48"
"c3BhbiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKSI+4pePPC9zcGFuPjxzcGFuIGNsYXNzPSJjaGF0"
"LXRvZ2dsZS1sYWJlbCI+SEFSU0hBIEFJIEFTU0lTVEFOVDwvc3Bhbj48c3BhbiBjbGFzcz0iY2hh"
"dC10b2dnbGUtc3RhdHVzIj7il48gT25saW5lPC9zcGFuPjwvZGl2PgogICAgICA8c3BhbiBjbGFz"
"cz0iY2hhdC1hcnJvdyI+4pa8PC9zcGFuPgogICAgPC9kaXY+CiAgICA8ZGl2IGlkPSJjaGF0LW1l"
"c3NhZ2VzIj48ZGl2IGNsYXNzPSJtc2cgYWkiPjxkaXYgY2xhc3M9Im1zZy1hdmF0YXIiPkFJPC9k"
"aXY+PGRpdiBjbGFzcz0ibXNnLWJvZHkiPkhBUlNIQSBBSSB2Ny4wIG9ubGluZS4gU2VsZWN0IGEg"
"dG9vbCBhbmQgZW50ZXIgYSB0YXJnZXQgdG8gYmVnaW4uPC9kaXY+PC9kaXY+PC9kaXY+CiAgICA8"
"ZGl2IGNsYXNzPSJjaGF0LWlucHV0LXJvdyI+CiAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0i"
"Y2hhdC1pbnB1dCIgY2xhc3M9ImNoYXQtaW5wdXQiIHBsYWNlaG9sZGVyPSJBc2sgSEFSU0hBIEFJ"
"Li4uIiBvbmtleWRvd249ImlmKGV2ZW50LmtleT09PSdFbnRlcicpc2VuZENoYXQoKSI+CiAgICAg"
"IDxidXR0b24gY2xhc3M9ImNoYXQtc2VuZCIgb25jbGljaz0ic2VuZENoYXQoKSI+U0VORDwvYnV0"
"dG9uPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2Pgo8L2Rpdj4KCjwhLS0gUkVQT1JUIE1PREFM"
"IC0tPgo8ZGl2IGNsYXNzPSJtb2RhbC1vdmVybGF5IiBpZD0icmVwb3J0LW1vZGFsIj4KICA8ZGl2"
"IGNsYXNzPSJtb2RhbC1ib3giPgogICAgPGRpdiBjbGFzcz0ibW9kYWwtaGRyIj48ZGl2IGNsYXNz"
"PSJtb2RhbC10aXRsZSI+SEFSU0hBIHY3LjAg4oCUIFZBUFQgUkVQT1JUPC9kaXY+PGJ1dHRvbiBj"
"bGFzcz0ibW9kYWwtY2xvc2UiIG9uY2xpY2s9ImNsb3NlUmVwb3J0KCkiPkNMT1NFPC9idXR0b24+"
"PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1ib2R5Ij48ZGl2IGlkPSJycCI+PC9kaXY+PC9k"
"aXY+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1mb290ZXIiPjxidXR0b24gY2xhc3M9ImRsLWJ0biBw"
"cmltYXJ5IiBvbmNsaWNrPSJkb3dubG9hZEhUTUwoKSI+RG93bmxvYWQgSFRNTDwvYnV0dG9uPjxi"
"dXR0b24gY2xhc3M9ImRsLWJ0biBzZWNvbmRhcnkiIG9uY2xpY2s9ImRvd25sb2FkVFhUKCkiPkRv"
"d25sb2FkIFRYVDwvYnV0dG9uPjwvZGl2PgogIDwvZGl2Pgo8L2Rpdj4KCjxzY3JpcHQ+Ci8qID09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT0KICAgU1RBVEUKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwp2YXIgc2NhbkNvdW50PTAsY3VycmVudEF1ZGlv"
"PW51bGwsYWxsUG9ydHM9W10sYWxsVGhyZWF0cz1bXSxsYXN0VGFyZ2V0PScnOwp2YXIgU0M9e25l"
"dDowLHdlYjowLGluZjowLHJlYzowfTsKdmFyIHJpc2tDaGFydHM9e30sdGhyZWF0Q2hhcnRzPXt9"
"Owp2YXIgc2V2Q29sb3JzPXtDUklUSUNBTDonI2Q5MDQyOScsSElHSDonI2U4NWQwNCcsTUVESVVN"
"OicjZTA5ZjNlJyxMT1c6JyMyZDZhNGYnfTsKdmFyIHNldkJnPXtDUklUSUNBTDoncmdiYSgyMTcs"
"NCw0MSwwLjEpJyxISUdIOidyZ2JhKDIzMiw5Myw0LDAuMSknLE1FRElVTToncmdiYSgyMjQsMTU5"
"LDYyLDAuMSknLExPVzoncmdiYSg0NSwxMDYsNzksMC4xKSd9Owp2YXIgdGFyZ2V0SGlzdG9yeT1b"
"XTsKdmFyIGxhc3RQaGFzZT0naWRsZSc7CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIENMT0NLCiAgID09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0g"
"Ki8KZnVuY3Rpb24gdXBkYXRlQ2xvY2soKXtkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2xvY2sn"
"KS50ZXh0Q29udGVudD1uZXcgRGF0ZSgpLnRvTG9jYWxlVGltZVN0cmluZygnZW4tVVMnLHtob3Vy"
"OicyLWRpZ2l0JyxtaW51dGU6JzItZGlnaXQnLHNlY29uZDonMi1kaWdpdCd9KX0Kc2V0SW50ZXJ2"
"YWwodXBkYXRlQ2xvY2ssMTAwMCk7dXBkYXRlQ2xvY2soKTsKCi8qID09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgVEFCUwog"
"ICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09ICovCmZ1bmN0aW9uIHN3aXRjaFRhYih0YWIsYnRuKXsKICBkb2N1bWVudC5xdWVy"
"eVNlbGVjdG9yQWxsKCcudGFiLXBhbmUnKS5mb3JFYWNoKGZ1bmN0aW9uKHApe3AuY2xhc3NMaXN0"
"LnJlbW92ZSgnYWN0aXZlJyl9KTsKICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcudGFiLWJ0"
"bicpLmZvckVhY2goZnVuY3Rpb24oYil7Yi5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKX0pOwog"
"IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwYW5lLScrdGFiKS5jbGFzc0xpc3QuYWRkKCdhY3Rp"
"dmUnKTsKICBpZihidG4pYnRuLmNsYXNzTGlzdC5hZGQoJ2FjdGl2ZScpOwogIGlmKHRhYj09PSdy"
"aXNrJylzZXRUaW1lb3V0KHJlZnJlc2hSaXNrQ2hhcnRzLDYwKTsKICBpZih0YWI9PT0ndGdyYXBo"
"JylzZXRUaW1lb3V0KHJlZnJlc2hUaHJlYXRDaGFydHMsNjApOwp9CmZ1bmN0aW9uIHRvZ2dsZUNo"
"YXQoKXtkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2hhdC1wYW5lbCcpLmNsYXNzTGlzdC50b2dn"
"bGUoJ2NvbGxhcHNlZCcpfQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBTSURFQkFSIERST1BET1dOUwogICA9PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09ICovCmZ1bmN0aW9uIHRvZ2dsZVNlY3Rpb24oaGVhZGVyKXsKICBoZWFkZXIucGFyZW50RWxl"
"bWVudC5jbGFzc0xpc3QudG9nZ2xlKCdvcGVuJyk7Cn0KCi8qID09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgVE9PTCBTRUFS"
"Q0ggLyBGSUxURVIKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PSAqLwpmdW5jdGlvbiBmaWx0ZXJUb29scyhxdWVyeSl7CiAg"
"dmFyIHE9cXVlcnkudG9Mb3dlckNhc2UoKS50cmltKCk7CiAgdmFyIG5hdnM9ZG9jdW1lbnQucXVl"
"cnlTZWxlY3RvckFsbCgnLnMtbmF2Jyk7CiAgdmFyIHNlY3Rpb25zPWRvY3VtZW50LnF1ZXJ5U2Vs"
"ZWN0b3JBbGwoJy5zLXNlY3Rpb24nKTsKICBpZighcSl7CiAgICBuYXZzLmZvckVhY2goZnVuY3Rp"
"b24obil7bi5zdHlsZS5kaXNwbGF5PScnfSk7CiAgICBzZWN0aW9ucy5mb3JFYWNoKGZ1bmN0aW9u"
"KHMpewogICAgICB2YXIgaGRyPXMucXVlcnlTZWxlY3RvcignLnMtc2VjdGlvbi1oZWFkZXInKTsK"
"ICAgICAgaWYoaGRyKWhkci5zdHlsZS5kaXNwbGF5PScnOwogICAgfSk7CiAgICByZXR1cm47CiAg"
"fQogIHNlY3Rpb25zLmZvckVhY2goZnVuY3Rpb24ocyl7cy5jbGFzc0xpc3QuYWRkKCdvcGVuJyl9"
"KTsKICBuYXZzLmZvckVhY2goZnVuY3Rpb24obil7CiAgICB2YXIgbmFtZT0obi5nZXRBdHRyaWJ1"
"dGUoJ2RhdGEtbmFtZScpfHwnJykrJyAnKyhuLnRleHRDb250ZW50fHwnJyk7CiAgICBuLnN0eWxl"
"LmRpc3BsYXk9bmFtZS50b0xvd2VyQ2FzZSgpLmluZGV4T2YocSk+PTA/Jyc6J25vbmUnOwogIH0p"
"OwogIHNlY3Rpb25zLmZvckVhY2goZnVuY3Rpb24ocyl7CiAgICB2YXIgYm9keT1zLnF1ZXJ5U2Vs"
"ZWN0b3IoJy5zLXNlY3Rpb24tYm9keScpOwogICAgaWYoIWJvZHkpcmV0dXJuOwogICAgdmFyIHZp"
"c2libGU9Ym9keS5xdWVyeVNlbGVjdG9yQWxsKCcucy1uYXY6bm90KFtzdHlsZSo9ImRpc3BsYXk6"
"IG5vbmUiXSknKTsKICAgIHZhciBoZHI9cy5xdWVyeVNlbGVjdG9yKCcucy1zZWN0aW9uLWhlYWRl"
"cicpOwogICAgaWYoaGRyKWhkci5zdHlsZS5kaXNwbGF5PXZpc2libGUubGVuZ3RoPjA/Jyc6J25v"
"bmUnOwogIH0pOwp9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09CiAgIFRBUkdFVCBISVNUT1JZCiAgID09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8K"
"ZnVuY3Rpb24gYWRkVGFyZ2V0SGlzdG9yeSh0KXsKICBpZighdHx8dGFyZ2V0SGlzdG9yeS5pbmRl"
"eE9mKHQpPj0wKXJldHVybjsKICB0YXJnZXRIaXN0b3J5LnVuc2hpZnQodCk7CiAgaWYodGFyZ2V0"
"SGlzdG9yeS5sZW5ndGg+MTApdGFyZ2V0SGlzdG9yeS5wb3AoKTsKfQpmdW5jdGlvbiBzaG93VGFy"
"Z2V0SGlzdG9yeSgpewogIHZhciBib3g9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RhcmdldC1o"
"aXN0b3J5Jyk7CiAgdmFyIGlucD1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGFyZ2V0LWlucHV0"
"JykudmFsdWUudHJpbSgpLnRvTG93ZXJDYXNlKCk7CiAgaWYoIXRhcmdldEhpc3RvcnkubGVuZ3Ro"
"KXtib3guY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpO3JldHVybn0KICB2YXIgZmlsdGVyZWQ9dGFy"
"Z2V0SGlzdG9yeS5maWx0ZXIoZnVuY3Rpb24odCl7cmV0dXJuICFpbnB8fHQudG9Mb3dlckNhc2Uo"
"KS5pbmRleE9mKGlucCk+PTB9KTsKICBpZighZmlsdGVyZWQubGVuZ3RoKXtib3guY2xhc3NMaXN0"
"LnJlbW92ZSgnc2hvdycpO3JldHVybn0KICB2YXIgaD0nPGRpdiBjbGFzcz0iaC10aC1sYWJlbCIg"
"c3R5bGU9InBhZGRpbmc6NnB4IDE0cHggMnB4Ij5SRUNFTlQgVEFSR0VUUzwvZGl2Pic7CiAgZmls"
"dGVyZWQuZm9yRWFjaChmdW5jdGlvbih0KXsKICAgIGgrPSc8ZGl2IGNsYXNzPSJoLXRoLWl0ZW0i"
"IG9uY2xpY2s9InNlbGVjdFRhcmdldCgmcXVvdDsnK3QucmVwbGFjZSgvIi9nLCcnKSsnJnF1b3Q7"
"KSI+Jyt0Kyc8L2Rpdj4nOwogIH0pOwogIGJveC5pbm5lckhUTUw9aDtib3guY2xhc3NMaXN0LmFk"
"ZCgnc2hvdycpOwp9CmZ1bmN0aW9uIHNlbGVjdFRhcmdldCh0KXsKICBkb2N1bWVudC5nZXRFbGVt"
"ZW50QnlJZCgndGFyZ2V0LWlucHV0JykudmFsdWU9dDsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJ"
"ZCgndGFyZ2V0LWhpc3RvcnknKS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7Cn0KZG9jdW1lbnQu"
"YWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLGZ1bmN0aW9uKGUpewogIGlmKCFlLnRhcmdldC5jbG9z"
"ZXN0KCcuaC10YXJnZXQnKSl7dmFyIGVsPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0YXJnZXQt"
"aGlzdG9yeScpO2lmKGVsKWVsLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKX0KfSk7CgovKiA9PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09CiAgIFVUSUxTCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT0gKi8KZnVuY3Rpb24gcGxheVZvaWNlKCl7aWYoY3VycmVu"
"dEF1ZGlvKWN1cnJlbnRBdWRpby5wYXVzZSgpO2N1cnJlbnRBdWRpbz1uZXcgQXVkaW8oJy92b2lj"
"ZT90PScrRGF0ZS5ub3coKSk7Y3VycmVudEF1ZGlvLnBsYXkoKS5jYXRjaChmdW5jdGlvbigpe30p"
"fQpmdW5jdGlvbiBub3RpZnkobXNnKXt2YXIgZWw9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2"
"Jyk7ZWwuY2xhc3NOYW1lPSdub3RpZic7ZWwudGV4dENvbnRlbnQ9bXNnO2RvY3VtZW50LmJvZHku"
"YXBwZW5kQ2hpbGQoZWwpO3NldFRpbWVvdXQoZnVuY3Rpb24oKXtlbC5yZW1vdmUoKX0sMzUwMCl9"
"Cgp2YXIgdGVybWluYWw9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Rlcm1pbmFsLW91dHB1dCcp"
"OwpmdW5jdGlvbiB0ZXJtTGluZSh0LGMpe2lmKCFjKWM9J3Jlc3VsdCc7KHQrJycpLnNwbGl0KCdc"
"bicpLmZvckVhY2goZnVuY3Rpb24obCl7aWYoIWwudHJpbSgpKXJldHVybjt2YXIgZD1kb2N1bWVu"
"dC5jcmVhdGVFbGVtZW50KCdkaXYnKTtkLmNsYXNzTmFtZT0ndGwgJytjO2QudGV4dENvbnRlbnQ9"
"bDt0ZXJtaW5hbC5hcHBlbmRDaGlsZChkKX0pO3Rlcm1pbmFsLnNjcm9sbFRvcD10ZXJtaW5hbC5z"
"Y3JvbGxIZWlnaHR9CmZ1bmN0aW9uIGNsZWFyVGVybWluYWwoKXt0ZXJtaW5hbC5pbm5lckhUTUw9"
"JzxkaXYgY2xhc3M9InRsIGhkciI+Ly8gQ0xFQVJFRCDigJQgSEFSU0hBIEFJIHY3LjA8L2Rpdj4n"
"fQpmdW5jdGlvbiBjb3B5T3V0cHV0KCl7bmF2aWdhdG9yLmNsaXBib2FyZC53cml0ZVRleHQodGVy"
"bWluYWwuaW5uZXJUZXh0KS50aGVuKGZ1bmN0aW9uKCl7bm90aWZ5KCdDb3BpZWQhJyl9KX0KZnVu"
"Y3Rpb24gc2V0TG9hZGluZyhvbil7ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2xvYWRpbmctYmFy"
"Jykuc3R5bGUuZGlzcGxheT1vbj8nYmxvY2snOidub25lJ30KCmZ1bmN0aW9uIHVwZGF0ZVN0YXRz"
"KCl7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N0YXQtc2NhbnMnKS50ZXh0Q29udGVudD1z"
"Y2FuQ291bnQ7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N0YXQtcG9ydHMnKS50ZXh0Q29u"
"dGVudD1hbGxQb3J0cy5sZW5ndGg7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N0YXQtdGhy"
"ZWF0cycpLnRleHRDb250ZW50PWFsbFRocmVhdHMubGVuZ3RoOwogIGRvY3VtZW50LmdldEVsZW1l"
"bnRCeUlkKCdzY2FuLWJhcicpLnN0eWxlLndpZHRoPU1hdGgubWluKDEwMCxzY2FuQ291bnQqMTAp"
"KyclJzsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncG9ydC1iYXInKS5zdHlsZS53aWR0aD1N"
"YXRoLm1pbigxMDAsYWxsUG9ydHMubGVuZ3RoKjUpKyclJzsKICBkb2N1bWVudC5nZXRFbGVtZW50"
"QnlJZCgndGhyZWF0LWJhcicpLnN0eWxlLndpZHRoPU1hdGgubWluKDEwMCxhbGxUaHJlYXRzLmxl"
"bmd0aCoxMCkrJyUnOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdobS1zY2FucycpLnRleHRD"
"b250ZW50PXNjYW5Db3VudDsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnaG0tcG9ydHMnKS50"
"ZXh0Q29udGVudD1hbGxQb3J0cy5sZW5ndGg7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ht"
"LXRocmVhdHMnKS50ZXh0Q29udGVudD1hbGxUaHJlYXRzLmxlbmd0aDsKfQoKLyogPT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQog"
"ICBQT1JUIERBU0hCT0FSRAogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCmZ1bmN0aW9uIHVwZGF0ZVBvcnREYXNoKHBv"
"cnRzLHRhcmdldCl7CiAgaWYoIXBvcnRzfHwhcG9ydHMubGVuZ3RoKXJldHVybjsKICBwb3J0cy5m"
"b3JFYWNoKGZ1bmN0aW9uKHApe2lmKCFhbGxQb3J0cy5maW5kKGZ1bmN0aW9uKHgpe3JldHVybiB4"
"LnBvcnQ9PT1wLnBvcnQmJngucHJvdG89PT1wLnByb3RvfSkpYWxsUG9ydHMucHVzaChwKX0pOwog"
"IHZhciB0b3RhbD1hbGxQb3J0cy5sZW5ndGgsY3JpdD0wLGhpZ2g9MCxtZWQ9MCxsb3c9MDsKICBh"
"bGxQb3J0cy5mb3JFYWNoKGZ1bmN0aW9uKHApe2lmKHAuc2V2ZXJpdHk9PT0nQ1JJVElDQUwnKWNy"
"aXQrKztlbHNlIGlmKHAuc2V2ZXJpdHk9PT0nSElHSCcpaGlnaCsrO2Vsc2UgaWYocC5zZXZlcml0"
"eT09PSdNRURJVU0nKW1lZCsrO2Vsc2UgbG93Kyt9KTsKICB2YXIgYmFkZ2U9ZG9jdW1lbnQuZ2V0"
"RWxlbWVudEJ5SWQoJ3BvcnQtYmFkZ2UnKTtiYWRnZS5jbGFzc0xpc3QuYWRkKCdzaG93JywnYi1v"
"cmFuZ2UnKTtiYWRnZS50ZXh0Q29udGVudD10b3RhbDsKICB2YXIgc29ydGVkPWFsbFBvcnRzLnNs"
"aWNlKCkuc29ydChmdW5jdGlvbihhLGIpe3ZhciBvPXtDUklUSUNBTDowLEhJR0g6MSxNRURJVU06"
"MixMT1c6M307cmV0dXJuKG9bYS5zZXZlcml0eV18fDMpLShvW2Iuc2V2ZXJpdHldfHwzKXx8YS5w"
"b3J0LWIucG9ydH0pOwogIHZhciBoPSc8ZGl2IGNsYXNzPSJkYXNoLWdyaWQgY29scy00IiBzdHls"
"ZT0ibWFyZ2luLWJvdHRvbToyMHB4Ij4nOwogIGgrPSc8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNs"
"YXNzPSJjYXJkLXN1YnRpdGxlIj5Dcml0aWNhbDwvZGl2PjxkaXYgY2xhc3M9InN0YXQtbnVtIHJl"
"ZCI+Jytjcml0Kyc8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LWJhci13cmFwIj48ZGl2IGNsYXNzPSJz"
"dGF0LWJhciI+PGRpdiBjbGFzcz0ic3RhdC1iYXItZmlsbCByZWQiIHN0eWxlPSJ3aWR0aDonK01h"
"dGgubWluKDEwMCxjcml0KjI1KSsnJSI+PC9kaXY+PC9kaXY+PC9kaXY+PC9kaXY+JzsKICBoKz0n"
"PGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0iY2FyZC1zdWJ0aXRsZSI+SGlnaDwvZGl2Pjxk"
"aXYgY2xhc3M9InN0YXQtbnVtIG9yYW5nZSI+JytoaWdoKyc8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0"
"LWJhci13cmFwIj48ZGl2IGNsYXNzPSJzdGF0LWJhciI+PGRpdiBjbGFzcz0ic3RhdC1iYXItZmls"
"bCBvcmFuZ2UiIHN0eWxlPSJ3aWR0aDonK01hdGgubWluKDEwMCxoaWdoKjE4KSsnJSI+PC9kaXY+"
"PC9kaXY+PC9kaXY+PC9kaXY+JzsKICBoKz0nPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0i"
"Y2FyZC1zdWJ0aXRsZSI+TWVkaXVtPC9kaXY+PGRpdiBjbGFzcz0ic3RhdC1udW0geWVsbG93Ij4n"
"K21lZCsnPC9kaXY+PGRpdiBjbGFzcz0ic3RhdC1iYXItd3JhcCI+PGRpdiBjbGFzcz0ic3RhdC1i"
"YXIiPjxkaXYgY2xhc3M9InN0YXQtYmFyLWZpbGwgeWVsbG93IiBzdHlsZT0id2lkdGg6JytNYXRo"
"Lm1pbigxMDAsbWVkKjE4KSsnJSI+PC9kaXY+PC9kaXY+PC9kaXY+PC9kaXY+JzsKICBoKz0nPGRp"
"diBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0iY2FyZC1zdWJ0aXRsZSI+TG93PC9kaXY+PGRpdiBj"
"bGFzcz0ic3RhdC1udW0gZ3JlZW4iPicrbG93Kyc8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LWJhci13"
"cmFwIj48ZGl2IGNsYXNzPSJzdGF0LWJhciI+PGRpdiBjbGFzcz0ic3RhdC1iYXItZmlsbCBncmVl"
"biIgc3R5bGU9IndpZHRoOicrTWF0aC5taW4oMTAwLGxvdyoxOCkrJyUiPjwvZGl2PjwvZGl2Pjwv"
"ZGl2PjwvZGl2Pic7CiAgaCs9JzwvZGl2Pic7CiAgaCs9JzxkaXYgY2xhc3M9ImNhcmQiPjxkaXYg"
"Y2xhc3M9ImNhcmQtaGVhZGVyIj48ZGl2PjxkaXYgY2xhc3M9ImNhcmQtdGl0bGUiPk9wZW4gUG9y"
"dHMg4oCUICcrKHRhcmdldHx8bGFzdFRhcmdldHx8Jz8nKSsnPC9kaXY+PGRpdiBjbGFzcz0iY2Fy"
"ZC1zdWJ0aXRsZSI+Jyt0b3RhbCsnIHBvcnRzPC9kaXY+PC9kaXY+PC9kaXY+JzsKICBoKz0nPGRp"
"diBjbGFzcz0icG9ydC10YWJsZS13cmFwIj48dGFibGUgY2xhc3M9InBvcnQtdGFibGUiPjx0aGVh"
"ZD48dHI+PHRoPlBvcnQ8L3RoPjx0aD5TZXJ2aWNlPC90aD48dGg+UmlzazwvdGg+PHRoPkRlc2Ny"
"aXB0aW9uPC90aD48dGg+UmVtZWRpYXRpb248L3RoPjwvdHI+PC90aGVhZD48dGJvZHk+JzsKICBz"
"b3J0ZWQuZm9yRWFjaChmdW5jdGlvbihwKXsKICAgIGgrPSc8dHI+PHRkPjxzcGFuIGNsYXNzPSJw"
"LW51bSI+JytwLnBvcnQrJzwvc3Bhbj48ZGl2IGNsYXNzPSJwLXByb3RvIj4nK3AucHJvdG8udG9V"
"cHBlckNhc2UoKSsnPC9kaXY+PC90ZD4nOwogICAgaCs9Jzx0ZD48c3BhbiBjbGFzcz0icC1zdmMi"
"PicrcC5zZXJ2aWNlKyc8L3NwYW4+JysocC52ZXJzaW9uPyc8ZGl2IGNsYXNzPSJwLXZlciI+Jytw"
"LnZlcnNpb24uc3Vic3RyaW5nKDAsMzUpKyc8L2Rpdj4nOicnKSsnPC90ZD4nOwogICAgaCs9Jzx0"
"ZD48c3BhbiBjbGFzcz0ic2V2ICcrcC5zZXZlcml0eSsnIj4nK3Auc2V2ZXJpdHkrJzwvc3Bhbj48"
"L3RkPic7CiAgICBoKz0nPHRkIGNsYXNzPSJwLWRlc2MiPicrcC5kZXNjKyc8L3RkPjx0ZCBjbGFz"
"cz0icC1maXgiPicrcC5maXgrJzwvdGQ+PC90cj4nOwogIH0pOwogIGgrPSc8L3Rib2R5PjwvdGFi"
"bGU+PC9kaXY+PC9kaXY+JzsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncG9ydC1kYXNoJyku"
"aW5uZXJIVE1MPWg7dXBkYXRlU3RhdHMoKTsKfQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBUSFJFQVQgREFTSEJP"
"QVJECiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT0gKi8KZnVuY3Rpb24gdXBkYXRlVGhyZWF0RGFzaCh0aHJlYXRzKXsKICBp"
"ZighdGhyZWF0c3x8IXRocmVhdHMubGVuZ3RoKXJldHVybjsKICB0aHJlYXRzLmZvckVhY2goZnVu"
"Y3Rpb24odCl7aWYoIWFsbFRocmVhdHMuZmluZChmdW5jdGlvbih4KXtyZXR1cm4geC5uYW1lPT09"
"dC5uYW1lfSkpYWxsVGhyZWF0cy5wdXNoKHQpfSk7CiAgdmFyIGJhZGdlPWRvY3VtZW50LmdldEVs"
"ZW1lbnRCeUlkKCd0aHJlYXQtYmFkZ2UnKTtiYWRnZS5jbGFzc0xpc3QuYWRkKCdzaG93JywnYi1y"
"ZWQnKTtiYWRnZS50ZXh0Q29udGVudD1hbGxUaHJlYXRzLmxlbmd0aDsKICB2YXIgaD0nPGRpdiBj"
"bGFzcz0iZGFzaC1ncmlkIGNvbHMtMSIgc3R5bGU9ImdhcDoxNHB4Ij4nOwogIGFsbFRocmVhdHMu"
"Zm9yRWFjaChmdW5jdGlvbih0LGkpewogICAgaCs9JzxkaXYgY2xhc3M9InRocmVhdC1jYXJkICcr"
"dC5zZXZlcml0eSsnIiBzdHlsZT0iYW5pbWF0aW9uLWRlbGF5OicrKGkqMC4wNSkrJ3MiPjxkaXYg"
"Y2xhc3M9InRjLWhkciI+PGRpdiBjbGFzcz0idGMtbmFtZSI+Jyt0Lm5hbWUrJzwvZGl2PjxzcGFu"
"IGNsYXNzPSJzZXYgJyt0LnNldmVyaXR5KyciPicrdC5zZXZlcml0eSsnPC9zcGFuPjwvZGl2Pic7"
"CiAgICBoKz0nPGRpdiBjbGFzcz0idGMtZGVzYyI+Jyt0LmRlc2MrJzwvZGl2Pic7CiAgICBoKz0n"
"PGRpdiBjbGFzcz0idGMtZml4Ij48ZGl2IGNsYXNzPSJ0Yy1maXgtbGFiZWwiPlJFTUVESUFUSU9O"
"PC9kaXY+PGRpdiBjbGFzcz0idGMtZml4LXRleHQiPicrdC5maXgrJzwvZGl2PjwvZGl2PjwvZGl2"
"Pic7CiAgfSk7CiAgaCs9JzwvZGl2Pic7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RocmVh"
"dC1kYXNoJykuaW5uZXJIVE1MPWg7dXBkYXRlU3RhdHMoKTsKfQoKLyogPT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBSVU4g"
"VE9PTCAoaW50ZWdyYXRlZCB3aXRoIHRhcmdldCBoaXN0b3J5KQogICA9PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCmZ1bmN0"
"aW9uIHJ1blRvb2wodG9vbCxidG4sY2F0KXsKICB2YXIgdGFyZ2V0PWRvY3VtZW50LmdldEVsZW1l"
"bnRCeUlkKCd0YXJnZXQtaW5wdXQnKS52YWx1ZS50cmltKCk7CiAgdmFyIG5vVD1bJ25ldHdvcmtf"
"c2NhbicsJ215X2lwJywnc3lzdGVtX2luZm8nLCd3ZWF0aGVyJywnYXJwX3NjYW4nXTsKICB2YXIg"
"bmVlZD10cnVlO2Zvcih2YXIgaT0wO2k8bm9ULmxlbmd0aDtpKyspe2lmKG5vVFtpXT09PXRvb2wp"
"e25lZWQ9ZmFsc2U7YnJlYWt9fQogIGlmKG5lZWQmJiF0YXJnZXQpe25vdGlmeSgnRW50ZXIgYSB0"
"YXJnZXQgZmlyc3QuJyk7dGVybUxpbmUoJ1BsZWFzZSBlbnRlciBhIHRhcmdldC4nLCdlcnJvcicp"
"O3JldHVybn0KICBpZih0YXJnZXQpe2xhc3RUYXJnZXQ9dGFyZ2V0O2FkZFRhcmdldEhpc3Rvcnko"
"dGFyZ2V0KX0KICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcucy1uYXYnKS5mb3JFYWNoKGZ1"
"bmN0aW9uKGIpe2IuY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJyl9KTsKICBpZihidG4pYnRuLmNs"
"YXNzTGlzdC5hZGQoJ2FjdGl2ZScpOwogIHNldExvYWRpbmcodHJ1ZSk7CiAgc3dpdGNoVGFiKCd0"
"ZXJtaW5hbCcsZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLnRhYi1idG4nKVswXSk7CiAgdGVy"
"bUxpbmUoJycsJ2hkcicpOwogIHRlcm1MaW5lKCfigJQgWycrY2F0LnRvVXBwZXJDYXNlKCkrJ10g"
"Jyt0b29sLnRvVXBwZXJDYXNlKCkrKHRhcmdldD8nIOKGkiAnK3RhcmdldDonJykrJyDigJQnLCdo"
"ZHInKTsKICB0ZXJtTGluZSgnaGFyc2hhQGthbGk6fiQgJyt0b29sKyh0YXJnZXQ/JyAnK3Rhcmdl"
"dDonJykrJy4uLicsJ3Byb21wdCcpOwogIHZhciB0MD1EYXRlLm5vdygpOwogIGZldGNoKCcvc2Nh"
"bicse21ldGhvZDonUE9TVCcsaGVhZGVyczp7J0NvbnRlbnQtVHlwZSc6J2FwcGxpY2F0aW9uL2pz"
"b24nfSxib2R5OkpTT04uc3RyaW5naWZ5KHt0b29sOnRvb2wsdGFyZ2V0OnRhcmdldH0pfSkKICAu"
"dGhlbihmdW5jdGlvbihyKXtyZXR1cm4gci5qc29uKCl9KQogIC50aGVuKGZ1bmN0aW9uKGRhdGEp"
"ewogICAgdmFyIGVsPSgoRGF0ZS5ub3coKS10MCkvMTAwMCkudG9GaXhlZCgxKTsKICAgIHRlcm1M"
"aW5lKGRhdGEub3V0cHV0fHxkYXRhLmVycm9yfHwnTm8gb3V0cHV0LicsZGF0YS5lcnJvcj8nZXJy"
"b3InOidyZXN1bHQnKTsKICAgIHRlcm1MaW5lKCdDb21wbGV0ZWQgaW4gJytlbCsncyDigJQgJyso"
"ZGF0YS50aW1lc3RhbXB8fCcnKSwnaW5mbycpOwogICAgc2NhbkNvdW50Kys7U0NbY2F0XT0oU0Nb"
"Y2F0XXx8MCkrMTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzdGF0LWxhc3QtdG9vbCcp"
"LnRleHRDb250ZW50PXRvb2wudG9VcHBlckNhc2UoKTsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRC"
"eUlkKCdzdGF0LWxhc3QtdGltZScpLnRleHRDb250ZW50PWVsKydzIMK3ICcrbmV3IERhdGUoKS50"
"b0xvY2FsZVRpbWVTdHJpbmcoKTsKICAgIHVwZGF0ZVN0YXRzKCk7CiAgICBpZihkYXRhLnBvcnRz"
"JiZkYXRhLnBvcnRzLmxlbmd0aCl7dXBkYXRlUG9ydERhc2goZGF0YS5wb3J0cyx0YXJnZXQpO3Rl"
"cm1MaW5lKGRhdGEucG9ydHMubGVuZ3RoKycgcG9ydHMg4oCUIGNoZWNrIFBvcnRzIHRhYicsJ2lu"
"Zm8nKTtub3RpZnkoZGF0YS5wb3J0cy5sZW5ndGgrJyBwb3J0cyBmb3VuZCEnKX0KICAgIGlmKGRh"
"dGEudGhyZWF0cyYmZGF0YS50aHJlYXRzLmxlbmd0aCl7dXBkYXRlVGhyZWF0RGFzaChkYXRhLnRo"
"cmVhdHMpO3Rlcm1MaW5lKGRhdGEudGhyZWF0cy5sZW5ndGgrJyB0aHJlYXRzIOKAlCBjaGVjayBU"
"aHJlYXRzIHRhYicsJ2Vycm9yJyk7bm90aWZ5KGRhdGEudGhyZWF0cy5sZW5ndGgrJyB0aHJlYXRz"
"IGRldGVjdGVkIScpfQogICAgaWYoZGF0YS5oYXNfdm9pY2UpcGxheVZvaWNlKCk7CiAgfSkKICAu"
"Y2F0Y2goZnVuY3Rpb24oZSl7dGVybUxpbmUoJ0Vycm9yOiAnK2UubWVzc2FnZSwnZXJyb3InKX0p"
"CiAgLmZpbmFsbHkoZnVuY3Rpb24oKXtzZXRMb2FkaW5nKGZhbHNlKX0pOwp9CgovKiA9PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"CiAgIENIQVQKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PSAqLwpmdW5jdGlvbiBzZW5kQ2hhdCgpewogIHZhciBpbnA9ZG9j"
"dW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NoYXQtaW5wdXQnKTt2YXIgbXNnPWlucC52YWx1ZS50cmlt"
"KCk7aWYoIW1zZylyZXR1cm47aW5wLnZhbHVlPScnOwogIHZhciBib3g9ZG9jdW1lbnQuZ2V0RWxl"
"bWVudEJ5SWQoJ2NoYXQtbWVzc2FnZXMnKTsKICB2YXIgdT1kb2N1bWVudC5jcmVhdGVFbGVtZW50"
"KCdkaXYnKTt1LmNsYXNzTmFtZT0nbXNnIHVzZXInO3UuaW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJt"
"c2ctYXZhdGFyIj5ZT1U8L2Rpdj48ZGl2IGNsYXNzPSJtc2ctYm9keSI+Jyttc2cucmVwbGFjZSgv"
"PC9nLCcmbHQ7JykucmVwbGFjZSgvPi9nLCcmZ3Q7JykrJzwvZGl2Pic7CiAgYm94LmFwcGVuZENo"
"aWxkKHUpO2JveC5zY3JvbGxUb3A9Ym94LnNjcm9sbEhlaWdodDsKICBmZXRjaCgnL2NoYXQnLHtt"
"ZXRob2Q6J1BPU1QnLGhlYWRlcnM6eydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJ30s"
"Ym9keTpKU09OLnN0cmluZ2lmeSh7bWVzc2FnZTptc2d9KX0pCiAgLnRoZW4oZnVuY3Rpb24ocil7"
"cmV0dXJuIHIuanNvbigpfSkKICAudGhlbihmdW5jdGlvbihkKXt2YXIgYT1kb2N1bWVudC5jcmVh"
"dGVFbGVtZW50KCdkaXYnKTthLmNsYXNzTmFtZT0nbXNnIGFpJzthLmlubmVySFRNTD0nPGRpdiBj"
"bGFzcz0ibXNnLWF2YXRhciI+QUk8L2Rpdj48ZGl2IGNsYXNzPSJtc2ctYm9keSI+JytkLnJlc3Bv"
"bnNlKyc8L2Rpdj4nO2JveC5hcHBlbmRDaGlsZChhKTtib3guc2Nyb2xsVG9wPWJveC5zY3JvbGxI"
"ZWlnaHQ7aWYoZC5oYXNfdm9pY2UpcGxheVZvaWNlKCl9KQogIC5jYXRjaChmdW5jdGlvbigpe3Zh"
"ciBlPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpO2UuY2xhc3NOYW1lPSdtc2cgYWknO2Uu"
"aW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJtc2ctYXZhdGFyIj5BSTwvZGl2PjxkaXYgY2xhc3M9Im1z"
"Zy1ib2R5IiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkLWxpZ2h0KSI+Q29ubmVjdGlvbiBlcnJvci48"
"L2Rpdj4nO2JveC5hcHBlbmRDaGlsZChlKX0pOwp9CgovKiA9PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIFJFUE9SVAogICA9"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09ICovCmZ1bmN0aW9uIG9wZW5SZXBvcnQoKXsKICB2YXIgbm93PW5ldyBEYXRlKCkudG9M"
"b2NhbGVTdHJpbmcoKTsKICB2YXIgc29ydGVkPWFsbFBvcnRzLnNsaWNlKCkuc29ydChmdW5jdGlv"
"bihhLGIpe3ZhciBvPXtDUklUSUNBTDowLEhJR0g6MSxNRURJVU06MixMT1c6M307cmV0dXJuKG9b"
"YS5zZXZlcml0eV18fDMpLShvW2Iuc2V2ZXJpdHldfHwzKXx8YS5wb3J0LWIucG9ydH0pOwogIHZh"
"ciBoPSc8ZGl2IGNsYXNzPSJycC1oZHIiPjxkaXYgY2xhc3M9InJwLXQiPkhBUlNIQSB2Ny4wIFZB"
"UFQgUkVQT1JUPC9kaXY+PGRpdiBjbGFzcz0icnAtcyI+V2ViICsgTmV0d29yayArIEluZnJhc3Ry"
"dWN0dXJlIFZBUFQgU3VpdGU8L2Rpdj48ZGl2IHN0eWxlPSJtYXJnaW4tdG9wOjVweDtmb250LXNp"
"emU6MTBweDtjb2xvcjp2YXIoLS10eC1mYWludCkiPkFuYWx5c3Q6IEhBUlNIQSB8IFRhcmdldDog"
"JysobGFzdFRhcmdldHx8J011bHRpcGxlJykrJyB8ICcrbm93Kyc8L2Rpdj48L2Rpdj4nOwogIGgr"
"PSc8ZGl2IGNsYXNzPSJycC1zZWMiPjxkaXYgY2xhc3M9InJwLXN0Ij5FWEVDVVRJVkUgU1VNTUFS"
"WTwvZGl2PjxkaXYgc3R5bGU9ImZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLXR4LW11dGVkKSI+"
"U2NhbnM6ICcrc2NhbkNvdW50KycgwrcgUG9ydHM6ICcrYWxsUG9ydHMubGVuZ3RoKycgwrcgVGhy"
"ZWF0czogJythbGxUaHJlYXRzLmxlbmd0aCsnPC9kaXY+PC9kaXY+JzsKICBpZihzb3J0ZWQubGVu"
"Z3RoKXtoKz0nPGRpdiBjbGFzcz0icnAtc2VjIj48ZGl2IGNsYXNzPSJycC1zdCI+T1BFTiBQT1JU"
"UyAoJytzb3J0ZWQubGVuZ3RoKycpPC9kaXY+Jztzb3J0ZWQuZm9yRWFjaChmdW5jdGlvbihwKXto"
"Kz0nPGRpdiBjbGFzcz0icnAtcHIiPjxkaXY+PHNwYW4gc3R5bGU9ImNvbG9yOnZhcigtLXJlZCk7"
"Zm9udC13ZWlnaHQ6Ym9sZCI+JytwLnBvcnQrJy8nK3AucHJvdG8rJzwvc3Bhbj48L2Rpdj48ZGl2"
"IHN0eWxlPSJjb2xvcjp2YXIoLS10eC1kYXJrKTtmb250LXdlaWdodDo2MDAiPicrcC5zZXJ2aWNl"
"Kyc8L2Rpdj48ZGl2PjxzcGFuIGNsYXNzPSJzZXYgJytwLnNldmVyaXR5KyciPicrcC5zZXZlcml0"
"eSsnPC9zcGFuPjwvZGl2PjxkaXYgc3R5bGU9ImNvbG9yOnZhcigtLXR4LW11dGVkKTtmb250LXNp"
"emU6MTBweCI+JytwLmRlc2MrJzwvZGl2PjwvZGl2Pid9KTtoKz0nPC9kaXY+J30KICBpZihhbGxU"
"aHJlYXRzLmxlbmd0aCl7aCs9JzxkaXYgY2xhc3M9InJwLXNlYyI+PGRpdiBjbGFzcz0icnAtc3Qi"
"PlZVTE5FUkFCSUxJVElFUyAoJythbGxUaHJlYXRzLmxlbmd0aCsnKTwvZGl2Pic7YWxsVGhyZWF0"
"cy5mb3JFYWNoKGZ1bmN0aW9uKHQsaSl7aCs9JzxkaXYgY2xhc3M9InJwLXRoICcrdC5zZXZlcml0"
"eSsnIj48ZGl2IGNsYXNzPSJycC10biI+JysoaSsxKSsnLiAnK3QubmFtZSsnIDxzcGFuIGNsYXNz"
"PSJzZXYgJyt0LnNldmVyaXR5KyciPicrdC5zZXZlcml0eSsnPC9zcGFuPjwvZGl2PjxkaXYgY2xh"
"c3M9InJwLXRkIj4nK3QuZGVzYysnPC9kaXY+PGRpdiBjbGFzcz0icnAtdGYiPkZJWDogJyt0LmZp"
"eCsnPC9kaXY+PC9kaXY+J30pO2grPSc8L2Rpdj4nfQogIGlmKCFzb3J0ZWQubGVuZ3RoJiYhYWxs"
"VGhyZWF0cy5sZW5ndGgpaCs9JzxkaXYgc3R5bGU9ImNvbG9yOnZhcigtLXNldi1sb3cpO3BhZGRp"
"bmc6MTZweCAwIj5ObyBkYXRhIHlldC4gUnVuIHNjYW5zIGZpcnN0LjwvZGl2Pic7CiAgZG9jdW1l"
"bnQuZ2V0RWxlbWVudEJ5SWQoJ3JwJykuaW5uZXJIVE1MPWg7ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5"
"SWQoJ3JlcG9ydC1tb2RhbCcpLmNsYXNzTGlzdC5hZGQoJ29wZW4nKTsKfQpmdW5jdGlvbiBjbG9z"
"ZVJlcG9ydCgpe2RvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZXBvcnQtbW9kYWwnKS5jbGFzc0xp"
"c3QucmVtb3ZlKCdvcGVuJyl9CgpmdW5jdGlvbiBkb3dubG9hZEhUTUwoKXsKICB2YXIgbm93PW5l"
"dyBEYXRlKCkudG9Mb2NhbGVTdHJpbmcoKTt2YXIgc29ydGVkPWFsbFBvcnRzLnNsaWNlKCkuc29y"
"dChmdW5jdGlvbihhLGIpe3ZhciBvPXtDUklUSUNBTDowLEhJR0g6MSxNRURJVU06MixMT1c6M307"
"cmV0dXJuKG9bYS5zZXZlcml0eV18fDMpLShvW2Iuc2V2ZXJpdHldfHwzKXx8YS5wb3J0LWIucG9y"
"dH0pOwogIHZhciBiPSc8IURPQ1RZUEUgaHRtbD48aHRtbD48aGVhZD48bWV0YSBjaGFyc2V0PSJV"
"VEYtOCI+PHRpdGxlPkhBUlNIQSB2Ny4wPC90aXRsZT48c3R5bGU+Ym9keXtmb250LWZhbWlseTpt"
"b25vc3BhY2U7YmFja2dyb3VuZDojZmZmO2NvbG9yOiMzYTNhNDQ7cGFkZGluZzozMHB4O21heC13"
"aWR0aDoxMTAwcHg7bWFyZ2luOmF1dG99aDF7Y29sb3I6I2U2Mzk0Njt0ZXh0LWFsaWduOmNlbnRl"
"cn1oMntjb2xvcjojZTYzOTQ2O2ZvbnQtc2l6ZToxMnB4O21hcmdpbi10b3A6MThweH10YWJsZXt3"
"aWR0aDoxMDAlO2JvcmRlci1jb2xsYXBzZTpjb2xsYXBzZX10aCx0ZHtwYWRkaW5nOjVweDtib3Jk"
"ZXItYm90dG9tOjFweCBzb2xpZCAjZWNlY2VmO2ZvbnQtc2l6ZToxMHB4O3RleHQtYWxpZ246bGVm"
"dH0uY2FyZHtib3JkZXItbGVmdDo0cHggc29saWQgI2Q5MDQyOTtwYWRkaW5nOjhweCAxMnB4O21h"
"cmdpbjo1cHggMDtiYWNrZ3JvdW5kOiNmN2Y3Zjg7Ym9yZGVyLXJhZGl1czo2cHh9PC9zdHlsZT48"
"L2hlYWQ+PGJvZHk+JzsKICBiKz0nPGgxPkhBUlNIQSB2Ny4wIFZBUFQgUkVQT1JUPC9oMT48cCBz"
"dHlsZT0idGV4dC1hbGlnbjpjZW50ZXI7Y29sb3I6I2IwYjBiYSI+Jytub3crJzwvcD4nOwogIGlm"
"KHNvcnRlZC5sZW5ndGgpe2IrPSc8aDI+T1BFTiBQT1JUUzwvaDI+PHRhYmxlPjx0cj48dGg+UE9S"
"VDwvdGg+PHRoPlNFUlZJQ0U8L3RoPjx0aD5SSVNLPC90aD48dGg+REVTQzwvdGg+PC90cj4nO3Nv"
"cnRlZC5mb3JFYWNoKGZ1bmN0aW9uKHApe2IrPSc8dHI+PHRkPicrcC5wb3J0KycvJytwLnByb3Rv"
"Kyc8L3RkPjx0ZD4nK3Auc2VydmljZSsnPC90ZD48dGQ+JytwLnNldmVyaXR5Kyc8L3RkPjx0ZD4n"
"K3AuZGVzYysnPC90ZD48L3RyPid9KTtiKz0nPC90YWJsZT4nfQogIGlmKGFsbFRocmVhdHMubGVu"
"Z3RoKXtiKz0nPGgyPlZVTE5FUkFCSUxJVElFUzwvaDI+JzthbGxUaHJlYXRzLmZvckVhY2goZnVu"
"Y3Rpb24odCxpKXtiKz0nPGRpdiBjbGFzcz0iY2FyZCI+PGI+JysoaSsxKSsnLiAnK3QubmFtZSsn"
"PC9iPiBbJyt0LnNldmVyaXR5KyddPHA+Jyt0LmRlc2MrJzwvcD48cCBzdHlsZT0iY29sb3I6IzJk"
"NmE0ZiI+RklYOiAnK3QuZml4Kyc8L3A+PC9kaXY+J30pfQogIGIrPSc8L2JvZHk+PC9odG1sPic7"
"CiAgdmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnYScpO2EuaHJlZj1VUkwuY3JlYXRlT2Jq"
"ZWN0VVJMKG5ldyBCbG9iKFtiXSx7dHlwZTondGV4dC9odG1sJ30pKTthLmRvd25sb2FkPSdIQVJT"
"SEFfdjdfVkFQVC5odG1sJzthLmNsaWNrKCk7bm90aWZ5KCdSZXBvcnQgZG93bmxvYWRlZCEnKTsK"
"fQpmdW5jdGlvbiBkb3dubG9hZFRYVCgpewogIHZhciBub3c9bmV3IERhdGUoKS50b0xvY2FsZVN0"
"cmluZygpO3ZhciB0PSdIQVJTSEEgdjcuMCBWQVBUIFJFUE9SVFxuJytub3crJ1xuXG4nOwogIGFs"
"bFBvcnRzLmZvckVhY2goZnVuY3Rpb24ocCl7dCs9cC5wb3J0KycvJytwLnByb3RvKycgJytwLnNl"
"cnZpY2UrJyBbJytwLnNldmVyaXR5KyddICcrcC5kZXNjKydcbid9KTsKICBpZihhbGxUaHJlYXRz"
"Lmxlbmd0aCl7dCs9J1xuVlVMTkVSQUJJTElUSUVTOlxuJzthbGxUaHJlYXRzLmZvckVhY2goZnVu"
"Y3Rpb24odGgsaSl7dCs9KGkrMSkrJy4gJyt0aC5uYW1lKycgWycrdGguc2V2ZXJpdHkrJ10gJyt0"
"aC5kZXNjKydcbkZJWDogJyt0aC5maXgrJ1xuXG4nfSl9CiAgdmFyIGE9ZG9jdW1lbnQuY3JlYXRl"
"RWxlbWVudCgnYScpO2EuaHJlZj1VUkwuY3JlYXRlT2JqZWN0VVJMKG5ldyBCbG9iKFt0XSx7dHlw"
"ZTondGV4dC9wbGFpbid9KSk7YS5kb3dubG9hZD0nSEFSU0hBX3Y3X1ZBUFQudHh0JzthLmNsaWNr"
"KCk7bm90aWZ5KCdUWFQgZG93bmxvYWRlZCEnKTsKfQpkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgn"
"cmVwb3J0LW1vZGFsJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLGZ1bmN0aW9uKGUpe2lmKGUu"
"dGFyZ2V0PT09dGhpcyljbG9zZVJlcG9ydCgpfSk7CgovKiA9PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIENIQVJUUwogICA9"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09ICovCkNoYXJ0LmRlZmF1bHRzLmNvbG9yPScjOGE4YTk2JztDaGFydC5kZWZhdWx0cy5i"
"b3JkZXJDb2xvcj0ncmdiYSgwLDAsMCwwLjA2KSc7CkNoYXJ0LmRlZmF1bHRzLmZvbnQuZmFtaWx5"
"PSInSUJNIFBsZXggTW9ubycsbW9ub3NwYWNlIjtDaGFydC5kZWZhdWx0cy5mb250LnNpemU9MTA7"
"CkNoYXJ0LmRlZmF1bHRzLnBsdWdpbnMubGVnZW5kLmxhYmVscy5ib3hXaWR0aD0xMDtDaGFydC5k"
"ZWZhdWx0cy5wbHVnaW5zLmxlZ2VuZC5sYWJlbHMucGFkZGluZz0xNDsKCmZ1bmN0aW9uIGRlc3Ry"
"b3lDaGFydHMobyl7T2JqZWN0LmtleXMobykuZm9yRWFjaChmdW5jdGlvbihrKXtpZihvW2tdKXtv"
"W2tdLmRlc3Ryb3koKTtvW2tdPW51bGx9fSl9CmZ1bmN0aW9uIGNhbGNSaXNrU2NvcmUocCx0KXtp"
"ZighcC5sZW5ndGgmJiF0Lmxlbmd0aClyZXR1cm4gMDt2YXIgcz0wO3AuZm9yRWFjaChmdW5jdGlv"
"bih4KXtpZih4LnNldmVyaXR5PT09J0NSSVRJQ0FMJylzKz0yNTtlbHNlIGlmKHguc2V2ZXJpdHk9"
"PT0nSElHSCcpcys9MTU7ZWxzZSBpZih4LnNldmVyaXR5PT09J01FRElVTScpcys9ODtlbHNlIHMr"
"PTN9KTt0LmZvckVhY2goZnVuY3Rpb24oeCl7aWYoeC5zZXZlcml0eT09PSdDUklUSUNBTCcpcys9"
"MzA7ZWxzZSBpZih4LnNldmVyaXR5PT09J0hJR0gnKXMrPTIwO2Vsc2UgaWYoeC5zZXZlcml0eT09"
"PSdNRURJVU0nKXMrPTEwO2Vsc2Ugcys9NH0pO3JldHVybiBNYXRoLm1pbigxMDAsTWF0aC5yb3Vu"
"ZChzKSl9CmZ1bmN0aW9uIGdldFJpc2tDb2xvcihzKXtpZihzPj03NSlyZXR1cm4nI2Q5MDQyOSc7"
"aWYocz49NTApcmV0dXJuJyNlODVkMDQnO2lmKHM+PTI1KXJldHVybicjZTA5ZjNlJztyZXR1cm4n"
"IzJkNmE0Zid9CmZ1bmN0aW9uIGdldFJpc2tMYWJlbChzKXtpZihzPj03NSlyZXR1cm4nQ1JJVElD"
"QUwnO2lmKHM+PTUwKXJldHVybidISUdIJztpZihzPj0yNSlyZXR1cm4nTUVESVVNJztyZXR1cm4n"
"TE9XJ30KCmZ1bmN0aW9uIHJlZnJlc2hSaXNrQ2hhcnRzKCl7CiAgZGVzdHJveUNoYXJ0cyhyaXNr"
"Q2hhcnRzKTt2YXIgYz1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncmlzay1jb250ZW50Jyk7CiAg"
"aWYoIWFsbFBvcnRzLmxlbmd0aCYmIWFsbFRocmVhdHMubGVuZ3RoKXtjLmlubmVySFRNTD0nPGRp"
"diBjbGFzcz0iZW1wdHktc3RhdGUiPjxkaXYgY2xhc3M9ImVtcHR5LWljbyI+8J+TijwvZGl2Pjxk"
"aXYgY2xhc3M9ImVtcHR5LXRpdGxlIj5ObyBSaXNrIERhdGE8L2Rpdj48ZGl2IGNsYXNzPSJlbXB0"
"eS1zdWIiPlJ1biBzY2FucyBmaXJzdDwvZGl2PjwvZGl2Pic7cmV0dXJufQogIHZhciBjcml0PTAs"
"aGlnaD0wLG1lZD0wLGxvdz0wOwogIGFsbFBvcnRzLmZvckVhY2goZnVuY3Rpb24ocCl7aWYocC5z"
"ZXZlcml0eT09PSdDUklUSUNBTCcpY3JpdCsrO2Vsc2UgaWYocC5zZXZlcml0eT09PSdISUdIJylo"
"aWdoKys7ZWxzZSBpZihwLnNldmVyaXR5PT09J01FRElVTScpbWVkKys7ZWxzZSBsb3crK30pOwog"
"IGFsbFRocmVhdHMuZm9yRWFjaChmdW5jdGlvbih0KXtpZih0LnNldmVyaXR5PT09J0NSSVRJQ0FM"
"Jyljcml0Kys7ZWxzZSBpZih0LnNldmVyaXR5PT09J0hJR0gnKWhpZ2grKztlbHNlIGlmKHQuc2V2"
"ZXJpdHk9PT0nTUVESVVNJyltZWQrKztlbHNlIGxvdysrfSk7CiAgdmFyIHNjb3JlPWNhbGNSaXNr"
"U2NvcmUoYWxsUG9ydHMsYWxsVGhyZWF0cyksckM9Z2V0Umlza0NvbG9yKHNjb3JlKSxyTD1nZXRS"
"aXNrTGFiZWwoc2NvcmUpOwogIHZhciBzdmNNYXA9e307YWxsUG9ydHMuZm9yRWFjaChmdW5jdGlv"
"bihwKXt2YXIgcz1wLnNlcnZpY2V8fCc/JztpZighc3ZjTWFwW3NdKXN2Y01hcFtzXT17YzowLGg6"
"MCxtOjAsbDowLHQ6MH07c3ZjTWFwW3NdLnQrKztpZihwLnNldmVyaXR5PT09J0NSSVRJQ0FMJylz"
"dmNNYXBbc10uYysrO2Vsc2UgaWYocC5zZXZlcml0eT09PSdISUdIJylzdmNNYXBbc10uaCsrO2Vs"
"c2UgaWYocC5zZXZlcml0eT09PSdNRURJVU0nKXN2Y01hcFtzXS5tKys7ZWxzZSBzdmNNYXBbc10u"
"bCsrfSk7CiAgdmFyIHNOPU9iamVjdC5rZXlzKHN2Y01hcCkuc29ydChmdW5jdGlvbihhLGIpe3Jl"
"dHVybiBzdmNNYXBbYl0udC1zdmNNYXBbYV0udH0pLnNsaWNlKDAsMTApOwogIHZhciBoPSc8ZGl2"
"IGNsYXNzPSJkYXNoLWdyaWQgY29scy0yIiBzdHlsZT0ibWFyZ2luLWJvdHRvbToyMHB4Ij4nOwog"
"IGgrPSc8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLWhlYWRlciI+PGRpdj48ZGl2"
"IGNsYXNzPSJjYXJkLXRpdGxlIj5PdmVyYWxsIFJpc2sgU2NvcmU8L2Rpdj48L2Rpdj48L2Rpdj4n"
"OwogIGgrPSc8ZGl2IGNsYXNzPSJyaXNrLWdhdWdlIj48ZGl2IGNsYXNzPSJyaXNrLWNpcmNsZSIg"
"c3R5bGU9ImNvbG9yOicrckMrJztib3JkZXItY29sb3I6JytyQysnMjUiPjxkaXYgY2xhc3M9InJp"
"c2stdmFsIiBzdHlsZT0iY29sb3I6JytyQysnIj4nK3Njb3JlKyc8L2Rpdj48ZGl2IGNsYXNzPSJy"
"aXNrLWxhYmVsIj4nK3JMKyc8L2Rpdj48L2Rpdj4nOwogIGgrPSc8ZGl2IGNsYXNzPSJyaXNrLWRl"
"dGFpbHMiPjxkaXYgY2xhc3M9InJpc2stcm93Ij48ZGl2IGNsYXNzPSJyaXNrLWRvdCIgc3R5bGU9"
"ImJhY2tncm91bmQ6dmFyKC0tcmVkKSI+PC9kaXY+UG9ydHM8c3BhbiBjbGFzcz0icmlzay12YWwt"
"c20iIHN0eWxlPSJjb2xvcjp2YXIoLS1zZXYtaGlnaCkiPicrYWxsUG9ydHMubGVuZ3RoKyc8L3Nw"
"YW4+PC9kaXY+JzsKICBoKz0nPGRpdiBjbGFzcz0icmlzay1yb3ciPjxkaXYgY2xhc3M9InJpc2st"
"ZG90IiBzdHlsZT0iYmFja2dyb3VuZDp2YXIoLS1zZXYtY3JpdCkiPjwvZGl2PlRocmVhdHM8c3Bh"
"biBjbGFzcz0icmlzay12YWwtc20iIHN0eWxlPSJjb2xvcjp2YXIoLS1zZXYtY3JpdCkiPicrYWxs"
"VGhyZWF0cy5sZW5ndGgrJzwvc3Bhbj48L2Rpdj48L2Rpdj48L2Rpdj48L2Rpdj4nOwogIGgrPSc8"
"ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXRpdGxlIj5TZXZlcml0eSBEaXN0cmli"
"dXRpb248L2Rpdj48ZGl2IGNsYXNzPSJjaGFydC13cmFwIj48Y2FudmFzIGlkPSJjaC1zZXYiPjwv"
"Y2FudmFzPjwvZGl2PjwvZGl2Pic7CiAgaCs9JzwvZGl2Pic7CiAgaWYoc04ubGVuZ3RoKXtoKz0n"
"PGRpdiBjbGFzcz0iZGFzaC1ncmlkIGNvbHMtMiI+PGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFz"
"cz0iY2FyZC10aXRsZSI+UmlzayBieSBTZXJ2aWNlPC9kaXY+PGRpdiBjbGFzcz0iY2hhcnQtd3Jh"
"cCI+PGNhbnZhcyBpZD0iY2gtc3ZjIj48L2NhbnZhcz48L2Rpdj48L2Rpdj4nOwogIGgrPSc8ZGl2"
"IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXRpdGxlIj5SaXNrIGJ5IENhdGVnb3J5PC9k"
"aXY+PGRpdiBjbGFzcz0iY2hhcnQtd3JhcCI+PGNhbnZhcyBpZD0iY2gtY2F0Ij48L2NhbnZhcz48"
"L2Rpdj48L2Rpdj48L2Rpdj4nfQogIGMuaW5uZXJIVE1MPWg7CiAgdmFyIHgxPWRvY3VtZW50Lmdl"
"dEVsZW1lbnRCeUlkKCdjaC1zZXYnKTtpZih4MSlyaXNrQ2hhcnRzLnM9bmV3IENoYXJ0KHgxLHt0"
"eXBlOidkb3VnaG51dCcsZGF0YTp7bGFiZWxzOlsnQ3JpdGljYWwnLCdIaWdoJywnTWVkaXVtJywn"
"TG93J10sZGF0YXNldHM6W3tkYXRhOltjcml0LGhpZ2gsbWVkLGxvd10sYmFja2dyb3VuZENvbG9y"
"OltzZXZDb2xvcnMuQ1JJVElDQUwsc2V2Q29sb3JzLkhJR0gsc2V2Q29sb3JzLk1FRElVTSxzZXZD"
"b2xvcnMuTE9XXSxib3JkZXJXaWR0aDowLGhvdmVyT2Zmc2V0Ojh9XX0sb3B0aW9uczp7cmVzcG9u"
"c2l2ZTp0cnVlLG1haW50YWluQXNwZWN0UmF0aW86ZmFsc2UsY3V0b3V0Oic3MCUnLHBsdWdpbnM6"
"e2xlZ2VuZDp7cG9zaXRpb246J3JpZ2h0J319fX0pOwogIHZhciB4Mj1kb2N1bWVudC5nZXRFbGVt"
"ZW50QnlJZCgnY2gtc3ZjJyk7aWYoeDImJnNOLmxlbmd0aClyaXNrQ2hhcnRzLnY9bmV3IENoYXJ0"
"KHgyLHt0eXBlOidiYXInLGRhdGE6e2xhYmVsczpzTixkYXRhc2V0czpbe2xhYmVsOidDcml0Jyxk"
"YXRhOnNOLm1hcChmdW5jdGlvbihzKXtyZXR1cm4gc3ZjTWFwW3NdLmN9KSxiYWNrZ3JvdW5kQ29s"
"b3I6c2V2QmcuQ1JJVElDQUwsYm9yZGVyQ29sb3I6c2V2Q29sb3JzLkNSSVRJQ0FMLGJvcmRlcldp"
"ZHRoOjF9LHtsYWJlbDonSGlnaCcsZGF0YTpzTi5tYXAoZnVuY3Rpb24ocyl7cmV0dXJuIHN2Y01h"
"cFtzXS5ofSksYmFja2dyb3VuZENvbG9yOnNldkJnLkhJR0gsYm9yZGVyQ29sb3I6c2V2Q29sb3Jz"
"LkhJR0gsYm9yZGVyV2lkdGg6MX0se2xhYmVsOidMb3cnLGRhdGE6c04ubWFwKGZ1bmN0aW9uKHMp"
"e3JldHVybiBzdmNNYXBbc10ubH0pLGJhY2tncm91bmRDb2xvcjpzZXZCZy5MT1csYm9yZGVyQ29s"
"b3I6c2V2Q29sb3JzLkxPVyxib3JkZXJXaWR0aDoxfV19LG9wdGlvbnM6e3Jlc3BvbnNpdmU6dHJ1"
"ZSxtYWludGFpbkFzcGVjdFJhdGlvOmZhbHNlLGluZGV4QXhpczoneScsc2NhbGVzOnt4OntzdGFj"
"a2VkOnRydWV9LHk6e3N0YWNrZWQ6dHJ1ZSxncmlkOntkaXNwbGF5OmZhbHNlfX19LHBsdWdpbnM6"
"e2xlZ2VuZDp7cG9zaXRpb246J3RvcCcsbGFiZWxzOntib3hXaWR0aDo4fX19fX0pOwogIHZhciBj"
"Tj0wLGNXPTAsY0k9MDthbGxUaHJlYXRzLmZvckVhY2goZnVuY3Rpb24odCl7dmFyIG49dC5uYW1l"
"LnRvTG93ZXJDYXNlKCk7aWYobi5pbmRleE9mKCdzcWwnKT49MHx8bi5pbmRleE9mKCd4c3MnKT49"
"MHx8bi5pbmRleE9mKCdoZWFkZXInKT49MHx8bi5pbmRleE9mKCdzc2wnKT49MCljVysrO2Vsc2Ug"
"aWYobi5pbmRleE9mKCdzbWInKT49MHx8bi5pbmRleE9mKCdzbm1wJyk+PTB8fG4uaW5kZXhPZign"
"cG9ydCcpPj0wKWNOKys7ZWxzZSBjSSsrfSk7CiAgdmFyIHgzPWRvY3VtZW50LmdldEVsZW1lbnRC"
"eUlkKCdjaC1jYXQnKTtpZih4MylyaXNrQ2hhcnRzLmM9bmV3IENoYXJ0KHgzLHt0eXBlOidkb3Vn"
"aG51dCcsZGF0YTp7bGFiZWxzOlsnTmV0d29yaycsJ1dlYicsJ0luZnJhc3RydWN0dXJlJ10sZGF0"
"YXNldHM6W3tkYXRhOltNYXRoLm1heChjTixTQy5uZXR8fDApLE1hdGgubWF4KGNXLFNDLndlYnx8"
"MCksTWF0aC5tYXgoY0ksU0MuaW5mfHwwKV0sYmFja2dyb3VuZENvbG9yOlsnIzBhMGEwYycsJyNl"
"NjM5NDYnLCcjOGE4YTk2J10sYm9yZGVyV2lkdGg6MH1dfSxvcHRpb25zOntyZXNwb25zaXZlOnRy"
"dWUsbWFpbnRhaW5Bc3BlY3RSYXRpbzpmYWxzZSxjdXRvdXQ6JzcwJScscGx1Z2luczp7bGVnZW5k"
"Ontwb3NpdGlvbjoncmlnaHQnfX19fSk7Cn0KCmZ1bmN0aW9uIHJlZnJlc2hUaHJlYXRDaGFydHMo"
"KXsKICBkZXN0cm95Q2hhcnRzKHRocmVhdENoYXJ0cyk7dmFyIGM9ZG9jdW1lbnQuZ2V0RWxlbWVu"
"dEJ5SWQoJ3RncmFwaC1jb250ZW50Jyk7CiAgaWYoIWFsbFRocmVhdHMubGVuZ3RoJiYhYWxsUG9y"
"dHMubGVuZ3RoKXtjLmlubmVySFRNTD0nPGRpdiBjbGFzcz0iZW1wdHktc3RhdGUiPjxkaXYgY2xh"
"c3M9ImVtcHR5LWljbyI+8J+VuDwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXRpdGxlIj5ObyBUaHJl"
"YXQgRGF0YTwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXN1YiI+UnVuIHNjYW5zIGZpcnN0PC9kaXY+"
"PC9kaXY+JztyZXR1cm59CiAgdmFyIGNhdHM9e2luamVjdGlvbjowLGNvbmZpZzowLGNyeXB0bzow"
"LGV4cG9zdXJlOjAsYXV0aDowLG5ldHdvcms6MH07CiAgYWxsVGhyZWF0cy5mb3JFYWNoKGZ1bmN0"
"aW9uKHQpe3ZhciBuPXQubmFtZS50b0xvd2VyQ2FzZSgpO2lmKG4uaW5kZXhPZignc3FsJyk+PTB8"
"fG4uaW5kZXhPZigneHNzJyk+PTB8fG4uaW5kZXhPZignaW5qZWN0Jyk+PTApY2F0cy5pbmplY3Rp"
"b24rKztlbHNlIGlmKG4uaW5kZXhPZignaGVhZGVyJyk+PTB8fG4uaW5kZXhPZignY29ycycpPj0w"
"fHxuLmluZGV4T2YoJ2NvbmZpZycpPj0wKWNhdHMuY29uZmlnKys7ZWxzZSBpZihuLmluZGV4T2Yo"
"J3NzbCcpPj0wfHxuLmluZGV4T2YoJ3RscycpPj0wKWNhdHMuY3J5cHRvKys7ZWxzZSBpZihuLmlu"
"ZGV4T2YoJ2V4cG9zdXJlJyk+PTB8fG4uaW5kZXhPZignaW5mbycpPj0wKWNhdHMuZXhwb3N1cmUr"
"KztlbHNlIGlmKG4uaW5kZXhPZignYXV0aCcpPj0wfHxuLmluZGV4T2YoJ2Z0cCcpPj0wfHxuLmlu"
"ZGV4T2YoJ3NzaCcpPj0wKWNhdHMuYXV0aCsrO2Vsc2UgY2F0cy5uZXR3b3JrKyt9KTsKICB2YXIg"
"c3Y9e0NSSVRJQ0FMOjAsSElHSDowLE1FRElVTTowLExPVzowfTthbGxUaHJlYXRzLmZvckVhY2go"
"ZnVuY3Rpb24odCl7c3ZbdC5zZXZlcml0eV09KHN2W3Quc2V2ZXJpdHldfHwwKSsxfSk7CiAgdmFy"
"IGg9JzxkaXYgY2xhc3M9ImRhc2gtZ3JpZCBjb2xzLTIiIHN0eWxlPSJtYXJnaW4tYm90dG9tOjIw"
"cHgiPic7CiAgaCs9JzxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtdGl0bGUiPkF0"
"dGFjayBWZWN0b3IgQW5hbHlzaXM8L2Rpdj48ZGl2IGNsYXNzPSJjaGFydC13cmFwIj48Y2FudmFz"
"IGlkPSJjaC1yYWRhciI+PC9jYW52YXM+PC9kaXY+PC9kaXY+JzsKICBoKz0nPGRpdiBjbGFzcz0i"
"Y2FyZCI+PGRpdiBjbGFzcz0iY2FyZC10aXRsZSI+VGhyZWF0cyBieSBTZXZlcml0eTwvZGl2Pjxk"
"aXYgY2xhc3M9ImNoYXJ0LXdyYXAiPjxjYW52YXMgaWQ9ImNoLXRzZXYiPjwvY2FudmFzPjwvZGl2"
"PjwvZGl2PjwvZGl2Pic7CiAgaCs9JzxkaXYgY2xhc3M9ImRhc2gtZ3JpZCBjb2xzLTEiPjxkaXYg"
"Y2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtdGl0bGUiPkNvbWJpbmVkIFJpc2sgT3ZlcnZp"
"ZXc8L2Rpdj48ZGl2IGNsYXNzPSJjaGFydC13cmFwIiBzdHlsZT0ibWluLWhlaWdodDoyMjBweCI+"
"PGNhbnZhcyBpZD0iY2gtY29tYm8iPjwvY2FudmFzPjwvZGl2PjwvZGl2PjwvZGl2Pic7CiAgYy5p"
"bm5lckhUTUw9aDsKICB2YXIgcjE9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NoLXJhZGFyJyk7"
"aWYocjEpdGhyZWF0Q2hhcnRzLnI9bmV3IENoYXJ0KHIxLHt0eXBlOidyYWRhcicsZGF0YTp7bGFi"
"ZWxzOlsnSW5qZWN0aW9uJywnTWlzY29uZmlnJywnQ3J5cHRvJywnRXhwb3N1cmUnLCdBdXRoJywn"
"TmV0d29yayddLGRhdGFzZXRzOlt7ZGF0YTpbY2F0cy5pbmplY3Rpb24sY2F0cy5jb25maWcsY2F0"
"cy5jcnlwdG8sY2F0cy5leHBvc3VyZSxjYXRzLmF1dGgsY2F0cy5uZXR3b3JrXSxiYWNrZ3JvdW5k"
"Q29sb3I6J3JnYmEoMjMwLDU3LDcwLDAuMSknLGJvcmRlckNvbG9yOicjZTYzOTQ2Jyxib3JkZXJX"
"aWR0aDoyLHBvaW50QmFja2dyb3VuZENvbG9yOicjZTYzOTQ2Jyxwb2ludFJhZGl1czo0fV19LG9w"
"dGlvbnM6e3Jlc3BvbnNpdmU6dHJ1ZSxtYWludGFpbkFzcGVjdFJhdGlvOmZhbHNlLHNjYWxlczp7"
"cjp7YmVnaW5BdFplcm86dHJ1ZSxncmlkOntjb2xvcjoncmdiYSgwLDAsMCwwLjA2KSd9LHRpY2tz"
"OntkaXNwbGF5OmZhbHNlfX19LHBsdWdpbnM6e2xlZ2VuZDp7ZGlzcGxheTpmYWxzZX19fX0pOwog"
"IHZhciByMj1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2gtdHNldicpO2lmKHIyKXRocmVhdENo"
"YXJ0cy5zPW5ldyBDaGFydChyMix7dHlwZTonYmFyJyxkYXRhOntsYWJlbHM6WydDcml0aWNhbCcs"
"J0hpZ2gnLCdNZWRpdW0nLCdMb3cnXSxkYXRhc2V0czpbe2RhdGE6W3N2LkNSSVRJQ0FMLHN2LkhJ"
"R0gsc3YuTUVESVVNLHN2LkxPV10sYmFja2dyb3VuZENvbG9yOltzZXZCZy5DUklUSUNBTCxzZXZC"
"Zy5ISUdILHNldkJnLk1FRElVTSxzZXZCZy5MT1ddLGJvcmRlckNvbG9yOltzZXZDb2xvcnMuQ1JJ"
"VElDQUwsc2V2Q29sb3JzLkhJR0gsc2V2Q29sb3JzLk1FRElVTSxzZXZDb2xvcnMuTE9XXSxib3Jk"
"ZXJXaWR0aDoxLGJvcmRlclJhZGl1czo4fV19LG9wdGlvbnM6e3Jlc3BvbnNpdmU6dHJ1ZSxtYWlu"
"dGFpbkFzcGVjdFJhdGlvOmZhbHNlLHNjYWxlczp7eDp7Z3JpZDp7ZGlzcGxheTpmYWxzZX19LHk6"
"e2JlZ2luQXRaZXJvOnRydWUsdGlja3M6e3N0ZXBTaXplOjF9fX0scGx1Z2luczp7bGVnZW5kOntk"
"aXNwbGF5OmZhbHNlfX19fSk7CiAgdmFyIHI1PWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjaC1j"
"b21ibycpO2lmKHI1KXt2YXIgcFM9e0NSSVRJQ0FMOjAsSElHSDowLE1FRElVTTowLExPVzowfTth"
"bGxQb3J0cy5mb3JFYWNoKGZ1bmN0aW9uKHApe3BTW3Auc2V2ZXJpdHldPShwU1twLnNldmVyaXR5"
"XXx8MCkrMX0pO3RocmVhdENoYXJ0cy5jPW5ldyBDaGFydChyNSx7dHlwZTonYmFyJyxkYXRhOnts"
"YWJlbHM6WydDcml0aWNhbCcsJ0hpZ2gnLCdNZWRpdW0nLCdMb3cnXSxkYXRhc2V0czpbe2xhYmVs"
"OidQb3J0cycsZGF0YTpbcFMuQ1JJVElDQUwscFMuSElHSCxwUy5NRURJVU0scFMuTE9XXSxiYWNr"
"Z3JvdW5kQ29sb3I6J3JnYmEoMTAsMTAsMTIsMC4wOCknLGJvcmRlckNvbG9yOicjMGEwYTBjJyxi"
"b3JkZXJXaWR0aDoxLGJvcmRlclJhZGl1czo2fSx7bGFiZWw6J1RocmVhdHMnLGRhdGE6W3N2LkNS"
"SVRJQ0FMLHN2LkhJR0gsc3YuTUVESVVNLHN2LkxPV10sYmFja2dyb3VuZENvbG9yOidyZ2JhKDIz"
"MCw1Nyw3MCwwLjEpJyxib3JkZXJDb2xvcjonI2U2Mzk0NicsYm9yZGVyV2lkdGg6MSxib3JkZXJS"
"YWRpdXM6Nn1dfSxvcHRpb25zOntyZXNwb25zaXZlOnRydWUsbWFpbnRhaW5Bc3BlY3RSYXRpbzpm"
"YWxzZSxzY2FsZXM6e3g6e2dyaWQ6e2Rpc3BsYXk6ZmFsc2V9fSx5OntiZWdpbkF0WmVybzp0cnVl"
"LHRpY2tzOntzdGVwU2l6ZToxfX19LHBsdWdpbnM6e2xlZ2VuZDp7cG9zaXRpb246J3RvcCcsbGFi"
"ZWxzOntib3hXaWR0aDoxMH19fX19KX0KfQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBTQ0FOIFNUQVRVUyBQT0xM"
"SU5HIChTSU5HTEUgQ0xFQU4gVkVSU0lPTikKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpmdW5jdGlvbiBwb2xsU2Nh"
"blN0YXR1cygpewogIGZldGNoKCcvc2Nhbl9zdGF0dXMnKS50aGVuKGZ1bmN0aW9uKHIpe3JldHVy"
"biByLmpzb24oKX0pLnRoZW4oZnVuY3Rpb24ocyl7CiAgICB2YXIgaW5kaWNhdG9yPWRvY3VtZW50"
"LmdldEVsZW1lbnRCeUlkKCdzY2FuLWluZGljYXRvcicpOwogICAgdmFyIGJhckZpbGw9ZG9jdW1l"
"bnQuZ2V0RWxlbWVudEJ5SWQoJ3NjYW4tYmFyLWZpbGwnKTsKICAgIHZhciBiYWRnZT1kb2N1bWVu"
"dC5nZXRFbGVtZW50QnlJZCgnc2Nhbi1zdGF0dXMtYmFkZ2UnKTsKICAgIHZhciBsaXZlQ2FyZD1k"
"b2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbGl2ZS1zY2FuLWNhcmQnKTsKICAgIHZhciBtcD1kb2N1"
"bWVudC5nZXRFbGVtZW50QnlJZCgnaC1taW5pLXByb2dyZXNzJyk7CiAgICB2YXIgbWJhcj1kb2N1"
"bWVudC5nZXRFbGVtZW50QnlJZCgnaC1taW5pLWJhcicpOwoKICAgIC8qIE1pbmkgcHJvZ3Jlc3Mg"
"YmFyICovCiAgICBpZihzLmFjdGl2ZSl7bXAuY2xhc3NMaXN0LmFkZCgnYWN0aXZlJyk7bWJhci5z"
"dHlsZS53aWR0aD1zLnBlcmNlbnQrJyUnfQogICAgZWxzZXttYmFyLnN0eWxlLndpZHRoPXMucGhh"
"c2U9PT0nY29tcGxldGUnPycxMDAlJzonMCUnOwogICAgICBpZihzLnBoYXNlPT09J2NvbXBsZXRl"
"JylzZXRUaW1lb3V0KGZ1bmN0aW9uKCl7bXAuY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJyl9LDIw"
"MDApOwogICAgICBlbHNlIG1wLmNsYXNzTGlzdC5yZW1vdmUoJ2FjdGl2ZScpOwogICAgfQoKICAg"
"IC8qIFNjYW4gU3RhdHVzIHRhYiBpbmRpY2F0b3IgKi8KICAgIGluZGljYXRvci5jbGFzc05hbWU9"
"J3NjYW4taW5kaWNhdG9yJzsKICAgIGJhckZpbGwuY2xhc3NOYW1lPSdzY2FuLWJhci1maWxsLWxp"
"dmUnOwogICAgaWYocy5hY3RpdmUpewogICAgICBpbmRpY2F0b3IuY2xhc3NOYW1lPSdzY2FuLWlu"
"ZGljYXRvciBydW5uaW5nJzsKICAgICAgYmFkZ2UuY2xhc3NOYW1lPSd0YWItYmFkZ2UgbGl2ZSc7"
"YmFkZ2UudGV4dENvbnRlbnQ9cy5wZXJjZW50KyclJzsKICAgICAgbGl2ZUNhcmQuc3R5bGUuYm9y"
"ZGVyTGVmdENvbG9yPSd2YXIoLS1yZWQpJzsKICAgIH0gZWxzZSBpZihzLnBoYXNlPT09J2NvbXBs"
"ZXRlJyl7CiAgICAgIGluZGljYXRvci5jbGFzc05hbWU9J3NjYW4taW5kaWNhdG9yIGNvbXBsZXRl"
"JzsKICAgICAgYmFyRmlsbC5jbGFzc05hbWU9J3NjYW4tYmFyLWZpbGwtbGl2ZSBjb21wbGV0ZSc7"
"CiAgICAgIGJhZGdlLmNsYXNzTmFtZT0ndGFiLWJhZGdlIGRvbmUnO2JhZGdlLnRleHRDb250ZW50"
"PSdcdTI3MTMnOwogICAgICBsaXZlQ2FyZC5zdHlsZS5ib3JkZXJMZWZ0Q29sb3I9J3ZhcigtLXNl"
"di1sb3cpJzsKICAgIH0gZWxzZSBpZihzLnBoYXNlPT09J2Vycm9yJyl7CiAgICAgIGluZGljYXRv"
"ci5jbGFzc05hbWU9J3NjYW4taW5kaWNhdG9yIGVycm9yJzsKICAgICAgYmFkZ2UuY2xhc3NOYW1l"
"PSd0YWItYmFkZ2Ugc2hvdyBiLXJlZCc7YmFkZ2UudGV4dENvbnRlbnQ9JyEnOwogICAgICBsaXZl"
"Q2FyZC5zdHlsZS5ib3JkZXJMZWZ0Q29sb3I9J3ZhcigtLXNldi1jcml0KSc7CiAgICB9IGVsc2Ug"
"ewogICAgICBiYWRnZS5jbGFzc05hbWU9J3RhYi1iYWRnZSc7CiAgICAgIGxpdmVDYXJkLnN0eWxl"
"LmJvcmRlckxlZnRDb2xvcj0ndmFyKC0td2hpdGUtNCknOwogICAgfQoKICAgIGRvY3VtZW50Lmdl"
"dEVsZW1lbnRCeUlkKCdzY2FuLXBjdC1udW0nKS50ZXh0Q29udGVudD1zLmFjdGl2ZXx8cy5waGFz"
"ZT09PSdjb21wbGV0ZSc/cy5wZXJjZW50KyclJzonXHUyMDE0JzsKICAgIGRvY3VtZW50LmdldEVs"
"ZW1lbnRCeUlkKCdzY2FuLXRvb2wtbmFtZScpLnRleHRDb250ZW50PXMudG9vbF9kaXNwbGF5fHxz"
"LnRvb2x8fCdcdTIwMTQnOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NjYW4tdGFyZ2V0"
"JykudGV4dENvbnRlbnQ9cy50YXJnZXR8fCdcdTIwMTQnOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVu"
"dEJ5SWQoJ3NjYW4tY2F0JykudGV4dENvbnRlbnQ9KHMuY2F0ZWdvcnl8fCdcdTIwMTQnKS50b1Vw"
"cGVyQ2FzZSgpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NjYW4tZWxhcHNlZCcpLnRl"
"eHRDb250ZW50PXMuZWxhcHNlZCsncyc7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2Nh"
"bi1tZXNzYWdlJykudGV4dENvbnRlbnQ9cy5tZXNzYWdlfHwnUmVhZHkgXHUyMDE0IHNlbGVjdCBh"
"IHRvb2wgdG8gYmVnaW4nOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NjYW4tcGN0LXRl"
"eHQnKS50ZXh0Q29udGVudD1zLnBlcmNlbnQrJyUnOwogICAgYmFyRmlsbC5zdHlsZS53aWR0aD1z"
"LnBlcmNlbnQrJyUnOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NzLXN1YnRpdGxlJyku"
"dGV4dENvbnRlbnQ9cy5hY3RpdmU/J1NjYW5uaW5nICcrcy50YXJnZXQrJy4uLic6cy5waGFzZT09"
"PSdjb21wbGV0ZSc/J0xhc3Qgc2NhbiBjb21wbGV0ZWQnOidObyBhY3RpdmUgc2Nhbic7CgogICAg"
"dmFyIHBiPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzY2FuLXBoYXNlLWJhZGdlJyk7CiAgICBw"
"Yi50ZXh0Q29udGVudD0ocy5waGFzZXx8J2lkbGUnKS50b1VwcGVyQ2FzZSgpOwogICAgaWYocy5h"
"Y3RpdmUpe3BiLnN0eWxlLmJhY2tncm91bmQ9J3ZhcigtLXJlZC1kaW0pJztwYi5zdHlsZS5jb2xv"
"cj0ndmFyKC0tcmVkKSd9CiAgICBlbHNlIGlmKHMucGhhc2U9PT0nY29tcGxldGUnKXtwYi5zdHls"
"ZS5iYWNrZ3JvdW5kPSd2YXIoLS1zZXYtbG93LWJnKSc7cGIuc3R5bGUuY29sb3I9J3ZhcigtLXNl"
"di1sb3cpJ30KICAgIGVsc2V7cGIuc3R5bGUuYmFja2dyb3VuZD0ndmFyKC0td2hpdGUtMiknO3Bi"
"LnN0eWxlLmNvbG9yPSd2YXIoLS10eC1tdXRlZCknfQoKICAgIHZhciB0Uz1zLmhpc3Rvcnk/cy5o"
"aXN0b3J5Lmxlbmd0aDowLHRQPTAsdFQ9MCx0RD0wOwogICAgaWYocy5oaXN0b3J5KXtzLmhpc3Rv"
"cnkuZm9yRWFjaChmdW5jdGlvbihoKXt0UCs9aC5wb3J0c3x8MDt0VCs9aC50aHJlYXRzfHwwO3RE"
"Kz1oLmVsYXBzZWR8fDB9KX0KICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzcy10b3RhbCcp"
"LnRleHRDb250ZW50PXRTOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NzLXBvcnRzJyku"
"dGV4dENvbnRlbnQ9dFA7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3MtdGhyZWF0cycp"
"LnRleHRDb250ZW50PXRUOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NzLWF2ZycpLnRl"
"eHRDb250ZW50PXRTPjA/KHREL3RTKS50b0ZpeGVkKDEpKydzJzonMHMnOwoKICAgIGlmKHMuaGlz"
"dG9yeSYmcy5oaXN0b3J5Lmxlbmd0aCl7CiAgICAgIHZhciByb3dzPScnOwogICAgICBzLmhpc3Rv"
"cnkuZm9yRWFjaChmdW5jdGlvbihoKXsKICAgICAgICByb3dzKz0nPHRyPjx0ZCBzdHlsZT0iY29s"
"b3I6dmFyKC0tc2V2LWxvdyk7Zm9udC13ZWlnaHQ6NzAwIj5cdTI3MTMgRG9uZTwvdGQ+JzsKICAg"
"ICAgICByb3dzKz0nPHRkIHN0eWxlPSJmb250LXdlaWdodDo2MDA7Y29sb3I6dmFyKC0tdHgtZGFy"
"aykiPicraC50b29sKyc8L3RkPic7CiAgICAgICAgcm93cys9Jzx0ZCBzdHlsZT0iZm9udC1mYW1p"
"bHk6SUJNIFBsZXggTW9ubyxtb25vc3BhY2U7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tcmVk"
"KSI+JytoLnRhcmdldCsnPC90ZD4nOwogICAgICAgIHJvd3MrPSc8dGQgc3R5bGU9ImZvbnQtZmFt"
"aWx5OklCTSBQbGV4IE1vbm8sbW9ub3NwYWNlO2ZvbnQtd2VpZ2h0OjcwMCI+JytoLmVsYXBzZWQr"
"J3M8L3RkPic7CiAgICAgICAgcm93cys9Jzx0ZD4nK2gucG9ydHMrJzwvdGQ+PHRkPicraC50aHJl"
"YXRzKyc8L3RkPic7CiAgICAgICAgcm93cys9Jzx0ZCBzdHlsZT0iY29sb3I6dmFyKC0tdHgtZmFp"
"bnQpIj4nK2gudGltZSsnPC90ZD48L3RyPic7CiAgICAgIH0pOwogICAgICBkb2N1bWVudC5nZXRF"
"bGVtZW50QnlJZCgnc3MtaGlzdG9yeS10YWJsZScpLmlubmVySFRNTD1yb3dzOwogICAgfQoKICAg"
"IGlmKHMuYWN0aXZlICYmIGxhc3RQaGFzZSE9PSdzY2FubmluZycgJiYgbGFzdFBoYXNlIT09J2lu"
"aXRpYWxpemluZycgJiYgbGFzdFBoYXNlIT09J2FuYWx5emluZycpewogICAgICBzd2l0Y2hUYWIo"
"J3NjYW5zdGF0dXMnLGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy50YWItYnRuJylbNV0pOwog"
"ICAgfQogICAgbGFzdFBoYXNlPXMucGhhc2U7CiAgfSkuY2F0Y2goZnVuY3Rpb24oKXt9KTsKfQpz"
"ZXRJbnRlcnZhbChwb2xsU2NhblN0YXR1cyw4MDApOwoKLyogPT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBBVFRBQ0sgQ0hB"
"SU4gVklTVUFMSVpBVElPTgogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCmZ1bmN0aW9uIHJlZnJlc2hBdHRhY2tDaGFp"
"bnMoKXsKICBmZXRjaCgnL2F0dGFja19jaGFpbnMnKS50aGVuKGZ1bmN0aW9uKHIpe3JldHVybiBy"
"Lmpzb24oKX0pLnRoZW4oZnVuY3Rpb24oZGF0YSl7CiAgICB2YXIgY2hhaW5zID0gZGF0YS5jaGFp"
"bnMgfHwgW107CiAgICB2YXIgY29udGFpbmVyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2No"
"YWlucy1jb250ZW50Jyk7CiAgICB2YXIgYmFkZ2UgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgn"
"Y2hhaW4tYmFkZ2UnKTsKCiAgICBpZighY2hhaW5zLmxlbmd0aCl7CiAgICAgIGNvbnRhaW5lci5p"
"bm5lckhUTUw9JzxkaXYgY2xhc3M9ImVtcHR5LXN0YXRlIj48ZGl2IGNsYXNzPSJlbXB0eS1pY28i"
"PuKbkzwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXRpdGxlIj5ObyBBdHRhY2sgQ2hhaW5zIFlldDwv"
"ZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXN1YiI+UnVuIG11bHRpcGxlIHNjYW5zIHRvIGRpc2NvdmVy"
"IGF0dGFjayBwYXRocy4gVGhlIGVuZ2luZSBjb25uZWN0cyB2dWxuZXJhYmlsaXRpZXMgaW50byBr"
"aWxsIGNoYWlucy48L2Rpdj48L2Rpdj4nOwogICAgICBiYWRnZS5jbGFzc05hbWU9J3RhYi1iYWRn"
"ZSc7CiAgICAgIHJldHVybjsKICAgIH0KCiAgICBiYWRnZS5jbGFzc05hbWU9J3RhYi1iYWRnZSBz"
"aG93IGItcmVkJzsKICAgIGJhZGdlLnRleHRDb250ZW50PWNoYWlucy5sZW5ndGg7CgogICAgdmFy"
"IGNyaXRDaGFpbnM9MCxoaWdoQ2hhaW5zPTAsdG90YWxDb3N0PScnOwogICAgY2hhaW5zLmZvckVh"
"Y2goZnVuY3Rpb24oYyl7aWYoYy5zZXZlcml0eT09PSdDUklUSUNBTCcpY3JpdENoYWlucysrO2lm"
"KGMuc2V2ZXJpdHk9PT0nSElHSCcpaGlnaENoYWlucysrfSk7CgogICAgdmFyIGg9Jyc7CiAgICAv"
"LyBTdW1tYXJ5IHN0YXRzCiAgICBoKz0nPGRpdiBjbGFzcz0iY2hhaW4tc3VtbWFyeSI+JzsKICAg"
"IGgrPSc8ZGl2IGNsYXNzPSJjaGFpbi1zdGF0Ij48ZGl2IGNsYXNzPSJjaGFpbi1zdGF0LW51bSIg"
"c3R5bGU9ImNvbG9yOnZhcigtLXJlZCkiPicrY2hhaW5zLmxlbmd0aCsnPC9kaXY+PGRpdiBjbGFz"
"cz0iY2hhaW4tc3RhdC1sYWJlbCI+QXR0YWNrIENoYWlucyBGb3VuZDwvZGl2PjwvZGl2Pic7CiAg"
"ICBoKz0nPGRpdiBjbGFzcz0iY2hhaW4tc3RhdCI+PGRpdiBjbGFzcz0iY2hhaW4tc3RhdC1udW0i"
"IHN0eWxlPSJjb2xvcjojZDkwNDI5Ij4nK2NyaXRDaGFpbnMrJzwvZGl2PjxkaXYgY2xhc3M9ImNo"
"YWluLXN0YXQtbGFiZWwiPkNyaXRpY2FsIENoYWluczwvZGl2PjwvZGl2Pic7CiAgICBoKz0nPGRp"
"diBjbGFzcz0iY2hhaW4tc3RhdCI+PGRpdiBjbGFzcz0iY2hhaW4tc3RhdC1udW0iIHN0eWxlPSJj"
"b2xvcjojZTg1ZDA0Ij4nK2hpZ2hDaGFpbnMrJzwvZGl2PjxkaXYgY2xhc3M9ImNoYWluLXN0YXQt"
"bGFiZWwiPkhpZ2ggQ2hhaW5zPC9kaXY+PC9kaXY+JzsKICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFp"
"bi1zdGF0Ij48ZGl2IGNsYXNzPSJjaGFpbi1zdGF0LW51bSIgc3R5bGU9ImNvbG9yOnZhcigtLXR4"
"LWRhcmspIj4nK2NoYWlucy5yZWR1Y2UoZnVuY3Rpb24oYSxjKXtyZXR1cm4gYStjLmNvbmZpcm1l"
"ZF9zdGVwc30sMCkrJzwvZGl2PjxkaXYgY2xhc3M9ImNoYWluLXN0YXQtbGFiZWwiPkNvbmZpcm1l"
"ZCBTdGVwczwvZGl2PjwvZGl2Pic7CiAgICBoKz0nPC9kaXY+JzsKCiAgICAvLyBBZHZhbmNlZCBy"
"ZXBvcnQgYnV0dG9uCiAgICBoKz0nPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2p1c3RpZnktY29u"
"dGVudDpzcGFjZS1iZXR3ZWVuO2FsaWduLWl0ZW1zOmNlbnRlcjttYXJnaW4tYm90dG9tOjE2cHgi"
"Pic7CiAgICBoKz0nPGRpdiBzdHlsZT0iZm9udC1mYW1pbHk6U3luZSxzYW5zLXNlcmlmO2ZvbnQt"
"c2l6ZToxOHB4O2ZvbnQtd2VpZ2h0OjgwMDtjb2xvcjp2YXIoLS10eC1kYXJrKSI+S2lsbCBDaGFp"
"biBBbmFseXNpczwvZGl2Pic7CiAgICBoKz0nPGJ1dHRvbiBjbGFzcz0iYnRuLWFkdi1yZXBvcnQi"
"IG9uY2xpY2s9ImRvd25sb2FkQWR2YW5jZWRSZXBvcnQoKSI+4qyHIERvd25sb2FkIEFkdmFuY2Vk"
"IFJlcG9ydDwvYnV0dG9uPic7CiAgICBoKz0nPC9kaXY+JzsKCiAgICAvLyBFYWNoIGNoYWluCiAg"
"ICBjaGFpbnMuZm9yRWFjaChmdW5jdGlvbihjLGlkeCl7CiAgICAgIGgrPSc8ZGl2IGNsYXNzPSJj"
"aGFpbi1jYXJkICcrYy5zZXZlcml0eSsnIiBzdHlsZT0iYW5pbWF0aW9uLWRlbGF5OicrKGlkeCow"
"LjA4KSsncyI+JzsKCiAgICAgIC8vIEhlYWRlcgogICAgICBoKz0nPGRpdiBjbGFzcz0iY2hhaW4t"
"aGVhZGVyIj48ZGl2Pic7CiAgICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFpbi1uYW1lIj4nK2MubmFt"
"ZSsnPC9kaXY+JzsKICAgICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLWtpbGxjaGFpbiI+JytjLmtp"
"bGxfY2hhaW4rJzwvZGl2Pic7CiAgICAgIGgrPSc8L2Rpdj48ZGl2IHN0eWxlPSJkaXNwbGF5OmZs"
"ZXg7Z2FwOjhweDthbGlnbi1pdGVtczpjZW50ZXIiPic7CiAgICAgIGgrPSc8c3BhbiBjbGFzcz0i"
"c2V2ICcrYy5zZXZlcml0eSsnIj4nK2Muc2V2ZXJpdHkrJzwvc3Bhbj4nOwogICAgICBoKz0nPHNw"
"YW4gY2xhc3M9ImNoYWluLWNvbmZpZGVuY2UgJysoYy5jb25maWRlbmNlPj03NT8naGlnaCc6J21l"
"ZCcpKyciPicrYy5jb25maWRlbmNlKyclIE1hdGNoPC9zcGFuPic7CiAgICAgIGgrPSc8L2Rpdj48"
"L2Rpdj4nOwoKICAgICAgLy8gS2lsbCBDaGFpbiBGbG93CiAgICAgIGgrPSc8ZGl2IGNsYXNzPSJj"
"aGFpbi1mbG93Ij4nOwogICAgICBjLnN0ZXBzLmZvckVhY2goZnVuY3Rpb24oc3RlcCxzaSl7CiAg"
"ICAgICAgaWYoc2k+MCl7CiAgICAgICAgICBoKz0nPGRpdiBjbGFzcz0iY2hhaW4tYXJyb3cgJyso"
"c3RlcC5zdGF0dXM9PT0nY29uZmlybWVkJz8nY29uZmlybWVkJzonJykrJyI+PC9kaXY+JzsKICAg"
"ICAgICB9CiAgICAgICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLXN0ZXAiPic7CiAgICAgICAgaCs9"
"JzxkaXYgY2xhc3M9ImNoYWluLXN0ZXAtZG90ICcrc3RlcC5zdGF0dXMrJyI+Jysoc3RlcC5zdGF0"
"dXM9PT0nY29uZmlybWVkJz8n4pyTJzonPycpKyc8L2Rpdj4nOwogICAgICAgIGgrPSc8ZGl2IGNs"
"YXNzPSJjaGFpbi1zdGVwLXBoYXNlIj4nK3N0ZXAucGhhc2UrJzwvZGl2Pic7CiAgICAgICAgaCs9"
"JzxkaXYgY2xhc3M9ImNoYWluLXN0ZXAtbGFiZWwiPicrc3RlcC5sYWJlbCsnPC9kaXY+JzsKICAg"
"ICAgICBoKz0nPC9kaXY+JzsKICAgICAgfSk7CiAgICAgIGgrPSc8L2Rpdj4nOwoKICAgICAgLy8g"
"SW1wYWN0CiAgICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFpbi1pbXBhY3QiPjxkaXYgY2xhc3M9ImNo"
"YWluLWltcGFjdC10aXRsZSI+4pqhIEFUVEFDSyBJTVBBQ1Q8L2Rpdj4nOwogICAgICBoKz0nPGRp"
"diBjbGFzcz0iY2hhaW4taW1wYWN0LXRleHQiPicrYy5pbXBhY3QrJzwvZGl2PjwvZGl2Pic7Cgog"
"ICAgICAvLyBCdXNpbmVzcyBJbXBhY3QgKyBDb3N0CiAgICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFp"
"bi1idXNpbmVzcyI+PGRpdiBjbGFzcz0iY2hhaW4tYnVzaW5lc3MtdGl0bGUiPvCfkrwgQlVTSU5F"
"U1MgSU1QQUNUPC9kaXY+JzsKICAgICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLWltcGFjdC10ZXh0"
"Ij4nK2MuYnVzaW5lc3NfaW1wYWN0Kyc8L2Rpdj4nOwogICAgICBoKz0nPGRpdiBjbGFzcz0iY2hh"
"aW4tY29zdCI+RXN0aW1hdGVkIENvc3Q6ICcrYy5jb3N0X2VzdGltYXRlKyc8L2Rpdj48L2Rpdj4n"
"OwoKICAgICAgLy8gRml4CiAgICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFpbi1maXgiPjxkaXYgY2xh"
"c3M9ImNoYWluLWZpeC10aXRsZSI+8J+boSBSRU1FRElBVElPTiBDT01NQU5EUzwvZGl2Pic7CiAg"
"ICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFpbi1maXgtY21kIj4nK2MuZml4Kyc8L2Rpdj48L2Rpdj4n"
"OwoKICAgICAgLy8gQ29tcGxpYW5jZQogICAgICBpZihjLmNvbXBsaWFuY2UgJiYgT2JqZWN0Lmtl"
"eXMoYy5jb21wbGlhbmNlKS5sZW5ndGgpewogICAgICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFpbi1j"
"b21wbGlhbmNlIj4nOwogICAgICAgIE9iamVjdC5rZXlzKGMuY29tcGxpYW5jZSkuZm9yRWFjaChm"
"dW5jdGlvbihmdyl7CiAgICAgICAgICBoKz0nPGRpdiBjbGFzcz0iY2hhaW4tY29tcC10YWciPicr"
"ZncrJzogJytjLmNvbXBsaWFuY2VbZnddKyc8L2Rpdj4nOwogICAgICAgIH0pOwogICAgICAgIGgr"
"PSc8L2Rpdj4nOwogICAgICB9CgogICAgICBoKz0nPC9kaXY+JzsKICAgIH0pOwoKICAgIGNvbnRh"
"aW5lci5pbm5lckhUTUw9aDsKICB9KS5jYXRjaChmdW5jdGlvbigpe30pOwp9CgovKiA9PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"CiAgIEFEVkFOQ0VEIFJFUE9SVCBET1dOTE9BRCAoMy1BdWRpZW5jZSkKICAgPT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpm"
"dW5jdGlvbiBkb3dubG9hZEFkdmFuY2VkUmVwb3J0KCl7CiAgZmV0Y2goJy9hZHZhbmNlZF9yZXBv"
"cnQnKS50aGVuKGZ1bmN0aW9uKHIpe3JldHVybiByLmpzb24oKX0pLnRoZW4oZnVuY3Rpb24ocnB0"
"KXsKICAgIGlmKHJwdC5lcnJvcil7bm90aWZ5KCdObyByZXBvcnQgZGF0YSB5ZXQuIFJ1biBzY2Fu"
"cyBmaXJzdC4nKTtyZXR1cm59CgogICAgdmFyIGNzcyA9ICdib2R5e2ZvbnQtZmFtaWx5OkhlbHZl"
"dGljYSxBcmlhbCxzYW5zLXNlcmlmO2NvbG9yOiMzYTNhNDQ7cGFkZGluZzo0MHB4O21heC13aWR0"
"aDoxMTAwcHg7bWFyZ2luOmF1dG87Zm9udC1zaXplOjEzcHg7bGluZS1oZWlnaHQ6MS42fScKICAg"
"ICAgKyAnaDF7Y29sb3I6I2U2Mzk0Njtmb250LXNpemU6MjhweDt0ZXh0LWFsaWduOmNlbnRlcjtt"
"YXJnaW4tYm90dG9tOjVweH0nCiAgICAgICsgJ2gye2NvbG9yOiNlNjM5NDY7Zm9udC1zaXplOjE2"
"cHg7Ym9yZGVyLWJvdHRvbToycHggc29saWQgI2U2Mzk0NjtwYWRkaW5nLWJvdHRvbTo2cHg7bWFy"
"Z2luLXRvcDozMHB4fScKICAgICAgKyAnaDN7Y29sb3I6IzBhMGEwYztmb250LXNpemU6MTNweDtt"
"YXJnaW4tdG9wOjE4cHh9JwogICAgICArICcubWV0YXt0ZXh0LWFsaWduOmNlbnRlcjtjb2xvcjoj"
"OGE4YTk2O2ZvbnQtc2l6ZToxMXB4O21hcmdpbi1ib3R0b206MzBweH0nCiAgICAgICsgJy5zY29y"
"ZS1ib3h7dGV4dC1hbGlnbjpjZW50ZXI7cGFkZGluZzozMHB4O2JvcmRlcjozcHggc29saWQgJyty"
"cHQucmlza19sZXZlbCsnO2JvcmRlci1yYWRpdXM6MTZweDttYXJnaW46MjBweCBhdXRvO21heC13"
"aWR0aDozMDBweH0nCiAgICAgICsgJy5zY29yZS1udW17Zm9udC1zaXplOjY0cHg7Zm9udC13ZWln"
"aHQ6OTAwO2NvbG9yOicrKCcjZDkwNDI5JykrJzt9JwogICAgICArICcuc2NvcmUtbGFiZWx7Zm9u"
"dC1zaXplOjE4cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOiMzYTNhNDR9JwogICAgICArICcuY2Fy"
"ZHtib3JkZXItbGVmdDo0cHggc29saWQgI2Q5MDQyOTtwYWRkaW5nOjEycHggMTZweDttYXJnaW46"
"MTBweCAwO2JhY2tncm91bmQ6I2Y3ZjdmODtib3JkZXItcmFkaXVzOjhweH0nCiAgICAgICsgJy5j"
"YXJkLkhJR0h7Ym9yZGVyLWxlZnQtY29sb3I6I2U4NWQwNH0uY2FyZC5NRURJVU17Ym9yZGVyLWxl"
"ZnQtY29sb3I6I2UwOWYzZX0uY2FyZC5MT1d7Ym9yZGVyLWxlZnQtY29sb3I6IzJkNmE0Zn0nCiAg"
"ICAgICsgJy5maXh7YmFja2dyb3VuZDojZjBmZGY0O2JvcmRlcjoxcHggc29saWQgI2JiZjdkMDtw"
"YWRkaW5nOjEycHg7Ym9yZGVyLXJhZGl1czo4cHg7bWFyZ2luOjhweCAwO2ZvbnQtZmFtaWx5Om1v"
"bm9zcGFjZTtmb250LXNpemU6MTFweDt3aGl0ZS1zcGFjZTpwcmUtd3JhcH0nCiAgICAgICsgJy5j"
"b21we2Rpc3BsYXk6aW5saW5lLWJsb2NrO2JhY2tncm91bmQ6I2YxZjVmOTtib3JkZXI6MXB4IHNv"
"bGlkICNlMmU4ZjA7cGFkZGluZzozcHggOHB4O2JvcmRlci1yYWRpdXM6NHB4O2ZvbnQtc2l6ZTox"
"MHB4O21hcmdpbjoycHh9JwogICAgICArICd0YWJsZXt3aWR0aDoxMDAlO2JvcmRlci1jb2xsYXBz"
"ZTpjb2xsYXBzZTttYXJnaW46MTBweCAwfXRoLHRke3BhZGRpbmc6NnB4IDEwcHg7Ym9yZGVyLWJv"
"dHRvbToxcHggc29saWQgI2VjZWNlZjt0ZXh0LWFsaWduOmxlZnQ7Zm9udC1zaXplOjExcHh9dGh7"
"YmFja2dyb3VuZDojZjdmN2Y4O2ZvbnQtd2VpZ2h0OjcwMH0nCiAgICAgICsgJy5zZXZ7cGFkZGlu"
"ZzoycHggOHB4O2JvcmRlci1yYWRpdXM6MTBweDtmb250LXNpemU6MTBweDtmb250LXdlaWdodDo3"
"MDB9JwogICAgICArICcuc2V2LkNSSVRJQ0FMe2JhY2tncm91bmQ6I2ZkZDtjb2xvcjojZDkwNDI5"
"fS5zZXYuSElHSHtiYWNrZ3JvdW5kOiNmZWQ7Y29sb3I6I2U4NWQwNH0uc2V2Lk1FRElVTXtiYWNr"
"Z3JvdW5kOiNmZmQ7Y29sb3I6I2I4ODYwYn0uc2V2LkxPV3tiYWNrZ3JvdW5kOiNkZmQ7Y29sb3I6"
"IzJkNmE0Zn0nCiAgICAgICsgJy5zZWN0aW9ue3BhZ2UtYnJlYWstaW5zaWRlOmF2b2lkfScKICAg"
"ICAgKyAnQG1lZGlhIHByaW50e2JvZHl7cGFkZGluZzoyMHB4fX0nOwoKICAgIHZhciBiID0gJzwh"
"RE9DVFlQRSBodG1sPjxodG1sPjxoZWFkPjxtZXRhIGNoYXJzZXQ9IlVURi04Ij48dGl0bGU+SEFS"
"U0hBIHY3LjAgQWR2YW5jZWQgVkFQVCBSZXBvcnQ8L3RpdGxlPjxzdHlsZT4nK2NzcysnPC9zdHls"
"ZT48L2hlYWQ+PGJvZHk+JzsKCiAgICAvLyBIRUFERVIKICAgIGIgKz0gJzxoMT5IQVJTSEEgdjcu"
"MDwvaDE+JzsKICAgIGIgKz0gJzxkaXYgc3R5bGU9InRleHQtYWxpZ246Y2VudGVyO2ZvbnQtc2l6"
"ZToxNnB4O2NvbG9yOiM4YThhOTY7bWFyZ2luLWJvdHRvbTo1cHgiPkFEVkFOQ0VEIFZBUFQgUkVQ"
"T1JUPC9kaXY+JzsKICAgIGIgKz0gJzxkaXYgY2xhc3M9Im1ldGEiPlRhcmdldDogJytycHQudGFy"
"Z2V0KycgfCBHZW5lcmF0ZWQ6ICcrcnB0LmdlbmVyYXRlZCsnPC9kaXY+JzsKCiAgICAvLyBSSVNL"
"IFNDT1JFCiAgICBiICs9ICc8ZGl2IGNsYXNzPSJzY29yZS1ib3giPjxkaXYgY2xhc3M9InNjb3Jl"
"LW51bSI+JytycHQucmlza19zY29yZSsnPC9kaXY+JzsKICAgIGIgKz0gJzxkaXYgY2xhc3M9InNj"
"b3JlLWxhYmVsIj4nK3JwdC5yaXNrX2xldmVsKycgUklTSzwvZGl2PjwvZGl2Pic7CgogICAgLy8g"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgICAvLyBTRUNUSU9O"
"IDE6IEVYRUNVVElWRSBTVU1NQVJZCiAgICAvLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT0KICAgIGIgKz0gJzxoMj7wn5OLIFNFQ1RJT04gMTogRVhFQ1VUSVZFIFNV"
"TU1BUlk8L2gyPic7CiAgICBiICs9ICc8ZGl2IHN0eWxlPSJiYWNrZ3JvdW5kOiNmZmY4Zjg7Ym9y"
"ZGVyOjFweCBzb2xpZCAjZmVjYWNhO3BhZGRpbmc6MTZweDtib3JkZXItcmFkaXVzOjhweDttYXJn"
"aW46MTJweCAwIj4nOwogICAgYiArPSAnPHAgc3R5bGU9ImZvbnQtc2l6ZToxNHB4O2ZvbnQtd2Vp"
"Z2h0OjYwMCI+JytycHQuZXhlY3V0aXZlLmhlYWRsaW5lKyc8L3A+JzsKICAgIGIgKz0gJzxwPicr"
"cnB0LmV4ZWN1dGl2ZS5yaXNrX3N1bW1hcnkrJzwvcD4nOwogICAgYiArPSAnPC9kaXY+JzsKCiAg"
"ICBiICs9ICc8aDM+S2V5IEJ1c2luZXNzIFJpc2tzPC9oMz4nOwogICAgaWYocnB0LmV4ZWN1dGl2"
"ZS5idXNpbmVzc19yaXNrcy5sZW5ndGgpewogICAgICBycHQuZXhlY3V0aXZlLmJ1c2luZXNzX3Jp"
"c2tzLmZvckVhY2goZnVuY3Rpb24ocixpKXsKICAgICAgICBiICs9ICc8ZGl2IGNsYXNzPSJjYXJk"
"IENSSVRJQ0FMIj48Yj5SaXNrICcrKGkrMSkrJzo8L2I+ICcrcisnPC9kaXY+JzsKICAgICAgfSk7"
"CiAgICB9CgogICAgYiArPSAnPGgzPkNvc3QgRXhwb3N1cmU8L2gzPic7CiAgICBpZihycHQuZXhl"
"Y3V0aXZlLmNvc3RfZXhwb3N1cmUubGVuZ3RoKXsKICAgICAgcnB0LmV4ZWN1dGl2ZS5jb3N0X2V4"
"cG9zdXJlLmZvckVhY2goZnVuY3Rpb24oYyxpKXsKICAgICAgICBiICs9ICc8ZGl2IGNsYXNzPSJj"
"YXJkIEhJR0giPjxiPkNoYWluICcrKGkrMSkrJzo8L2I+ICcrYysnPC9kaXY+JzsKICAgICAgfSk7"
"CiAgICB9CgogICAgYiArPSAnPGgzPlByaW9yaXR5IEFjdGlvbnM8L2gzPic7CiAgICBiICs9ICc8"
"dGFibGU+PHRyPjx0aD4jPC90aD48dGg+QXR0YWNrIENoYWluPC90aD48dGg+UHJpb3JpdHk8L3Ro"
"Pjx0aD5JbW1lZGlhdGUgQWN0aW9uPC90aD48L3RyPic7CiAgICBycHQuZXhlY3V0aXZlLnRvcF9y"
"ZWNvbW1lbmRhdGlvbnMuZm9yRWFjaChmdW5jdGlvbihyLGkpewogICAgICBiICs9ICc8dHI+PHRk"
"PicrKGkrMSkrJzwvdGQ+PHRkPicrci5jaGFpbisnPC90ZD48dGQ+PHNwYW4gY2xhc3M9InNldiAn"
"K3IucHJpb3JpdHkrJyI+JytyLnByaW9yaXR5Kyc8L3NwYW4+PC90ZD48dGQ+JytyLmFjdGlvbisn"
"PC90ZD48L3RyPic7CiAgICB9KTsKICAgIGIgKz0gJzwvdGFibGU+JzsKCiAgICAvLyA9PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgIC8vIFNFQ1RJT04gMjogVEVD"
"SE5JQ0FMIEZJTkRJTkdTCiAgICAvLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT0KICAgIGIgKz0gJzxoMj7wn5SnIFNFQ1RJT04gMjogVEVDSE5JQ0FMIEZJTkRJTkdT"
"PC9oMj4nOwoKICAgIC8vIEF0dGFjayBDaGFpbnMKICAgIHZhciBjaGFpbnMgPSBycHQudGVjaG5p"
"Y2FsLmNoYWlucyB8fCBbXTsKICAgIGlmKGNoYWlucy5sZW5ndGgpewogICAgICBiICs9ICc8aDM+"
"QXR0YWNrIENoYWlucyAoJytjaGFpbnMubGVuZ3RoKycgZm91bmQpPC9oMz4nOwogICAgICBjaGFp"
"bnMuZm9yRWFjaChmdW5jdGlvbihjLGkpewogICAgICAgIGIgKz0gJzxkaXYgY2xhc3M9InNlY3Rp"
"b24iPjxkaXYgY2xhc3M9ImNhcmQgJytjLnNldmVyaXR5KyciPjxiPkNoYWluICcrKGkrMSkrJzog"
"JytjLm5hbWUrJzwvYj4gPHNwYW4gY2xhc3M9InNldiAnK2Muc2V2ZXJpdHkrJyI+JytjLnNldmVy"
"aXR5Kyc8L3NwYW4+ICgnK2MuY29uZmlkZW5jZSsnJSBjb25maWRlbmNlKSc7CiAgICAgICAgYiAr"
"PSAnPGJyPjxzbWFsbCBzdHlsZT0iY29sb3I6IzhhOGE5NiI+S2lsbCBDaGFpbjogJytjLmtpbGxf"
"Y2hhaW4rJzwvc21hbGw+JzsKICAgICAgICBiICs9ICc8YnI+PGJyPjxiPkltcGFjdDo8L2I+ICcr"
"Yy5pbXBhY3Q7CiAgICAgICAgYiArPSAnPGJyPjxicj48Yj5TdGVwczo8L2I+PG9sIHN0eWxlPSJt"
"YXJnaW46NnB4IDAiPic7CiAgICAgICAgYy5zdGVwcy5mb3JFYWNoKGZ1bmN0aW9uKHMpewogICAg"
"ICAgICAgdmFyIGljb24gPSBzLnN0YXR1cz09PSdjb25maXJtZWQnID8gJ+KchScgOiAn4p2TJzsK"
"ICAgICAgICAgIGIgKz0gJzxsaT4nK2ljb24rJyBbJytzLnBoYXNlKyddICcrcy5sYWJlbCsnPC9s"
"aT4nOwogICAgICAgIH0pOwogICAgICAgIGIgKz0gJzwvb2w+JzsKICAgICAgICBiICs9ICc8ZGl2"
"IGNsYXNzPSJmaXgiPicrYy5maXgrJzwvZGl2Pic7CiAgICAgICAgYiArPSAnPC9kaXY+PC9kaXY+"
"JzsKICAgICAgfSk7CiAgICB9CgogICAgLy8gT3BlbiBQb3J0cwogICAgdmFyIHBvcnRzID0gcnB0"
"LnRlY2huaWNhbC5wb3J0cyB8fCBbXTsKICAgIGlmKHBvcnRzLmxlbmd0aCl7CiAgICAgIGIgKz0g"
"JzxoMz5PcGVuIFBvcnRzICgnK3BvcnRzLmxlbmd0aCsnKTwvaDM+JzsKICAgICAgYiArPSAnPHRh"
"YmxlPjx0cj48dGg+UG9ydDwvdGg+PHRoPlNlcnZpY2U8L3RoPjx0aD5SaXNrPC90aD48dGg+RGVz"
"Y3JpcHRpb248L3RoPjx0aD5SZW1lZGlhdGlvbjwvdGg+PC90cj4nOwogICAgICBwb3J0cy5mb3JF"
"YWNoKGZ1bmN0aW9uKHApewogICAgICAgIGIgKz0gJzx0cj48dGQ+JytwLnBvcnQrJy8nK3AucHJv"
"dG8rJzwvdGQ+PHRkPicrcC5zZXJ2aWNlKyc8L3RkPjx0ZD48c3BhbiBjbGFzcz0ic2V2ICcrcC5z"
"ZXZlcml0eSsnIj4nK3Auc2V2ZXJpdHkrJzwvc3Bhbj48L3RkPjx0ZD4nK3AuZGVzYysnPC90ZD48"
"dGQgc3R5bGU9ImZvbnQtc2l6ZToxMHB4Ij4nK3AuZml4Kyc8L3RkPjwvdHI+JzsKICAgICAgfSk7"
"CiAgICAgIGIgKz0gJzwvdGFibGU+JzsKICAgIH0KCiAgICAvLyBUaHJlYXRzCiAgICB2YXIgdGhy"
"ZWF0cyA9IHJwdC50ZWNobmljYWwudGhyZWF0cyB8fCBbXTsKICAgIGlmKHRocmVhdHMubGVuZ3Ro"
"KXsKICAgICAgYiArPSAnPGgzPlZ1bG5lcmFiaWxpdGllcyAoJyt0aHJlYXRzLmxlbmd0aCsnKTwv"
"aDM+JzsKICAgICAgdGhyZWF0cy5mb3JFYWNoKGZ1bmN0aW9uKHQsaSl7CiAgICAgICAgYiArPSAn"
"PGRpdiBjbGFzcz0iY2FyZCAnK3Quc2V2ZXJpdHkrJyI+PGI+JysoaSsxKSsnLiAnK3QubmFtZSsn"
"PC9iPiA8c3BhbiBjbGFzcz0ic2V2ICcrdC5zZXZlcml0eSsnIj4nK3Quc2V2ZXJpdHkrJzwvc3Bh"
"bj4nOwogICAgICAgIGIgKz0gJzxicj4nK3QuZGVzYzsKICAgICAgICBiICs9ICc8ZGl2IGNsYXNz"
"PSJmaXgiPkZJWDogJyt0LmZpeCsnPC9kaXY+PC9kaXY+JzsKICAgICAgfSk7CiAgICB9CgogICAg"
"Ly8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgICAvLyBTRUNU"
"SU9OIDM6IENPTVBMSUFOQ0UgTUFQUElORwogICAgLy8gPT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09CiAgICBiICs9ICc8aDI+8J+TnCBTRUNUSU9OIDM6IENPTVBMSUFO"
"Q0UgTUFQUElORzwvaDI+JzsKICAgIHZhciBmdyA9IHJwdC5jb21wbGlhbmNlLmZyYW1ld29ya3Mg"
"fHwge307CiAgICB2YXIgZndLZXlzID0gT2JqZWN0LmtleXMoZncpOwogICAgaWYoZndLZXlzLmxl"
"bmd0aCl7CiAgICAgIGZ3S2V5cy5mb3JFYWNoKGZ1bmN0aW9uKGZrKXsKICAgICAgICBiICs9ICc8"
"aDM+JytmaysnPC9oMz4nOwogICAgICAgIGIgKz0gJzx0YWJsZT48dHI+PHRoPkNvbnRyb2w8L3Ro"
"Pjx0aD5Jc3N1ZSBGb3VuZDwvdGg+PHRoPlNldmVyaXR5PC90aD48L3RyPic7CiAgICAgICAgZndb"
"ZmtdLmZvckVhY2goZnVuY3Rpb24oaXRlbSl7CiAgICAgICAgICBiICs9ICc8dHI+PHRkPjxzcGFu"
"IGNsYXNzPSJjb21wIj4nK2l0ZW0uY29udHJvbCsnPC9zcGFuPjwvdGQ+PHRkPicraXRlbS5pc3N1"
"ZSsnPC90ZD48dGQ+PHNwYW4gY2xhc3M9InNldiAnK2l0ZW0uc2V2ZXJpdHkrJyI+JytpdGVtLnNl"
"dmVyaXR5Kyc8L3NwYW4+PC90ZD48L3RyPic7CiAgICAgICAgfSk7CiAgICAgICAgYiArPSAnPC90"
"YWJsZT4nOwogICAgICB9KTsKICAgIH0gZWxzZSB7CiAgICAgIGIgKz0gJzxwIHN0eWxlPSJjb2xv"
"cjojOGE4YTk2Ij5ObyBjb21wbGlhbmNlIGRhdGEgYXZhaWxhYmxlIHlldC4gUnVuIG1vcmUgc2Nh"
"bnMgdG8gZ2VuZXJhdGUgY29tcGxpYW5jZSBtYXBwaW5nLjwvcD4nOwogICAgfQoKICAgIC8vIEZP"
"T1RFUgogICAgYiArPSAnPGRpdiBzdHlsZT0ibWFyZ2luLXRvcDo0MHB4O3BhZGRpbmctdG9wOjIw"
"cHg7Ym9yZGVyLXRvcDoycHggc29saWQgI2VjZWNlZjt0ZXh0LWFsaWduOmNlbnRlcjtjb2xvcjoj"
"OGE4YTk2O2ZvbnQtc2l6ZToxMHB4Ij4nOwogICAgYiArPSAnSEFSU0hBIHY3LjAgVkFQVCBTdWl0"
"ZSDigJQgQWR2YW5jZWQgU2VjdXJpdHkgUmVwb3J0PGJyPic7CiAgICBiICs9ICdHZW5lcmF0ZWQ6"
"ICcrcnB0LmdlbmVyYXRlZCsnIHwgQ2xhc3NpZmljYXRpb246IENPTkZJREVOVElBTCc7CiAgICBi"
"ICs9ICc8L2Rpdj4nOwoKICAgIGIgKz0gJzwvYm9keT48L2h0bWw+JzsKCiAgICB2YXIgYSA9IGRv"
"Y3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2EnKTsKICAgIGEuaHJlZiA9IFVSTC5jcmVhdGVPYmplY3RV"
"UkwobmV3IEJsb2IoW2JdLHt0eXBlOid0ZXh0L2h0bWwnfSkpOwogICAgYS5kb3dubG9hZCA9ICdI"
"QVJTSEFfdjdfQWR2YW5jZWRfVkFQVF9SZXBvcnQuaHRtbCc7CiAgICBhLmNsaWNrKCk7CiAgICBu"
"b3RpZnkoJ0FkdmFuY2VkIHJlcG9ydCBkb3dubG9hZGVkIScpOwogIH0pLmNhdGNoKGZ1bmN0aW9u"
"KGUpe25vdGlmeSgnRXJyb3IgZ2VuZXJhdGluZyByZXBvcnQ6ICcrZS5tZXNzYWdlKX0pOwp9Cgov"
"KiBSZWZyZXNoIGNoYWlucyB3aGVuIHN3aXRjaGluZyB0byB0aGUgdGFiICovCnZhciBfb3JpZ1N3"
"aXRjaFRhYiA9IHN3aXRjaFRhYjsKc3dpdGNoVGFiID0gZnVuY3Rpb24odGFiLCBidG4pIHsKICBf"
"b3JpZ1N3aXRjaFRhYih0YWIsIGJ0bik7CiAgaWYodGFiID09PSAnY2hhaW5zJykgcmVmcmVzaEF0"
"dGFja0NoYWlucygpOwp9OwoKLyogQWxzbyByZWZyZXNoIGFmdGVyIGVhY2ggc2NhbiBjb21wbGV0"
"ZXMgKi8KdmFyIGNoYWluUG9sbENvdW50ID0gMDsKc2V0SW50ZXJ2YWwoZnVuY3Rpb24oKXsKICBp"
"ZihsYXN0UGhhc2UgPT09ICdjb21wbGV0ZScgJiYgY2hhaW5Qb2xsQ291bnQgPCAzKXsKICAgIHJl"
"ZnJlc2hBdHRhY2tDaGFpbnMoKTsKICAgIGNoYWluUG9sbENvdW50Kys7CiAgfQogIGlmKGxhc3RQ"
"aGFzZSAhPT0gJ2NvbXBsZXRlJykgY2hhaW5Qb2xsQ291bnQgPSAwOwp9LCAyMDAwKTsKCi8qIEtF"
"WUJPQVJEIFNIT1JUQ1VUUyAqLwpkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdrZXlkb3duJyxm"
"dW5jdGlvbihlKXsKICBpZihlLmN0cmxLZXkmJmUua2V5PT09Jy8nKXtlLnByZXZlbnREZWZhdWx0"
"KCk7ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Rvb2wtc2VhcmNoJykuZm9jdXMoKX0KfSk7Cjwv"
"c2NyaXB0PgoKPC9ib2R5Pgo8L2h0bWw+Cg=="
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
