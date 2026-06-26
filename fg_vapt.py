from flask import Flask, request, jsonify, send_file, Response
from gtts import gTTS
import subprocess, datetime, socket, os, random, re, json

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
        d = requests.get("https://api.open-meteo.com/v1/forecast?latitude=17.3850&longitude=78.4867&current_weather=true", timeout=5).json()["current_weather"]
        return "Location: Hyderabad\nTemp: "+str(d["temperature"])+"C\nWind: "+str(d["windspeed"])+" km/h"
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
    if any(w in m for w in ["hello","hi","hey","yo","sup"]): return get_greeting() + " FG! FG AI v7.0 online. Web + Network + Infra VAPT armed and ready!"
    if any(w in m for w in ["bye","goodbye","see you","later"]): return "Stay safe FG! FG AI standing by. 🛡️"
    if any(w in m for w in ["thanks","thank you","thx"]): return "You're welcome FG! Always here to help with your security assessments."

    # --- Identity ---
    if any(p in m for p in ["who are you","your name","what are you","about you"]): return "I am FG AI v7.0 — a comprehensive VAPT (Vulnerability Assessment & Penetration Testing) suite. I cover Web, Network, and Infrastructure security testing with 30+ integrated tools. Built by FG!"
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
        return "FG AI v7.0 can help with: 🔍 Run 30+ VAPT scans (sidebar tools) | 📊 Risk Analysis & Threat Graphs | 💬 Ask me about any security concept — SQLi, XSS, CVEs, OWASP, encryption, network attacks, best practices | 📄 Generate VAPT reports | 🛡 Get remediation advice for any vulnerability. Try asking: 'What is SQL injection?', 'How to prevent XSS?', 'Explain OWASP Top 10', 'What is CVSS?'"

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
        "weather":       (get_weather,                   "system",  "Weather retrieved for Hyderabad FG"),
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


_HTML_B64 = (
"PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04"
"Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlh"
"bC1zY2FsZT0xLjAiPgo8dGl0bGU+SEFSU0hBIOKAlCBWQVBUIENvbW1hbmQgU3VpdGU8L3RpdGxlPgo8"
"c2NyaXB0IHNyYz0iaHR0cHM6Ly9jZG5qcy5jbG91ZGZsYXJlLmNvbS9hamF4L2xpYnMvQ2hhcnQuanMv"
"NC40LjEvY2hhcnQudW1kLm1pbi5qcyI+PC9zY3JpcHQ+CjxsaW5rIGhyZWY9Imh0dHBzOi8vZm9udHMu"
"Z29vZ2xlYXBpcy5jb20vY3NzMj9mYW1pbHk9T3V0Zml0OndnaHRAMzAwOzQwMDs1MDA7NjAwOzcwMDs4"
"MDA7OTAwJmZhbWlseT1JQk0rUGxleCtNb25vOndnaHRAMzAwOzQwMDs1MDA7NjAwOzcwMCZmYW1pbHk9"
"U3luZTp3Z2h0QDQwMDs1MDA7NjAwOzcwMDs4MDAmZGlzcGxheT1zd2FwIiByZWw9InN0eWxlc2hlZXQi"
"Pgo8c3R5bGU+Ci8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT0KICAgSEFSU0hBIHY3LjAg4oCUIENyb3dkU3RyaWtlLUluc3BpcmVkIFZB"
"UFQgRGFzaGJvYXJkCiAgIFBhbGV0dGU6IE1hdHRlIEJsYWNrIMK3IFB1cmUgV2hpdGUgwrcgU2lnbmFs"
"IFJlZAogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09ICovCiosKjo6YmVmb3JlLCo6OmFmdGVye21hcmdpbjowO3BhZGRpbmc6MDtib3gt"
"c2l6aW5nOmJvcmRlci1ib3h9Cgo6cm9vdHsKICAvKiBCTEFDSyBTUEVDVFJVTSAqLwogIC0tYmxhY2s6"
"IzBhMGEwYzsKICAtLWJsYWNrLTI6IzExMTExNTsKICAtLWJsYWNrLTM6IzE4MTgxYzsKICAtLWJsYWNr"
"LTQ6IzFlMWUyNDsKICAtLWJsYWNrLTU6IzI4MjgyZjsKICAvKiBXSElURSBTUEVDVFJVTSAqLwogIC0t"
"d2hpdGU6I2ZmZmZmZjsKICAtLXdoaXRlLTI6I2Y3ZjdmODsKICAtLXdoaXRlLTM6I2VjZWNlZjsKICAt"
"LXdoaXRlLTQ6I2RkZGRlMjsKICAtLXdoaXRlLTU6I2M4YzhkMDsKICAvKiBSRUQg4oCUIFRIRSBJREVO"
"VElUWSAqLwogIC0tcmVkOiNlNjM5NDY7CiAgLS1yZWQtZGFyazojYzExMjFmOwogIC0tcmVkLWxpZ2h0"
"OiNmZjZiNmI7CiAgLS1yZWQtZ2xvdzpyZ2JhKDIzMCw1Nyw3MCwwLjM1KTsKICAtLXJlZC1kaW06cmdi"
"YSgyMzAsNTcsNzAsMC4wOCk7CiAgLS1yZWQtYm9yZGVyOnJnYmEoMjMwLDU3LDcwLDAuMik7CiAgLyog"
"U0VWRVJJVFkgKG9uIHdoaXRlKSAqLwogIC0tc2V2LWNyaXQ6I2Q5MDQyOTsKICAtLXNldi1jcml0LWJn"
"OnJnYmEoMjE3LDQsNDEsMC4wNik7CiAgLS1zZXYtY3JpdC1ib3JkZXI6cmdiYSgyMTcsNCw0MSwwLjE4"
"KTsKICAtLXNldi1oaWdoOiNlODVkMDQ7CiAgLS1zZXYtaGlnaC1iZzpyZ2JhKDIzMiw5Myw0LDAuMDYp"
"OwogIC0tc2V2LWhpZ2gtYm9yZGVyOnJnYmEoMjMyLDkzLDQsMC4xOCk7CiAgLS1zZXYtbWVkOiNlMDlm"
"M2U7CiAgLS1zZXYtbWVkLWJnOnJnYmEoMjI0LDE1OSw2MiwwLjA4KTsKICAtLXNldi1tZWQtYm9yZGVy"
"OnJnYmEoMjI0LDE1OSw2MiwwLjIpOwogIC0tc2V2LWxvdzojMmQ2YTRmOwogIC0tc2V2LWxvdy1iZzpy"
"Z2JhKDQ1LDEwNiw3OSwwLjA2KTsKICAtLXNldi1sb3ctYm9yZGVyOnJnYmEoNDUsMTA2LDc5LDAuMTgp"
"OwogIC8qIFRFWFQgKi8KICAtLXR4LWRhcms6IzBhMGEwYzsKICAtLXR4LWJvZHk6IzNhM2E0NDsKICAt"
"LXR4LW11dGVkOiM4YThhOTY7CiAgLS10eC1mYWludDojYjBiMGJhOwogIC0tdHgtb24tZGFyazojZjBm"
"MGYyOwogIC0tdHgtb24tZGFyay1tdXRlZDojOGE4YTk2OwogIC8qIExBWU9VVCAqLwogIC0tc2lkZWJh"
"ci13OjIzMHB4OwogIC0taGVhZGVyLWg6NjBweDsKICAtLXJhZGl1czo4cHg7CiAgLS1yYWRpdXMtbGc6"
"MTRweDsKICAtLXJhZGl1cy14bDoyMHB4Owp9CgpodG1sLGJvZHl7CiAgaGVpZ2h0OjEwMCU7b3ZlcmZs"
"b3c6aGlkZGVuOwogIGZvbnQtZmFtaWx5OidPdXRmaXQnLHN5c3RlbS11aSxzYW5zLXNlcmlmOwogIGJh"
"Y2tncm91bmQ6dmFyKC0td2hpdGUtMik7Y29sb3I6dmFyKC0tdHgtYm9keSk7CiAgZm9udC1zaXplOjEz"
"cHg7bGluZS1oZWlnaHQ6MS41OwogIC13ZWJraXQtZm9udC1zbW9vdGhpbmc6YW50aWFsaWFzZWQ7Cn0K"
"Ci8qIFNDUk9MTEJBUiDigJQgdGhpbiwgZGFyayAqLwo6Oi13ZWJraXQtc2Nyb2xsYmFye3dpZHRoOjVw"
"eDtoZWlnaHQ6NXB4fQo6Oi13ZWJraXQtc2Nyb2xsYmFyLXRyYWNre2JhY2tncm91bmQ6dHJhbnNwYXJl"
"bnR9Cjo6LXdlYmtpdC1zY3JvbGxiYXItdGh1bWJ7YmFja2dyb3VuZDp2YXIoLS13aGl0ZS00KTtib3Jk"
"ZXItcmFkaXVzOjEwcHh9Ci5zaWRlYmFyIDo6LXdlYmtpdC1zY3JvbGxiYXItdGh1bWJ7YmFja2dyb3Vu"
"ZDp2YXIoLS1ibGFjay01KX0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgQU5JTUFUSU9OUwogICA9PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCkBrZXlmcmFt"
"ZXMgZmFkZVVwe2Zyb217b3BhY2l0eTowO3RyYW5zZm9ybTp0cmFuc2xhdGVZKDE2cHgpfXRve29wYWNp"
"dHk6MTt0cmFuc2Zvcm06bm9uZX19CkBrZXlmcmFtZXMgZmFkZUlue2Zyb217b3BhY2l0eTowfXRve29w"
"YWNpdHk6MX19CkBrZXlmcmFtZXMgc2xpZGVJbkxlZnR7ZnJvbXtvcGFjaXR5OjA7dHJhbnNmb3JtOnRy"
"YW5zbGF0ZVgoLTIwcHgpfXRve29wYWNpdHk6MTt0cmFuc2Zvcm06bm9uZX19CkBrZXlmcmFtZXMgcHVs"
"c2V7MCUsMTAwJXtvcGFjaXR5OjF9NTAle29wYWNpdHk6LjR9fQpAa2V5ZnJhbWVzIHNjYW5saW5lezAl"
"e3RvcDotMnB4fTEwMCV7dG9wOjEwMCV9fQpAa2V5ZnJhbWVzIGdsb3d7MCUsMTAwJXtib3gtc2hhZG93"
"OjAgMCA4cHggdmFyKC0tcmVkLWdsb3cpfTUwJXtib3gtc2hhZG93OjAgMCAyMHB4IHZhcigtLXJlZC1n"
"bG93KSwwIDAgNDBweCByZ2JhKDIzMCw1Nyw3MCwwLjE1KX19CkBrZXlmcmFtZXMgc2hpbW1lcnswJXti"
"YWNrZ3JvdW5kLXBvc2l0aW9uOjIwMCUgMH0xMDAle2JhY2tncm91bmQtcG9zaXRpb246LTIwMCUgMH19"
"CkBrZXlmcmFtZXMgc3Bpbnt0b3t0cmFuc2Zvcm06cm90YXRlKDM2MGRlZyl9fQpAa2V5ZnJhbWVzIGJv"
"cmRlckdsb3d7MCUsMTAwJXtib3JkZXItY29sb3I6cmdiYSgyMzAsNTcsNzAsMC4xNSl9NTAle2JvcmRl"
"ci1jb2xvcjpyZ2JhKDIzMCw1Nyw3MCwwLjQpfX0KQGtleWZyYW1lcyB0eXBld3JpdGVye2Zyb217d2lk"
"dGg6MH10b3t3aWR0aDoxMDAlfX0KQGtleWZyYW1lcyBncmlkUHVsc2V7MCUsMTAwJXtvcGFjaXR5Oi4w"
"M301MCV7b3BhY2l0eTouMDZ9fQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBBUFAgTEFZT1VUCiAgID09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KLmFwcHtk"
"aXNwbGF5OmZsZXg7aGVpZ2h0OjEwMHZoO3dpZHRoOjEwMHZ3fQoKLyogPT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBTSURFQkFSIOKA"
"lCBNQVRURSBCTEFDSwogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09ICovCi5zaWRlYmFyewogIHdpZHRoOnZhcigtLXNpZGViYXItdyk7"
"bWluLXdpZHRoOnZhcigtLXNpZGViYXItdyk7CiAgYmFja2dyb3VuZDp2YXIoLS1ibGFjayk7CiAgZGlz"
"cGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjsKICBvdmVyZmxvdzpoaWRkZW47CiAgcG9zaXRp"
"b246cmVsYXRpdmU7CiAgei1pbmRleDoxMDsKfQovKiBTdWJ0bGUgZ3JpZCBwYXR0ZXJuIG9uIHNpZGVi"
"YXIgKi8KLnNpZGViYXI6OmJlZm9yZXsKICBjb250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRlO2luc2V0"
"OjA7CiAgYmFja2dyb3VuZC1pbWFnZToKICAgIGxpbmVhci1ncmFkaWVudChyZ2JhKDIzMCw1Nyw3MCww"
"LjAzKSAxcHgsdHJhbnNwYXJlbnQgMXB4KSwKICAgIGxpbmVhci1ncmFkaWVudCg5MGRlZyxyZ2JhKDIz"
"MCw1Nyw3MCwwLjAzKSAxcHgsdHJhbnNwYXJlbnQgMXB4KTsKICBiYWNrZ3JvdW5kLXNpemU6MjRweCAy"
"NHB4OwogIGFuaW1hdGlvbjpncmlkUHVsc2UgNHMgZWFzZSBpbmZpbml0ZTsKICBwb2ludGVyLWV2ZW50"
"czpub25lOwp9Cgouc2lkZWJhci1zY3JvbGx7ZmxleDoxO292ZXJmbG93LXk6YXV0bztwb3NpdGlvbjpy"
"ZWxhdGl2ZTt6LWluZGV4OjF9CgovKiBMT0dPICovCi5zLWxvZ297CiAgcGFkZGluZzoxOHB4IDIwcHg7"
"ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTJweDsKICBib3JkZXItYm90dG9tOjFw"
"eCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMDYpOwogIGFuaW1hdGlvbjpmYWRlSW4gLjZzIGVhc2U7"
"Cn0KLnMtbG9nby1tYXJrewogIHdpZHRoOjM2cHg7aGVpZ2h0OjM2cHg7Ym9yZGVyLXJhZGl1czp2YXIo"
"LS1yYWRpdXMpOwogIGJhY2tncm91bmQ6dmFyKC0tcmVkKTsKICBkaXNwbGF5OmZsZXg7YWxpZ24taXRl"
"bXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpjZW50ZXI7CiAgZm9udC1mYW1pbHk6J1N5bmUnLHNhbnMt"
"c2VyaWY7Zm9udC13ZWlnaHQ6ODAwO2ZvbnQtc2l6ZToxNnB4O2NvbG9yOiNmZmY7CiAgcG9zaXRpb246"
"cmVsYXRpdmU7CiAgYW5pbWF0aW9uOmdsb3cgM3MgZWFzZSBpbmZpbml0ZTsKfQoucy1sb2dvLXRleHR7"
"Zm9udC1mYW1pbHk6J1N5bmUnLHNhbnMtc2VyaWY7Zm9udC1zaXplOjE4cHg7Zm9udC13ZWlnaHQ6ODAw"
"O2NvbG9yOnZhcigtLXdoaXRlKTtsZXR0ZXItc3BhY2luZzoycHh9Ci5zLWxvZ28tc3Vie2ZvbnQtc2l6"
"ZTo5cHg7Y29sb3I6dmFyKC0tdHgtb24tZGFyay1tdXRlZCk7bGV0dGVyLXNwYWNpbmc6M3B4O2ZvbnQt"
"d2VpZ2h0OjUwMDttYXJnaW4tdG9wOjFweH0KCi8qIE5BViBTRUNUSU9OUyAqLwovKiBTSURFQkFSIFNF"
"QVJDSCAqLwoucy1zZWFyY2h7cGFkZGluZzoxMHB4IDEycHggNnB4O3Bvc2l0aW9uOnJlbGF0aXZlfQou"
"cy1zZWFyY2gtaW5wdXR7CiAgd2lkdGg6MTAwJTtiYWNrZ3JvdW5kOnZhcigtLWJsYWNrLTMpO2JvcmRl"
"cjoxcHggc29saWQgcmdiYSgyNTUsMjU1LDI1NSwwLjA2KTsKICBib3JkZXItcmFkaXVzOjZweDtwYWRk"
"aW5nOjhweCAxMnB4IDhweCAzMnB4O2NvbG9yOnZhcigtLXR4LW9uLWRhcmspOwogIGZvbnQtc2l6ZTox"
"MXB4O2ZvbnQtZmFtaWx5OidPdXRmaXQnLHNhbnMtc2VyaWY7b3V0bGluZTpub25lOwogIHRyYW5zaXRp"
"b246Ym9yZGVyLWNvbG9yIC4yczsKfQoucy1zZWFyY2gtaW5wdXQ6Zm9jdXN7Ym9yZGVyLWNvbG9yOnZh"
"cigtLXJlZCl9Ci5zLXNlYXJjaC1pbnB1dDo6cGxhY2Vob2xkZXJ7Y29sb3I6cmdiYSgyNTUsMjU1LDI1"
"NSwwLjIpfQoucy1zZWFyY2gtaWNvbntwb3NpdGlvbjphYnNvbHV0ZTtsZWZ0OjIycHg7dG9wOjUwJTt0"
"cmFuc2Zvcm06dHJhbnNsYXRlWSgtNTAlKTtmb250LXNpemU6MTJweDtvcGFjaXR5Oi4zO3BvaW50ZXIt"
"ZXZlbnRzOm5vbmV9CgovKiBEUk9QRE9XTiBTRUNUSU9OUyAqLwoucy1zZWN0aW9ue3BhZGRpbmc6NHB4"
"IDEycHggMnB4fQoucy1zZWN0aW9uLWhlYWRlcnsKICBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2Vu"
"dGVyO2dhcDo4cHg7CiAgcGFkZGluZzo4cHggOHB4O2JvcmRlci1yYWRpdXM6NnB4O2N1cnNvcjpwb2lu"
"dGVyOwogIHRyYW5zaXRpb246YWxsIC4yczt1c2VyLXNlbGVjdDpub25lOwp9Ci5zLXNlY3Rpb24taGVh"
"ZGVyOmhvdmVye2JhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjAzKX0KLnMtc2VjdGlvbi1pY29u"
"e2ZvbnQtc2l6ZToxNHB4O3dpZHRoOjIwcHg7dGV4dC1hbGlnbjpjZW50ZXI7ZmxleC1zaHJpbms6MDtv"
"cGFjaXR5Oi42fQoucy1zZWN0aW9uLXRpdGxlewogIGZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxt"
"b25vc3BhY2U7CiAgZm9udC1zaXplOjlweDtmb250LXdlaWdodDo2MDA7Y29sb3I6dmFyKC0tdHgtb24t"
"ZGFyay1tdXRlZCk7CiAgbGV0dGVyLXNwYWNpbmc6Mi41cHg7dGV4dC10cmFuc2Zvcm06dXBwZXJjYXNl"
"O2ZsZXg6MTsKfQoucy1zZWN0aW9uLWNvdW50ewogIGZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxt"
"b25vc3BhY2U7Zm9udC1zaXplOjhweDtmb250LXdlaWdodDo3MDA7CiAgcGFkZGluZzoycHggNnB4O2Jv"
"cmRlci1yYWRpdXM6OHB4OwogIGJhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjA2KTtjb2xvcjp2"
"YXIoLS10eC1vbi1kYXJrLW11dGVkKTsKICBtaW4td2lkdGg6MThweDt0ZXh0LWFsaWduOmNlbnRlcjsK"
"fQoucy1zZWN0aW9uLWFycm93ewogIGZvbnQtc2l6ZToxMHB4O2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUs"
"MC4yKTsKICB0cmFuc2l0aW9uOnRyYW5zZm9ybSAuM3MgY3ViaWMtYmV6aWVyKC40LDAsLjIsMSk7Cn0K"
"LnMtc2VjdGlvbi5vcGVuIC5zLXNlY3Rpb24tYXJyb3d7dHJhbnNmb3JtOnJvdGF0ZSgxODBkZWcpfQou"
"cy1zZWN0aW9uLWJvZHl7CiAgbWF4LWhlaWdodDowO292ZXJmbG93OmhpZGRlbjsKICB0cmFuc2l0aW9u"
"Om1heC1oZWlnaHQgLjM1cyBjdWJpYy1iZXppZXIoLjQsMCwuMiwxKSxvcGFjaXR5IC4zcztvcGFjaXR5"
"OjA7Cn0KLnMtc2VjdGlvbi5vcGVuIC5zLXNlY3Rpb24tYm9keXttYXgtaGVpZ2h0OjYwMHB4O29wYWNp"
"dHk6MX0KCi5zLW5hdnsKICBkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMHB4Owog"
"IHBhZGRpbmc6N3B4IDEycHg7Ym9yZGVyLXJhZGl1czo2cHg7CiAgY3Vyc29yOnBvaW50ZXI7dHJhbnNp"
"dGlvbjphbGwgLjJzOwogIGNvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC40NSk7Zm9udC1zaXplOjEycHg7"
"Zm9udC13ZWlnaHQ6NTAwOwogIG1hcmdpbi1ib3R0b206MXB4O2JvcmRlcjoxcHggc29saWQgdHJhbnNw"
"YXJlbnQ7CiAgYmFja2dyb3VuZDp0cmFuc3BhcmVudDt3aWR0aDoxMDAlO3RleHQtYWxpZ246bGVmdDsK"
"ICBmb250LWZhbWlseTonT3V0Zml0JyxzYW5zLXNlcmlmOwogIHBvc2l0aW9uOnJlbGF0aXZlO292ZXJm"
"bG93OmhpZGRlbjsKfQoucy1uYXY6OmJlZm9yZXsKICBjb250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRl"
"O2xlZnQ6MDt0b3A6MDtib3R0b206MDt3aWR0aDowOwogIGJhY2tncm91bmQ6dmFyKC0tcmVkKTt0cmFu"
"c2l0aW9uOndpZHRoIC4yNXM7Ym9yZGVyLXJhZGl1czo2cHggMCAwIDZweDsKfQoucy1uYXY6aG92ZXJ7"
"Y29sb3I6cmdiYSgyNTUsMjU1LDI1NSwwLjgpO2JhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjA0"
"KX0KLnMtbmF2OmhvdmVyOjpiZWZvcmV7d2lkdGg6M3B4fQoucy1uYXYuYWN0aXZle2NvbG9yOiNmZmY7"
"YmFja2dyb3VuZDpyZ2JhKDIzMCw1Nyw3MCwwLjEyKTtib3JkZXItY29sb3I6cmdiYSgyMzAsNTcsNzAs"
"MC4xNSl9Ci5zLW5hdi5hY3RpdmU6OmJlZm9yZXt3aWR0aDozcHg7YmFja2dyb3VuZDp2YXIoLS1yZWQp"
"fQoucy1uYXYgLmljb3tmb250LXNpemU6MTRweDt3aWR0aDoyMHB4O3RleHQtYWxpZ246Y2VudGVyO2Zs"
"ZXgtc2hyaW5rOjB9Ci5zLW5hdiAubGJse2ZsZXg6MX0KLnMtdGFnewogIGZvbnQtZmFtaWx5OidJQk0g"
"UGxleCBNb25vJyxtb25vc3BhY2U7CiAgZm9udC1zaXplOjhweDtmb250LXdlaWdodDo3MDA7cGFkZGlu"
"ZzoycHggNnB4OwogIGJvcmRlci1yYWRpdXM6M3B4O2xldHRlci1zcGFjaW5nOi41cHg7Cn0KLnMtdGFn"
"LnJ7YmFja2dyb3VuZDpyZ2JhKDIzMCw1Nyw3MCwwLjIpO2NvbG9yOnZhcigtLXJlZC1saWdodCl9Ci5z"
"LXRhZy5ve2JhY2tncm91bmQ6cmdiYSgyMzIsOTMsNCwwLjE1KTtjb2xvcjojZmY4YzQyfQoKLyogU0lE"
"RUJBUiBGT09URVIgKi8KLnMtZm9vdGVyewogIHBhZGRpbmc6MTRweCAxNnB4O2JvcmRlci10b3A6MXB4"
"IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wNik7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNl"
"bnRlcjtnYXA6MTBweDsKICBwb3NpdGlvbjpyZWxhdGl2ZTt6LWluZGV4OjE7Cn0KLnMtYXZhdGFyewog"
"IHdpZHRoOjMycHg7aGVpZ2h0OjMycHg7Ym9yZGVyLXJhZGl1czo1MCU7CiAgYmFja2dyb3VuZDp2YXIo"
"LS1yZWQpOwogIGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNl"
"bnRlcjsKICBmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjtmb250LXNpemU6MTFweDtmb250LXdl"
"aWdodDo4MDA7Y29sb3I6I2ZmZjsKfQoucy11bmFtZXtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo2"
"MDA7Y29sb3I6dmFyKC0td2hpdGUpfQoucy11cm9sZXtmb250LXNpemU6OS41cHg7Y29sb3I6dmFyKC0t"
"dHgtb24tZGFyay1tdXRlZCk7bGV0dGVyLXNwYWNpbmc6LjVweH0KCi8qID09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgTUFJTiBBUkVB"
"CiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT0gKi8KLm1haW57ZmxleDoxO2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47"
"b3ZlcmZsb3c6aGlkZGVuO21pbi13aWR0aDowO2JhY2tncm91bmQ6dmFyKC0td2hpdGUtMil9CgovKiA9"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09CiAgIEhFQURFUiDigJQgQkxBQ0sgQkFSCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KLmhlYWRlcnsKICBoZWlnaHQ6dmFy"
"KC0taGVhZGVyLWgpO21pbi1oZWlnaHQ6dmFyKC0taGVhZGVyLWgpOwogIHBhZGRpbmc6MCAyOHB4O2Rp"
"c3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjE2cHg7CiAgYmFja2dyb3VuZDp2YXIoLS1i"
"bGFjay0yKTsKICBwb3NpdGlvbjpyZWxhdGl2ZTt6LWluZGV4OjU7CiAgYW5pbWF0aW9uOmZhZGVJbiAu"
"NXMgZWFzZTsKfQovKiBSZWQgYWNjZW50IGxpbmUgdW5kZXIgaGVhZGVyICovCi5oZWFkZXI6OmFmdGVy"
"ewogIGNvbnRlbnQ6Jyc7cG9zaXRpb246YWJzb2x1dGU7Ym90dG9tOjA7bGVmdDowO3JpZ2h0OjA7aGVp"
"Z2h0OjJweDsKICBiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1yZWQpLHZhcigt"
"LXJlZC1kYXJrKSx0cmFuc3BhcmVudCA4MCUpOwogIG9wYWNpdHk6LjY7Cn0KCi5oLWxlZnR7ZGlzcGxh"
"eTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTRweDtmbGV4OjE7bWluLXdpZHRoOjB9Ci5oLXRp"
"dGxlewogIGZvbnQtZmFtaWx5OidTeW5lJyxzYW5zLXNlcmlmOwogIGZvbnQtc2l6ZToxNXB4O2ZvbnQt"
"d2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS13aGl0ZSk7CiAgbGV0dGVyLXNwYWNpbmc6MXB4O3doaXRlLXNw"
"YWNlOm5vd3JhcDsKfQouaC1zZXB7d2lkdGg6MXB4O2hlaWdodDoyOHB4O2JhY2tncm91bmQ6cmdiYSgy"
"NTUsMjU1LDI1NSwwLjEpO2ZsZXgtc2hyaW5rOjB9CgouaC10YXJnZXR7CiAgZGlzcGxheTpmbGV4O2Fs"
"aWduLWl0ZW1zOmNlbnRlcjtmbGV4OjE7bWF4LXdpZHRoOjQ0MHB4OwogIGJhY2tncm91bmQ6dmFyKC0t"
"YmxhY2stMyk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMDgpOwogIGJvcmRlci1y"
"YWRpdXM6dmFyKC0tcmFkaXVzKTtvdmVyZmxvdzpoaWRkZW47dHJhbnNpdGlvbjphbGwgLjNzOwp9Ci5o"
"LXRhcmdldDpmb2N1cy13aXRoaW57Ym9yZGVyLWNvbG9yOnZhcigtLXJlZCk7Ym94LXNoYWRvdzowIDAg"
"MCAzcHggdmFyKC0tcmVkLWdsb3cpfQouaC10YXJnZXQtcHJlewogIHBhZGRpbmc6MCAxMnB4O2ZvbnQt"
"ZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7CiAgZm9udC1zaXplOjlweDtjb2xvcjp2YXIo"
"LS1yZWQpO2xldHRlci1zcGFjaW5nOjJweDsKICBib3JkZXItcmlnaHQ6MXB4IHNvbGlkIHJnYmEoMjU1"
"LDI1NSwyNTUsMC4wNik7Zm9udC13ZWlnaHQ6NjAwOwp9Ci5oLXRhcmdldC1pbnB1dHsKICBmbGV4OjE7"
"YmFja2dyb3VuZDpub25lO2JvcmRlcjpub25lO291dGxpbmU6bm9uZTsKICBjb2xvcjp2YXIoLS10eC1v"
"bi1kYXJrKTtmb250LXNpemU6MTNweDtwYWRkaW5nOjEwcHggMTRweDsKICBmb250LWZhbWlseTonT3V0"
"Zml0JyxzYW5zLXNlcmlmOwp9Ci5oLXRhcmdldC1pbnB1dDo6cGxhY2Vob2xkZXJ7Y29sb3I6cmdiYSgy"
"NTUsMjU1LDI1NSwwLjIpfQoKLmgtcmlnaHR7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtn"
"YXA6MTBweDtmbGV4LXNocmluazowfQouaC1zdGF0dXN7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1z"
"OmNlbnRlcjtnYXA6NnB4OwogIHBhZGRpbmc6NXB4IDEycHg7Ym9yZGVyLXJhZGl1czoyMHB4OwogIGZv"
"bnQtc2l6ZToxMHB4O2ZvbnQtd2VpZ2h0OjYwMDtsZXR0ZXItc3BhY2luZzouOHB4OwogIGZvbnQtZmFt"
"aWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7CiAgYmFja2dyb3VuZDpyZ2JhKDQ1LDEwNiw3OSww"
"LjE1KTtjb2xvcjojNGFkZTgwOwp9Ci5oLXN0YXR1cyAuZG90e3dpZHRoOjZweDtoZWlnaHQ6NnB4O2Jv"
"cmRlci1yYWRpdXM6NTAlO2JhY2tncm91bmQ6Y3VycmVudENvbG9yO2FuaW1hdGlvbjpwdWxzZSAycyBp"
"bmZpbml0ZX0KLmgtY2xvY2t7Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250"
"LXNpemU6MTFweDtjb2xvcjp2YXIoLS10eC1vbi1kYXJrLW11dGVkKX0KCi5idG4tcmVwb3J0ewogIGRp"
"c3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjdweDsKICBwYWRkaW5nOjhweCAyMHB4O2Jv"
"cmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzKTsKICBiYWNrZ3JvdW5kOnZhcigtLXJlZCk7Y29sb3I6I2Zm"
"ZjsKICBib3JkZXI6bm9uZTtjdXJzb3I6cG9pbnRlcjtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo2"
"MDA7CiAgZm9udC1mYW1pbHk6J091dGZpdCcsc2Fucy1zZXJpZjtsZXR0ZXItc3BhY2luZzouNXB4Owog"
"IHRyYW5zaXRpb246YWxsIC4yNXM7cG9zaXRpb246cmVsYXRpdmU7b3ZlcmZsb3c6aGlkZGVuOwp9Ci5i"
"dG4tcmVwb3J0OjpiZWZvcmV7CiAgY29udGVudDonJztwb3NpdGlvbjphYnNvbHV0ZTtpbnNldDowOwog"
"IGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5zcGFyZW50LHJnYmEoMjU1LDI1NSwy"
"NTUsMC4xKSx0cmFuc3BhcmVudCk7CiAgdHJhbnNmb3JtOnRyYW5zbGF0ZVgoLTEwMCUpO3RyYW5zaXRp"
"b246dHJhbnNmb3JtIC42czsKfQouYnRuLXJlcG9ydDpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXJlZC1k"
"YXJrKTt0cmFuc2Zvcm06dHJhbnNsYXRlWSgtMXB4KTtib3gtc2hhZG93OjAgNHB4IDIwcHggdmFyKC0t"
"cmVkLWdsb3cpfQouYnRuLXJlcG9ydDpob3Zlcjo6YmVmb3Jle3RyYW5zZm9ybTp0cmFuc2xhdGVYKDEw"
"MCUpfQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PQogICBUQUIgTkFWIOKAlCBPTiBXSElURQogICA9PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi50YWItbmF2ewog"
"IGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjJweDsKICBwYWRkaW5nOjAgMjhweDti"
"YWNrZ3JvdW5kOnZhcigtLXdoaXRlKTsKICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS13aGl0"
"ZS0zKTsKICBhbmltYXRpb246ZmFkZUluIC42cyBlYXNlOwp9Ci50YWItYnRuewogIHBhZGRpbmc6MTRw"
"eCAyMnB4O2ZvbnQtc2l6ZToxMi41cHg7Zm9udC13ZWlnaHQ6NTAwOwogIGNvbG9yOnZhcigtLXR4LW11"
"dGVkKTtiYWNrZ3JvdW5kOm5vbmU7Ym9yZGVyOm5vbmU7Y3Vyc29yOnBvaW50ZXI7CiAgYm9yZGVyLWJv"
"dHRvbToycHggc29saWQgdHJhbnNwYXJlbnQ7CiAgdHJhbnNpdGlvbjphbGwgLjJzO2ZvbnQtZmFtaWx5"
"OidPdXRmaXQnLHNhbnMtc2VyaWY7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6"
"OHB4OwogIHBvc2l0aW9uOnJlbGF0aXZlO2xldHRlci1zcGFjaW5nOi4zcHg7Cn0KLnRhYi1idG46aG92"
"ZXJ7Y29sb3I6dmFyKC0tdHgtZGFyayl9Ci50YWItYnRuLmFjdGl2ZXtjb2xvcjp2YXIoLS1yZWQpO2Jv"
"cmRlci1ib3R0b20tY29sb3I6dmFyKC0tcmVkKTtmb250LXdlaWdodDo3MDB9Ci50YWItYmFkZ2V7CiAg"
"Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTsKICBmb250LXNpemU6OXB4O2ZvbnQt"
"d2VpZ2h0OjcwMDtwYWRkaW5nOjJweCA3cHg7CiAgYm9yZGVyLXJhZGl1czoxMHB4O2JhY2tncm91bmQ6"
"dmFyKC0td2hpdGUtMyk7CiAgY29sb3I6dmFyKC0tdHgtbXV0ZWQpO2Rpc3BsYXk6bm9uZTsKfQoudGFi"
"LWJhZGdlLnNob3d7ZGlzcGxheTppbmxpbmUtYmxvY2t9Ci50YWItYmFkZ2UuYi1yZWR7YmFja2dyb3Vu"
"ZDp2YXIoLS1zZXYtY3JpdC1iZyk7Y29sb3I6dmFyKC0tc2V2LWNyaXQpfQoudGFiLWJhZGdlLmItb3Jh"
"bmdle2JhY2tncm91bmQ6dmFyKC0tc2V2LWhpZ2gtYmcpO2NvbG9yOnZhcigtLXNldi1oaWdoKX0KCi8q"
"ID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT0KICAgQ09OVEVOVCDigJQgV0hJVEUgQVJFQQogICA9PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi5jb250ZW50e2ZsZXg6MTtv"
"dmVyZmxvdzpoaWRkZW47ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbn0KLnRhYi1wYW5l"
"e2Rpc3BsYXk6bm9uZTtmbGV4OjE7b3ZlcmZsb3cteTphdXRvO3BhZGRpbmc6MjRweCAyOHB4fQoudGFi"
"LXBhbmUuYWN0aXZle2Rpc3BsYXk6YmxvY2s7YW5pbWF0aW9uOmZhZGVVcCAuNHMgZWFzZX0KCi8qID09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT0KICAgVEVSTUlOQUwg4oCUIEFMV0FZUyBEQVJLCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KLnRlcm1pbmFsLWNhcmR7CiAg"
"YmFja2dyb3VuZDp2YXIoLS1ibGFjayk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAu"
"MDYpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzLWxnKTtvdmVyZmxvdzpoaWRkZW47CiAgcG9z"
"aXRpb246cmVsYXRpdmU7CiAgYW5pbWF0aW9uOmZhZGVVcCAuNXMgZWFzZTsKfQovKiBTY2FuIGxpbmUg"
"ZWZmZWN0ICovCi50ZXJtaW5hbC1jYXJkOjphZnRlcnsKICBjb250ZW50OicnO3Bvc2l0aW9uOmFic29s"
"dXRlO2xlZnQ6MDtyaWdodDowO2hlaWdodDoycHg7CiAgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQo"
"OTBkZWcsdHJhbnNwYXJlbnQsdmFyKC0tcmVkLWdsb3cpLHRyYW5zcGFyZW50KTsKICBhbmltYXRpb246"
"c2NhbmxpbmUgNHMgbGluZWFyIGluZmluaXRlOwogIHBvaW50ZXItZXZlbnRzOm5vbmU7b3BhY2l0eTou"
"NTsKfQoudGVybS1oZWFkZXJ7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5"
"LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjsKICBwYWRkaW5nOjEwcHggMThweDtib3JkZXItYm90dG9tOjFw"
"eCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMDYpOwogIGJhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjMp"
"Owp9Ci50ZXJtLWRvdHN7ZGlzcGxheTpmbGV4O2dhcDo2cHh9Ci50ZXJtLWRvdHMgc3Bhbnt3aWR0aDox"
"MHB4O2hlaWdodDoxMHB4O2JvcmRlci1yYWRpdXM6NTAlfQoudGVybS1kb3RzIC5kMXtiYWNrZ3JvdW5k"
"OnZhcigtLXJlZCl9Ci50ZXJtLWRvdHMgLmQye2JhY2tncm91bmQ6I2UwOWYzZX0KLnRlcm0tZG90cyAu"
"ZDN7YmFja2dyb3VuZDojMmQ2YTRmfQoudGVybS10aXRsZXtmb250LWZhbWlseTonSUJNIFBsZXggTW9u"
"bycsbW9ub3NwYWNlO2ZvbnQtc2l6ZToxMHB4O2NvbG9yOnZhcigtLXR4LW9uLWRhcmstbXV0ZWQpO2xl"
"dHRlci1zcGFjaW5nOjEuNXB4fQoudGVybS1hY3Rpb25ze2Rpc3BsYXk6ZmxleDtnYXA6NnB4fQoudGVy"
"bS1hY3R7CiAgcGFkZGluZzo0cHggMTJweDtib3JkZXItcmFkaXVzOjRweDsKICBiYWNrZ3JvdW5kOnJn"
"YmEoMjU1LDI1NSwyNTUsMC4wNSk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwyNTUsMjU1LDAuMDgp"
"OwogIGNvbG9yOnZhcigtLXR4LW9uLWRhcmstbXV0ZWQpO2ZvbnQtc2l6ZTo5LjVweDtmb250LXdlaWdo"
"dDo2MDA7CiAgZm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtjdXJzb3I6cG9pbnRl"
"cjsKICB0cmFuc2l0aW9uOmFsbCAuMTVzO2xldHRlci1zcGFjaW5nOi41cHg7Cn0KLnRlcm0tYWN0Omhv"
"dmVye2JhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjEpO2NvbG9yOnZhcigtLXdoaXRlKX0KCi5s"
"b2FkaW5nLWJhcntoZWlnaHQ6MnB4O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHZhcigt"
"LXJlZCksI2ZmNmI2Yix2YXIoLS1yZWQpKTtiYWNrZ3JvdW5kLXNpemU6MjAwJSAxMDAlO2FuaW1hdGlv"
"bjpzaGltbWVyIDEuNXMgaW5maW5pdGU7ZGlzcGxheTpub25lfQoKI3Rlcm1pbmFsLW91dHB1dHsKICBw"
"YWRkaW5nOjE2cHggMThweDttaW4taGVpZ2h0OjI2MHB4O21heC1oZWlnaHQ6NTB2aDsKICBvdmVyZmxv"
"dy15OmF1dG87Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTEu"
"NXB4OwogIGNvbG9yOnZhcigtLXR4LW9uLWRhcmstbXV0ZWQpOwp9Ci50bHtwYWRkaW5nOjJweCAwO2xp"
"bmUtaGVpZ2h0OjEuNjU7d29yZC1icmVhazpicmVhay1hbGx9Ci50bC5oZHJ7Y29sb3I6dmFyKC0tcmVk"
"KTtmb250LXdlaWdodDo2MDB9Ci50bC5wcm9tcHR7Y29sb3I6IzRhZGU4MH0KLnRsLnJlc3VsdHtjb2xv"
"cjp2YXIoLS10eC1vbi1kYXJrLW11dGVkKX0KLnRsLmVycm9ye2NvbG9yOnZhcigtLXJlZC1saWdodCl9"
"Ci50bC5pbmZve2NvbG9yOnJnYmEoMjU1LDI1NSwyNTUsMC4zKX0KLmJsaW5re2FuaW1hdGlvbjpwdWxz"
"ZSAxcyBzdGVwLWVuZCBpbmZpbml0ZX0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgREFTSEJPQVJEIENBUkRTIOKAlCBXSElU"
"RSBDQVJEUyBPTiBMSUdIVCBCRwogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi5kYXNoLWdyaWR7ZGlzcGxheTpncmlkO2dhcDox"
"OHB4fQouZGFzaC1ncmlkLmNvbHMtNHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDQsMWZyKX0K"
"LmRhc2gtZ3JpZC5jb2xzLTN7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgzLDFmcil9Ci5kYXNo"
"LWdyaWQuY29scy0ye2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMiwxZnIpfQouZGFzaC1ncmlk"
"LmNvbHMtMXtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MWZyfQoKLmNhcmR7CiAgYmFja2dyb3VuZDp2YXIo"
"LS13aGl0ZSk7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTsKICBib3JkZXItcmFkaXVz"
"OnZhcigtLXJhZGl1cy1sZyk7CiAgcGFkZGluZzoyMHB4IDIycHg7CiAgdHJhbnNpdGlvbjphbGwgLjI1"
"czsKICBwb3NpdGlvbjpyZWxhdGl2ZTsKICBhbmltYXRpb246ZmFkZVVwIC41cyBlYXNlIGJvdGg7Cn0K"
"LmNhcmQ6bnRoLWNoaWxkKDEpe2FuaW1hdGlvbi1kZWxheTouMDVzfQouY2FyZDpudGgtY2hpbGQoMil7"
"YW5pbWF0aW9uLWRlbGF5Oi4xc30KLmNhcmQ6bnRoLWNoaWxkKDMpe2FuaW1hdGlvbi1kZWxheTouMTVz"
"fQouY2FyZDpudGgtY2hpbGQoNCl7YW5pbWF0aW9uLWRlbGF5Oi4yc30KLmNhcmQ6aG92ZXJ7Ym9yZGVy"
"LWNvbG9yOnZhcigtLXdoaXRlLTQpO2JveC1zaGFkb3c6MCA0cHggMjBweCByZ2JhKDAsMCwwLDAuMDQp"
"fQoKLmNhcmQtaGVhZGVye2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250"
"ZW50OnNwYWNlLWJldHdlZW47bWFyZ2luLWJvdHRvbToxNnB4fQouY2FyZC10aXRsZXtmb250LXNpemU6"
"MTRweDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tdHgtZGFyayk7Zm9udC1mYW1pbHk6J091dGZp"
"dCcsc2Fucy1zZXJpZn0KLmNhcmQtc3VidGl0bGV7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tdHgt"
"bXV0ZWQpO21hcmdpbi10b3A6MnB4fQoKLyogU1RBVCBOVU1CRVJTICovCi5zdGF0LW51bXsKICBmb250"
"LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjsKICBmb250LXNpemU6MzRweDtmb250LXdlaWdodDo4MDA7"
"bGluZS1oZWlnaHQ6MTsKICBjb2xvcjp2YXIoLS10eC1kYXJrKTtsZXR0ZXItc3BhY2luZzotMXB4Owp9"
"Ci5zdGF0LW51bS5yZWR7Y29sb3I6dmFyKC0tc2V2LWNyaXQpfQouc3RhdC1udW0ub3Jhbmdle2NvbG9y"
"OnZhcigtLXNldi1oaWdoKX0KLnN0YXQtbnVtLnllbGxvd3tjb2xvcjp2YXIoLS1zZXYtbWVkKX0KLnN0"
"YXQtbnVtLmdyZWVue2NvbG9yOnZhcigtLXNldi1sb3cpfQouc3RhdC1udW0uYnJhbmR7Y29sb3I6dmFy"
"KC0tcmVkKX0KCi5zdGF0LWJhci13cmFwe21hcmdpbi10b3A6MTBweH0KLnN0YXQtYmFye2hlaWdodDo2"
"cHg7Ym9yZGVyLXJhZGl1czoxMHB4O2JhY2tncm91bmQ6dmFyKC0td2hpdGUtMyk7b3ZlcmZsb3c6aGlk"
"ZGVufQouc3RhdC1iYXItZmlsbHtoZWlnaHQ6MTAwJTtib3JkZXItcmFkaXVzOjEwcHg7dHJhbnNpdGlv"
"bjp3aWR0aCAuOHMgY3ViaWMtYmV6aWVyKC40LDAsLjIsMSl9Ci5zdGF0LWJhci1maWxsLnJlZHtiYWNr"
"Z3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1zZXYtY3JpdCksI2Y4NzE3MSl9Ci5zdGF0"
"LWJhci1maWxsLm9yYW5nZXtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1zZXYt"
"aGlnaCksI2ZiOTIzYyl9Ci5zdGF0LWJhci1maWxsLnllbGxvd3tiYWNrZ3JvdW5kOmxpbmVhci1ncmFk"
"aWVudCg5MGRlZyx2YXIoLS1zZXYtbWVkKSwjZmJiZjI0KX0KLnN0YXQtYmFyLWZpbGwuZ3JlZW57YmFj"
"a2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsdmFyKC0tc2V2LWxvdyksIzM0ZDM5OSl9Ci5zdGF0"
"LWJhci1maWxsLmJyYW5ke2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHZhcigtLXJlZCks"
"dmFyKC0tcmVkLWxpZ2h0KSl9Cgouc3RhdC1zdWJ7Zm9udC1zaXplOjEwLjVweDtjb2xvcjp2YXIoLS10"
"eC1tdXRlZCk7bWFyZ2luLXRvcDo4cHg7Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFj"
"ZX0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT0KICAgUE9SVCBUQUJMRSDigJQgQ0xFQU4gV0hJVEUKICAgPT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwoucG9ydC10"
"YWJsZS13cmFwe292ZXJmbG93LXg6YXV0b30KLnBvcnQtdGFibGV7d2lkdGg6MTAwJTtib3JkZXItY29s"
"bGFwc2U6Y29sbGFwc2U7Zm9udC1zaXplOjEycHh9Ci5wb3J0LXRhYmxlIHRoZWFkIHRoewogIHRleHQt"
"YWxpZ246bGVmdDtwYWRkaW5nOjEwcHggMTRweDsKICBmb250LWZhbWlseTonSUJNIFBsZXggTW9ubycs"
"bW9ub3NwYWNlOwogIGZvbnQtc2l6ZTo5cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXR4LWZh"
"aW50KTsKICBsZXR0ZXItc3BhY2luZzoxLjVweDt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7CiAgYm9y"
"ZGVyLWJvdHRvbToycHggc29saWQgdmFyKC0td2hpdGUtMyk7CiAgYmFja2dyb3VuZDp2YXIoLS13aGl0"
"ZS0yKTsKfQoucG9ydC10YWJsZSB0Ym9keSB0cntib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS13"
"aGl0ZS0zKTt0cmFuc2l0aW9uOmJhY2tncm91bmQgLjE1c30KLnBvcnQtdGFibGUgdGJvZHkgdHI6aG92"
"ZXJ7YmFja2dyb3VuZDp2YXIoLS1yZWQtZGltKX0KLnBvcnQtdGFibGUgdGJvZHkgdHI6bGFzdC1jaGls"
"ZHtib3JkZXItYm90dG9tOm5vbmV9Ci5wb3J0LXRhYmxlIHRke3BhZGRpbmc6MTBweCAxNHB4O3ZlcnRp"
"Y2FsLWFsaWduOnRvcH0KLnAtbnVte2ZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7"
"Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXJlZCk7Zm9udC1zaXplOjEzcHh9Ci5wLXByb3Rve2Zv"
"bnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjlweDtjb2xvcjp2YXIo"
"LS10eC1mYWludCl9Ci5wLXN2Y3tjb2xvcjp2YXIoLS10eC1kYXJrKTtmb250LXdlaWdodDo2MDA7Zm9u"
"dC1zaXplOjEycHh9Ci5wLXZlcntmb250LXNpemU6MTBweDtjb2xvcjp2YXIoLS10eC1tdXRlZCk7bWFy"
"Z2luLXRvcDoycHh9Ci5wLWRlc2N7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpO2ZvbnQtc2l6ZToxMXB4O21h"
"eC13aWR0aDoyNjBweH0KLnAtZml4e2NvbG9yOnZhcigtLXNldi1sb3cpO2ZvbnQtc2l6ZToxMXB4O21h"
"eC13aWR0aDoyMjBweH0KCi8qIFNFVkVSSVRZIEJBREdFUyDigJQgb24gd2hpdGUgYmcgKi8KLnNldnsK"
"ICBkaXNwbGF5OmlubGluZS1mbGV4O3BhZGRpbmc6M3B4IDEwcHg7Ym9yZGVyLXJhZGl1czoyMHB4Owog"
"IGZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7CiAgZm9udC1zaXplOjguNXB4O2Zv"
"bnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzouOHB4Owp9Ci5zZXYuQ1JJVElDQUx7YmFja2dyb3Vu"
"ZDp2YXIoLS1zZXYtY3JpdC1iZyk7Y29sb3I6dmFyKC0tc2V2LWNyaXQpO2JvcmRlcjoxcHggc29saWQg"
"dmFyKC0tc2V2LWNyaXQtYm9yZGVyKX0KLnNldi5ISUdIe2JhY2tncm91bmQ6dmFyKC0tc2V2LWhpZ2gt"
"YmcpO2NvbG9yOnZhcigtLXNldi1oaWdoKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLXNldi1oaWdoLWJv"
"cmRlcil9Ci5zZXYuTUVESVVNe2JhY2tncm91bmQ6dmFyKC0tc2V2LW1lZC1iZyk7Y29sb3I6dmFyKC0t"
"c2V2LW1lZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1zZXYtbWVkLWJvcmRlcil9Ci5zZXYuTE9Xe2Jh"
"Y2tncm91bmQ6dmFyKC0tc2V2LWxvdy1iZyk7Y29sb3I6dmFyKC0tc2V2LWxvdyk7Ym9yZGVyOjFweCBz"
"b2xpZCB2YXIoLS1zZXYtbG93LWJvcmRlcil9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIFRIUkVBVCBDQVJEUyDigJQgV0hJ"
"VEUgV0lUSCBSRUQgTEVGVCBCT1JERVIKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwoudGhyZWF0LWNhcmR7CiAgYmFja2dyb3Vu"
"ZDp2YXIoLS13aGl0ZSk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTsKICBib3JkZXItcmFk"
"aXVzOnZhcigtLXJhZGl1cy1sZyk7cGFkZGluZzoxOHB4IDIycHg7CiAgYm9yZGVyLWxlZnQ6NHB4IHNv"
"bGlkIHZhcigtLXdoaXRlLTQpOwogIHRyYW5zaXRpb246YWxsIC4yNXM7CiAgYW5pbWF0aW9uOmZhZGVV"
"cCAuNXMgZWFzZSBib3RoOwp9Ci50aHJlYXQtY2FyZDpob3Zlcntib3gtc2hhZG93OjAgNHB4IDIwcHgg"
"cmdiYSgwLDAsMCwwLjA1KTt0cmFuc2Zvcm06dHJhbnNsYXRlWSgtMXB4KX0KLnRocmVhdC1jYXJkLkNS"
"SVRJQ0FMe2JvcmRlci1sZWZ0LWNvbG9yOnZhcigtLXNldi1jcml0KX0KLnRocmVhdC1jYXJkLkhJR0h7"
"Ym9yZGVyLWxlZnQtY29sb3I6dmFyKC0tc2V2LWhpZ2gpfQoudGhyZWF0LWNhcmQuTUVESVVNe2JvcmRl"
"ci1sZWZ0LWNvbG9yOnZhcigtLXNldi1tZWQpfQoudGhyZWF0LWNhcmQuTE9Xe2JvcmRlci1sZWZ0LWNv"
"bG9yOnZhcigtLXNldi1sb3cpfQoudGMtaGRye2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7"
"anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47bWFyZ2luLWJvdHRvbToxMHB4fQoudGMtbmFtZXtm"
"b250LXNpemU6MTNweDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFyKC0tdHgtZGFyayl9Ci50Yy1kZXNj"
"e2ZvbnQtc2l6ZToxMnB4O2NvbG9yOnZhcigtLXR4LW11dGVkKTttYXJnaW4tYm90dG9tOjE0cHg7bGlu"
"ZS1oZWlnaHQ6MS43fQoudGMtZml4ewogIHBhZGRpbmc6MTBweCAxNHB4O2JvcmRlci1yYWRpdXM6dmFy"
"KC0tcmFkaXVzKTsKICBiYWNrZ3JvdW5kOnZhcigtLXNldi1sb3ctYmcpO2JvcmRlcjoxcHggc29saWQg"
"dmFyKC0tc2V2LWxvdy1ib3JkZXIpOwp9Ci50Yy1maXgtbGFiZWx7Zm9udC1mYW1pbHk6J0lCTSBQbGV4"
"IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6OC41cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigt"
"LXNldi1sb3cpO2xldHRlci1zcGFjaW5nOjEuNXB4O21hcmdpbi1ib3R0b206M3B4fQoudGMtZml4LXRl"
"eHR7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tc2V2LWxvdyk7bGluZS1oZWlnaHQ6MS41fQoKLyog"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PQogICBDSEFSVCBDQVJEUwogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi5jaGFydC13cmFwe3Bvc2l0aW9uOnJlbGF0aXZl"
"O21pbi1oZWlnaHQ6MjAwcHh9Ci5jaGFydC13cmFwIGNhbnZhc3t3aWR0aDoxMDAlIWltcG9ydGFudDto"
"ZWlnaHQ6MTAwJSFpbXBvcnRhbnR9CgovKiBSSVNLIEdBVUdFICovCi5yaXNrLWdhdWdle2Rpc3BsYXk6"
"ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjI4cHg7cGFkZGluZzo4cHggMH0KLnJpc2stY2lyY2xl"
"ewogIHdpZHRoOjExMHB4O2hlaWdodDoxMTBweDtib3JkZXItcmFkaXVzOjUwJTsKICBkaXNwbGF5OmZs"
"ZXg7ZmxleC1kaXJlY3Rpb246Y29sdW1uO2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6"
"Y2VudGVyOwogIGJvcmRlcjozcHggc29saWQgdmFyKC0td2hpdGUtMyk7cG9zaXRpb246cmVsYXRpdmU7"
"ZmxleC1zaHJpbms6MDsKfQoucmlzay1jaXJjbGU6OmFmdGVyewogIGNvbnRlbnQ6Jyc7cG9zaXRpb246"
"YWJzb2x1dGU7aW5zZXQ6LTNweDtib3JkZXItcmFkaXVzOjUwJTsKICBib3JkZXI6M3B4IHNvbGlkIHRy"
"YW5zcGFyZW50O2JvcmRlci10b3AtY29sb3I6Y3VycmVudENvbG9yOwogIGFuaW1hdGlvbjpzcGluIDIu"
"NXMgbGluZWFyIGluZmluaXRlOwp9Ci5yaXNrLXZhbHtmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJp"
"Zjtmb250LXNpemU6MzZweDtmb250LXdlaWdodDo4MDA7bGluZS1oZWlnaHQ6MX0KLnJpc2stbGFiZWx7"
"Zm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6OXB4O2ZvbnQtd2Vp"
"Z2h0OjcwMDtsZXR0ZXItc3BhY2luZzoycHg7bWFyZ2luLXRvcDo0cHg7Y29sb3I6dmFyKC0tdHgtbXV0"
"ZWQpfQoucmlzay1kZXRhaWxze2Rpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47Z2FwOjEw"
"cHh9Ci5yaXNrLXJvd3tkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMHB4O2ZvbnQt"
"c2l6ZToxMnB4O2NvbG9yOnZhcigtLXR4LWJvZHkpfQoucmlzay1kb3R7d2lkdGg6OHB4O2hlaWdodDo4"
"cHg7Ym9yZGVyLXJhZGl1czo1MCU7ZmxleC1zaHJpbms6MH0KLnJpc2stdmFsLXNte2ZvbnQtZmFtaWx5"
"OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC13ZWlnaHQ6NzAwO21hcmdpbi1sZWZ0OmF1dG99"
"CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09CiAgIEVNUFRZIFNUQVRFCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KLmVtcHR5LXN0YXRle2Rpc3BsYXk6Zmxl"
"eDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47YWxpZ24taXRlbXM6Y2VudGVyO2p1c3RpZnktY29udGVudDpj"
"ZW50ZXI7cGFkZGluZzo2MHB4IDIwcHg7dGV4dC1hbGlnbjpjZW50ZXJ9Ci5lbXB0eS1pY297Zm9udC1z"
"aXplOjQwcHg7bWFyZ2luLWJvdHRvbToxNnB4O29wYWNpdHk6LjM1fQouZW1wdHktdGl0bGV7Zm9udC1z"
"aXplOjE0cHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXR4LW11dGVkKTttYXJnaW4tYm90dG9t"
"OjZweH0KLmVtcHR5LXN1Yntmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS10eC1mYWludCk7bWF4LXdp"
"ZHRoOjMwMHB4fQoKLyogPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PQogICBDSEFUIFBBTkVMIOKAlCBEQVJLIEJPVFRPTSBCQVIKICAgPT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PSAqLwouY2hhdC1wYW5lbHsKICBib3JkZXItdG9wOjJweCBzb2xpZCB2YXIoLS1yZWQpOwogIGJhY2tn"
"cm91bmQ6dmFyKC0tYmxhY2spOwogIGRpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1bW47CiAg"
"bWF4LWhlaWdodDoyNDBweDt0cmFuc2l0aW9uOm1heC1oZWlnaHQgLjM1cyBjdWJpYy1iZXppZXIoLjQs"
"MCwuMiwxKTsKICBwb3NpdGlvbjpyZWxhdGl2ZTsKfQouY2hhdC1wYW5lbC5jb2xsYXBzZWR7bWF4LWhl"
"aWdodDo0NnB4fQouY2hhdC10b2dnbGV7CiAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtq"
"dXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjsKICBwYWRkaW5nOjAgMjRweDtoZWlnaHQ6NDZweDtt"
"aW4taGVpZ2h0OjQ2cHg7CiAgY3Vyc29yOnBvaW50ZXI7Cn0KLmNoYXQtdG9nZ2xlLWxlZnR7ZGlzcGxh"
"eTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTBweH0KLmNoYXQtdG9nZ2xlLWxhYmVse2ZvbnQt"
"c2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS13aGl0ZSk7bGV0dGVyLXNwYWNpbmc6"
"LjVweH0KLmNoYXQtdG9nZ2xlLXN0YXR1c3tmb250LXNpemU6MTBweDtjb2xvcjojNGFkZTgwO2ZvbnQt"
"d2VpZ2h0OjUwMH0KLmNoYXQtYXJyb3d7Zm9udC1zaXplOjEycHg7Y29sb3I6dmFyKC0tdHgtb24tZGFy"
"ay1tdXRlZCk7dHJhbnNpdGlvbjp0cmFuc2Zvcm0gLjNzfQouY2hhdC1wYW5lbC5jb2xsYXBzZWQgLmNo"
"YXQtYXJyb3d7dHJhbnNmb3JtOnJvdGF0ZSgxODBkZWcpfQoKI2NoYXQtbWVzc2FnZXN7ZmxleDoxO292"
"ZXJmbG93LXk6YXV0bztwYWRkaW5nOjEwcHggMjRweH0KLm1zZ3tkaXNwbGF5OmZsZXg7Z2FwOjEwcHg7"
"bWFyZ2luLWJvdHRvbToxMHB4O2FuaW1hdGlvbjpmYWRlVXAgLjNzIGVhc2V9Ci5tc2ctYXZhdGFyewog"
"IHdpZHRoOjI2cHg7aGVpZ2h0OjI2cHg7Ym9yZGVyLXJhZGl1czo2cHg7CiAgZGlzcGxheTpmbGV4O2Fs"
"aWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOwogIGZvbnQtc2l6ZTo4cHg7Zm9u"
"dC13ZWlnaHQ6NzAwO2ZsZXgtc2hyaW5rOjA7CiAgZm9udC1mYW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1v"
"bm9zcGFjZTsKfQoubXNnLmFpIC5tc2ctYXZhdGFye2JhY2tncm91bmQ6cmdiYSgyMzAsNTcsNzAsMC4x"
"NSk7Y29sb3I6dmFyKC0tcmVkLWxpZ2h0KX0KLm1zZy51c2VyIC5tc2ctYXZhdGFye2JhY2tncm91bmQ6"
"cmdiYSgyNTUsMjU1LDI1NSwwLjA4KTtjb2xvcjp2YXIoLS10eC1vbi1kYXJrLW11dGVkKX0KLm1zZy1i"
"b2R5ewogIGJhY2tncm91bmQ6dmFyKC0tYmxhY2stMyk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDI1NSwy"
"NTUsMjU1LDAuMDYpOwogIGJvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzKTtwYWRkaW5nOjlweCAxM3B4"
"OwogIGZvbnQtc2l6ZToxMnB4O2xpbmUtaGVpZ2h0OjEuNjtjb2xvcjp2YXIoLS10eC1vbi1kYXJrLW11"
"dGVkKTttYXgtd2lkdGg6ODUlOwp9CgouY2hhdC1pbnB1dC1yb3d7ZGlzcGxheTpmbGV4O2dhcDo4cHg7"
"cGFkZGluZzo4cHggMjRweCAxMnB4fQouY2hhdC1pbnB1dHsKICBmbGV4OjE7YmFja2dyb3VuZDp2YXIo"
"LS1ibGFjay0zKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wOCk7CiAgYm9yZGVy"
"LXJhZGl1czp2YXIoLS1yYWRpdXMpO3BhZGRpbmc6OXB4IDE0cHg7CiAgY29sb3I6dmFyKC0tdHgtb24t"
"ZGFyayk7Zm9udC1zaXplOjEycHg7b3V0bGluZTpub25lOwogIGZvbnQtZmFtaWx5OidPdXRmaXQnLHNh"
"bnMtc2VyaWY7dHJhbnNpdGlvbjpib3JkZXItY29sb3IgLjJzOwp9Ci5jaGF0LWlucHV0OmZvY3Vze2Jv"
"cmRlci1jb2xvcjp2YXIoLS1yZWQpfQouY2hhdC1pbnB1dDo6cGxhY2Vob2xkZXJ7Y29sb3I6cmdiYSgy"
"NTUsMjU1LDI1NSwwLjIpfQouY2hhdC1zZW5kewogIHBhZGRpbmc6MCAyMHB4O2JvcmRlci1yYWRpdXM6"
"dmFyKC0tcmFkaXVzKTsKICBiYWNrZ3JvdW5kOnZhcigtLXJlZCk7Y29sb3I6I2ZmZjtib3JkZXI6bm9u"
"ZTsKICBmb250LXNpemU6MTJweDtmb250LXdlaWdodDo3MDA7Y3Vyc29yOnBvaW50ZXI7CiAgZm9udC1m"
"YW1pbHk6J091dGZpdCcsc2Fucy1zZXJpZjt0cmFuc2l0aW9uOmFsbCAuMnM7Cn0KLmNoYXQtc2VuZDpo"
"b3ZlcntiYWNrZ3JvdW5kOnZhcigtLXJlZC1kYXJrKX0KCi8qID09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgUkVQT1JUIE1PREFMCiAg"
"ID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT0gKi8KLm1vZGFsLW92ZXJsYXl7ZGlzcGxheTpub25lO3Bvc2l0aW9uOmZpeGVkO2luc2V0OjA7"
"ei1pbmRleDoxMDAwO2JhY2tncm91bmQ6cmdiYSgwLDAsMCwwLjUpO2JhY2tkcm9wLWZpbHRlcjpibHVy"
"KDEycHgpO2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyfQoubW9kYWwtb3Zl"
"cmxheS5vcGVue2Rpc3BsYXk6ZmxleH0KLm1vZGFsLWJveHtiYWNrZ3JvdW5kOnZhcigtLXdoaXRlKTti"
"b3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cy14bCk7d2lkdGg6OTAlO21heC13aWR0aDo5MDBweDttYXgt"
"aGVpZ2h0Ojg1dmg7ZGlzcGxheTpmbGV4O2ZsZXgtZGlyZWN0aW9uOmNvbHVtbjtib3gtc2hhZG93OjAg"
"MjRweCA2NHB4IHJnYmEoMCwwLDAsMC4zKTthbmltYXRpb246ZmFkZVVwIC40cyBlYXNlfQoubW9kYWwt"
"aGRye2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OnNwYWNlLWJl"
"dHdlZW47cGFkZGluZzoxOHB4IDI0cHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0td2hpdGUt"
"Myl9Ci5tb2RhbC10aXRsZXtmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjtmb250LXNpemU6MTZw"
"eDtmb250LXdlaWdodDo4MDA7Y29sb3I6dmFyKC0tdHgtZGFyayk7bGV0dGVyLXNwYWNpbmc6MXB4fQou"
"bW9kYWwtY2xvc2V7cGFkZGluZzo2cHggMTZweDtib3JkZXItcmFkaXVzOjZweDtiYWNrZ3JvdW5kOnZh"
"cigtLXdoaXRlLTIpO2JvcmRlcjoxcHggc29saWQgdmFyKC0td2hpdGUtMyk7Y29sb3I6dmFyKC0tdHgt"
"bXV0ZWQpO2N1cnNvcjpwb2ludGVyO2ZvbnQtc2l6ZToxMXB4O2ZvbnQtd2VpZ2h0OjYwMDtmb250LWZh"
"bWlseTonSUJNIFBsZXggTW9ubycsbW9ub3NwYWNlO3RyYW5zaXRpb246YWxsIC4xNXN9Ci5tb2RhbC1j"
"bG9zZTpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXdoaXRlLTMpfQoubW9kYWwtYm9keXtmbGV4OjE7b3Zl"
"cmZsb3cteTphdXRvO3BhZGRpbmc6MjRweH0KLm1vZGFsLWZvb3RlcntkaXNwbGF5OmZsZXg7Z2FwOjEw"
"cHg7cGFkZGluZzoxNnB4IDI0cHg7Ym9yZGVyLXRvcDoxcHggc29saWQgdmFyKC0td2hpdGUtMyl9Ci5k"
"bC1idG57cGFkZGluZzo4cHggMjBweDtib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cyk7Ym9yZGVyOm5v"
"bmU7Y3Vyc29yOnBvaW50ZXI7Zm9udC1zaXplOjEycHg7Zm9udC13ZWlnaHQ6NzAwO3RyYW5zaXRpb246"
"YWxsIC4ycztmb250LWZhbWlseTonT3V0Zml0JyxzYW5zLXNlcmlmfQouZGwtYnRuLnByaW1hcnl7YmFj"
"a2dyb3VuZDp2YXIoLS1yZWQpO2NvbG9yOiNmZmZ9Ci5kbC1idG4ucHJpbWFyeTpob3ZlcntiYWNrZ3Jv"
"dW5kOnZhcigtLXJlZC1kYXJrKX0KLmRsLWJ0bi5zZWNvbmRhcnl7YmFja2dyb3VuZDp2YXIoLS13aGl0"
"ZS0yKTtjb2xvcjp2YXIoLS10eC1ib2R5KTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLXdoaXRlLTMpfQou"
"ZGwtYnRuLnNlY29uZGFyeTpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXdoaXRlLTMpfQoKLyogUmVwb3J0"
"IGlubmVyICovCi5ycC1oZHJ7dGV4dC1hbGlnbjpjZW50ZXI7cGFkZGluZzoxNnB4IDAgMjBweDtib3Jk"
"ZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTttYXJnaW4tYm90dG9tOjIwcHh9Ci5ycC10"
"e2ZvbnQtZmFtaWx5OidTeW5lJyxzYW5zLXNlcmlmO2ZvbnQtc2l6ZToyMHB4O2ZvbnQtd2VpZ2h0Ojgw"
"MDtjb2xvcjp2YXIoLS1yZWQpO2xldHRlci1zcGFjaW5nOjJweH0KLnJwLXN7Zm9udC1zaXplOjExcHg7"
"Y29sb3I6dmFyKC0tdHgtbXV0ZWQpO21hcmdpbi10b3A6NHB4fQoucnAtc2Vje21hcmdpbi1ib3R0b206"
"MjBweH0KLnJwLXN0e2ZvbnQtZmFtaWx5OidJQk0gUGxleCBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXpl"
"OjExcHg7Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXJlZCk7bGV0dGVyLXNwYWNpbmc6MS41cHg7"
"bWFyZ2luLWJvdHRvbToxMHB4fQoucnAtcHJ7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1u"
"czo4MHB4IDEyMHB4IDgwcHggMWZyO2dhcDo4cHg7cGFkZGluZzo2cHggMDtmb250LXNpemU6MTFweDti"
"b3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKX0KLnJwLXRoe3BhZGRpbmc6MTBweCAx"
"NHB4O21hcmdpbi1ib3R0b206NnB4O2JvcmRlci1yYWRpdXM6dmFyKC0tcmFkaXVzKTtib3JkZXItbGVm"
"dDozcHggc29saWQgdmFyKC0td2hpdGUtNCk7YmFja2dyb3VuZDp2YXIoLS13aGl0ZS0yKX0KLnJwLXRo"
"LkNSSVRJQ0FMe2JvcmRlci1sZWZ0LWNvbG9yOnZhcigtLXNldi1jcml0KX0ucnAtdGguSElHSHtib3Jk"
"ZXItbGVmdC1jb2xvcjp2YXIoLS1zZXYtaGlnaCl9LnJwLXRoLk1FRElVTXtib3JkZXItbGVmdC1jb2xv"
"cjp2YXIoLS1zZXYtbWVkKX0ucnAtdGguTE9Xe2JvcmRlci1sZWZ0LWNvbG9yOnZhcigtLXNldi1sb3cp"
"fQoucnAtdG57Zm9udC13ZWlnaHQ6NzAwO2NvbG9yOnZhcigtLXR4LWRhcmspO2ZvbnQtc2l6ZToxMnB4"
"O21hcmdpbi1ib3R0b206NHB4fQoucnAtdGR7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tdHgtbXV0"
"ZWQpfQoucnAtdGZ7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tc2V2LWxvdyk7bWFyZ2luLXRvcDo0"
"cHh9CgovKiBOT1RJRklDQVRJT04gKi8KLm5vdGlmewogIHBvc2l0aW9uOmZpeGVkO3RvcDoyMHB4O3Jp"
"Z2h0OjIwcHg7ei1pbmRleDoyMDAwOwogIGJhY2tncm91bmQ6dmFyKC0tYmxhY2spO2JvcmRlcjoxcHgg"
"c29saWQgcmdiYSgyMzAsNTcsNzAsMC4yKTsKICBib3JkZXItcmFkaXVzOnZhcigtLXJhZGl1cyk7cGFk"
"ZGluZzoxMnB4IDIwcHg7CiAgY29sb3I6dmFyKC0td2hpdGUpO2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2Vp"
"Z2h0OjYwMDsKICBib3gtc2hhZG93OjAgOHB4IDMwcHggcmdiYSgwLDAsMCwwLjMpOwogIGFuaW1hdGlv"
"bjpmYWRlVXAgLjNzIGVhc2U7Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgU0NBTiBTVEFUVVMgVEFCIFNUWUxFUwogICA9"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09ICovCi5zY2FuLWluZGljYXRvcnsKICB3aWR0aDo0OHB4O2hlaWdodDo0OHB4O2JvcmRlci1yYWRp"
"dXM6NTAlOwogIGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1jb250ZW50OmNl"
"bnRlcjsKICBwb3NpdGlvbjpyZWxhdGl2ZTtmbGV4LXNocmluazowOwogIGJhY2tncm91bmQ6dmFyKC0t"
"d2hpdGUtMik7Ym9yZGVyOjJweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTsKfQouc2Nhbi1pbmRpY2F0b3Iu"
"cnVubmluZ3tiYWNrZ3JvdW5kOnZhcigtLXJlZC1kaW0pO2JvcmRlci1jb2xvcjp2YXIoLS1yZWQtYm9y"
"ZGVyKX0KLnNjYW4taW5kaWNhdG9yLnJ1bm5pbmc6OmFmdGVyewogIGNvbnRlbnQ6Jyc7cG9zaXRpb246"
"YWJzb2x1dGU7aW5zZXQ6LTJweDtib3JkZXItcmFkaXVzOjUwJTsKICBib3JkZXI6MnB4IHNvbGlkIHRy"
"YW5zcGFyZW50O2JvcmRlci10b3AtY29sb3I6dmFyKC0tcmVkKTsKICBhbmltYXRpb246c3BpbiAxcyBs"
"aW5lYXIgaW5maW5pdGU7Cn0KLnNjYW4taW5kaWNhdG9yLmNvbXBsZXRle2JhY2tncm91bmQ6dmFyKC0t"
"c2V2LWxvdy1iZyk7Ym9yZGVyLWNvbG9yOnZhcigtLXNldi1sb3ctYm9yZGVyKX0KLnNjYW4taW5kaWNh"
"dG9yLmVycm9ye2JhY2tncm91bmQ6dmFyKC0tc2V2LWNyaXQtYmcpO2JvcmRlci1jb2xvcjp2YXIoLS1z"
"ZXYtY3JpdC1ib3JkZXIpfQouc2Nhbi1wY3R7Zm9udC1mYW1pbHk6J1N5bmUnLHNhbnMtc2VyaWY7Zm9u"
"dC1zaXplOjEzcHg7Zm9udC13ZWlnaHQ6ODAwO2NvbG9yOnZhcigtLXR4LW11dGVkKX0KLnNjYW4taW5k"
"aWNhdG9yLnJ1bm5pbmcgLnNjYW4tcGN0e2NvbG9yOnZhcigtLXJlZCl9Ci5zY2FuLWluZGljYXRvci5j"
"b21wbGV0ZSAuc2Nhbi1wY3R7Y29sb3I6dmFyKC0tc2V2LWxvdyl9Ci5zY2FuLWluZGljYXRvci5lcnJv"
"ciAuc2Nhbi1wY3R7Y29sb3I6dmFyKC0tc2V2LWNyaXQpfQouc2Nhbi1tZXRhLWl0ZW17CiAgZm9udC1m"
"YW1pbHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTBweDsKICBjb2xvcjp2YXIo"
"LS10eC1tdXRlZCk7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NHB4Owp9Ci5zY2Fu"
"LW1ldGEtaXRlbSAuZG90e3dpZHRoOjVweDtoZWlnaHQ6NXB4O2JvcmRlci1yYWRpdXM6NTAlO2ZsZXgt"
"c2hyaW5rOjB9Ci5zY2FuLWJhci10cmFja3toZWlnaHQ6MTBweDtiYWNrZ3JvdW5kOnZhcigtLXdoaXRl"
"LTMpO2JvcmRlci1yYWRpdXM6MTBweDtvdmVyZmxvdzpoaWRkZW59Ci5zY2FuLWJhci1maWxsLWxpdmV7"
"CiAgaGVpZ2h0OjEwMCU7Ym9yZGVyLXJhZGl1czoxMHB4O3RyYW5zaXRpb246d2lkdGggLjZzIGN1Ymlj"
"LWJlemllciguNCwwLC4yLDEpOwogIGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHZhcigt"
"LXJlZCksdmFyKC0tcmVkLWxpZ2h0KSk7cG9zaXRpb246cmVsYXRpdmU7Cn0KLnNjYW4tYmFyLWZpbGwt"
"bGl2ZS5jb21wbGV0ZXtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1zZXYtbG93"
"KSwjMzRkMzk5KX0KLnNjYW4tYmFyLWZpbGwtbGl2ZTo6YWZ0ZXJ7CiAgY29udGVudDonJztwb3NpdGlv"
"bjphYnNvbHV0ZTtpbnNldDowOwogIGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5z"
"cGFyZW50LHJnYmEoMjU1LDI1NSwyNTUsMC4yNSksdHJhbnNwYXJlbnQpOwogIGFuaW1hdGlvbjpzaGlt"
"bWVyIDEuNXMgaW5maW5pdGU7Cn0KLnRhYi1iYWRnZS5saXZle2Rpc3BsYXk6aW5saW5lLWJsb2NrO2Jh"
"Y2tncm91bmQ6dmFyKC0tcmVkKTtjb2xvcjojZmZmO2FuaW1hdGlvbjpwdWxzZSAxLjVzIGluZmluaXRl"
"fQoudGFiLWJhZGdlLmRvbmV7ZGlzcGxheTppbmxpbmUtYmxvY2s7YmFja2dyb3VuZDp2YXIoLS1zZXYt"
"bG93LWJnKTtjb2xvcjp2YXIoLS1zZXYtbG93KX0KCi8qIE1JTkkgU1RBVFMgSU4gSEVBREVSICovCi5o"
"LW1pbmktc3RhdHN7ZGlzcGxheTpmbGV4O2dhcDoxMHB4fQouaC1taW5pLXN0YXR7CiAgZm9udC1mYW1p"
"bHk6J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTBweDsKICBjb2xvcjp2YXIoLS10"
"eC1vbi1kYXJrLW11dGVkKTtkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDo0cHg7Cn0K"
"LmgtbWluaS1zdGF0IHN0cm9uZ3tjb2xvcjp2YXIoLS13aGl0ZSk7Zm9udC1zaXplOjExcHh9CgovKiBN"
"SU5JIFBST0dSRVNTIEJBUiAoYmVsb3cgaGVhZGVyKSAqLwouaC1taW5pLXByb2dyZXNzewogIGhlaWdo"
"dDozcHg7YmFja2dyb3VuZDp2YXIoLS1ibGFjay0zKTtwb3NpdGlvbjpyZWxhdGl2ZTtvdmVyZmxvdzpo"
"aWRkZW47CiAgb3BhY2l0eTowO3RyYW5zaXRpb246b3BhY2l0eSAuM3M7Cn0KLmgtbWluaS1wcm9ncmVz"
"cy5hY3RpdmV7b3BhY2l0eToxfQouaC1taW5pLWJhcnsKICBoZWlnaHQ6MTAwJTt3aWR0aDowJTsKICBi"
"YWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1yZWQpLHZhcigtLXJlZC1saWdodCkp"
"OwogIHRyYW5zaXRpb246d2lkdGggLjVzIGN1YmljLWJlemllciguNCwwLC4yLDEpO3Bvc2l0aW9uOnJl"
"bGF0aXZlOwp9Ci5oLW1pbmktYmFyOjphZnRlcnsKICBjb250ZW50OicnO3Bvc2l0aW9uOmFic29sdXRl"
"O2luc2V0OjA7CiAgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoOTBkZWcsdHJhbnNwYXJlbnQscmdi"
"YSgyNTUsMjU1LDI1NSwwLjMpLHRyYW5zcGFyZW50KTsKICBhbmltYXRpb246c2hpbW1lciAxLjJzIGlu"
"ZmluaXRlOwp9CgovKiBUQVJHRVQgSElTVE9SWSBEUk9QRE9XTiAqLwouaC10YXJnZXQtaGlzdG9yeXsK"
"ICBkaXNwbGF5Om5vbmU7cG9zaXRpb246YWJzb2x1dGU7dG9wOjEwMCU7bGVmdDowO3JpZ2h0OjA7ei1p"
"bmRleDoxMDA7CiAgYmFja2dyb3VuZDp2YXIoLS1ibGFjay0yKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEo"
"MjU1LDI1NSwyNTUsMC4xKTsKICBib3JkZXItcmFkaXVzOjAgMCB2YXIoLS1yYWRpdXMpIHZhcigtLXJh"
"ZGl1cyk7CiAgYm94LXNoYWRvdzowIDhweCAyNHB4IHJnYmEoMCwwLDAsMC40KTttYXgtaGVpZ2h0OjIw"
"MHB4O292ZXJmbG93LXk6YXV0bzsKfQouaC10YXJnZXQtaGlzdG9yeS5zaG93e2Rpc3BsYXk6YmxvY2t9"
"Ci5oLXRoLWl0ZW17CiAgcGFkZGluZzo4cHggMTRweDtmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS10"
"eC1vbi1kYXJrLW11dGVkKTsKICBjdXJzb3I6cG9pbnRlcjt0cmFuc2l0aW9uOmJhY2tncm91bmQgLjE1"
"czsKICBmb250LWZhbWlseTonSUJNIFBsZXggTW9ubycsbW9ub3NwYWNlO2JvcmRlci1ib3R0b206MXB4"
"IHNvbGlkIHJnYmEoMjU1LDI1NSwyNTUsMC4wNCk7Cn0KLmgtdGgtaXRlbTpob3ZlcntiYWNrZ3JvdW5k"
"OnJnYmEoMjMwLDU3LDcwLDAuMSk7Y29sb3I6dmFyKC0td2hpdGUpfQouaC10aC1pdGVtOmxhc3QtY2hp"
"bGR7Ym9yZGVyLWJvdHRvbTpub25lfQouaC10aC1sYWJlbHtmb250LXNpemU6OXB4O2NvbG9yOnJnYmEo"
"MjU1LDI1NSwyNTUsMC4yNSk7bWFyZ2luLWJvdHRvbToycHg7bGV0dGVyLXNwYWNpbmc6MXB4fQoKLyog"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PQogICBBVFRBQ0sgQ0hBSU4gVklTVUFMSVpBVElPTgogICA9PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCi5jaGFpbi1jYXJkewog"
"IGJhY2tncm91bmQ6dmFyKC0td2hpdGUpO2JvcmRlcjoxcHggc29saWQgdmFyKC0td2hpdGUtMyk7Ym9y"
"ZGVyLXJhZGl1czp2YXIoLS1yYWRpdXMpOwogIHBhZGRpbmc6MjBweDttYXJnaW4tYm90dG9tOjE2cHg7"
"cG9zaXRpb246cmVsYXRpdmU7b3ZlcmZsb3c6aGlkZGVuOwogIGJvcmRlci1sZWZ0OjRweCBzb2xpZCB2"
"YXIoLS13aGl0ZS00KTthbmltYXRpb246ZmFkZVVwIC40cyBlYXNlIGJvdGg7Cn0KLmNoYWluLWNhcmQu"
"Q1JJVElDQUx7Ym9yZGVyLWxlZnQtY29sb3I6I2Q5MDQyOX0KLmNoYWluLWNhcmQuSElHSHtib3JkZXIt"
"bGVmdC1jb2xvcjojZTg1ZDA0fQouY2hhaW4tY2FyZC5NRURJVU17Ym9yZGVyLWxlZnQtY29sb3I6I2Uw"
"OWYzZX0KCi5jaGFpbi1oZWFkZXJ7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmZsZXgtc3RhcnQ7anVz"
"dGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47Z2FwOjEycHg7bWFyZ2luLWJvdHRvbToxNHB4fQouY2hh"
"aW4tbmFtZXtmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjtmb250LXNpemU6MTZweDtmb250LXdl"
"aWdodDo4MDA7Y29sb3I6dmFyKC0tdHgtZGFyayl9Ci5jaGFpbi1raWxsY2hhaW57Zm9udC1mYW1pbHk6"
"J0lCTSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTBweDtjb2xvcjp2YXIoLS10eC1tdXRl"
"ZCk7bWFyZ2luLXRvcDoycHh9Ci5jaGFpbi1jb25maWRlbmNlewogIGZvbnQtZmFtaWx5OidJQk0gUGxl"
"eCBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjExcHg7Zm9udC13ZWlnaHQ6NzAwOwogIHBhZGRpbmc6"
"NHB4IDEwcHg7Ym9yZGVyLXJhZGl1czoyMHB4O3doaXRlLXNwYWNlOm5vd3JhcDsKfQouY2hhaW4tY29u"
"ZmlkZW5jZS5oaWdoe2JhY2tncm91bmQ6dmFyKC0tcmVkLWRpbSk7Y29sb3I6dmFyKC0tcmVkKX0KLmNo"
"YWluLWNvbmZpZGVuY2UubWVke2JhY2tncm91bmQ6cmdiYSgyMjQsMTU5LDYyLDAuMSk7Y29sb3I6I2Uw"
"OWYzZX0KCi8qIEtpbGwgQ2hhaW4gRmxvdyAqLwouY2hhaW4tZmxvd3sKICBkaXNwbGF5OmZsZXg7YWxp"
"Z24taXRlbXM6Y2VudGVyO2dhcDowO21hcmdpbjoxNnB4IDA7cGFkZGluZzoxMnB4IDA7CiAgb3ZlcmZs"
"b3cteDphdXRvOwp9Ci5jaGFpbi1zdGVwewogIGRpc3BsYXk6ZmxleDtmbGV4LWRpcmVjdGlvbjpjb2x1"
"bW47YWxpZ24taXRlbXM6Y2VudGVyO21pbi13aWR0aDoxMjBweDsKICBwb3NpdGlvbjpyZWxhdGl2ZTtm"
"bGV4LXNocmluazowOwp9Ci5jaGFpbi1zdGVwLWRvdHsKICB3aWR0aDozNnB4O2hlaWdodDozNnB4O2Jv"
"cmRlci1yYWRpdXM6NTAlOwogIGRpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7anVzdGlmeS1j"
"b250ZW50OmNlbnRlcjsKICBmb250LXNpemU6MTRweDtmb250LXdlaWdodDo4MDA7Y29sb3I6I2ZmZjtw"
"b3NpdGlvbjpyZWxhdGl2ZTt6LWluZGV4OjI7Cn0KLmNoYWluLXN0ZXAtZG90LmNvbmZpcm1lZHtiYWNr"
"Z3JvdW5kOnZhcigtLXJlZCk7Ym94LXNoYWRvdzowIDAgMTJweCByZ2JhKDIzMCw1Nyw3MCwwLjMpfQou"
"Y2hhaW4tc3RlcC1kb3Qubm90X2ZvdW5ke2JhY2tncm91bmQ6dmFyKC0td2hpdGUtMyk7Y29sb3I6dmFy"
"KC0tdHgtZmFpbnQpfQouY2hhaW4tc3RlcC1waGFzZXsKICBmb250LWZhbWlseTonSUJNIFBsZXggTW9u"
"bycsbW9ub3NwYWNlO2ZvbnQtc2l6ZTo4cHg7Zm9udC13ZWlnaHQ6NzAwOwogIGxldHRlci1zcGFjaW5n"
"OjFweDtjb2xvcjp2YXIoLS10eC1mYWludCk7bWFyZ2luLXRvcDo2cHg7Cn0KLmNoYWluLXN0ZXAtbGFi"
"ZWx7CiAgZm9udC1zaXplOjEwcHg7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpO3RleHQtYWxpZ246Y2VudGVy"
"O21hcmdpbi10b3A6M3B4OwogIG1heC13aWR0aDoxMTBweDtsaW5lLWhlaWdodDoxLjM7Cn0KLmNoYWlu"
"LWFycm93ewogIHdpZHRoOjQwcHg7aGVpZ2h0OjJweDtiYWNrZ3JvdW5kOnZhcigtLXdoaXRlLTQpO3Bv"
"c2l0aW9uOnJlbGF0aXZlO2ZsZXgtc2hyaW5rOjA7CiAgbWFyZ2luLXRvcDotMjBweDsKfQouY2hhaW4t"
"YXJyb3cuY29uZmlybWVke2JhY2tncm91bmQ6dmFyKC0tcmVkKX0KLmNoYWluLWFycm93OjphZnRlcnsK"
"ICBjb250ZW50OifigLonO3Bvc2l0aW9uOmFic29sdXRlO3JpZ2h0Oi00cHg7dG9wOi04cHg7CiAgZm9u"
"dC1zaXplOjE0cHg7Y29sb3I6aW5oZXJpdDsKfQouY2hhaW4tYXJyb3cuY29uZmlybWVkOjphZnRlcntj"
"b2xvcjp2YXIoLS1yZWQpfQoKLyogSW1wYWN0ICYgQnVzaW5lc3MgKi8KLmNoYWluLWltcGFjdHsKICBi"
"YWNrZ3JvdW5kOnJnYmEoMjE3LDQsNDEsMC4wNCk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDIxNyw0LDQx"
"LDAuMSk7CiAgYm9yZGVyLXJhZGl1czo4cHg7cGFkZGluZzoxMnB4IDE0cHg7bWFyZ2luOjEycHggMDsK"
"fQouY2hhaW4taW1wYWN0LXRpdGxle2ZvbnQtc2l6ZTo5cHg7Zm9udC13ZWlnaHQ6NzAwO2xldHRlci1z"
"cGFjaW5nOjEuNXB4O2NvbG9yOnZhcigtLXJlZCk7bWFyZ2luLWJvdHRvbTo0cHh9Ci5jaGFpbi1pbXBh"
"Y3QtdGV4dHtmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS10eC1kYXJrKTtsaW5lLWhlaWdodDoxLjV9"
"Ci5jaGFpbi1idXNpbmVzc3sKICBiYWNrZ3JvdW5kOnJnYmEoMTAsMTAsMTIsMC4wMyk7Ym9yZGVyOjFw"
"eCBzb2xpZCB2YXIoLS13aGl0ZS0zKTsKICBib3JkZXItcmFkaXVzOjhweDtwYWRkaW5nOjEycHggMTRw"
"eDttYXJnaW46OHB4IDA7Cn0KLmNoYWluLWJ1c2luZXNzLXRpdGxle2ZvbnQtc2l6ZTo5cHg7Zm9udC13"
"ZWlnaHQ6NzAwO2xldHRlci1zcGFjaW5nOjEuNXB4O2NvbG9yOnZhcigtLXR4LW11dGVkKTttYXJnaW4t"
"Ym90dG9tOjRweH0KLmNoYWluLWNvc3R7Zm9udC1mYW1pbHk6J1N5bmUnLHNhbnMtc2VyaWY7Zm9udC13"
"ZWlnaHQ6ODAwO2NvbG9yOnZhcigtLXJlZCk7Zm9udC1zaXplOjE0cHg7bWFyZ2luLXRvcDo0cHh9Cgov"
"KiBGaXggU2VjdGlvbiAqLwouY2hhaW4tZml4ewogIGJhY2tncm91bmQ6cmdiYSg0NSwxMDYsNzksMC4w"
"NCk7Ym9yZGVyOjFweCBzb2xpZCByZ2JhKDQ1LDEwNiw3OSwwLjEyKTsKICBib3JkZXItcmFkaXVzOjhw"
"eDtwYWRkaW5nOjEycHggMTRweDttYXJnaW4tdG9wOjEwcHg7Cn0KLmNoYWluLWZpeC10aXRsZXtmb250"
"LXNpemU6OXB4O2ZvbnQtd2VpZ2h0OjcwMDtsZXR0ZXItc3BhY2luZzoxLjVweDtjb2xvcjp2YXIoLS1z"
"ZXYtbG93KTttYXJnaW4tYm90dG9tOjZweH0KLmNoYWluLWZpeC1jbWR7CiAgZm9udC1mYW1pbHk6J0lC"
"TSBQbGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTFweDsKICBjb2xvcjp2YXIoLS10eC1kYXJr"
"KTtsaW5lLWhlaWdodDoxLjg7d2hpdGUtc3BhY2U6cHJlLXdyYXA7Cn0KCi8qIENvbXBsaWFuY2UgVGFn"
"cyAqLwouY2hhaW4tY29tcGxpYW5jZXtkaXNwbGF5OmZsZXg7ZmxleC13cmFwOndyYXA7Z2FwOjZweDtt"
"YXJnaW4tdG9wOjEwcHh9Ci5jaGFpbi1jb21wLXRhZ3sKICBmb250LWZhbWlseTonSUJNIFBsZXggTW9u"
"bycsbW9ub3NwYWNlO2ZvbnQtc2l6ZTo5cHg7Zm9udC13ZWlnaHQ6NjAwOwogIHBhZGRpbmc6M3B4IDhw"
"eDtib3JkZXItcmFkaXVzOjRweDsKICBiYWNrZ3JvdW5kOnZhcigtLXdoaXRlLTIpO2JvcmRlcjoxcHgg"
"c29saWQgdmFyKC0td2hpdGUtMyk7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpOwp9CgovKiBTdW1tYXJ5IFN0"
"YXRzICovCi5jaGFpbi1zdW1tYXJ5ewogIGRpc3BsYXk6Z3JpZDtncmlkLXRlbXBsYXRlLWNvbHVtbnM6"
"cmVwZWF0KDQsMWZyKTtnYXA6MTJweDttYXJnaW4tYm90dG9tOjIwcHg7Cn0KLmNoYWluLXN0YXR7CiAg"
"YmFja2dyb3VuZDp2YXIoLS13aGl0ZSk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS13aGl0ZS0zKTtib3Jk"
"ZXItcmFkaXVzOnZhcigtLXJhZGl1cyk7CiAgcGFkZGluZzoxNnB4O3RleHQtYWxpZ246Y2VudGVyOwp9"
"Ci5jaGFpbi1zdGF0LW51bXtmb250LWZhbWlseTonU3luZScsc2Fucy1zZXJpZjtmb250LXNpemU6Mjhw"
"eDtmb250LXdlaWdodDo4MDB9Ci5jaGFpbi1zdGF0LWxhYmVse2ZvbnQtc2l6ZToxMHB4O2NvbG9yOnZh"
"cigtLXR4LW11dGVkKTttYXJnaW4tdG9wOjRweDtsZXR0ZXItc3BhY2luZzowLjVweH0KCi8qIFJlcG9y"
"dCBCdXR0b24gKi8KLmJ0bi1hZHYtcmVwb3J0ewogIGJhY2tncm91bmQ6dmFyKC0tYmxhY2spO2NvbG9y"
"OnZhcigtLXdoaXRlKTtib3JkZXI6bm9uZTsKICBwYWRkaW5nOjEwcHggMjBweDtib3JkZXItcmFkaXVz"
"OnZhcigtLXJhZGl1cyk7Y3Vyc29yOnBvaW50ZXI7CiAgZm9udC1mYW1pbHk6J091dGZpdCcsc2Fucy1z"
"ZXJpZjtmb250LXNpemU6MTJweDtmb250LXdlaWdodDo2MDA7CiAgdHJhbnNpdGlvbjphbGwgLjJzOwp9"
"Ci5idG4tYWR2LXJlcG9ydDpob3ZlcntiYWNrZ3JvdW5kOnZhcigtLXJlZCl9CgpAbWVkaWEobWF4LXdp"
"ZHRoOjkwMHB4KXsuc2lkZWJhcntkaXNwbGF5Om5vbmV9LmRhc2gtZ3JpZC5jb2xzLTQsLmNoYWluLXN1"
"bW1hcnl7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgyLDFmcil9fQo8L3N0eWxlPgo8L2hlYWQ+"
"Cjxib2R5Pgo8ZGl2IGNsYXNzPSJhcHAiPgoKPCEtLSA9PT09PT09PT09PT09PT09IFNJREVCQVIgPT09"
"PT09PT09PT09PT09PSAtLT4KPGFzaWRlIGNsYXNzPSJzaWRlYmFyIj4KICA8ZGl2IGNsYXNzPSJzaWRl"
"YmFyLXNjcm9sbCI+CiAgICA8ZGl2IGNsYXNzPSJzLWxvZ28iPgogICAgICA8ZGl2IGNsYXNzPSJzLWxv"
"Z28tbWFyayI+SDwvZGl2PgogICAgICA8ZGl2PjxkaXYgY2xhc3M9InMtbG9nby10ZXh0Ij5IQVJTSEE8"
"L2Rpdj48ZGl2IGNsYXNzPSJzLWxvZ28tc3ViIj5WQVBUIFNVSVRFIHY3LjA8L2Rpdj48L2Rpdj4KICAg"
"IDwvZGl2PgoKICAgIDwhLS0gU0VBUkNIIC0tPgogICAgPGRpdiBjbGFzcz0icy1zZWFyY2giPgogICAg"
"ICA8c3BhbiBjbGFzcz0icy1zZWFyY2gtaWNvbiI+8J+UjTwvc3Bhbj4KICAgICAgPGlucHV0IHR5cGU9"
"InRleHQiIGNsYXNzPSJzLXNlYXJjaC1pbnB1dCIgaWQ9InRvb2wtc2VhcmNoIiBwbGFjZWhvbGRlcj0i"
"U2VhcmNoIHRvb2xzLi4uIiBvbmlucHV0PSJmaWx0ZXJUb29scyh0aGlzLnZhbHVlKSI+CiAgICA8L2Rp"
"dj4KCiAgICA8IS0tIE5FVFdPUksgLS0+CiAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rpb24gb3BlbiIgZGF0"
"YS1zZWN0aW9uPSJuZXQiPgogICAgICA8ZGl2IGNsYXNzPSJzLXNlY3Rpb24taGVhZGVyIiBvbmNsaWNr"
"PSJ0b2dnbGVTZWN0aW9uKHRoaXMpIj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWljb24i"
"PvCfk6E8L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi10aXRsZSI+TmV0d29yazwv"
"c3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWNvdW50Ij45PC9zcGFuPgogICAgICAg"
"IDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tYXJyb3ciPuKWvDwvc3Bhbj4KICAgICAgPC9kaXY+CiAgICAg"
"IDxkaXYgY2xhc3M9InMtc2VjdGlvbi1ib2R5Ij4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIg"
"b25jbGljaz0icnVuVG9vbCgnbm1hcF9zY2FuJyx0aGlzLCduZXQnKSIgZGF0YS1uYW1lPSJwb3J0IHNj"
"YW5uZXIgbm1hcCI+PHNwYW4gY2xhc3M9ImljbyI+8J+UjTwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5Q"
"b3J0IFNjYW5uZXI8L3NwYW4+PHNwYW4gY2xhc3M9InMtdGFnIHIiPkNPUkU8L3NwYW4+PC9idXR0b24+"
"CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ25tYXBfdG9wMTAw"
"Jyx0aGlzLCduZXQnKSIgZGF0YS1uYW1lPSJxdWljayB0b3AgMTAwIGZhc3QiPjxzcGFuIGNsYXNzPSJp"
"Y28iPuKaoTwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5RdWljayBUb3AgMTAwPC9zcGFuPjwvYnV0dG9u"
"PgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdubWFwX3Z1bG4n"
"LHRoaXMsJ25ldCcpIiBkYXRhLW5hbWU9InZ1bG5lcmFiaWxpdHkgY3ZlIHNjYW4iPjxzcGFuIGNsYXNz"
"PSJpY28iPvCfm6E8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+VnVsbiBTY2FuPC9zcGFuPjxzcGFuIGNs"
"YXNzPSJzLXRhZyByIj5DVkU8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1u"
"YXYiIG9uY2xpY2s9InJ1blRvb2woJ3VkcF9zY2FuJyx0aGlzLCduZXQnKSIgZGF0YS1uYW1lPSJ1ZHAg"
"c2NhbiI+PHNwYW4gY2xhc3M9ImljbyI+8J+ToTwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5VRFAgU2Nh"
"bjwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVu"
"VG9vbCgnZmlyZXdhbGxfZGV0ZWN0Jyx0aGlzLCduZXQnKSIgZGF0YS1uYW1lPSJmaXJld2FsbCBkZXRl"
"Y3Qgd2FmIj48c3BhbiBjbGFzcz0iaWNvIj7wn6exPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkZpcmV3"
"YWxsIERldGVjdDwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25j"
"bGljaz0icnVuVG9vbCgnc21iX2VudW0nLHRoaXMsJ25ldCcpIiBkYXRhLW5hbWU9InNtYiBlbnVtIHNo"
"YXJlIj48c3BhbiBjbGFzcz0iaWNvIj7wn5OCPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPlNNQiBFbnVt"
"PC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5U"
"b29sKCdzbm1wX2NoZWNrJyx0aGlzLCduZXQnKSIgZGF0YS1uYW1lPSJzbm1wIGNoZWNrIGNvbW11bml0"
"eSI+PHNwYW4gY2xhc3M9ImljbyI+8J+Tijwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5TTk1QIENoZWNr"
"PC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5U"
"b29sKCdiYW5uZXJfZ3JhYicsdGhpcywnbmV0JykiIGRhdGEtbmFtZT0iYmFubmVyIGdyYWIgc2Vydmlj"
"ZSB2ZXJzaW9uIj48c3BhbiBjbGFzcz0iaWNvIj7wn4+3PC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkJh"
"bm5lciBHcmFiPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNs"
"aWNrPSJydW5Ub29sKCdhcnBfc2NhbicsdGhpcywnbmV0JykiIGRhdGEtbmFtZT0iYXJwIHNjYW4gbG9j"
"YWwiPjxzcGFuIGNsYXNzPSJpY28iPvCfk4s8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+QVJQIFNjYW48"
"L3NwYW4+PC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CgogICAgPCEtLSBXRUIgLS0+CiAg"
"ICA8ZGl2IGNsYXNzPSJzLXNlY3Rpb24gb3BlbiIgZGF0YS1zZWN0aW9uPSJ3ZWIiPgogICAgICA8ZGl2"
"IGNsYXNzPSJzLXNlY3Rpb24taGVhZGVyIiBvbmNsaWNrPSJ0b2dnbGVTZWN0aW9uKHRoaXMpIj4KICAg"
"ICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWljb24iPvCfjJA8L3NwYW4+CiAgICAgICAgPHNwYW4g"
"Y2xhc3M9InMtc2VjdGlvbi10aXRsZSI+V2ViPC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNl"
"Y3Rpb24tY291bnQiPjEwPC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tYXJyb3ci"
"PuKWvDwvc3Bhbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbi1ib2R5Ij4K"
"ICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnc3FsbWFwX2NoZWNr"
"Jyx0aGlzLCd3ZWInKSIgZGF0YS1uYW1lPSJzcWwgaW5qZWN0aW9uIHNxbGkgc3FsbWFwIj48c3BhbiBj"
"bGFzcz0iaWNvIj7wn5KJPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPlNRTCBJbmplY3Rpb248L3NwYW4+"
"PHNwYW4gY2xhc3M9InMtdGFnIHIiPkNSSVQ8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBj"
"bGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ3hzc19zY2FuJyx0aGlzLCd3ZWInKSIgZGF0YS1u"
"YW1lPSJ4c3MgY3Jvc3Mgc2l0ZSBzY3JpcHRpbmciPjxzcGFuIGNsYXNzPSJpY28iPuKaoDwvc3Bhbj48"
"c3BhbiBjbGFzcz0ibGJsIj5YU1MgU2Nhbm5lcjwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9u"
"IGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnbmlrdG9fc2NhbicsdGhpcywnd2ViJykiIGRh"
"dGEtbmFtZT0ibmlrdG8gd2ViIHNjYW4iPjxzcGFuIGNsYXNzPSJpY28iPvCfjJA8L3NwYW4+PHNwYW4g"
"Y2xhc3M9ImxibCI+TmlrdG8gU2Nhbjwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNz"
"PSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnaGVhZGVyX2NoZWNrJyx0aGlzLCd3ZWInKSIgZGF0YS1u"
"YW1lPSJoZWFkZXIgYXVkaXQgaHR0cCBzZWN1cml0eSI+PHNwYW4gY2xhc3M9ImljbyI+8J+Tizwvc3Bh"
"bj48c3BhbiBjbGFzcz0ibGJsIj5IZWFkZXIgQXVkaXQ8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1"
"dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ3NzbF9jaGVjaycsdGhpcywnd2ViJyki"
"IGRhdGEtbmFtZT0ic3NsIHRscyBjZXJ0aWZpY2F0ZSBodHRwcyI+PHNwYW4gY2xhc3M9ImljbyI+8J+U"
"kjwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5TU0wvVExTIENoZWNrPC9zcGFuPjwvYnV0dG9uPgogICAg"
"ICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCd3YWZfZGV0ZWN0Jyx0aGlz"
"LCd3ZWInKSIgZGF0YS1uYW1lPSJ3YWYgd2ViIGFwcGxpY2F0aW9uIGZpcmV3YWxsIj48c3BhbiBjbGFz"
"cz0iaWNvIj7wn5uhPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPldBRiBEZXRlY3Q8L3NwYW4+PC9idXR0"
"b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ2NvcnNfY2hl"
"Y2snLHRoaXMsJ3dlYicpIiBkYXRhLW5hbWU9ImNvcnMgY3Jvc3Mgb3JpZ2luIj48c3BhbiBjbGFzcz0i"
"aWNvIj7wn5SXPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkNPUlMgQ2hlY2s8L3NwYW4+PC9idXR0b24+"
"CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ2Rpcl9lbnVtJyx0"
"aGlzLCd3ZWInKSIgZGF0YS1uYW1lPSJkaXJlY3RvcnkgZW51bWVyYXRpb24gYnJ1dGUgZGlyYnVzdGVy"
"Ij48c3BhbiBjbGFzcz0iaWNvIj7wn5OBPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkRpcmVjdG9yeSBF"
"bnVtPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJy"
"dW5Ub29sKCdjbXNfZGV0ZWN0Jyx0aGlzLCd3ZWInKSIgZGF0YS1uYW1lPSJjbXMgZGV0ZWN0IHdvcmRw"
"cmVzcyBqb29tbGEgZHJ1cGFsIj48c3BhbiBjbGFzcz0iaWNvIj7wn4+XPC9zcGFuPjxzcGFuIGNsYXNz"
"PSJsYmwiPkNNUyBEZXRlY3Q8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1u"
"YXYiIG9uY2xpY2s9InJ1blRvb2woJ2FkbWluX2ZpbmRlcicsdGhpcywnd2ViJykiIGRhdGEtbmFtZT0i"
"YWRtaW4gZmluZGVyIHBhbmVsIGxvZ2luIj48c3BhbiBjbGFzcz0iaWNvIj7wn5SRPC9zcGFuPjxzcGFu"
"IGNsYXNzPSJsYmwiPkFkbWluIEZpbmRlcjwvc3Bhbj48L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICA8"
"L2Rpdj4KCiAgICA8IS0tIElORlJBU1RSVUNUVVJFIC0tPgogICAgPGRpdiBjbGFzcz0icy1zZWN0aW9u"
"IiBkYXRhLXNlY3Rpb249ImluZiI+CiAgICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbi1oZWFkZXIiIG9u"
"Y2xpY2s9InRvZ2dsZVNlY3Rpb24odGhpcykiPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24t"
"aWNvbiI+8J+WpTwvc3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLXRpdGxlIj5JbmZy"
"YXN0cnVjdHVyZTwvc3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWNvdW50Ij42PC9z"
"cGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tYXJyb3ciPuKWvDwvc3Bhbj4KICAgICAg"
"PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbi1ib2R5Ij4KICAgICAgICA8YnV0dG9uIGNs"
"YXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnc3NoX2F1ZGl0Jyx0aGlzLCdpbmYnKSIgZGF0YS1u"
"YW1lPSJzc2ggYXVkaXQga2V5Ij48c3BhbiBjbGFzcz0iaWNvIj7wn5SQPC9zcGFuPjxzcGFuIGNsYXNz"
"PSJsYmwiPlNTSCBBdWRpdDwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5h"
"diIgb25jbGljaz0icnVuVG9vbCgnZnRwX2NoZWNrJyx0aGlzLCdpbmYnKSIgZGF0YS1uYW1lPSJmdHAg"
"YW5vbnltb3VzIGNoZWNrIj48c3BhbiBjbGFzcz0iaWNvIj7wn5OkPC9zcGFuPjxzcGFuIGNsYXNzPSJs"
"YmwiPkZUUCBDaGVjazwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIg"
"b25jbGljaz0icnVuVG9vbCgncmRwX2NoZWNrJyx0aGlzLCdpbmYnKSIgZGF0YS1uYW1lPSJyZHAgcmVt"
"b3RlIGRlc2t0b3AgYmx1ZWtlZXAiPjxzcGFuIGNsYXNzPSJpY28iPvCflqU8L3NwYW4+PHNwYW4gY2xh"
"c3M9ImxibCI+UkRQIENoZWNrPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9InMt"
"bmF2IiBvbmNsaWNrPSJydW5Ub29sKCdkYl9leHBvc2UnLHRoaXMsJ2luZicpIiBkYXRhLW5hbWU9ImRh"
"dGFiYXNlIGV4cG9zdXJlIG15c3FsIHBvc3RncmVzIHJlZGlzIG1vbmdvIj48c3BhbiBjbGFzcz0iaWNv"
"Ij7wn5eEPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkRCIEV4cG9zdXJlPC9zcGFuPjwvYnV0dG9uPgog"
"ICAgICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdkb2NrZXJfY2hlY2sn"
"LHRoaXMsJ2luZicpIiBkYXRhLW5hbWU9ImRvY2tlciBjb250YWluZXIgYXBpIj48c3BhbiBjbGFzcz0i"
"aWNvIj7wn5CzPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkRvY2tlciBDaGVjazwvc3Bhbj48L2J1dHRv"
"bj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnazhzX2NoZWNr"
"Jyx0aGlzLCdpbmYnKSIgZGF0YS1uYW1lPSJrdWJlcm5ldGVzIGs4cyBjbHVzdGVyIj48c3BhbiBjbGFz"
"cz0iaWNvIj7imLg8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+SzhzIENoZWNrPC9zcGFuPjwvYnV0dG9u"
"PgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgoKICAgIDwhLS0gTlVDTEVJIC0tPgogICAgPGRpdiBjbGFz"
"cz0icy1zZWN0aW9uIiBkYXRhLXNlY3Rpb249Im51YyI+CiAgICAgIDxkaXYgY2xhc3M9InMtc2VjdGlv"
"bi1oZWFkZXIiIG9uY2xpY2s9InRvZ2dsZVNlY3Rpb24odGhpcykiPgogICAgICAgIDxzcGFuIGNsYXNz"
"PSJzLXNlY3Rpb24taWNvbiI+4piiPC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24t"
"dGl0bGUiPk51Y2xlaTwvc3Bhbj4KICAgICAgICA8c3BhbiBjbGFzcz0icy1zZWN0aW9uLWNvdW50Ij42"
"PC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tYXJyb3ciPuKWvDwvc3Bhbj4KICAg"
"ICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9InMtc2VjdGlvbi1ib2R5Ij4KICAgICAgICA8YnV0dG9u"
"IGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnbnVjbGVpX2Z1bGwnLHRoaXMsJ3dlYicpIiBk"
"YXRhLW5hbWU9Im51Y2xlaSBmdWxsIHNjYW4gYWxsIHRlbXBsYXRlcyI+PHNwYW4gY2xhc3M9ImljbyI+"
"4piiPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPkZ1bGwgU2Nhbjwvc3Bhbj48c3BhbiBjbGFzcz0icy10"
"YWcgciI+Q09SRTwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25j"
"bGljaz0icnVuVG9vbCgnbnVjbGVpX2N2ZScsdGhpcywnd2ViJykiIGRhdGEtbmFtZT0ibnVjbGVpIGN2"
"ZSB2dWxuZXJhYmlsaXR5Ij48c3BhbiBjbGFzcz0iaWNvIj7wn5SlPC9zcGFuPjxzcGFuIGNsYXNzPSJs"
"YmwiPkNWRSBTY2FuPC9zcGFuPjxzcGFuIGNsYXNzPSJzLXRhZyByIj5DVkU8L3NwYW4+PC9idXR0b24+"
"CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ251Y2xlaV9jcml0"
"aWNhbCcsdGhpcywnd2ViJykiIGRhdGEtbmFtZT0ibnVjbGVpIGNyaXRpY2FsIGhpZ2ggc2V2ZXJpdHki"
"PjxzcGFuIGNsYXNzPSJpY28iPvCfmqg8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+Q3JpdGljYWwvSGln"
"aDwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJzLW5hdiIgb25jbGljaz0icnVu"
"VG9vbCgnbnVjbGVpX21pc2NvbmZpZycsdGhpcywnd2ViJykiIGRhdGEtbmFtZT0ibnVjbGVpIG1pc2Nv"
"bmZpZ3VyYXRpb24gZXhwb3NlZCI+PHNwYW4gY2xhc3M9ImljbyI+4pqZPC9zcGFuPjxzcGFuIGNsYXNz"
"PSJsYmwiPk1pc2NvbmZpZyBTY2FuPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9"
"InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdudWNsZWlfdGVjaCcsdGhpcywnd2ViJykiIGRhdGEtbmFt"
"ZT0ibnVjbGVpIHRlY2hub2xvZ3kgZGV0ZWN0IGZpbmdlcnByaW50Ij48c3BhbiBjbGFzcz0iaWNvIj7w"
"n5SsPC9zcGFuPjxzcGFuIGNsYXNzPSJsYmwiPlRlY2ggRGV0ZWN0PC9zcGFuPjwvYnV0dG9uPgogICAg"
"ICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdudWNsZWlfbmV0d29yaycs"
"dGhpcywnaW5mJykiIGRhdGEtbmFtZT0ibnVjbGVpIG5ldHdvcmsgcHJvdG9jb2wiPjxzcGFuIGNsYXNz"
"PSJpY28iPvCfjJA8L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+TmV0d29yayBTY2FuPC9zcGFuPjwvYnV0"
"dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgoKICAgIDwhLS0gUkVDT04gLS0+CiAgICA8ZGl2IGNs"
"YXNzPSJzLXNlY3Rpb24iIGRhdGEtc2VjdGlvbj0icmVjIj4KICAgICAgPGRpdiBjbGFzcz0icy1zZWN0"
"aW9uLWhlYWRlciIgb25jbGljaz0idG9nZ2xlU2VjdGlvbih0aGlzKSI+CiAgICAgICAgPHNwYW4gY2xh"
"c3M9InMtc2VjdGlvbi1pY29uIj7wn5W1PC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rp"
"b24tdGl0bGUiPlJlY29uPC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzLXNlY3Rpb24tY291bnQi"
"Pjc8L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9InMtc2VjdGlvbi1hcnJvdyI+4pa8PC9zcGFuPgog"
"ICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0icy1zZWN0aW9uLWJvZHkiPgogICAgICAgIDxidXR0"
"b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCd3aG9pcycsdGhpcywncmVjJykiIGRhdGEt"
"bmFtZT0id2hvaXMgZG9tYWluIHJlZ2lzdHJhdGlvbiI+PHNwYW4gY2xhc3M9ImljbyI+8J+MjTwvc3Bh"
"bj48c3BhbiBjbGFzcz0ibGJsIj5XSE9JUzwvc3Bhbj48L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIGNs"
"YXNzPSJzLW5hdiIgb25jbGljaz0icnVuVG9vbCgnZG5zX2xvb2t1cCcsdGhpcywncmVjJykiIGRhdGEt"
"bmFtZT0iZG5zIGxvb2t1cCByZWNvcmRzIj48c3BhbiBjbGFzcz0iaWNvIj7wn5OhPC9zcGFuPjxzcGFu"
"IGNsYXNzPSJsYmwiPkROUyBMb29rdXA8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFz"
"cz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ3N1YmRvbWFpbl9lbnVtJyx0aGlzLCdyZWMnKSIgZGF0"
"YS1uYW1lPSJzdWJkb21haW4gZW51bWVyYXRpb24iPjxzcGFuIGNsYXNzPSJpY28iPvCflI48L3NwYW4+"
"PHNwYW4gY2xhc3M9ImxibCI+U3ViZG9tYWluIEVudW08L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1"
"dHRvbiBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ3RyYWNlcm91dGUnLHRoaXMsJ3JlYycp"
"IiBkYXRhLW5hbWU9InRyYWNlcm91dGUgaG9wcyI+PHNwYW4gY2xhc3M9ImljbyI+8J+bpDwvc3Bhbj48"
"c3BhbiBjbGFzcz0ibGJsIj5UcmFjZXJvdXRlPC9zcGFuPjwvYnV0dG9uPgogICAgICAgIDxidXR0b24g"
"Y2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCduZXR3b3JrX3NjYW4nLHRoaXMsJ3JlYycpIiBk"
"YXRhLW5hbWU9ImxvY2FsIG5ldHdvcmsgc2NhbiBkaXNjb3ZlciI+PHNwYW4gY2xhc3M9ImljbyI+8J+T"
"tjwvc3Bhbj48c3BhbiBjbGFzcz0ibGJsIj5Mb2NhbCBOZXR3b3JrPC9zcGFuPjwvYnV0dG9uPgogICAg"
"ICAgIDxidXR0b24gY2xhc3M9InMtbmF2IiBvbmNsaWNrPSJydW5Ub29sKCdteV9pcCcsdGhpcywncmVj"
"JykiIGRhdGEtbmFtZT0ibXkgaXAgYWRkcmVzcyBwdWJsaWMiPjxzcGFuIGNsYXNzPSJpY28iPvCfj6A8"
"L3NwYW4+PHNwYW4gY2xhc3M9ImxibCI+TXkgSVA8L3NwYW4+PC9idXR0b24+CiAgICAgICAgPGJ1dHRv"
"biBjbGFzcz0icy1uYXYiIG9uY2xpY2s9InJ1blRvb2woJ3N5c3RlbV9pbmZvJyx0aGlzLCdyZWMnKSIg"
"ZGF0YS1uYW1lPSJzeXN0ZW0gaW5mbyBjcHUgcmFtIG9zIj48c3BhbiBjbGFzcz0iaWNvIj7wn5K7PC9z"
"cGFuPjxzcGFuIGNsYXNzPSJsYmwiPlN5c3RlbSBJbmZvPC9zcGFuPjwvYnV0dG9uPgogICAgICA8L2Rp"
"dj4KICAgIDwvZGl2PgogIDwvZGl2PgogIDxkaXYgY2xhc3M9InMtZm9vdGVyIj4KICAgIDxkaXYgY2xh"
"c3M9InMtYXZhdGFyIj5IQTwvZGl2PgogICAgPGRpdj48ZGl2IGNsYXNzPSJzLXVuYW1lIj5IQVJTSEE8"
"L2Rpdj48ZGl2IGNsYXNzPSJzLXVyb2xlIj5MZXZlbCA1IMK3IDM4IFRvb2xzIEFybWVkPC9kaXY+PC9k"
"aXY+CiAgPC9kaXY+CjwvYXNpZGU+Cgo8IS0tID09PT09PT09PT09PT09PT0gTUFJTiA9PT09PT09PT09"
"PT09PT09IC0tPgo8ZGl2IGNsYXNzPSJtYWluIj4KICA8aGVhZGVyIGNsYXNzPSJoZWFkZXIiPgogICAg"
"PGRpdiBjbGFzcz0iaC1sZWZ0Ij4KICAgICAgPGRpdiBjbGFzcz0iaC10aXRsZSI+VkFQVCBEYXNoYm9h"
"cmQ8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iaC1zZXAiPjwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJo"
"LXRhcmdldCIgc3R5bGU9InBvc2l0aW9uOnJlbGF0aXZlIj4KICAgICAgICA8ZGl2IGNsYXNzPSJoLXRh"
"cmdldC1wcmUiPlRBUkdFVDwvZGl2PgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0idGFyZ2V0"
"LWlucHV0IiBjbGFzcz0iaC10YXJnZXQtaW5wdXQiIHBsYWNlaG9sZGVyPSJFbnRlciBJUCwgZG9tYWlu"
"LCBvciBVUkwuLi4iIG9uZm9jdXM9InNob3dUYXJnZXRIaXN0b3J5KCkiIG9uaW5wdXQ9InNob3dUYXJn"
"ZXRIaXN0b3J5KCkiIGF1dG9jb21wbGV0ZT0ib2ZmIj4KICAgICAgICA8ZGl2IGNsYXNzPSJoLXRhcmdl"
"dC1oaXN0b3J5IiBpZD0idGFyZ2V0LWhpc3RvcnkiPjwvZGl2PgogICAgICA8L2Rpdj4KICAgIDwvZGl2"
"PgogICAgPGRpdiBjbGFzcz0iaC1yaWdodCI+CiAgICAgIDxkaXYgY2xhc3M9ImgtbWluaS1zdGF0cyIg"
"aWQ9ImgtbWluaS1zdGF0cyI+CiAgICAgICAgPHNwYW4gY2xhc3M9ImgtbWluaS1zdGF0IiB0aXRsZT0i"
"U2NhbnMiPvCflI0gPHN0cm9uZyBpZD0iaG0tc2NhbnMiPjA8L3N0cm9uZz48L3NwYW4+CiAgICAgICAg"
"PHNwYW4gY2xhc3M9ImgtbWluaS1zdGF0IiB0aXRsZT0iUG9ydHMiPvCfk6EgPHN0cm9uZyBpZD0iaG0t"
"cG9ydHMiPjA8L3N0cm9uZz48L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9ImgtbWluaS1zdGF0IiB0"
"aXRsZT0iVGhyZWF0cyI+4pqgIDxzdHJvbmcgaWQ9ImhtLXRocmVhdHMiPjA8L3N0cm9uZz48L3NwYW4+"
"CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJoLXN0YXR1cyI+PHNwYW4gY2xhc3M9ImRvdCI+"
"PC9zcGFuPk9OTElORTwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJoLWNsb2NrIiBpZD0iY2xvY2siPjwv"
"ZGl2PgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4tcmVwb3J0IiBvbmNsaWNrPSJvcGVuUmVwb3J0KCki"
"PvCfk4QgUmVwb3J0PC9idXR0b24+CiAgICA8L2Rpdj4KICA8L2hlYWRlcj4KICA8IS0tIE1JTkkgUFJP"
"R1JFU1MgQkFSIC0tPgogIDxkaXYgY2xhc3M9ImgtbWluaS1wcm9ncmVzcyIgaWQ9ImgtbWluaS1wcm9n"
"cmVzcyI+PGRpdiBjbGFzcz0iaC1taW5pLWJhciIgaWQ9ImgtbWluaS1iYXIiPjwvZGl2PjwvZGl2Pgog"
"IDxuYXYgY2xhc3M9InRhYi1uYXYiPgogICAgPGJ1dHRvbiBjbGFzcz0idGFiLWJ0biBhY3RpdmUiIG9u"
"Y2xpY2s9InN3aXRjaFRhYigndGVybWluYWwnLHRoaXMpIj5UZXJtaW5hbDwvYnV0dG9uPgogICAgPGJ1"
"dHRvbiBjbGFzcz0idGFiLWJ0biIgb25jbGljaz0ic3dpdGNoVGFiKCdwb3J0cycsdGhpcykiPlBvcnRz"
"IDxzcGFuIGNsYXNzPSJ0YWItYmFkZ2UiIGlkPSJwb3J0LWJhZGdlIj4wPC9zcGFuPjwvYnV0dG9uPgog"
"ICAgPGJ1dHRvbiBjbGFzcz0idGFiLWJ0biIgb25jbGljaz0ic3dpdGNoVGFiKCd0aHJlYXRzJyx0aGlz"
"KSI+VGhyZWF0cyA8c3BhbiBjbGFzcz0idGFiLWJhZGdlIiBpZD0idGhyZWF0LWJhZGdlIj4wPC9zcGFu"
"PjwvYnV0dG9uPgogICAgPGJ1dHRvbiBjbGFzcz0idGFiLWJ0biIgb25jbGljaz0ic3dpdGNoVGFiKCdy"
"aXNrJyx0aGlzKSI+UmlzayBBbmFseXNpczwvYnV0dG9uPgogICAgPGJ1dHRvbiBjbGFzcz0idGFiLWJ0"
"biIgb25jbGljaz0ic3dpdGNoVGFiKCd0Z3JhcGgnLHRoaXMpIj5UaHJlYXQgR3JhcGg8L2J1dHRvbj4K"
"ICAgIDxidXR0b24gY2xhc3M9InRhYi1idG4iIG9uY2xpY2s9InN3aXRjaFRhYignc2NhbnN0YXR1cycs"
"dGhpcykiPlNjYW4gU3RhdHVzIDxzcGFuIGNsYXNzPSJ0YWItYmFkZ2UiIGlkPSJzY2FuLXN0YXR1cy1i"
"YWRnZSI+4pePPC9zcGFuPjwvYnV0dG9uPgogICAgPGJ1dHRvbiBjbGFzcz0idGFiLWJ0biIgb25jbGlj"
"az0ic3dpdGNoVGFiKCdjaGFpbnMnLHRoaXMpIj5BdHRhY2sgQ2hhaW5zIDxzcGFuIGNsYXNzPSJ0YWIt"
"YmFkZ2UiIGlkPSJjaGFpbi1iYWRnZSI+4pePPC9zcGFuPjwvYnV0dG9uPgogIDwvbmF2PgoKICA8ZGl2"
"IGNsYXNzPSJjb250ZW50Ij4KICAgIDwhLS0gVEVSTUlOQUwgLS0+CiAgICA8ZGl2IGNsYXNzPSJ0YWIt"
"cGFuZSBhY3RpdmUiIGlkPSJwYW5lLXRlcm1pbmFsIj4KICAgICAgPGRpdiBjbGFzcz0idGVybWluYWwt"
"Y2FyZCI+CiAgICAgICAgPGRpdiBjbGFzcz0idGVybS1oZWFkZXIiPgogICAgICAgICAgPGRpdiBjbGFz"
"cz0idGVybS1kb3RzIj48c3BhbiBjbGFzcz0iZDEiPjwvc3Bhbj48c3BhbiBjbGFzcz0iZDIiPjwvc3Bh"
"bj48c3BhbiBjbGFzcz0iZDMiPjwvc3Bhbj48L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9InRlcm0t"
"dGl0bGUiPkhBUlNIQSB2Ny4wIOKAlCBPVVRQVVQ8L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9InRl"
"cm0tYWN0aW9ucyI+PGJ1dHRvbiBjbGFzcz0idGVybS1hY3QiIG9uY2xpY2s9ImNvcHlPdXRwdXQoKSI+"
"Q09QWTwvYnV0dG9uPjxidXR0b24gY2xhc3M9InRlcm0tYWN0IiBvbmNsaWNrPSJjbGVhclRlcm1pbmFs"
"KCkiPkNMRUFSPC9idXR0b24+PC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0i"
"bG9hZGluZy1iYXIiIGlkPSJsb2FkaW5nLWJhciI+PC9kaXY+CiAgICAgICAgPGRpdiBpZD0idGVybWlu"
"YWwtb3V0cHV0Ij4KICAgICAgICAgIDxkaXYgY2xhc3M9InRsIGhkciI+Ly8gSEFSU0hBIHY3LjAg4oCU"
"IFdFQiArIE5FVFdPUksgKyBJTkZSQVNUUlVDVFVSRSBWQVBUIFNVSVRFPC9kaXY+CiAgICAgICAgICA8"
"ZGl2IGNsYXNzPSJ0bCBwcm9tcHQiPmhhcnNoYUBrYWxpOn4kIDxzcGFuIGNsYXNzPSJibGluayI+fDwv"
"c3Bhbj48L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9InRsIGluZm8iPlsgV0VCICAgICBdIFNRTCBJ"
"bmplY3Rpb24sIFhTUywgV0FGLCBDT1JTLCBBZG1pbiBGaW5kZXIsIENNUywgU1NMPC9kaXY+CiAgICAg"
"ICAgICA8ZGl2IGNsYXNzPSJ0bCBpbmZvIj5bIE5FVFdPUksgXSBQb3J0IFNjYW4sIFVEUCwgRmlyZXdh"
"bGwsIFNNQiwgU05NUCwgQmFubmVyLCBBUlA8L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9InRsIGlu"
"Zm8iPlsgSU5GUkEgICBdIFNTSCwgRlRQLCBSRFAsIERCIEV4cG9zdXJlLCBEb2NrZXIsIEs4cywgQ1ZF"
"IFNjYW48L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9InRsIHJlc3VsdCI+WyBSRUFEWSAgIF0gU2Vs"
"ZWN0IGEgdG9vbCBmcm9tIHNpZGViYXIgYW5kIGVudGVyIHRhcmdldCB0byBiZWdpbi48L2Rpdj4KICAg"
"ICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImRhc2gtZ3JpZCBjb2xzLTQi"
"IHN0eWxlPSJtYXJnaW4tdG9wOjIwcHgiPgogICAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xh"
"c3M9ImNhcmQtc3VidGl0bGUiPlRvdGFsIFNjYW5zPC9kaXY+PGRpdiBjbGFzcz0ic3RhdC1udW0gYnJh"
"bmQiIGlkPSJzdGF0LXNjYW5zIj4wPC9kaXY+PGRpdiBjbGFzcz0ic3RhdC1iYXItd3JhcCI+PGRpdiBj"
"bGFzcz0ic3RhdC1iYXIiPjxkaXYgY2xhc3M9InN0YXQtYmFyLWZpbGwgYnJhbmQiIGlkPSJzY2FuLWJh"
"ciIgc3R5bGU9IndpZHRoOjAlIj48L2Rpdj48L2Rpdj48L2Rpdj48L2Rpdj4KICAgICAgICA8ZGl2IGNs"
"YXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxlIj5PcGVuIFBvcnRzPC9kaXY+PGRpdiBj"
"bGFzcz0ic3RhdC1udW0gb3JhbmdlIiBpZD0ic3RhdC1wb3J0cyI+MDwvZGl2PjxkaXYgY2xhc3M9InN0"
"YXQtYmFyLXdyYXAiPjxkaXYgY2xhc3M9InN0YXQtYmFyIj48ZGl2IGNsYXNzPSJzdGF0LWJhci1maWxs"
"IG9yYW5nZSIgaWQ9InBvcnQtYmFyIiBzdHlsZT0id2lkdGg6MCUiPjwvZGl2PjwvZGl2PjwvZGl2Pjwv"
"ZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUiPlRo"
"cmVhdHMgRm91bmQ8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LW51bSByZWQiIGlkPSJzdGF0LXRocmVhdHMi"
"PjA8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LWJhci13cmFwIj48ZGl2IGNsYXNzPSJzdGF0LWJhciI+PGRp"
"diBjbGFzcz0ic3RhdC1iYXItZmlsbCByZWQiIGlkPSJ0aHJlYXQtYmFyIiBzdHlsZT0id2lkdGg6MCUi"
"PjwvZGl2PjwvZGl2PjwvZGl2PjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xh"
"c3M9ImNhcmQtc3VidGl0bGUiPkxhc3QgVG9vbDwvZGl2PjxkaXYgc3R5bGU9ImZvbnQtc2l6ZToxNHB4"
"O2ZvbnQtd2VpZ2h0OjcwMDtjb2xvcjp2YXIoLS10eC1kYXJrKTttYXJnaW4tdG9wOjRweCIgaWQ9InN0"
"YXQtbGFzdC10b29sIj7igJQ8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LXN1YiIgaWQ9InN0YXQtbGFzdC10"
"aW1lIj5Bd2FpdGluZyBzY2FuPC9kaXY+PC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CgogICAg"
"PCEtLSBQT1JUUyAtLT4KICAgIDxkaXYgY2xhc3M9InRhYi1wYW5lIiBpZD0icGFuZS1wb3J0cyI+PGRp"
"diBpZD0icG9ydC1kYXNoIj48ZGl2IGNsYXNzPSJlbXB0eS1zdGF0ZSI+PGRpdiBjbGFzcz0iZW1wdHkt"
"aWNvIj7wn5SNPC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktdGl0bGUiPk5vIFBvcnRzIEZvdW5kIFlldDwv"
"ZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXN1YiI+UnVuIGEgcG9ydCBzY2FuIHRvIHBvcHVsYXRlIHRoaXMg"
"ZGFzaGJvYXJkPC9kaXY+PC9kaXY+PC9kaXY+PC9kaXY+CgogICAgPCEtLSBUSFJFQVRTIC0tPgogICAg"
"PGRpdiBjbGFzcz0idGFiLXBhbmUiIGlkPSJwYW5lLXRocmVhdHMiPjxkaXYgaWQ9InRocmVhdC1kYXNo"
"Ij48ZGl2IGNsYXNzPSJlbXB0eS1zdGF0ZSI+PGRpdiBjbGFzcz0iZW1wdHktaWNvIj7wn5uhPC9kaXY+"
"PGRpdiBjbGFzcz0iZW1wdHktdGl0bGUiPk5vIFRocmVhdHMgRGV0ZWN0ZWQ8L2Rpdj48ZGl2IGNsYXNz"
"PSJlbXB0eS1zdWIiPlJ1biB2dWxuZXJhYmlsaXR5IHNjYW5zIHRvIGRpc2NvdmVyIHRocmVhdHM8L2Rp"
"dj48L2Rpdj48L2Rpdj48L2Rpdj4KCiAgICA8IS0tIFJJU0sgQU5BTFlTSVMgLS0+CiAgICA8ZGl2IGNs"
"YXNzPSJ0YWItcGFuZSIgaWQ9InBhbmUtcmlzayI+PGRpdiBpZD0icmlzay1jb250ZW50Ij48ZGl2IGNs"
"YXNzPSJlbXB0eS1zdGF0ZSI+PGRpdiBjbGFzcz0iZW1wdHktaWNvIj7wn5OKPC9kaXY+PGRpdiBjbGFz"
"cz0iZW1wdHktdGl0bGUiPk5vIFJpc2sgRGF0YTwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXN1YiI+UnVu"
"IHNjYW5zIHRvIGdlbmVyYXRlIHJpc2sgYW5hbHlzaXM8L2Rpdj48L2Rpdj48L2Rpdj48L2Rpdj4KCiAg"
"ICA8IS0tIFRIUkVBVCBHUkFQSCAtLT4KICAgIDxkaXYgY2xhc3M9InRhYi1wYW5lIiBpZD0icGFuZS10"
"Z3JhcGgiPjxkaXYgaWQ9InRncmFwaC1jb250ZW50Ij48ZGl2IGNsYXNzPSJlbXB0eS1zdGF0ZSI+PGRp"
"diBjbGFzcz0iZW1wdHktaWNvIj7wn5W4PC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktdGl0bGUiPk5vIFRo"
"cmVhdCBEYXRhPC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktc3ViIj5SdW4gc2NhbnMgdG8gZ2VuZXJhdGUg"
"dGhyZWF0IGFuYWx5c2lzPC9kaXY+PC9kaXY+PC9kaXY+PC9kaXY+CgogICAgPCEtLSBTQ0FOIFNUQVRV"
"UyAtLT4KICAgIDxkaXYgY2xhc3M9InRhYi1wYW5lIiBpZD0icGFuZS1zY2Fuc3RhdHVzIj4KICAgICAg"
"PGRpdiBpZD0ic2Nhbi1zdGF0dXMtY29udGVudCI+CiAgICAgICAgPCEtLSBMaXZlIFNjYW4gQ2FyZCAt"
"LT4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIiBpZD0ibGl2ZS1zY2FuLWNhcmQiIHN0eWxlPSJtYXJn"
"aW4tYm90dG9tOjIwcHg7Ym9yZGVyLWxlZnQ6NHB4IHNvbGlkIHZhcigtLXdoaXRlLTQpIj4KICAgICAg"
"ICAgIDxkaXYgY2xhc3M9ImNhcmQtaGVhZGVyIj4KICAgICAgICAgICAgPGRpdj48ZGl2IGNsYXNzPSJj"
"YXJkLXRpdGxlIj5DdXJyZW50IFNjYW48L2Rpdj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxlIiBpZD0i"
"c3Mtc3VidGl0bGUiPk5vIGFjdGl2ZSBzY2FuPC9kaXY+PC9kaXY+CiAgICAgICAgICAgIDxkaXYgY2xh"
"c3M9InNjYW4taW5kaWNhdG9yIiBpZD0ic2Nhbi1pbmRpY2F0b3IiIHN0eWxlPSJ3aWR0aDo0MnB4O2hl"
"aWdodDo0MnB4Ij48c3BhbiBjbGFzcz0ic2Nhbi1wY3QiIGlkPSJzY2FuLXBjdC1udW0iIHN0eWxlPSJm"
"b250LXNpemU6MTJweCI+4oCUPC9zcGFuPjwvZGl2PgogICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8"
"ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoyMHB4O21hcmdpbi1i"
"b3R0b206MTRweCI+CiAgICAgICAgICAgIDxkaXYgc3R5bGU9ImZsZXg6MSI+CiAgICAgICAgICAgICAg"
"PGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmJhc2VsaW5lO2dhcDoxMHB4O21hcmdp"
"bi1ib3R0b206NnB4Ij4KICAgICAgICAgICAgICAgIDxkaXYgaWQ9InNjYW4tdG9vbC1uYW1lIiBzdHls"
"ZT0iZm9udC1zaXplOjE2cHg7Zm9udC13ZWlnaHQ6ODAwO2NvbG9yOnZhcigtLXR4LWRhcmspO2ZvbnQt"
"ZmFtaWx5OidTeW5lJyxzYW5zLXNlcmlmIj7igJQ8L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgaWQ9"
"InNjYW4tcGhhc2UtYmFkZ2UiIHN0eWxlPSJmb250LWZhbWlseTonSUJNIFBsZXggTW9ubycsbW9ub3Nw"
"YWNlO2ZvbnQtc2l6ZTo5cHg7Zm9udC13ZWlnaHQ6NzAwO3BhZGRpbmc6M3B4IDEwcHg7Ym9yZGVyLXJh"
"ZGl1czoyMHB4O2JhY2tncm91bmQ6dmFyKC0td2hpdGUtMik7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpO2xl"
"dHRlci1zcGFjaW5nOjFweCI+SURMRTwvZGl2PgogICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAg"
"ICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6MTZweDtmbGV4LXdyYXA6d3JhcCI+CiAgICAg"
"ICAgICAgICAgICA8ZGl2IGNsYXNzPSJzY2FuLW1ldGEtaXRlbSI+PGRpdiBjbGFzcz0iZG90IiBzdHls"
"ZT0iYmFja2dyb3VuZDp2YXIoLS1yZWQpIj48L2Rpdj5UYXJnZXQ6IDxzdHJvbmcgaWQ9InNjYW4tdGFy"
"Z2V0IiBzdHlsZT0iY29sb3I6dmFyKC0tdHgtZGFyaykiPuKAlDwvc3Ryb25nPjwvZGl2PgogICAgICAg"
"ICAgICAgICAgPGRpdiBjbGFzcz0ic2Nhbi1tZXRhLWl0ZW0iPjxkaXYgY2xhc3M9ImRvdCIgc3R5bGU9"
"ImJhY2tncm91bmQ6dmFyKC0tc2V2LWhpZ2gpIj48L2Rpdj5DYXRlZ29yeTogPHN0cm9uZyBpZD0ic2Nh"
"bi1jYXQiIHN0eWxlPSJjb2xvcjp2YXIoLS10eC1kYXJrKSI+4oCUPC9zdHJvbmc+PC9kaXY+CiAgICAg"
"ICAgICAgICAgICA8ZGl2IGNsYXNzPSJzY2FuLW1ldGEtaXRlbSI+PGRpdiBjbGFzcz0iZG90IiBzdHls"
"ZT0iYmFja2dyb3VuZDp2YXIoLS1zZXYtbG93KSI+PC9kaXY+RWxhcHNlZDogPHN0cm9uZyBpZD0ic2Nh"
"bi1lbGFwc2VkIiBzdHlsZT0iY29sb3I6dmFyKC0tdHgtZGFyaykiPjAuMHM8L3N0cm9uZz48L2Rpdj4K"
"ICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8L2Rpdj4KICAg"
"ICAgICAgIDwhLS0gUHJvZ3Jlc3MgQmFyIC0tPgogICAgICAgICAgPGRpdiBzdHlsZT0ibWFyZ2luLWJv"
"dHRvbTo4cHgiPgogICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250"
"ZW50OnNwYWNlLWJldHdlZW47bWFyZ2luLWJvdHRvbTo1cHgiPgogICAgICAgICAgICAgIDxkaXYgaWQ9"
"InNjYW4tbWVzc2FnZSIgc3R5bGU9ImZvbnQtc2l6ZToxMXB4O2NvbG9yOnZhcigtLXR4LW11dGVkKTtm"
"b250LXN0eWxlOml0YWxpYyI+UmVhZHkg4oCUIHNlbGVjdCBhIHRvb2wgdG8gYmVnaW48L2Rpdj4KICAg"
"ICAgICAgICAgICA8ZGl2IGlkPSJzY2FuLXBjdC10ZXh0IiBzdHlsZT0iZm9udC1mYW1pbHk6J0lCTSBQ"
"bGV4IE1vbm8nLG1vbm9zcGFjZTtmb250LXNpemU6MTFweDtmb250LXdlaWdodDo3MDA7Y29sb3I6dmFy"
"KC0tdHgtZGFyaykiPjAlPC9kaXY+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICA8ZGl2IGNs"
"YXNzPSJzY2FuLWJhci10cmFjayI+PGRpdiBjbGFzcz0ic2Nhbi1iYXItZmlsbC1saXZlIiBpZD0ic2Nh"
"bi1iYXItZmlsbCIgc3R5bGU9IndpZHRoOjAlIj48L2Rpdj48L2Rpdj4KICAgICAgICAgIDwvZGl2Pgog"
"ICAgICAgIDwvZGl2PgoKICAgICAgICA8IS0tIFN0YXRzIFJvdyAtLT4KICAgICAgICA8ZGl2IGNsYXNz"
"PSJkYXNoLWdyaWQgY29scy00IiBzdHlsZT0ibWFyZ2luLWJvdHRvbToyMHB4Ij4KICAgICAgICAgIDxk"
"aXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtc3VidGl0bGUiPlRvdGFsIFNjYW5zPC9kaXY+"
"PGRpdiBjbGFzcz0ic3RhdC1udW0gYnJhbmQiIGlkPSJzcy10b3RhbCI+MDwvZGl2PjwvZGl2PgogICAg"
"ICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0iY2FyZC1zdWJ0aXRsZSI+UG9ydHMgRm91"
"bmQ8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LW51bSBvcmFuZ2UiIGlkPSJzcy1wb3J0cyI+MDwvZGl2Pjwv"
"ZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0iY2FyZC1zdWJ0aXRsZSI+"
"VGhyZWF0cyBGb3VuZDwvZGl2PjxkaXYgY2xhc3M9InN0YXQtbnVtIHJlZCIgaWQ9InNzLXRocmVhdHMi"
"PjA8L2Rpdj48L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQt"
"c3VidGl0bGUiPkF2ZyBEdXJhdGlvbjwvZGl2PjxkaXYgY2xhc3M9InN0YXQtbnVtIiBpZD0ic3MtYXZn"
"IiBzdHlsZT0iY29sb3I6dmFyKC0tdHgtZGFyaykiPjBzPC9kaXY+PC9kaXY+CiAgICAgICAgPC9kaXY+"
"CgogICAgICAgIDwhLS0gU2NhbiBIaXN0b3J5IFRhYmxlIC0tPgogICAgICAgIDxkaXYgY2xhc3M9ImNh"
"cmQiPgogICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZC1oZWFkZXIiPjxkaXY+PGRpdiBjbGFzcz0iY2Fy"
"ZC10aXRsZSI+U2NhbiBIaXN0b3J5PC9kaXY+PGRpdiBjbGFzcz0iY2FyZC1zdWJ0aXRsZSI+TGFzdCAx"
"NSBjb21wbGV0ZWQgc2NhbnM8L2Rpdj48L2Rpdj48L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9InBv"
"cnQtdGFibGUtd3JhcCI+CiAgICAgICAgICAgIDx0YWJsZSBjbGFzcz0icG9ydC10YWJsZSI+CiAgICAg"
"ICAgICAgICAgPHRoZWFkPjx0cj48dGg+U3RhdHVzPC90aD48dGg+VG9vbDwvdGg+PHRoPlRhcmdldDwv"
"dGg+PHRoPkR1cmF0aW9uPC90aD48dGg+UG9ydHM8L3RoPjx0aD5UaHJlYXRzPC90aD48dGg+VGltZTwv"
"dGg+PC90cj48L3RoZWFkPgogICAgICAgICAgICAgIDx0Ym9keSBpZD0ic3MtaGlzdG9yeS10YWJsZSI+"
"CiAgICAgICAgICAgICAgICA8dHI+PHRkIGNvbHNwYW49IjciIHN0eWxlPSJ0ZXh0LWFsaWduOmNlbnRl"
"cjtjb2xvcjp2YXIoLS10eC1mYWludCk7cGFkZGluZzozMHB4Ij5ObyBzY2FucyBjb21wbGV0ZWQgeWV0"
"PC90ZD48L3RyPgogICAgICAgICAgICAgIDwvdGJvZHk+CiAgICAgICAgICAgIDwvdGFibGU+CiAgICAg"
"ICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KCiAgICA8IS0t"
"IEFUVEFDSyBDSEFJTlMgLS0+CiAgICA8ZGl2IGNsYXNzPSJ0YWItcGFuZSIgaWQ9InBhbmUtY2hhaW5z"
"Ij4KICAgICAgPGRpdiBpZD0iY2hhaW5zLWNvbnRlbnQiPgogICAgICAgIDxkaXYgY2xhc3M9ImVtcHR5"
"LXN0YXRlIj48ZGl2IGNsYXNzPSJlbXB0eS1pY28iPuKbkzwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXRp"
"dGxlIj5ObyBBdHRhY2sgQ2hhaW5zIFlldDwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXN1YiI+UnVuIG11"
"bHRpcGxlIHNjYW5zIHRvIGRpc2NvdmVyIGF0dGFjayBwYXRocy4gVGhlIGVuZ2luZSBjb25uZWN0cyB2"
"dWxuZXJhYmlsaXRpZXMgaW50byBraWxsIGNoYWlucyBhdXRvbWF0aWNhbGx5LjwvZGl2PjwvZGl2Pgog"
"ICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2PgoKICA8ZGl2IGNsYXNzPSJjaGF0LXBhbmVsIGNv"
"bGxhcHNlZCIgaWQ9ImNoYXQtcGFuZWwiPgogICAgPGRpdiBjbGFzcz0iY2hhdC10b2dnbGUiIG9uY2xp"
"Y2s9InRvZ2dsZUNoYXQoKSI+CiAgICAgIDxkaXYgY2xhc3M9ImNoYXQtdG9nZ2xlLWxlZnQiPjxzcGFu"
"IHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQpIj7il488L3NwYW4+PHNwYW4gY2xhc3M9ImNoYXQtdG9nZ2xl"
"LWxhYmVsIj5IQVJTSEEgQUkgQVNTSVNUQU5UPC9zcGFuPjxzcGFuIGNsYXNzPSJjaGF0LXRvZ2dsZS1z"
"dGF0dXMiPuKXjyBPbmxpbmU8L3NwYW4+PC9kaXY+CiAgICAgIDxzcGFuIGNsYXNzPSJjaGF0LWFycm93"
"Ij7ilrw8L3NwYW4+CiAgICA8L2Rpdj4KICAgIDxkaXYgaWQ9ImNoYXQtbWVzc2FnZXMiPjxkaXYgY2xh"
"c3M9Im1zZyBhaSI+PGRpdiBjbGFzcz0ibXNnLWF2YXRhciI+QUk8L2Rpdj48ZGl2IGNsYXNzPSJtc2ct"
"Ym9keSI+SEFSU0hBIEFJIHY3LjAgb25saW5lLiBTZWxlY3QgYSB0b29sIGFuZCBlbnRlciBhIHRhcmdl"
"dCB0byBiZWdpbi48L2Rpdj48L2Rpdj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNoYXQtaW5wdXQtcm93"
"Ij4KICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJjaGF0LWlucHV0IiBjbGFzcz0iY2hhdC1pbnB1"
"dCIgcGxhY2Vob2xkZXI9IkFzayBIQVJTSEEgQUkuLi4iIG9ua2V5ZG93bj0iaWYoZXZlbnQua2V5PT09"
"J0VudGVyJylzZW5kQ2hhdCgpIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iY2hhdC1zZW5kIiBvbmNsaWNr"
"PSJzZW5kQ2hhdCgpIj5TRU5EPC9idXR0b24+CiAgICA8L2Rpdj4KICA8L2Rpdj4KPC9kaXY+CjwvZGl2"
"PgoKPCEtLSBSRVBPUlQgTU9EQUwgLS0+CjxkaXYgY2xhc3M9Im1vZGFsLW92ZXJsYXkiIGlkPSJyZXBv"
"cnQtbW9kYWwiPgogIDxkaXYgY2xhc3M9Im1vZGFsLWJveCI+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1o"
"ZHIiPjxkaXYgY2xhc3M9Im1vZGFsLXRpdGxlIj5IQVJTSEEgdjcuMCDigJQgVkFQVCBSRVBPUlQ8L2Rp"
"dj48YnV0dG9uIGNsYXNzPSJtb2RhbC1jbG9zZSIgb25jbGljaz0iY2xvc2VSZXBvcnQoKSI+Q0xPU0U8"
"L2J1dHRvbj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im1vZGFsLWJvZHkiPjxkaXYgaWQ9InJwIj48L2Rp"
"dj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im1vZGFsLWZvb3RlciI+PGJ1dHRvbiBjbGFzcz0iZGwtYnRu"
"IHByaW1hcnkiIG9uY2xpY2s9ImRvd25sb2FkSFRNTCgpIj5Eb3dubG9hZCBIVE1MPC9idXR0b24+PGJ1"
"dHRvbiBjbGFzcz0iZGwtYnRuIHNlY29uZGFyeSIgb25jbGljaz0iZG93bmxvYWRUWFQoKSI+RG93bmxv"
"YWQgVFhUPC9idXR0b24+PC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPHNjcmlwdD4KLyogPT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBT"
"VEFURQogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09ICovCnZhciBzY2FuQ291bnQ9MCxjdXJyZW50QXVkaW89bnVsbCxhbGxQb3J0cz1b"
"XSxhbGxUaHJlYXRzPVtdLGxhc3RUYXJnZXQ9Jyc7CnZhciBTQz17bmV0OjAsd2ViOjAsaW5mOjAscmVj"
"OjB9Owp2YXIgcmlza0NoYXJ0cz17fSx0aHJlYXRDaGFydHM9e307CnZhciBzZXZDb2xvcnM9e0NSSVRJ"
"Q0FMOicjZDkwNDI5JyxISUdIOicjZTg1ZDA0JyxNRURJVU06JyNlMDlmM2UnLExPVzonIzJkNmE0Zid9"
"Owp2YXIgc2V2Qmc9e0NSSVRJQ0FMOidyZ2JhKDIxNyw0LDQxLDAuMSknLEhJR0g6J3JnYmEoMjMyLDkz"
"LDQsMC4xKScsTUVESVVNOidyZ2JhKDIyNCwxNTksNjIsMC4xKScsTE9XOidyZ2JhKDQ1LDEwNiw3OSww"
"LjEpJ307CnZhciB0YXJnZXRIaXN0b3J5PVtdOwp2YXIgbGFzdFBoYXNlPSdpZGxlJzsKCi8qID09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0K"
"ICAgQ0xPQ0sKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PSAqLwpmdW5jdGlvbiB1cGRhdGVDbG9jaygpe2RvY3VtZW50LmdldEVsZW1l"
"bnRCeUlkKCdjbG9jaycpLnRleHRDb250ZW50PW5ldyBEYXRlKCkudG9Mb2NhbGVUaW1lU3RyaW5nKCdl"
"bi1VUycse2hvdXI6JzItZGlnaXQnLG1pbnV0ZTonMi1kaWdpdCcsc2Vjb25kOicyLWRpZ2l0J30pfQpz"
"ZXRJbnRlcnZhbCh1cGRhdGVDbG9jaywxMDAwKTt1cGRhdGVDbG9jaygpOwoKLyogPT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICBUQUJT"
"CiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT0gKi8KZnVuY3Rpb24gc3dpdGNoVGFiKHRhYixidG4pewogIGRvY3VtZW50LnF1ZXJ5U2Vs"
"ZWN0b3JBbGwoJy50YWItcGFuZScpLmZvckVhY2goZnVuY3Rpb24ocCl7cC5jbGFzc0xpc3QucmVtb3Zl"
"KCdhY3RpdmUnKX0pOwogIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy50YWItYnRuJykuZm9yRWFj"
"aChmdW5jdGlvbihiKXtiLmNsYXNzTGlzdC5yZW1vdmUoJ2FjdGl2ZScpfSk7CiAgZG9jdW1lbnQuZ2V0"
"RWxlbWVudEJ5SWQoJ3BhbmUtJyt0YWIpLmNsYXNzTGlzdC5hZGQoJ2FjdGl2ZScpOwogIGlmKGJ0bili"
"dG4uY2xhc3NMaXN0LmFkZCgnYWN0aXZlJyk7CiAgaWYodGFiPT09J3Jpc2snKXNldFRpbWVvdXQocmVm"
"cmVzaFJpc2tDaGFydHMsNjApOwogIGlmKHRhYj09PSd0Z3JhcGgnKXNldFRpbWVvdXQocmVmcmVzaFRo"
"cmVhdENoYXJ0cyw2MCk7Cn0KZnVuY3Rpb24gdG9nZ2xlQ2hhdCgpe2RvY3VtZW50LmdldEVsZW1lbnRC"
"eUlkKCdjaGF0LXBhbmVsJykuY2xhc3NMaXN0LnRvZ2dsZSgnY29sbGFwc2VkJyl9CgovKiA9PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAg"
"IFNJREVCQVIgRFJPUERPV05TCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KZnVuY3Rpb24gdG9nZ2xlU2VjdGlvbihoZWFkZXIp"
"ewogIGhlYWRlci5wYXJlbnRFbGVtZW50LmNsYXNzTGlzdC50b2dnbGUoJ29wZW4nKTsKfQoKLyogPT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PQogICBUT09MIFNFQVJDSCAvIEZJTFRFUgogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCmZ1bmN0aW9uIGZpbHRlclRvb2xzKHF1"
"ZXJ5KXsKICB2YXIgcT1xdWVyeS50b0xvd2VyQ2FzZSgpLnRyaW0oKTsKICB2YXIgbmF2cz1kb2N1bWVu"
"dC5xdWVyeVNlbGVjdG9yQWxsKCcucy1uYXYnKTsKICB2YXIgc2VjdGlvbnM9ZG9jdW1lbnQucXVlcnlT"
"ZWxlY3RvckFsbCgnLnMtc2VjdGlvbicpOwogIGlmKCFxKXsKICAgIG5hdnMuZm9yRWFjaChmdW5jdGlv"
"bihuKXtuLnN0eWxlLmRpc3BsYXk9Jyd9KTsKICAgIHNlY3Rpb25zLmZvckVhY2goZnVuY3Rpb24ocyl7"
"CiAgICAgIHZhciBoZHI9cy5xdWVyeVNlbGVjdG9yKCcucy1zZWN0aW9uLWhlYWRlcicpOwogICAgICBp"
"ZihoZHIpaGRyLnN0eWxlLmRpc3BsYXk9Jyc7CiAgICB9KTsKICAgIHJldHVybjsKICB9CiAgc2VjdGlv"
"bnMuZm9yRWFjaChmdW5jdGlvbihzKXtzLmNsYXNzTGlzdC5hZGQoJ29wZW4nKX0pOwogIG5hdnMuZm9y"
"RWFjaChmdW5jdGlvbihuKXsKICAgIHZhciBuYW1lPShuLmdldEF0dHJpYnV0ZSgnZGF0YS1uYW1lJyl8"
"fCcnKSsnICcrKG4udGV4dENvbnRlbnR8fCcnKTsKICAgIG4uc3R5bGUuZGlzcGxheT1uYW1lLnRvTG93"
"ZXJDYXNlKCkuaW5kZXhPZihxKT49MD8nJzonbm9uZSc7CiAgfSk7CiAgc2VjdGlvbnMuZm9yRWFjaChm"
"dW5jdGlvbihzKXsKICAgIHZhciBib2R5PXMucXVlcnlTZWxlY3RvcignLnMtc2VjdGlvbi1ib2R5Jyk7"
"CiAgICBpZighYm9keSlyZXR1cm47CiAgICB2YXIgdmlzaWJsZT1ib2R5LnF1ZXJ5U2VsZWN0b3JBbGwo"
"Jy5zLW5hdjpub3QoW3N0eWxlKj0iZGlzcGxheTogbm9uZSJdKScpOwogICAgdmFyIGhkcj1zLnF1ZXJ5"
"U2VsZWN0b3IoJy5zLXNlY3Rpb24taGVhZGVyJyk7CiAgICBpZihoZHIpaGRyLnN0eWxlLmRpc3BsYXk9"
"dmlzaWJsZS5sZW5ndGg+MD8nJzonbm9uZSc7CiAgfSk7Cn0KCi8qID09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgVEFSR0VUIEhJU1RP"
"UlkKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PSAqLwpmdW5jdGlvbiBhZGRUYXJnZXRIaXN0b3J5KHQpewogIGlmKCF0fHx0YXJnZXRI"
"aXN0b3J5LmluZGV4T2YodCk+PTApcmV0dXJuOwogIHRhcmdldEhpc3RvcnkudW5zaGlmdCh0KTsKICBp"
"Zih0YXJnZXRIaXN0b3J5Lmxlbmd0aD4xMCl0YXJnZXRIaXN0b3J5LnBvcCgpOwp9CmZ1bmN0aW9uIHNo"
"b3dUYXJnZXRIaXN0b3J5KCl7CiAgdmFyIGJveD1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGFyZ2V0"
"LWhpc3RvcnknKTsKICB2YXIgaW5wPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0YXJnZXQtaW5wdXQn"
"KS52YWx1ZS50cmltKCkudG9Mb3dlckNhc2UoKTsKICBpZighdGFyZ2V0SGlzdG9yeS5sZW5ndGgpe2Jv"
"eC5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7cmV0dXJufQogIHZhciBmaWx0ZXJlZD10YXJnZXRIaXN0"
"b3J5LmZpbHRlcihmdW5jdGlvbih0KXtyZXR1cm4gIWlucHx8dC50b0xvd2VyQ2FzZSgpLmluZGV4T2Yo"
"aW5wKT49MH0pOwogIGlmKCFmaWx0ZXJlZC5sZW5ndGgpe2JveC5jbGFzc0xpc3QucmVtb3ZlKCdzaG93"
"Jyk7cmV0dXJufQogIHZhciBoPSc8ZGl2IGNsYXNzPSJoLXRoLWxhYmVsIiBzdHlsZT0icGFkZGluZzo2"
"cHggMTRweCAycHgiPlJFQ0VOVCBUQVJHRVRTPC9kaXY+JzsKICBmaWx0ZXJlZC5mb3JFYWNoKGZ1bmN0"
"aW9uKHQpewogICAgaCs9JzxkaXYgY2xhc3M9ImgtdGgtaXRlbSIgb25jbGljaz0ic2VsZWN0VGFyZ2V0"
"KCZxdW90OycrdC5yZXBsYWNlKC8iL2csJycpKycmcXVvdDspIj4nK3QrJzwvZGl2Pic7CiAgfSk7CiAg"
"Ym94LmlubmVySFRNTD1oO2JveC5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7Cn0KZnVuY3Rpb24gc2VsZWN0"
"VGFyZ2V0KHQpewogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0YXJnZXQtaW5wdXQnKS52YWx1ZT10"
"OwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd0YXJnZXQtaGlzdG9yeScpLmNsYXNzTGlzdC5yZW1v"
"dmUoJ3Nob3cnKTsKfQpkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsZnVuY3Rpb24oZSl7"
"CiAgaWYoIWUudGFyZ2V0LmNsb3Nlc3QoJy5oLXRhcmdldCcpKXt2YXIgZWw9ZG9jdW1lbnQuZ2V0RWxl"
"bWVudEJ5SWQoJ3RhcmdldC1oaXN0b3J5Jyk7aWYoZWwpZWwuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycp"
"fQp9KTsKCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT0KICAgVVRJTFMKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSAqLwpmdW5jdGlvbiBwbGF5Vm9pY2UoKXtpZihj"
"dXJyZW50QXVkaW8pY3VycmVudEF1ZGlvLnBhdXNlKCk7Y3VycmVudEF1ZGlvPW5ldyBBdWRpbygnL3Zv"
"aWNlP3Q9JytEYXRlLm5vdygpKTtjdXJyZW50QXVkaW8ucGxheSgpLmNhdGNoKGZ1bmN0aW9uKCl7fSl9"
"CmZ1bmN0aW9uIG5vdGlmeShtc2cpe3ZhciBlbD1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTtl"
"bC5jbGFzc05hbWU9J25vdGlmJztlbC50ZXh0Q29udGVudD1tc2c7ZG9jdW1lbnQuYm9keS5hcHBlbmRD"
"aGlsZChlbCk7c2V0VGltZW91dChmdW5jdGlvbigpe2VsLnJlbW92ZSgpfSwzNTAwKX0KCnZhciB0ZXJt"
"aW5hbD1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGVybWluYWwtb3V0cHV0Jyk7CmZ1bmN0aW9uIHRl"
"cm1MaW5lKHQsYyl7aWYoIWMpYz0ncmVzdWx0JzsodCsnJykuc3BsaXQoJ1xuJykuZm9yRWFjaChmdW5j"
"dGlvbihsKXtpZighbC50cmltKCkpcmV0dXJuO3ZhciBkPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2Rp"
"dicpO2QuY2xhc3NOYW1lPSd0bCAnK2M7ZC50ZXh0Q29udGVudD1sO3Rlcm1pbmFsLmFwcGVuZENoaWxk"
"KGQpfSk7dGVybWluYWwuc2Nyb2xsVG9wPXRlcm1pbmFsLnNjcm9sbEhlaWdodH0KZnVuY3Rpb24gY2xl"
"YXJUZXJtaW5hbCgpe3Rlcm1pbmFsLmlubmVySFRNTD0nPGRpdiBjbGFzcz0idGwgaGRyIj4vLyBDTEVB"
"UkVEIOKAlCBIQVJTSEEgQUkgdjcuMDwvZGl2Pid9CmZ1bmN0aW9uIGNvcHlPdXRwdXQoKXtuYXZpZ2F0"
"b3IuY2xpcGJvYXJkLndyaXRlVGV4dCh0ZXJtaW5hbC5pbm5lclRleHQpLnRoZW4oZnVuY3Rpb24oKXtu"
"b3RpZnkoJ0NvcGllZCEnKX0pfQpmdW5jdGlvbiBzZXRMb2FkaW5nKG9uKXtkb2N1bWVudC5nZXRFbGVt"
"ZW50QnlJZCgnbG9hZGluZy1iYXInKS5zdHlsZS5kaXNwbGF5PW9uPydibG9jayc6J25vbmUnfQoKZnVu"
"Y3Rpb24gdXBkYXRlU3RhdHMoKXsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3RhdC1zY2Fucycp"
"LnRleHRDb250ZW50PXNjYW5Db3VudDsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3RhdC1wb3J0"
"cycpLnRleHRDb250ZW50PWFsbFBvcnRzLmxlbmd0aDsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgn"
"c3RhdC10aHJlYXRzJykudGV4dENvbnRlbnQ9YWxsVGhyZWF0cy5sZW5ndGg7CiAgZG9jdW1lbnQuZ2V0"
"RWxlbWVudEJ5SWQoJ3NjYW4tYmFyJykuc3R5bGUud2lkdGg9TWF0aC5taW4oMTAwLHNjYW5Db3VudCox"
"MCkrJyUnOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwb3J0LWJhcicpLnN0eWxlLndpZHRoPU1h"
"dGgubWluKDEwMCxhbGxQb3J0cy5sZW5ndGgqNSkrJyUnOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlk"
"KCd0aHJlYXQtYmFyJykuc3R5bGUud2lkdGg9TWF0aC5taW4oMTAwLGFsbFRocmVhdHMubGVuZ3RoKjEw"
"KSsnJSc7CiAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2htLXNjYW5zJykudGV4dENvbnRlbnQ9c2Nh"
"bkNvdW50OwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdobS1wb3J0cycpLnRleHRDb250ZW50PWFs"
"bFBvcnRzLmxlbmd0aDsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnaG0tdGhyZWF0cycpLnRleHRD"
"b250ZW50PWFsbFRocmVhdHMubGVuZ3RoOwp9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIFBPUlQgREFTSEJPQVJECiAgID09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT0gKi8KZnVuY3Rpb24gdXBkYXRlUG9ydERhc2gocG9ydHMsdGFyZ2V0KXsKICBpZighcG9ydHN8fCFw"
"b3J0cy5sZW5ndGgpcmV0dXJuOwogIHBvcnRzLmZvckVhY2goZnVuY3Rpb24ocCl7aWYoIWFsbFBvcnRz"
"LmZpbmQoZnVuY3Rpb24oeCl7cmV0dXJuIHgucG9ydD09PXAucG9ydCYmeC5wcm90bz09PXAucHJvdG99"
"KSlhbGxQb3J0cy5wdXNoKHApfSk7CiAgdmFyIHRvdGFsPWFsbFBvcnRzLmxlbmd0aCxjcml0PTAsaGln"
"aD0wLG1lZD0wLGxvdz0wOwogIGFsbFBvcnRzLmZvckVhY2goZnVuY3Rpb24ocCl7aWYocC5zZXZlcml0"
"eT09PSdDUklUSUNBTCcpY3JpdCsrO2Vsc2UgaWYocC5zZXZlcml0eT09PSdISUdIJyloaWdoKys7ZWxz"
"ZSBpZihwLnNldmVyaXR5PT09J01FRElVTScpbWVkKys7ZWxzZSBsb3crK30pOwogIHZhciBiYWRnZT1k"
"b2N1bWVudC5nZXRFbGVtZW50QnlJZCgncG9ydC1iYWRnZScpO2JhZGdlLmNsYXNzTGlzdC5hZGQoJ3No"
"b3cnLCdiLW9yYW5nZScpO2JhZGdlLnRleHRDb250ZW50PXRvdGFsOwogIHZhciBzb3J0ZWQ9YWxsUG9y"
"dHMuc2xpY2UoKS5zb3J0KGZ1bmN0aW9uKGEsYil7dmFyIG89e0NSSVRJQ0FMOjAsSElHSDoxLE1FRElV"
"TToyLExPVzozfTtyZXR1cm4ob1thLnNldmVyaXR5XXx8MyktKG9bYi5zZXZlcml0eV18fDMpfHxhLnBv"
"cnQtYi5wb3J0fSk7CiAgdmFyIGg9JzxkaXYgY2xhc3M9ImRhc2gtZ3JpZCBjb2xzLTQiIHN0eWxlPSJt"
"YXJnaW4tYm90dG9tOjIwcHgiPic7CiAgaCs9JzxkaXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNh"
"cmQtc3VidGl0bGUiPkNyaXRpY2FsPC9kaXY+PGRpdiBjbGFzcz0ic3RhdC1udW0gcmVkIj4nK2NyaXQr"
"JzwvZGl2PjxkaXYgY2xhc3M9InN0YXQtYmFyLXdyYXAiPjxkaXYgY2xhc3M9InN0YXQtYmFyIj48ZGl2"
"IGNsYXNzPSJzdGF0LWJhci1maWxsIHJlZCIgc3R5bGU9IndpZHRoOicrTWF0aC5taW4oMTAwLGNyaXQq"
"MjUpKyclIj48L2Rpdj48L2Rpdj48L2Rpdj48L2Rpdj4nOwogIGgrPSc8ZGl2IGNsYXNzPSJjYXJkIj48"
"ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxlIj5IaWdoPC9kaXY+PGRpdiBjbGFzcz0ic3RhdC1udW0gb3Jh"
"bmdlIj4nK2hpZ2grJzwvZGl2PjxkaXYgY2xhc3M9InN0YXQtYmFyLXdyYXAiPjxkaXYgY2xhc3M9InN0"
"YXQtYmFyIj48ZGl2IGNsYXNzPSJzdGF0LWJhci1maWxsIG9yYW5nZSIgc3R5bGU9IndpZHRoOicrTWF0"
"aC5taW4oMTAwLGhpZ2gqMTgpKyclIj48L2Rpdj48L2Rpdj48L2Rpdj48L2Rpdj4nOwogIGgrPSc8ZGl2"
"IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxlIj5NZWRpdW08L2Rpdj48ZGl2IGNs"
"YXNzPSJzdGF0LW51bSB5ZWxsb3ciPicrbWVkKyc8L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LWJhci13cmFw"
"Ij48ZGl2IGNsYXNzPSJzdGF0LWJhciI+PGRpdiBjbGFzcz0ic3RhdC1iYXItZmlsbCB5ZWxsb3ciIHN0"
"eWxlPSJ3aWR0aDonK01hdGgubWluKDEwMCxtZWQqMTgpKyclIj48L2Rpdj48L2Rpdj48L2Rpdj48L2Rp"
"dj4nOwogIGgrPSc8ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRpdGxlIj5Mb3c8"
"L2Rpdj48ZGl2IGNsYXNzPSJzdGF0LW51bSBncmVlbiI+Jytsb3crJzwvZGl2PjxkaXYgY2xhc3M9InN0"
"YXQtYmFyLXdyYXAiPjxkaXYgY2xhc3M9InN0YXQtYmFyIj48ZGl2IGNsYXNzPSJzdGF0LWJhci1maWxs"
"IGdyZWVuIiBzdHlsZT0id2lkdGg6JytNYXRoLm1pbigxMDAsbG93KjE4KSsnJSI+PC9kaXY+PC9kaXY+"
"PC9kaXY+PC9kaXY+JzsKICBoKz0nPC9kaXY+JzsKICBoKz0nPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBj"
"bGFzcz0iY2FyZC1oZWFkZXIiPjxkaXY+PGRpdiBjbGFzcz0iY2FyZC10aXRsZSI+T3BlbiBQb3J0cyDi"
"gJQgJysodGFyZ2V0fHxsYXN0VGFyZ2V0fHwnPycpKyc8L2Rpdj48ZGl2IGNsYXNzPSJjYXJkLXN1YnRp"
"dGxlIj4nK3RvdGFsKycgcG9ydHM8L2Rpdj48L2Rpdj48L2Rpdj4nOwogIGgrPSc8ZGl2IGNsYXNzPSJw"
"b3J0LXRhYmxlLXdyYXAiPjx0YWJsZSBjbGFzcz0icG9ydC10YWJsZSI+PHRoZWFkPjx0cj48dGg+UG9y"
"dDwvdGg+PHRoPlNlcnZpY2U8L3RoPjx0aD5SaXNrPC90aD48dGg+RGVzY3JpcHRpb248L3RoPjx0aD5S"
"ZW1lZGlhdGlvbjwvdGg+PC90cj48L3RoZWFkPjx0Ym9keT4nOwogIHNvcnRlZC5mb3JFYWNoKGZ1bmN0"
"aW9uKHApewogICAgaCs9Jzx0cj48dGQ+PHNwYW4gY2xhc3M9InAtbnVtIj4nK3AucG9ydCsnPC9zcGFu"
"PjxkaXYgY2xhc3M9InAtcHJvdG8iPicrcC5wcm90by50b1VwcGVyQ2FzZSgpKyc8L2Rpdj48L3RkPic7"
"CiAgICBoKz0nPHRkPjxzcGFuIGNsYXNzPSJwLXN2YyI+JytwLnNlcnZpY2UrJzwvc3Bhbj4nKyhwLnZl"
"cnNpb24/JzxkaXYgY2xhc3M9InAtdmVyIj4nK3AudmVyc2lvbi5zdWJzdHJpbmcoMCwzNSkrJzwvZGl2"
"Pic6JycpKyc8L3RkPic7CiAgICBoKz0nPHRkPjxzcGFuIGNsYXNzPSJzZXYgJytwLnNldmVyaXR5Kyci"
"PicrcC5zZXZlcml0eSsnPC9zcGFuPjwvdGQ+JzsKICAgIGgrPSc8dGQgY2xhc3M9InAtZGVzYyI+Jytw"
"LmRlc2MrJzwvdGQ+PHRkIGNsYXNzPSJwLWZpeCI+JytwLmZpeCsnPC90ZD48L3RyPic7CiAgfSk7CiAg"
"aCs9JzwvdGJvZHk+PC90YWJsZT48L2Rpdj48L2Rpdj4nOwogIGRvY3VtZW50LmdldEVsZW1lbnRCeUlk"
"KCdwb3J0LWRhc2gnKS5pbm5lckhUTUw9aDt1cGRhdGVTdGF0cygpOwp9CgovKiA9PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIFRIUkVB"
"VCBEQVNIQk9BUkQKICAgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PSAqLwpmdW5jdGlvbiB1cGRhdGVUaHJlYXREYXNoKHRocmVhdHMpewog"
"IGlmKCF0aHJlYXRzfHwhdGhyZWF0cy5sZW5ndGgpcmV0dXJuOwogIHRocmVhdHMuZm9yRWFjaChmdW5j"
"dGlvbih0KXtpZighYWxsVGhyZWF0cy5maW5kKGZ1bmN0aW9uKHgpe3JldHVybiB4Lm5hbWU9PT10Lm5h"
"bWV9KSlhbGxUaHJlYXRzLnB1c2godCl9KTsKICB2YXIgYmFkZ2U9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5"
"SWQoJ3RocmVhdC1iYWRnZScpO2JhZGdlLmNsYXNzTGlzdC5hZGQoJ3Nob3cnLCdiLXJlZCcpO2JhZGdl"
"LnRleHRDb250ZW50PWFsbFRocmVhdHMubGVuZ3RoOwogIHZhciBoPSc8ZGl2IGNsYXNzPSJkYXNoLWdy"
"aWQgY29scy0xIiBzdHlsZT0iZ2FwOjE0cHgiPic7CiAgYWxsVGhyZWF0cy5mb3JFYWNoKGZ1bmN0aW9u"
"KHQsaSl7CiAgICBoKz0nPGRpdiBjbGFzcz0idGhyZWF0LWNhcmQgJyt0LnNldmVyaXR5KyciIHN0eWxl"
"PSJhbmltYXRpb24tZGVsYXk6JysoaSowLjA1KSsncyI+PGRpdiBjbGFzcz0idGMtaGRyIj48ZGl2IGNs"
"YXNzPSJ0Yy1uYW1lIj4nK3QubmFtZSsnPC9kaXY+PHNwYW4gY2xhc3M9InNldiAnK3Quc2V2ZXJpdHkr"
"JyI+Jyt0LnNldmVyaXR5Kyc8L3NwYW4+PC9kaXY+JzsKICAgIGgrPSc8ZGl2IGNsYXNzPSJ0Yy1kZXNj"
"Ij4nK3QuZGVzYysnPC9kaXY+JzsKICAgIGgrPSc8ZGl2IGNsYXNzPSJ0Yy1maXgiPjxkaXYgY2xhc3M9"
"InRjLWZpeC1sYWJlbCI+UkVNRURJQVRJT048L2Rpdj48ZGl2IGNsYXNzPSJ0Yy1maXgtdGV4dCI+Jyt0"
"LmZpeCsnPC9kaXY+PC9kaXY+PC9kaXY+JzsKICB9KTsKICBoKz0nPC9kaXY+JzsKICBkb2N1bWVudC5n"
"ZXRFbGVtZW50QnlJZCgndGhyZWF0LWRhc2gnKS5pbm5lckhUTUw9aDt1cGRhdGVTdGF0cygpOwp9Cgov"
"KiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09CiAgIFJVTiBUT09MIChpbnRlZ3JhdGVkIHdpdGggdGFyZ2V0IGhpc3RvcnkpCiAgID09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0g"
"Ki8KZnVuY3Rpb24gcnVuVG9vbCh0b29sLGJ0bixjYXQpewogIHZhciB0YXJnZXQ9ZG9jdW1lbnQuZ2V0"
"RWxlbWVudEJ5SWQoJ3RhcmdldC1pbnB1dCcpLnZhbHVlLnRyaW0oKTsKICB2YXIgbm9UPVsnbmV0d29y"
"a19zY2FuJywnbXlfaXAnLCdzeXN0ZW1faW5mbycsJ3dlYXRoZXInLCdhcnBfc2NhbiddOwogIHZhciBu"
"ZWVkPXRydWU7Zm9yKHZhciBpPTA7aTxub1QubGVuZ3RoO2krKyl7aWYobm9UW2ldPT09dG9vbCl7bmVl"
"ZD1mYWxzZTticmVha319CiAgaWYobmVlZCYmIXRhcmdldCl7bm90aWZ5KCdFbnRlciBhIHRhcmdldCBm"
"aXJzdC4nKTt0ZXJtTGluZSgnUGxlYXNlIGVudGVyIGEgdGFyZ2V0LicsJ2Vycm9yJyk7cmV0dXJufQog"
"IGlmKHRhcmdldCl7bGFzdFRhcmdldD10YXJnZXQ7YWRkVGFyZ2V0SGlzdG9yeSh0YXJnZXQpfQogIGRv"
"Y3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJy5zLW5hdicpLmZvckVhY2goZnVuY3Rpb24oYil7Yi5jbGFz"
"c0xpc3QucmVtb3ZlKCdhY3RpdmUnKX0pOwogIGlmKGJ0bilidG4uY2xhc3NMaXN0LmFkZCgnYWN0aXZl"
"Jyk7CiAgc2V0TG9hZGluZyh0cnVlKTsKICBzd2l0Y2hUYWIoJ3Rlcm1pbmFsJyxkb2N1bWVudC5xdWVy"
"eVNlbGVjdG9yQWxsKCcudGFiLWJ0bicpWzBdKTsKICB0ZXJtTGluZSgnJywnaGRyJyk7CiAgdGVybUxp"
"bmUoJ+KAlCBbJytjYXQudG9VcHBlckNhc2UoKSsnXSAnK3Rvb2wudG9VcHBlckNhc2UoKSsodGFyZ2V0"
"Pycg4oaSICcrdGFyZ2V0OicnKSsnIOKAlCcsJ2hkcicpOwogIHRlcm1MaW5lKCdoYXJzaGFAa2FsaTp+"
"JCAnK3Rvb2wrKHRhcmdldD8nICcrdGFyZ2V0OicnKSsnLi4uJywncHJvbXB0Jyk7CiAgdmFyIHQwPURh"
"dGUubm93KCk7CiAgZmV0Y2goJy9zY2FuJyx7bWV0aG9kOidQT1NUJyxoZWFkZXJzOnsnQ29udGVudC1U"
"eXBlJzonYXBwbGljYXRpb24vanNvbid9LGJvZHk6SlNPTi5zdHJpbmdpZnkoe3Rvb2w6dG9vbCx0YXJn"
"ZXQ6dGFyZ2V0fSl9KQogIC50aGVuKGZ1bmN0aW9uKHIpe3JldHVybiByLmpzb24oKX0pCiAgLnRoZW4o"
"ZnVuY3Rpb24oZGF0YSl7CiAgICB2YXIgZWw9KChEYXRlLm5vdygpLXQwKS8xMDAwKS50b0ZpeGVkKDEp"
"OwogICAgdGVybUxpbmUoZGF0YS5vdXRwdXR8fGRhdGEuZXJyb3J8fCdObyBvdXRwdXQuJyxkYXRhLmVy"
"cm9yPydlcnJvcic6J3Jlc3VsdCcpOwogICAgdGVybUxpbmUoJ0NvbXBsZXRlZCBpbiAnK2VsKydzIOKA"
"lCAnKyhkYXRhLnRpbWVzdGFtcHx8JycpLCdpbmZvJyk7CiAgICBzY2FuQ291bnQrKztTQ1tjYXRdPShT"
"Q1tjYXRdfHwwKSsxOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N0YXQtbGFzdC10b29sJyku"
"dGV4dENvbnRlbnQ9dG9vbC50b1VwcGVyQ2FzZSgpOwogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQo"
"J3N0YXQtbGFzdC10aW1lJykudGV4dENvbnRlbnQ9ZWwrJ3MgwrcgJytuZXcgRGF0ZSgpLnRvTG9jYWxl"
"VGltZVN0cmluZygpOwogICAgdXBkYXRlU3RhdHMoKTsKICAgIGlmKGRhdGEucG9ydHMmJmRhdGEucG9y"
"dHMubGVuZ3RoKXt1cGRhdGVQb3J0RGFzaChkYXRhLnBvcnRzLHRhcmdldCk7dGVybUxpbmUoZGF0YS5w"
"b3J0cy5sZW5ndGgrJyBwb3J0cyDigJQgY2hlY2sgUG9ydHMgdGFiJywnaW5mbycpO25vdGlmeShkYXRh"
"LnBvcnRzLmxlbmd0aCsnIHBvcnRzIGZvdW5kIScpfQogICAgaWYoZGF0YS50aHJlYXRzJiZkYXRhLnRo"
"cmVhdHMubGVuZ3RoKXt1cGRhdGVUaHJlYXREYXNoKGRhdGEudGhyZWF0cyk7dGVybUxpbmUoZGF0YS50"
"aHJlYXRzLmxlbmd0aCsnIHRocmVhdHMg4oCUIGNoZWNrIFRocmVhdHMgdGFiJywnZXJyb3InKTtub3Rp"
"ZnkoZGF0YS50aHJlYXRzLmxlbmd0aCsnIHRocmVhdHMgZGV0ZWN0ZWQhJyl9CiAgICBpZihkYXRhLmhh"
"c192b2ljZSlwbGF5Vm9pY2UoKTsKICB9KQogIC5jYXRjaChmdW5jdGlvbihlKXt0ZXJtTGluZSgnRXJy"
"b3I6ICcrZS5tZXNzYWdlLCdlcnJvcicpfSkKICAuZmluYWxseShmdW5jdGlvbigpe3NldExvYWRpbmco"
"ZmFsc2UpfSk7Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT0KICAgQ0hBVAogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCmZ1bmN0aW9uIHNlbmRDaGF0KCl7"
"CiAgdmFyIGlucD1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2hhdC1pbnB1dCcpO3ZhciBtc2c9aW5w"
"LnZhbHVlLnRyaW0oKTtpZighbXNnKXJldHVybjtpbnAudmFsdWU9Jyc7CiAgdmFyIGJveD1kb2N1bWVu"
"dC5nZXRFbGVtZW50QnlJZCgnY2hhdC1tZXNzYWdlcycpOwogIHZhciB1PWRvY3VtZW50LmNyZWF0ZUVs"
"ZW1lbnQoJ2RpdicpO3UuY2xhc3NOYW1lPSdtc2cgdXNlcic7dS5pbm5lckhUTUw9JzxkaXYgY2xhc3M9"
"Im1zZy1hdmF0YXIiPllPVTwvZGl2PjxkaXYgY2xhc3M9Im1zZy1ib2R5Ij4nK21zZy5yZXBsYWNlKC88"
"L2csJyZsdDsnKS5yZXBsYWNlKC8+L2csJyZndDsnKSsnPC9kaXY+JzsKICBib3guYXBwZW5kQ2hpbGQo"
"dSk7Ym94LnNjcm9sbFRvcD1ib3guc2Nyb2xsSGVpZ2h0OwogIGZldGNoKCcvY2hhdCcse21ldGhvZDon"
"UE9TVCcsaGVhZGVyczp7J0NvbnRlbnQtVHlwZSc6J2FwcGxpY2F0aW9uL2pzb24nfSxib2R5OkpTT04u"
"c3RyaW5naWZ5KHttZXNzYWdlOm1zZ30pfSkKICAudGhlbihmdW5jdGlvbihyKXtyZXR1cm4gci5qc29u"
"KCl9KQogIC50aGVuKGZ1bmN0aW9uKGQpe3ZhciBhPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2Rpdicp"
"O2EuY2xhc3NOYW1lPSdtc2cgYWknO2EuaW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJtc2ctYXZhdGFyIj5B"
"STwvZGl2PjxkaXYgY2xhc3M9Im1zZy1ib2R5Ij4nK2QucmVzcG9uc2UrJzwvZGl2Pic7Ym94LmFwcGVu"
"ZENoaWxkKGEpO2JveC5zY3JvbGxUb3A9Ym94LnNjcm9sbEhlaWdodDtpZihkLmhhc192b2ljZSlwbGF5"
"Vm9pY2UoKX0pCiAgLmNhdGNoKGZ1bmN0aW9uKCl7dmFyIGU9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgn"
"ZGl2Jyk7ZS5jbGFzc05hbWU9J21zZyBhaSc7ZS5pbm5lckhUTUw9JzxkaXYgY2xhc3M9Im1zZy1hdmF0"
"YXIiPkFJPC9kaXY+PGRpdiBjbGFzcz0ibXNnLWJvZHkiIHN0eWxlPSJjb2xvcjp2YXIoLS1yZWQtbGln"
"aHQpIj5Db25uZWN0aW9uIGVycm9yLjwvZGl2Pic7Ym94LmFwcGVuZENoaWxkKGUpfSk7Cn0KCi8qID09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT0KICAgUkVQT1JUCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT0gKi8KZnVuY3Rpb24gb3BlblJlcG9ydCgpewogIHZhciBub3c9bmV3"
"IERhdGUoKS50b0xvY2FsZVN0cmluZygpOwogIHZhciBzb3J0ZWQ9YWxsUG9ydHMuc2xpY2UoKS5zb3J0"
"KGZ1bmN0aW9uKGEsYil7dmFyIG89e0NSSVRJQ0FMOjAsSElHSDoxLE1FRElVTToyLExPVzozfTtyZXR1"
"cm4ob1thLnNldmVyaXR5XXx8MyktKG9bYi5zZXZlcml0eV18fDMpfHxhLnBvcnQtYi5wb3J0fSk7CiAg"
"dmFyIGg9JzxkaXYgY2xhc3M9InJwLWhkciI+PGRpdiBjbGFzcz0icnAtdCI+SEFSU0hBIHY3LjAgVkFQ"
"VCBSRVBPUlQ8L2Rpdj48ZGl2IGNsYXNzPSJycC1zIj5XZWIgKyBOZXR3b3JrICsgSW5mcmFzdHJ1Y3R1"
"cmUgVkFQVCBTdWl0ZTwvZGl2PjxkaXYgc3R5bGU9Im1hcmdpbi10b3A6NXB4O2ZvbnQtc2l6ZToxMHB4"
"O2NvbG9yOnZhcigtLXR4LWZhaW50KSI+QW5hbHlzdDogSEFSU0hBIHwgVGFyZ2V0OiAnKyhsYXN0VGFy"
"Z2V0fHwnTXVsdGlwbGUnKSsnIHwgJytub3crJzwvZGl2PjwvZGl2Pic7CiAgaCs9JzxkaXYgY2xhc3M9"
"InJwLXNlYyI+PGRpdiBjbGFzcz0icnAtc3QiPkVYRUNVVElWRSBTVU1NQVJZPC9kaXY+PGRpdiBzdHls"
"ZT0iZm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tdHgtbXV0ZWQpIj5TY2FuczogJytzY2FuQ291bnQr"
"JyDCtyBQb3J0czogJythbGxQb3J0cy5sZW5ndGgrJyDCtyBUaHJlYXRzOiAnK2FsbFRocmVhdHMubGVu"
"Z3RoKyc8L2Rpdj48L2Rpdj4nOwogIGlmKHNvcnRlZC5sZW5ndGgpe2grPSc8ZGl2IGNsYXNzPSJycC1z"
"ZWMiPjxkaXYgY2xhc3M9InJwLXN0Ij5PUEVOIFBPUlRTICgnK3NvcnRlZC5sZW5ndGgrJyk8L2Rpdj4n"
"O3NvcnRlZC5mb3JFYWNoKGZ1bmN0aW9uKHApe2grPSc8ZGl2IGNsYXNzPSJycC1wciI+PGRpdj48c3Bh"
"biBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKTtmb250LXdlaWdodDpib2xkIj4nK3AucG9ydCsnLycrcC5w"
"cm90bysnPC9zcGFuPjwvZGl2PjxkaXYgc3R5bGU9ImNvbG9yOnZhcigtLXR4LWRhcmspO2ZvbnQtd2Vp"
"Z2h0OjYwMCI+JytwLnNlcnZpY2UrJzwvZGl2PjxkaXY+PHNwYW4gY2xhc3M9InNldiAnK3Auc2V2ZXJp"
"dHkrJyI+JytwLnNldmVyaXR5Kyc8L3NwYW4+PC9kaXY+PGRpdiBzdHlsZT0iY29sb3I6dmFyKC0tdHgt"
"bXV0ZWQpO2ZvbnQtc2l6ZToxMHB4Ij4nK3AuZGVzYysnPC9kaXY+PC9kaXY+J30pO2grPSc8L2Rpdj4n"
"fQogIGlmKGFsbFRocmVhdHMubGVuZ3RoKXtoKz0nPGRpdiBjbGFzcz0icnAtc2VjIj48ZGl2IGNsYXNz"
"PSJycC1zdCI+VlVMTkVSQUJJTElUSUVTICgnK2FsbFRocmVhdHMubGVuZ3RoKycpPC9kaXY+JzthbGxU"
"aHJlYXRzLmZvckVhY2goZnVuY3Rpb24odCxpKXtoKz0nPGRpdiBjbGFzcz0icnAtdGggJyt0LnNldmVy"
"aXR5KyciPjxkaXYgY2xhc3M9InJwLXRuIj4nKyhpKzEpKycuICcrdC5uYW1lKycgPHNwYW4gY2xhc3M9"
"InNldiAnK3Quc2V2ZXJpdHkrJyI+Jyt0LnNldmVyaXR5Kyc8L3NwYW4+PC9kaXY+PGRpdiBjbGFzcz0i"
"cnAtdGQiPicrdC5kZXNjKyc8L2Rpdj48ZGl2IGNsYXNzPSJycC10ZiI+RklYOiAnK3QuZml4Kyc8L2Rp"
"dj48L2Rpdj4nfSk7aCs9JzwvZGl2Pid9CiAgaWYoIXNvcnRlZC5sZW5ndGgmJiFhbGxUaHJlYXRzLmxl"
"bmd0aCloKz0nPGRpdiBzdHlsZT0iY29sb3I6dmFyKC0tc2V2LWxvdyk7cGFkZGluZzoxNnB4IDAiPk5v"
"IGRhdGEgeWV0LiBSdW4gc2NhbnMgZmlyc3QuPC9kaXY+JzsKICBkb2N1bWVudC5nZXRFbGVtZW50QnlJ"
"ZCgncnAnKS5pbm5lckhUTUw9aDtkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncmVwb3J0LW1vZGFsJyku"
"Y2xhc3NMaXN0LmFkZCgnb3BlbicpOwp9CmZ1bmN0aW9uIGNsb3NlUmVwb3J0KCl7ZG9jdW1lbnQuZ2V0"
"RWxlbWVudEJ5SWQoJ3JlcG9ydC1tb2RhbCcpLmNsYXNzTGlzdC5yZW1vdmUoJ29wZW4nKX0KCmZ1bmN0"
"aW9uIGRvd25sb2FkSFRNTCgpewogIHZhciBub3c9bmV3IERhdGUoKS50b0xvY2FsZVN0cmluZygpO3Zh"
"ciBzb3J0ZWQ9YWxsUG9ydHMuc2xpY2UoKS5zb3J0KGZ1bmN0aW9uKGEsYil7dmFyIG89e0NSSVRJQ0FM"
"OjAsSElHSDoxLE1FRElVTToyLExPVzozfTtyZXR1cm4ob1thLnNldmVyaXR5XXx8MyktKG9bYi5zZXZl"
"cml0eV18fDMpfHxhLnBvcnQtYi5wb3J0fSk7CiAgdmFyIGI9JzwhRE9DVFlQRSBodG1sPjxodG1sPjxo"
"ZWFkPjxtZXRhIGNoYXJzZXQ9IlVURi04Ij48dGl0bGU+SEFSU0hBIHY3LjA8L3RpdGxlPjxzdHlsZT5i"
"b2R5e2ZvbnQtZmFtaWx5Om1vbm9zcGFjZTtiYWNrZ3JvdW5kOiNmZmY7Y29sb3I6IzNhM2E0NDtwYWRk"
"aW5nOjMwcHg7bWF4LXdpZHRoOjExMDBweDttYXJnaW46YXV0b31oMXtjb2xvcjojZTYzOTQ2O3RleHQt"
"YWxpZ246Y2VudGVyfWgye2NvbG9yOiNlNjM5NDY7Zm9udC1zaXplOjEycHg7bWFyZ2luLXRvcDoxOHB4"
"fXRhYmxle3dpZHRoOjEwMCU7Ym9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlfXRoLHRke3BhZGRpbmc6NXB4"
"O2JvcmRlci1ib3R0b206MXB4IHNvbGlkICNlY2VjZWY7Zm9udC1zaXplOjEwcHg7dGV4dC1hbGlnbjps"
"ZWZ0fS5jYXJke2JvcmRlci1sZWZ0OjRweCBzb2xpZCAjZDkwNDI5O3BhZGRpbmc6OHB4IDEycHg7bWFy"
"Z2luOjVweCAwO2JhY2tncm91bmQ6I2Y3ZjdmODtib3JkZXItcmFkaXVzOjZweH08L3N0eWxlPjwvaGVh"
"ZD48Ym9keT4nOwogIGIrPSc8aDE+SEFSU0hBIHY3LjAgVkFQVCBSRVBPUlQ8L2gxPjxwIHN0eWxlPSJ0"
"ZXh0LWFsaWduOmNlbnRlcjtjb2xvcjojYjBiMGJhIj4nK25vdysnPC9wPic7CiAgaWYoc29ydGVkLmxl"
"bmd0aCl7Yis9JzxoMj5PUEVOIFBPUlRTPC9oMj48dGFibGU+PHRyPjx0aD5QT1JUPC90aD48dGg+U0VS"
"VklDRTwvdGg+PHRoPlJJU0s8L3RoPjx0aD5ERVNDPC90aD48L3RyPic7c29ydGVkLmZvckVhY2goZnVu"
"Y3Rpb24ocCl7Yis9Jzx0cj48dGQ+JytwLnBvcnQrJy8nK3AucHJvdG8rJzwvdGQ+PHRkPicrcC5zZXJ2"
"aWNlKyc8L3RkPjx0ZD4nK3Auc2V2ZXJpdHkrJzwvdGQ+PHRkPicrcC5kZXNjKyc8L3RkPjwvdHI+J30p"
"O2IrPSc8L3RhYmxlPid9CiAgaWYoYWxsVGhyZWF0cy5sZW5ndGgpe2IrPSc8aDI+VlVMTkVSQUJJTElU"
"SUVTPC9oMj4nO2FsbFRocmVhdHMuZm9yRWFjaChmdW5jdGlvbih0LGkpe2IrPSc8ZGl2IGNsYXNzPSJj"
"YXJkIj48Yj4nKyhpKzEpKycuICcrdC5uYW1lKyc8L2I+IFsnK3Quc2V2ZXJpdHkrJ108cD4nK3QuZGVz"
"YysnPC9wPjxwIHN0eWxlPSJjb2xvcjojMmQ2YTRmIj5GSVg6ICcrdC5maXgrJzwvcD48L2Rpdj4nfSl9"
"CiAgYis9JzwvYm9keT48L2h0bWw+JzsKICB2YXIgYT1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdhJyk7"
"YS5ocmVmPVVSTC5jcmVhdGVPYmplY3RVUkwobmV3IEJsb2IoW2JdLHt0eXBlOid0ZXh0L2h0bWwnfSkp"
"O2EuZG93bmxvYWQ9J0hBUlNIQV92N19WQVBULmh0bWwnO2EuY2xpY2soKTtub3RpZnkoJ1JlcG9ydCBk"
"b3dubG9hZGVkIScpOwp9CmZ1bmN0aW9uIGRvd25sb2FkVFhUKCl7CiAgdmFyIG5vdz1uZXcgRGF0ZSgp"
"LnRvTG9jYWxlU3RyaW5nKCk7dmFyIHQ9J0hBUlNIQSB2Ny4wIFZBUFQgUkVQT1JUXG4nK25vdysnXG5c"
"bic7CiAgYWxsUG9ydHMuZm9yRWFjaChmdW5jdGlvbihwKXt0Kz1wLnBvcnQrJy8nK3AucHJvdG8rJyAn"
"K3Auc2VydmljZSsnIFsnK3Auc2V2ZXJpdHkrJ10gJytwLmRlc2MrJ1xuJ30pOwogIGlmKGFsbFRocmVh"
"dHMubGVuZ3RoKXt0Kz0nXG5WVUxORVJBQklMSVRJRVM6XG4nO2FsbFRocmVhdHMuZm9yRWFjaChmdW5j"
"dGlvbih0aCxpKXt0Kz0oaSsxKSsnLiAnK3RoLm5hbWUrJyBbJyt0aC5zZXZlcml0eSsnXSAnK3RoLmRl"
"c2MrJ1xuRklYOiAnK3RoLmZpeCsnXG5cbid9KX0KICB2YXIgYT1kb2N1bWVudC5jcmVhdGVFbGVtZW50"
"KCdhJyk7YS5ocmVmPVVSTC5jcmVhdGVPYmplY3RVUkwobmV3IEJsb2IoW3RdLHt0eXBlOid0ZXh0L3Bs"
"YWluJ30pKTthLmRvd25sb2FkPSdIQVJTSEFfdjdfVkFQVC50eHQnO2EuY2xpY2soKTtub3RpZnkoJ1RY"
"VCBkb3dubG9hZGVkIScpOwp9CmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZXBvcnQtbW9kYWwnKS5h"
"ZGRFdmVudExpc3RlbmVyKCdjbGljaycsZnVuY3Rpb24oZSl7aWYoZS50YXJnZXQ9PT10aGlzKWNsb3Nl"
"UmVwb3J0KCl9KTsKCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT0KICAgQ0hBUlRTCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KQ2hhcnQuZGVmYXVsdHMuY29s"
"b3I9JyM4YThhOTYnO0NoYXJ0LmRlZmF1bHRzLmJvcmRlckNvbG9yPSdyZ2JhKDAsMCwwLDAuMDYpJzsK"
"Q2hhcnQuZGVmYXVsdHMuZm9udC5mYW1pbHk9IidJQk0gUGxleCBNb25vJyxtb25vc3BhY2UiO0NoYXJ0"
"LmRlZmF1bHRzLmZvbnQuc2l6ZT0xMDsKQ2hhcnQuZGVmYXVsdHMucGx1Z2lucy5sZWdlbmQubGFiZWxz"
"LmJveFdpZHRoPTEwO0NoYXJ0LmRlZmF1bHRzLnBsdWdpbnMubGVnZW5kLmxhYmVscy5wYWRkaW5nPTE0"
"OwoKZnVuY3Rpb24gZGVzdHJveUNoYXJ0cyhvKXtPYmplY3Qua2V5cyhvKS5mb3JFYWNoKGZ1bmN0aW9u"
"KGspe2lmKG9ba10pe29ba10uZGVzdHJveSgpO29ba109bnVsbH19KX0KZnVuY3Rpb24gY2FsY1Jpc2tT"
"Y29yZShwLHQpe2lmKCFwLmxlbmd0aCYmIXQubGVuZ3RoKXJldHVybiAwO3ZhciBzPTA7cC5mb3JFYWNo"
"KGZ1bmN0aW9uKHgpe2lmKHguc2V2ZXJpdHk9PT0nQ1JJVElDQUwnKXMrPTI1O2Vsc2UgaWYoeC5zZXZl"
"cml0eT09PSdISUdIJylzKz0xNTtlbHNlIGlmKHguc2V2ZXJpdHk9PT0nTUVESVVNJylzKz04O2Vsc2Ug"
"cys9M30pO3QuZm9yRWFjaChmdW5jdGlvbih4KXtpZih4LnNldmVyaXR5PT09J0NSSVRJQ0FMJylzKz0z"
"MDtlbHNlIGlmKHguc2V2ZXJpdHk9PT0nSElHSCcpcys9MjA7ZWxzZSBpZih4LnNldmVyaXR5PT09J01F"
"RElVTScpcys9MTA7ZWxzZSBzKz00fSk7cmV0dXJuIE1hdGgubWluKDEwMCxNYXRoLnJvdW5kKHMpKX0K"
"ZnVuY3Rpb24gZ2V0Umlza0NvbG9yKHMpe2lmKHM+PTc1KXJldHVybicjZDkwNDI5JztpZihzPj01MCly"
"ZXR1cm4nI2U4NWQwNCc7aWYocz49MjUpcmV0dXJuJyNlMDlmM2UnO3JldHVybicjMmQ2YTRmJ30KZnVu"
"Y3Rpb24gZ2V0Umlza0xhYmVsKHMpe2lmKHM+PTc1KXJldHVybidDUklUSUNBTCc7aWYocz49NTApcmV0"
"dXJuJ0hJR0gnO2lmKHM+PTI1KXJldHVybidNRURJVU0nO3JldHVybidMT1cnfQoKZnVuY3Rpb24gcmVm"
"cmVzaFJpc2tDaGFydHMoKXsKICBkZXN0cm95Q2hhcnRzKHJpc2tDaGFydHMpO3ZhciBjPWRvY3VtZW50"
"LmdldEVsZW1lbnRCeUlkKCdyaXNrLWNvbnRlbnQnKTsKICBpZighYWxsUG9ydHMubGVuZ3RoJiYhYWxs"
"VGhyZWF0cy5sZW5ndGgpe2MuaW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJlbXB0eS1zdGF0ZSI+PGRpdiBj"
"bGFzcz0iZW1wdHktaWNvIj7wn5OKPC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktdGl0bGUiPk5vIFJpc2sg"
"RGF0YTwvZGl2PjxkaXYgY2xhc3M9ImVtcHR5LXN1YiI+UnVuIHNjYW5zIGZpcnN0PC9kaXY+PC9kaXY+"
"JztyZXR1cm59CiAgdmFyIGNyaXQ9MCxoaWdoPTAsbWVkPTAsbG93PTA7CiAgYWxsUG9ydHMuZm9yRWFj"
"aChmdW5jdGlvbihwKXtpZihwLnNldmVyaXR5PT09J0NSSVRJQ0FMJyljcml0Kys7ZWxzZSBpZihwLnNl"
"dmVyaXR5PT09J0hJR0gnKWhpZ2grKztlbHNlIGlmKHAuc2V2ZXJpdHk9PT0nTUVESVVNJyltZWQrKztl"
"bHNlIGxvdysrfSk7CiAgYWxsVGhyZWF0cy5mb3JFYWNoKGZ1bmN0aW9uKHQpe2lmKHQuc2V2ZXJpdHk9"
"PT0nQ1JJVElDQUwnKWNyaXQrKztlbHNlIGlmKHQuc2V2ZXJpdHk9PT0nSElHSCcpaGlnaCsrO2Vsc2Ug"
"aWYodC5zZXZlcml0eT09PSdNRURJVU0nKW1lZCsrO2Vsc2UgbG93Kyt9KTsKICB2YXIgc2NvcmU9Y2Fs"
"Y1Jpc2tTY29yZShhbGxQb3J0cyxhbGxUaHJlYXRzKSxyQz1nZXRSaXNrQ29sb3Ioc2NvcmUpLHJMPWdl"
"dFJpc2tMYWJlbChzY29yZSk7CiAgdmFyIHN2Y01hcD17fTthbGxQb3J0cy5mb3JFYWNoKGZ1bmN0aW9u"
"KHApe3ZhciBzPXAuc2VydmljZXx8Jz8nO2lmKCFzdmNNYXBbc10pc3ZjTWFwW3NdPXtjOjAsaDowLG06"
"MCxsOjAsdDowfTtzdmNNYXBbc10udCsrO2lmKHAuc2V2ZXJpdHk9PT0nQ1JJVElDQUwnKXN2Y01hcFtz"
"XS5jKys7ZWxzZSBpZihwLnNldmVyaXR5PT09J0hJR0gnKXN2Y01hcFtzXS5oKys7ZWxzZSBpZihwLnNl"
"dmVyaXR5PT09J01FRElVTScpc3ZjTWFwW3NdLm0rKztlbHNlIHN2Y01hcFtzXS5sKyt9KTsKICB2YXIg"
"c049T2JqZWN0LmtleXMoc3ZjTWFwKS5zb3J0KGZ1bmN0aW9uKGEsYil7cmV0dXJuIHN2Y01hcFtiXS50"
"LXN2Y01hcFthXS50fSkuc2xpY2UoMCwxMCk7CiAgdmFyIGg9JzxkaXYgY2xhc3M9ImRhc2gtZ3JpZCBj"
"b2xzLTIiIHN0eWxlPSJtYXJnaW4tYm90dG9tOjIwcHgiPic7CiAgaCs9JzxkaXYgY2xhc3M9ImNhcmQi"
"PjxkaXYgY2xhc3M9ImNhcmQtaGVhZGVyIj48ZGl2PjxkaXYgY2xhc3M9ImNhcmQtdGl0bGUiPk92ZXJh"
"bGwgUmlzayBTY29yZTwvZGl2PjwvZGl2PjwvZGl2Pic7CiAgaCs9JzxkaXYgY2xhc3M9InJpc2stZ2F1"
"Z2UiPjxkaXYgY2xhc3M9InJpc2stY2lyY2xlIiBzdHlsZT0iY29sb3I6JytyQysnO2JvcmRlci1jb2xv"
"cjonK3JDKycyNSI+PGRpdiBjbGFzcz0icmlzay12YWwiIHN0eWxlPSJjb2xvcjonK3JDKyciPicrc2Nv"
"cmUrJzwvZGl2PjxkaXYgY2xhc3M9InJpc2stbGFiZWwiPicrckwrJzwvZGl2PjwvZGl2Pic7CiAgaCs9"
"JzxkaXYgY2xhc3M9InJpc2stZGV0YWlscyI+PGRpdiBjbGFzcz0icmlzay1yb3ciPjxkaXYgY2xhc3M9"
"InJpc2stZG90IiBzdHlsZT0iYmFja2dyb3VuZDp2YXIoLS1yZWQpIj48L2Rpdj5Qb3J0czxzcGFuIGNs"
"YXNzPSJyaXNrLXZhbC1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXNldi1oaWdoKSI+JythbGxQb3J0cy5s"
"ZW5ndGgrJzwvc3Bhbj48L2Rpdj4nOwogIGgrPSc8ZGl2IGNsYXNzPSJyaXNrLXJvdyI+PGRpdiBjbGFz"
"cz0icmlzay1kb3QiIHN0eWxlPSJiYWNrZ3JvdW5kOnZhcigtLXNldi1jcml0KSI+PC9kaXY+VGhyZWF0"
"czxzcGFuIGNsYXNzPSJyaXNrLXZhbC1zbSIgc3R5bGU9ImNvbG9yOnZhcigtLXNldi1jcml0KSI+Jyth"
"bGxUaHJlYXRzLmxlbmd0aCsnPC9zcGFuPjwvZGl2PjwvZGl2PjwvZGl2PjwvZGl2Pic7CiAgaCs9Jzxk"
"aXYgY2xhc3M9ImNhcmQiPjxkaXYgY2xhc3M9ImNhcmQtdGl0bGUiPlNldmVyaXR5IERpc3RyaWJ1dGlv"
"bjwvZGl2PjxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPjxjYW52YXMgaWQ9ImNoLXNldiI+PC9jYW52YXM+"
"PC9kaXY+PC9kaXY+JzsKICBoKz0nPC9kaXY+JzsKICBpZihzTi5sZW5ndGgpe2grPSc8ZGl2IGNsYXNz"
"PSJkYXNoLWdyaWQgY29scy0yIj48ZGl2IGNsYXNzPSJjYXJkIj48ZGl2IGNsYXNzPSJjYXJkLXRpdGxl"
"Ij5SaXNrIGJ5IFNlcnZpY2U8L2Rpdj48ZGl2IGNsYXNzPSJjaGFydC13cmFwIj48Y2FudmFzIGlkPSJj"
"aC1zdmMiPjwvY2FudmFzPjwvZGl2PjwvZGl2Pic7CiAgaCs9JzxkaXYgY2xhc3M9ImNhcmQiPjxkaXYg"
"Y2xhc3M9ImNhcmQtdGl0bGUiPlJpc2sgYnkgQ2F0ZWdvcnk8L2Rpdj48ZGl2IGNsYXNzPSJjaGFydC13"
"cmFwIj48Y2FudmFzIGlkPSJjaC1jYXQiPjwvY2FudmFzPjwvZGl2PjwvZGl2PjwvZGl2Pid9CiAgYy5p"
"bm5lckhUTUw9aDsKICB2YXIgeDE9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NoLXNldicpO2lmKHgx"
"KXJpc2tDaGFydHMucz1uZXcgQ2hhcnQoeDEse3R5cGU6J2RvdWdobnV0JyxkYXRhOntsYWJlbHM6WydD"
"cml0aWNhbCcsJ0hpZ2gnLCdNZWRpdW0nLCdMb3cnXSxkYXRhc2V0czpbe2RhdGE6W2NyaXQsaGlnaCxt"
"ZWQsbG93XSxiYWNrZ3JvdW5kQ29sb3I6W3NldkNvbG9ycy5DUklUSUNBTCxzZXZDb2xvcnMuSElHSCxz"
"ZXZDb2xvcnMuTUVESVVNLHNldkNvbG9ycy5MT1ddLGJvcmRlcldpZHRoOjAsaG92ZXJPZmZzZXQ6OH1d"
"fSxvcHRpb25zOntyZXNwb25zaXZlOnRydWUsbWFpbnRhaW5Bc3BlY3RSYXRpbzpmYWxzZSxjdXRvdXQ6"
"JzcwJScscGx1Z2luczp7bGVnZW5kOntwb3NpdGlvbjoncmlnaHQnfX19fSk7CiAgdmFyIHgyPWRvY3Vt"
"ZW50LmdldEVsZW1lbnRCeUlkKCdjaC1zdmMnKTtpZih4MiYmc04ubGVuZ3RoKXJpc2tDaGFydHMudj1u"
"ZXcgQ2hhcnQoeDIse3R5cGU6J2JhcicsZGF0YTp7bGFiZWxzOnNOLGRhdGFzZXRzOlt7bGFiZWw6J0Ny"
"aXQnLGRhdGE6c04ubWFwKGZ1bmN0aW9uKHMpe3JldHVybiBzdmNNYXBbc10uY30pLGJhY2tncm91bmRD"
"b2xvcjpzZXZCZy5DUklUSUNBTCxib3JkZXJDb2xvcjpzZXZDb2xvcnMuQ1JJVElDQUwsYm9yZGVyV2lk"
"dGg6MX0se2xhYmVsOidIaWdoJyxkYXRhOnNOLm1hcChmdW5jdGlvbihzKXtyZXR1cm4gc3ZjTWFwW3Nd"
"Lmh9KSxiYWNrZ3JvdW5kQ29sb3I6c2V2QmcuSElHSCxib3JkZXJDb2xvcjpzZXZDb2xvcnMuSElHSCxi"
"b3JkZXJXaWR0aDoxfSx7bGFiZWw6J0xvdycsZGF0YTpzTi5tYXAoZnVuY3Rpb24ocyl7cmV0dXJuIHN2"
"Y01hcFtzXS5sfSksYmFja2dyb3VuZENvbG9yOnNldkJnLkxPVyxib3JkZXJDb2xvcjpzZXZDb2xvcnMu"
"TE9XLGJvcmRlcldpZHRoOjF9XX0sb3B0aW9uczp7cmVzcG9uc2l2ZTp0cnVlLG1haW50YWluQXNwZWN0"
"UmF0aW86ZmFsc2UsaW5kZXhBeGlzOid5JyxzY2FsZXM6e3g6e3N0YWNrZWQ6dHJ1ZX0seTp7c3RhY2tl"
"ZDp0cnVlLGdyaWQ6e2Rpc3BsYXk6ZmFsc2V9fX0scGx1Z2luczp7bGVnZW5kOntwb3NpdGlvbjondG9w"
"JyxsYWJlbHM6e2JveFdpZHRoOjh9fX19fSk7CiAgdmFyIGNOPTAsY1c9MCxjST0wO2FsbFRocmVhdHMu"
"Zm9yRWFjaChmdW5jdGlvbih0KXt2YXIgbj10Lm5hbWUudG9Mb3dlckNhc2UoKTtpZihuLmluZGV4T2Yo"
"J3NxbCcpPj0wfHxuLmluZGV4T2YoJ3hzcycpPj0wfHxuLmluZGV4T2YoJ2hlYWRlcicpPj0wfHxuLmlu"
"ZGV4T2YoJ3NzbCcpPj0wKWNXKys7ZWxzZSBpZihuLmluZGV4T2YoJ3NtYicpPj0wfHxuLmluZGV4T2Yo"
"J3NubXAnKT49MHx8bi5pbmRleE9mKCdwb3J0Jyk+PTApY04rKztlbHNlIGNJKyt9KTsKICB2YXIgeDM9"
"ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NoLWNhdCcpO2lmKHgzKXJpc2tDaGFydHMuYz1uZXcgQ2hh"
"cnQoeDMse3R5cGU6J2RvdWdobnV0JyxkYXRhOntsYWJlbHM6WydOZXR3b3JrJywnV2ViJywnSW5mcmFz"
"dHJ1Y3R1cmUnXSxkYXRhc2V0czpbe2RhdGE6W01hdGgubWF4KGNOLFNDLm5ldHx8MCksTWF0aC5tYXgo"
"Y1csU0Mud2VifHwwKSxNYXRoLm1heChjSSxTQy5pbmZ8fDApXSxiYWNrZ3JvdW5kQ29sb3I6WycjMGEw"
"YTBjJywnI2U2Mzk0NicsJyM4YThhOTYnXSxib3JkZXJXaWR0aDowfV19LG9wdGlvbnM6e3Jlc3BvbnNp"
"dmU6dHJ1ZSxtYWludGFpbkFzcGVjdFJhdGlvOmZhbHNlLGN1dG91dDonNzAlJyxwbHVnaW5zOntsZWdl"
"bmQ6e3Bvc2l0aW9uOidyaWdodCd9fX19KTsKfQoKZnVuY3Rpb24gcmVmcmVzaFRocmVhdENoYXJ0cygp"
"ewogIGRlc3Ryb3lDaGFydHModGhyZWF0Q2hhcnRzKTt2YXIgYz1kb2N1bWVudC5nZXRFbGVtZW50QnlJ"
"ZCgndGdyYXBoLWNvbnRlbnQnKTsKICBpZighYWxsVGhyZWF0cy5sZW5ndGgmJiFhbGxQb3J0cy5sZW5n"
"dGgpe2MuaW5uZXJIVE1MPSc8ZGl2IGNsYXNzPSJlbXB0eS1zdGF0ZSI+PGRpdiBjbGFzcz0iZW1wdHkt"
"aWNvIj7wn5W4PC9kaXY+PGRpdiBjbGFzcz0iZW1wdHktdGl0bGUiPk5vIFRocmVhdCBEYXRhPC9kaXY+"
"PGRpdiBjbGFzcz0iZW1wdHktc3ViIj5SdW4gc2NhbnMgZmlyc3Q8L2Rpdj48L2Rpdj4nO3JldHVybn0K"
"ICB2YXIgY2F0cz17aW5qZWN0aW9uOjAsY29uZmlnOjAsY3J5cHRvOjAsZXhwb3N1cmU6MCxhdXRoOjAs"
"bmV0d29yazowfTsKICBhbGxUaHJlYXRzLmZvckVhY2goZnVuY3Rpb24odCl7dmFyIG49dC5uYW1lLnRv"
"TG93ZXJDYXNlKCk7aWYobi5pbmRleE9mKCdzcWwnKT49MHx8bi5pbmRleE9mKCd4c3MnKT49MHx8bi5p"
"bmRleE9mKCdpbmplY3QnKT49MCljYXRzLmluamVjdGlvbisrO2Vsc2UgaWYobi5pbmRleE9mKCdoZWFk"
"ZXInKT49MHx8bi5pbmRleE9mKCdjb3JzJyk+PTB8fG4uaW5kZXhPZignY29uZmlnJyk+PTApY2F0cy5j"
"b25maWcrKztlbHNlIGlmKG4uaW5kZXhPZignc3NsJyk+PTB8fG4uaW5kZXhPZigndGxzJyk+PTApY2F0"
"cy5jcnlwdG8rKztlbHNlIGlmKG4uaW5kZXhPZignZXhwb3N1cmUnKT49MHx8bi5pbmRleE9mKCdpbmZv"
"Jyk+PTApY2F0cy5leHBvc3VyZSsrO2Vsc2UgaWYobi5pbmRleE9mKCdhdXRoJyk+PTB8fG4uaW5kZXhP"
"ZignZnRwJyk+PTB8fG4uaW5kZXhPZignc3NoJyk+PTApY2F0cy5hdXRoKys7ZWxzZSBjYXRzLm5ldHdv"
"cmsrK30pOwogIHZhciBzdj17Q1JJVElDQUw6MCxISUdIOjAsTUVESVVNOjAsTE9XOjB9O2FsbFRocmVh"
"dHMuZm9yRWFjaChmdW5jdGlvbih0KXtzdlt0LnNldmVyaXR5XT0oc3ZbdC5zZXZlcml0eV18fDApKzF9"
"KTsKICB2YXIgaD0nPGRpdiBjbGFzcz0iZGFzaC1ncmlkIGNvbHMtMiIgc3R5bGU9Im1hcmdpbi1ib3R0"
"b206MjBweCI+JzsKICBoKz0nPGRpdiBjbGFzcz0iY2FyZCI+PGRpdiBjbGFzcz0iY2FyZC10aXRsZSI+"
"QXR0YWNrIFZlY3RvciBBbmFseXNpczwvZGl2PjxkaXYgY2xhc3M9ImNoYXJ0LXdyYXAiPjxjYW52YXMg"
"aWQ9ImNoLXJhZGFyIj48L2NhbnZhcz48L2Rpdj48L2Rpdj4nOwogIGgrPSc8ZGl2IGNsYXNzPSJjYXJk"
"Ij48ZGl2IGNsYXNzPSJjYXJkLXRpdGxlIj5UaHJlYXRzIGJ5IFNldmVyaXR5PC9kaXY+PGRpdiBjbGFz"
"cz0iY2hhcnQtd3JhcCI+PGNhbnZhcyBpZD0iY2gtdHNldiI+PC9jYW52YXM+PC9kaXY+PC9kaXY+PC9k"
"aXY+JzsKICBoKz0nPGRpdiBjbGFzcz0iZGFzaC1ncmlkIGNvbHMtMSI+PGRpdiBjbGFzcz0iY2FyZCI+"
"PGRpdiBjbGFzcz0iY2FyZC10aXRsZSI+Q29tYmluZWQgUmlzayBPdmVydmlldzwvZGl2PjxkaXYgY2xh"
"c3M9ImNoYXJ0LXdyYXAiIHN0eWxlPSJtaW4taGVpZ2h0OjIyMHB4Ij48Y2FudmFzIGlkPSJjaC1jb21i"
"byI+PC9jYW52YXM+PC9kaXY+PC9kaXY+PC9kaXY+JzsKICBjLmlubmVySFRNTD1oOwogIHZhciByMT1k"
"b2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2gtcmFkYXInKTtpZihyMSl0aHJlYXRDaGFydHMucj1uZXcg"
"Q2hhcnQocjEse3R5cGU6J3JhZGFyJyxkYXRhOntsYWJlbHM6WydJbmplY3Rpb24nLCdNaXNjb25maWcn"
"LCdDcnlwdG8nLCdFeHBvc3VyZScsJ0F1dGgnLCdOZXR3b3JrJ10sZGF0YXNldHM6W3tkYXRhOltjYXRz"
"LmluamVjdGlvbixjYXRzLmNvbmZpZyxjYXRzLmNyeXB0byxjYXRzLmV4cG9zdXJlLGNhdHMuYXV0aCxj"
"YXRzLm5ldHdvcmtdLGJhY2tncm91bmRDb2xvcjoncmdiYSgyMzAsNTcsNzAsMC4xKScsYm9yZGVyQ29s"
"b3I6JyNlNjM5NDYnLGJvcmRlcldpZHRoOjIscG9pbnRCYWNrZ3JvdW5kQ29sb3I6JyNlNjM5NDYnLHBv"
"aW50UmFkaXVzOjR9XX0sb3B0aW9uczp7cmVzcG9uc2l2ZTp0cnVlLG1haW50YWluQXNwZWN0UmF0aW86"
"ZmFsc2Usc2NhbGVzOntyOntiZWdpbkF0WmVybzp0cnVlLGdyaWQ6e2NvbG9yOidyZ2JhKDAsMCwwLDAu"
"MDYpJ30sdGlja3M6e2Rpc3BsYXk6ZmFsc2V9fX0scGx1Z2luczp7bGVnZW5kOntkaXNwbGF5OmZhbHNl"
"fX19fSk7CiAgdmFyIHIyPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjaC10c2V2Jyk7aWYocjIpdGhy"
"ZWF0Q2hhcnRzLnM9bmV3IENoYXJ0KHIyLHt0eXBlOidiYXInLGRhdGE6e2xhYmVsczpbJ0NyaXRpY2Fs"
"JywnSGlnaCcsJ01lZGl1bScsJ0xvdyddLGRhdGFzZXRzOlt7ZGF0YTpbc3YuQ1JJVElDQUwsc3YuSElH"
"SCxzdi5NRURJVU0sc3YuTE9XXSxiYWNrZ3JvdW5kQ29sb3I6W3NldkJnLkNSSVRJQ0FMLHNldkJnLkhJ"
"R0gsc2V2QmcuTUVESVVNLHNldkJnLkxPV10sYm9yZGVyQ29sb3I6W3NldkNvbG9ycy5DUklUSUNBTCxz"
"ZXZDb2xvcnMuSElHSCxzZXZDb2xvcnMuTUVESVVNLHNldkNvbG9ycy5MT1ddLGJvcmRlcldpZHRoOjEs"
"Ym9yZGVyUmFkaXVzOjh9XX0sb3B0aW9uczp7cmVzcG9uc2l2ZTp0cnVlLG1haW50YWluQXNwZWN0UmF0"
"aW86ZmFsc2Usc2NhbGVzOnt4OntncmlkOntkaXNwbGF5OmZhbHNlfX0seTp7YmVnaW5BdFplcm86dHJ1"
"ZSx0aWNrczp7c3RlcFNpemU6MX19fSxwbHVnaW5zOntsZWdlbmQ6e2Rpc3BsYXk6ZmFsc2V9fX19KTsK"
"ICB2YXIgcjU9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2NoLWNvbWJvJyk7aWYocjUpe3ZhciBwUz17"
"Q1JJVElDQUw6MCxISUdIOjAsTUVESVVNOjAsTE9XOjB9O2FsbFBvcnRzLmZvckVhY2goZnVuY3Rpb24o"
"cCl7cFNbcC5zZXZlcml0eV09KHBTW3Auc2V2ZXJpdHldfHwwKSsxfSk7dGhyZWF0Q2hhcnRzLmM9bmV3"
"IENoYXJ0KHI1LHt0eXBlOidiYXInLGRhdGE6e2xhYmVsczpbJ0NyaXRpY2FsJywnSGlnaCcsJ01lZGl1"
"bScsJ0xvdyddLGRhdGFzZXRzOlt7bGFiZWw6J1BvcnRzJyxkYXRhOltwUy5DUklUSUNBTCxwUy5ISUdI"
"LHBTLk1FRElVTSxwUy5MT1ddLGJhY2tncm91bmRDb2xvcjoncmdiYSgxMCwxMCwxMiwwLjA4KScsYm9y"
"ZGVyQ29sb3I6JyMwYTBhMGMnLGJvcmRlcldpZHRoOjEsYm9yZGVyUmFkaXVzOjZ9LHtsYWJlbDonVGhy"
"ZWF0cycsZGF0YTpbc3YuQ1JJVElDQUwsc3YuSElHSCxzdi5NRURJVU0sc3YuTE9XXSxiYWNrZ3JvdW5k"
"Q29sb3I6J3JnYmEoMjMwLDU3LDcwLDAuMSknLGJvcmRlckNvbG9yOicjZTYzOTQ2Jyxib3JkZXJXaWR0"
"aDoxLGJvcmRlclJhZGl1czo2fV19LG9wdGlvbnM6e3Jlc3BvbnNpdmU6dHJ1ZSxtYWludGFpbkFzcGVj"
"dFJhdGlvOmZhbHNlLHNjYWxlczp7eDp7Z3JpZDp7ZGlzcGxheTpmYWxzZX19LHk6e2JlZ2luQXRaZXJv"
"OnRydWUsdGlja3M6e3N0ZXBTaXplOjF9fX0scGx1Z2luczp7bGVnZW5kOntwb3NpdGlvbjondG9wJyxs"
"YWJlbHM6e2JveFdpZHRoOjEwfX19fX0pfQp9CgovKiA9PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIFNDQU4gU1RBVFVTIFBPTExJTkcg"
"KFNJTkdMRSBDTEVBTiBWRVJTSU9OKQogICA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09ICovCmZ1bmN0aW9uIHBvbGxTY2FuU3RhdHVzKCl7"
"CiAgZmV0Y2goJy9zY2FuX3N0YXR1cycpLnRoZW4oZnVuY3Rpb24ocil7cmV0dXJuIHIuanNvbigpfSku"
"dGhlbihmdW5jdGlvbihzKXsKICAgIHZhciBpbmRpY2F0b3I9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQo"
"J3NjYW4taW5kaWNhdG9yJyk7CiAgICB2YXIgYmFyRmlsbD1kb2N1bWVudC5nZXRFbGVtZW50QnlJZCgn"
"c2Nhbi1iYXItZmlsbCcpOwogICAgdmFyIGJhZGdlPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzY2Fu"
"LXN0YXR1cy1iYWRnZScpOwogICAgdmFyIGxpdmVDYXJkPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCds"
"aXZlLXNjYW4tY2FyZCcpOwogICAgdmFyIG1wPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdoLW1pbmkt"
"cHJvZ3Jlc3MnKTsKICAgIHZhciBtYmFyPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdoLW1pbmktYmFy"
"Jyk7CgogICAgLyogTWluaSBwcm9ncmVzcyBiYXIgKi8KICAgIGlmKHMuYWN0aXZlKXttcC5jbGFzc0xp"
"c3QuYWRkKCdhY3RpdmUnKTttYmFyLnN0eWxlLndpZHRoPXMucGVyY2VudCsnJSd9CiAgICBlbHNle21i"
"YXIuc3R5bGUud2lkdGg9cy5waGFzZT09PSdjb21wbGV0ZSc/JzEwMCUnOicwJSc7CiAgICAgIGlmKHMu"
"cGhhc2U9PT0nY29tcGxldGUnKXNldFRpbWVvdXQoZnVuY3Rpb24oKXttcC5jbGFzc0xpc3QucmVtb3Zl"
"KCdhY3RpdmUnKX0sMjAwMCk7CiAgICAgIGVsc2UgbXAuY2xhc3NMaXN0LnJlbW92ZSgnYWN0aXZlJyk7"
"CiAgICB9CgogICAgLyogU2NhbiBTdGF0dXMgdGFiIGluZGljYXRvciAqLwogICAgaW5kaWNhdG9yLmNs"
"YXNzTmFtZT0nc2Nhbi1pbmRpY2F0b3InOwogICAgYmFyRmlsbC5jbGFzc05hbWU9J3NjYW4tYmFyLWZp"
"bGwtbGl2ZSc7CiAgICBpZihzLmFjdGl2ZSl7CiAgICAgIGluZGljYXRvci5jbGFzc05hbWU9J3NjYW4t"
"aW5kaWNhdG9yIHJ1bm5pbmcnOwogICAgICBiYWRnZS5jbGFzc05hbWU9J3RhYi1iYWRnZSBsaXZlJzti"
"YWRnZS50ZXh0Q29udGVudD1zLnBlcmNlbnQrJyUnOwogICAgICBsaXZlQ2FyZC5zdHlsZS5ib3JkZXJM"
"ZWZ0Q29sb3I9J3ZhcigtLXJlZCknOwogICAgfSBlbHNlIGlmKHMucGhhc2U9PT0nY29tcGxldGUnKXsK"
"ICAgICAgaW5kaWNhdG9yLmNsYXNzTmFtZT0nc2Nhbi1pbmRpY2F0b3IgY29tcGxldGUnOwogICAgICBi"
"YXJGaWxsLmNsYXNzTmFtZT0nc2Nhbi1iYXItZmlsbC1saXZlIGNvbXBsZXRlJzsKICAgICAgYmFkZ2Uu"
"Y2xhc3NOYW1lPSd0YWItYmFkZ2UgZG9uZSc7YmFkZ2UudGV4dENvbnRlbnQ9J1x1MjcxMyc7CiAgICAg"
"IGxpdmVDYXJkLnN0eWxlLmJvcmRlckxlZnRDb2xvcj0ndmFyKC0tc2V2LWxvdyknOwogICAgfSBlbHNl"
"IGlmKHMucGhhc2U9PT0nZXJyb3InKXsKICAgICAgaW5kaWNhdG9yLmNsYXNzTmFtZT0nc2Nhbi1pbmRp"
"Y2F0b3IgZXJyb3InOwogICAgICBiYWRnZS5jbGFzc05hbWU9J3RhYi1iYWRnZSBzaG93IGItcmVkJzti"
"YWRnZS50ZXh0Q29udGVudD0nISc7CiAgICAgIGxpdmVDYXJkLnN0eWxlLmJvcmRlckxlZnRDb2xvcj0n"
"dmFyKC0tc2V2LWNyaXQpJzsKICAgIH0gZWxzZSB7CiAgICAgIGJhZGdlLmNsYXNzTmFtZT0ndGFiLWJh"
"ZGdlJzsKICAgICAgbGl2ZUNhcmQuc3R5bGUuYm9yZGVyTGVmdENvbG9yPSd2YXIoLS13aGl0ZS00KSc7"
"CiAgICB9CgogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NjYW4tcGN0LW51bScpLnRleHRDb250"
"ZW50PXMuYWN0aXZlfHxzLnBoYXNlPT09J2NvbXBsZXRlJz9zLnBlcmNlbnQrJyUnOidcdTIwMTQnOwog"
"ICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3NjYW4tdG9vbC1uYW1lJykudGV4dENvbnRlbnQ9cy50"
"b29sX2Rpc3BsYXl8fHMudG9vbHx8J1x1MjAxNCc7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgn"
"c2Nhbi10YXJnZXQnKS50ZXh0Q29udGVudD1zLnRhcmdldHx8J1x1MjAxNCc7CiAgICBkb2N1bWVudC5n"
"ZXRFbGVtZW50QnlJZCgnc2Nhbi1jYXQnKS50ZXh0Q29udGVudD0ocy5jYXRlZ29yeXx8J1x1MjAxNCcp"
"LnRvVXBwZXJDYXNlKCk7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2Nhbi1lbGFwc2VkJyku"
"dGV4dENvbnRlbnQ9cy5lbGFwc2VkKydzJzsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzY2Fu"
"LW1lc3NhZ2UnKS50ZXh0Q29udGVudD1zLm1lc3NhZ2V8fCdSZWFkeSBcdTIwMTQgc2VsZWN0IGEgdG9v"
"bCB0byBiZWdpbic7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc2Nhbi1wY3QtdGV4dCcpLnRl"
"eHRDb250ZW50PXMucGVyY2VudCsnJSc7CiAgICBiYXJGaWxsLnN0eWxlLndpZHRoPXMucGVyY2VudCsn"
"JSc7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3Mtc3VidGl0bGUnKS50ZXh0Q29udGVudD1z"
"LmFjdGl2ZT8nU2Nhbm5pbmcgJytzLnRhcmdldCsnLi4uJzpzLnBoYXNlPT09J2NvbXBsZXRlJz8nTGFz"
"dCBzY2FuIGNvbXBsZXRlZCc6J05vIGFjdGl2ZSBzY2FuJzsKCiAgICB2YXIgcGI9ZG9jdW1lbnQuZ2V0"
"RWxlbWVudEJ5SWQoJ3NjYW4tcGhhc2UtYmFkZ2UnKTsKICAgIHBiLnRleHRDb250ZW50PShzLnBoYXNl"
"fHwnaWRsZScpLnRvVXBwZXJDYXNlKCk7CiAgICBpZihzLmFjdGl2ZSl7cGIuc3R5bGUuYmFja2dyb3Vu"
"ZD0ndmFyKC0tcmVkLWRpbSknO3BiLnN0eWxlLmNvbG9yPSd2YXIoLS1yZWQpJ30KICAgIGVsc2UgaWYo"
"cy5waGFzZT09PSdjb21wbGV0ZScpe3BiLnN0eWxlLmJhY2tncm91bmQ9J3ZhcigtLXNldi1sb3ctYmcp"
"JztwYi5zdHlsZS5jb2xvcj0ndmFyKC0tc2V2LWxvdyknfQogICAgZWxzZXtwYi5zdHlsZS5iYWNrZ3Jv"
"dW5kPSd2YXIoLS13aGl0ZS0yKSc7cGIuc3R5bGUuY29sb3I9J3ZhcigtLXR4LW11dGVkKSd9CgogICAg"
"dmFyIHRTPXMuaGlzdG9yeT9zLmhpc3RvcnkubGVuZ3RoOjAsdFA9MCx0VD0wLHREPTA7CiAgICBpZihz"
"Lmhpc3Rvcnkpe3MuaGlzdG9yeS5mb3JFYWNoKGZ1bmN0aW9uKGgpe3RQKz1oLnBvcnRzfHwwO3RUKz1o"
"LnRocmVhdHN8fDA7dEQrPWguZWxhcHNlZHx8MH0pfQogICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQo"
"J3NzLXRvdGFsJykudGV4dENvbnRlbnQ9dFM7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3Mt"
"cG9ydHMnKS50ZXh0Q29udGVudD10UDsKICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzcy10aHJl"
"YXRzJykudGV4dENvbnRlbnQ9dFQ7CiAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3MtYXZnJyku"
"dGV4dENvbnRlbnQ9dFM+MD8odEQvdFMpLnRvRml4ZWQoMSkrJ3MnOicwcyc7CgogICAgaWYocy5oaXN0"
"b3J5JiZzLmhpc3RvcnkubGVuZ3RoKXsKICAgICAgdmFyIHJvd3M9Jyc7CiAgICAgIHMuaGlzdG9yeS5m"
"b3JFYWNoKGZ1bmN0aW9uKGgpewogICAgICAgIHJvd3MrPSc8dHI+PHRkIHN0eWxlPSJjb2xvcjp2YXIo"
"LS1zZXYtbG93KTtmb250LXdlaWdodDo3MDAiPlx1MjcxMyBEb25lPC90ZD4nOwogICAgICAgIHJvd3Mr"
"PSc8dGQgc3R5bGU9ImZvbnQtd2VpZ2h0OjYwMDtjb2xvcjp2YXIoLS10eC1kYXJrKSI+JytoLnRvb2wr"
"JzwvdGQ+JzsKICAgICAgICByb3dzKz0nPHRkIHN0eWxlPSJmb250LWZhbWlseTpJQk0gUGxleCBNb25v"
"LG1vbm9zcGFjZTtmb250LXNpemU6MTFweDtjb2xvcjp2YXIoLS1yZWQpIj4nK2gudGFyZ2V0Kyc8L3Rk"
"Pic7CiAgICAgICAgcm93cys9Jzx0ZCBzdHlsZT0iZm9udC1mYW1pbHk6SUJNIFBsZXggTW9ubyxtb25v"
"c3BhY2U7Zm9udC13ZWlnaHQ6NzAwIj4nK2guZWxhcHNlZCsnczwvdGQ+JzsKICAgICAgICByb3dzKz0n"
"PHRkPicraC5wb3J0cysnPC90ZD48dGQ+JytoLnRocmVhdHMrJzwvdGQ+JzsKICAgICAgICByb3dzKz0n"
"PHRkIHN0eWxlPSJjb2xvcjp2YXIoLS10eC1mYWludCkiPicraC50aW1lKyc8L3RkPjwvdHI+JzsKICAg"
"ICAgfSk7CiAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzcy1oaXN0b3J5LXRhYmxlJykuaW5u"
"ZXJIVE1MPXJvd3M7CiAgICB9CgogICAgaWYocy5hY3RpdmUgJiYgbGFzdFBoYXNlIT09J3NjYW5uaW5n"
"JyAmJiBsYXN0UGhhc2UhPT0naW5pdGlhbGl6aW5nJyAmJiBsYXN0UGhhc2UhPT0nYW5hbHl6aW5nJyl7"
"CiAgICAgIHN3aXRjaFRhYignc2NhbnN0YXR1cycsZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLnRh"
"Yi1idG4nKVs1XSk7CiAgICB9CiAgICBsYXN0UGhhc2U9cy5waGFzZTsKICB9KS5jYXRjaChmdW5jdGlv"
"bigpe30pOwp9CnNldEludGVydmFsKHBvbGxTY2FuU3RhdHVzLDgwMCk7CgovKiA9PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIEFUVEFD"
"SyBDSEFJTiBWSVNVQUxJWkFUSU9OCiAgID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gKi8KZnVuY3Rpb24gcmVmcmVzaEF0dGFja0NoYWlu"
"cygpewogIGZldGNoKCcvYXR0YWNrX2NoYWlucycpLnRoZW4oZnVuY3Rpb24ocil7cmV0dXJuIHIuanNv"
"bigpfSkudGhlbihmdW5jdGlvbihkYXRhKXsKICAgIHZhciBjaGFpbnMgPSBkYXRhLmNoYWlucyB8fCBb"
"XTsKICAgIHZhciBjb250YWluZXIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnY2hhaW5zLWNvbnRl"
"bnQnKTsKICAgIHZhciBiYWRnZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjaGFpbi1iYWRnZScp"
"OwoKICAgIGlmKCFjaGFpbnMubGVuZ3RoKXsKICAgICAgY29udGFpbmVyLmlubmVySFRNTD0nPGRpdiBj"
"bGFzcz0iZW1wdHktc3RhdGUiPjxkaXYgY2xhc3M9ImVtcHR5LWljbyI+4puTPC9kaXY+PGRpdiBjbGFz"
"cz0iZW1wdHktdGl0bGUiPk5vIEF0dGFjayBDaGFpbnMgWWV0PC9kaXY+PGRpdiBjbGFzcz0iZW1wdHkt"
"c3ViIj5SdW4gbXVsdGlwbGUgc2NhbnMgdG8gZGlzY292ZXIgYXR0YWNrIHBhdGhzLiBUaGUgZW5naW5l"
"IGNvbm5lY3RzIHZ1bG5lcmFiaWxpdGllcyBpbnRvIGtpbGwgY2hhaW5zLjwvZGl2PjwvZGl2Pic7CiAg"
"ICAgIGJhZGdlLmNsYXNzTmFtZT0ndGFiLWJhZGdlJzsKICAgICAgcmV0dXJuOwogICAgfQoKICAgIGJh"
"ZGdlLmNsYXNzTmFtZT0ndGFiLWJhZGdlIHNob3cgYi1yZWQnOwogICAgYmFkZ2UudGV4dENvbnRlbnQ9"
"Y2hhaW5zLmxlbmd0aDsKCiAgICB2YXIgY3JpdENoYWlucz0wLGhpZ2hDaGFpbnM9MCx0b3RhbENvc3Q9"
"Jyc7CiAgICBjaGFpbnMuZm9yRWFjaChmdW5jdGlvbihjKXtpZihjLnNldmVyaXR5PT09J0NSSVRJQ0FM"
"Jyljcml0Q2hhaW5zKys7aWYoYy5zZXZlcml0eT09PSdISUdIJyloaWdoQ2hhaW5zKyt9KTsKCiAgICB2"
"YXIgaD0nJzsKICAgIC8vIFN1bW1hcnkgc3RhdHMKICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFpbi1zdW1t"
"YXJ5Ij4nOwogICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLXN0YXQiPjxkaXYgY2xhc3M9ImNoYWluLXN0"
"YXQtbnVtIiBzdHlsZT0iY29sb3I6dmFyKC0tcmVkKSI+JytjaGFpbnMubGVuZ3RoKyc8L2Rpdj48ZGl2"
"IGNsYXNzPSJjaGFpbi1zdGF0LWxhYmVsIj5BdHRhY2sgQ2hhaW5zIEZvdW5kPC9kaXY+PC9kaXY+JzsK"
"ICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFpbi1zdGF0Ij48ZGl2IGNsYXNzPSJjaGFpbi1zdGF0LW51bSIg"
"c3R5bGU9ImNvbG9yOiNkOTA0MjkiPicrY3JpdENoYWlucysnPC9kaXY+PGRpdiBjbGFzcz0iY2hhaW4t"
"c3RhdC1sYWJlbCI+Q3JpdGljYWwgQ2hhaW5zPC9kaXY+PC9kaXY+JzsKICAgIGgrPSc8ZGl2IGNsYXNz"
"PSJjaGFpbi1zdGF0Ij48ZGl2IGNsYXNzPSJjaGFpbi1zdGF0LW51bSIgc3R5bGU9ImNvbG9yOiNlODVk"
"MDQiPicraGlnaENoYWlucysnPC9kaXY+PGRpdiBjbGFzcz0iY2hhaW4tc3RhdC1sYWJlbCI+SGlnaCBD"
"aGFpbnM8L2Rpdj48L2Rpdj4nOwogICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLXN0YXQiPjxkaXYgY2xh"
"c3M9ImNoYWluLXN0YXQtbnVtIiBzdHlsZT0iY29sb3I6dmFyKC0tdHgtZGFyaykiPicrY2hhaW5zLnJl"
"ZHVjZShmdW5jdGlvbihhLGMpe3JldHVybiBhK2MuY29uZmlybWVkX3N0ZXBzfSwwKSsnPC9kaXY+PGRp"
"diBjbGFzcz0iY2hhaW4tc3RhdC1sYWJlbCI+Q29uZmlybWVkIFN0ZXBzPC9kaXY+PC9kaXY+JzsKICAg"
"IGgrPSc8L2Rpdj4nOwoKICAgIC8vIEFkdmFuY2VkIHJlcG9ydCBidXR0b24KICAgIGgrPSc8ZGl2IHN0"
"eWxlPSJkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47YWxpZ24taXRlbXM6"
"Y2VudGVyO21hcmdpbi1ib3R0b206MTZweCI+JzsKICAgIGgrPSc8ZGl2IHN0eWxlPSJmb250LWZhbWls"
"eTpTeW5lLHNhbnMtc2VyaWY7Zm9udC1zaXplOjE4cHg7Zm9udC13ZWlnaHQ6ODAwO2NvbG9yOnZhcigt"
"LXR4LWRhcmspIj5LaWxsIENoYWluIEFuYWx5c2lzPC9kaXY+JzsKICAgIGgrPSc8YnV0dG9uIGNsYXNz"
"PSJidG4tYWR2LXJlcG9ydCIgb25jbGljaz0iZG93bmxvYWRBZHZhbmNlZFJlcG9ydCgpIj7irIcgRG93"
"bmxvYWQgQWR2YW5jZWQgUmVwb3J0PC9idXR0b24+JzsKICAgIGgrPSc8L2Rpdj4nOwoKICAgIC8vIEVh"
"Y2ggY2hhaW4KICAgIGNoYWlucy5mb3JFYWNoKGZ1bmN0aW9uKGMsaWR4KXsKICAgICAgaCs9JzxkaXYg"
"Y2xhc3M9ImNoYWluLWNhcmQgJytjLnNldmVyaXR5KyciIHN0eWxlPSJhbmltYXRpb24tZGVsYXk6Jyso"
"aWR4KjAuMDgpKydzIj4nOwoKICAgICAgLy8gSGVhZGVyCiAgICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFp"
"bi1oZWFkZXIiPjxkaXY+JzsKICAgICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLW5hbWUiPicrYy5uYW1l"
"Kyc8L2Rpdj4nOwogICAgICBoKz0nPGRpdiBjbGFzcz0iY2hhaW4ta2lsbGNoYWluIj4nK2Mua2lsbF9j"
"aGFpbisnPC9kaXY+JzsKICAgICAgaCs9JzwvZGl2PjxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6"
"OHB4O2FsaWduLWl0ZW1zOmNlbnRlciI+JzsKICAgICAgaCs9JzxzcGFuIGNsYXNzPSJzZXYgJytjLnNl"
"dmVyaXR5KyciPicrYy5zZXZlcml0eSsnPC9zcGFuPic7CiAgICAgIGgrPSc8c3BhbiBjbGFzcz0iY2hh"
"aW4tY29uZmlkZW5jZSAnKyhjLmNvbmZpZGVuY2U+PTc1PydoaWdoJzonbWVkJykrJyI+JytjLmNvbmZp"
"ZGVuY2UrJyUgTWF0Y2g8L3NwYW4+JzsKICAgICAgaCs9JzwvZGl2PjwvZGl2Pic7CgogICAgICAvLyBL"
"aWxsIENoYWluIEZsb3cKICAgICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLWZsb3ciPic7CiAgICAgIGMu"
"c3RlcHMuZm9yRWFjaChmdW5jdGlvbihzdGVwLHNpKXsKICAgICAgICBpZihzaT4wKXsKICAgICAgICAg"
"IGgrPSc8ZGl2IGNsYXNzPSJjaGFpbi1hcnJvdyAnKyhzdGVwLnN0YXR1cz09PSdjb25maXJtZWQnPydj"
"b25maXJtZWQnOicnKSsnIj48L2Rpdj4nOwogICAgICAgIH0KICAgICAgICBoKz0nPGRpdiBjbGFzcz0i"
"Y2hhaW4tc3RlcCI+JzsKICAgICAgICBoKz0nPGRpdiBjbGFzcz0iY2hhaW4tc3RlcC1kb3QgJytzdGVw"
"LnN0YXR1cysnIj4nKyhzdGVwLnN0YXR1cz09PSdjb25maXJtZWQnPyfinJMnOic/JykrJzwvZGl2Pic7"
"CiAgICAgICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLXN0ZXAtcGhhc2UiPicrc3RlcC5waGFzZSsnPC9k"
"aXY+JzsKICAgICAgICBoKz0nPGRpdiBjbGFzcz0iY2hhaW4tc3RlcC1sYWJlbCI+JytzdGVwLmxhYmVs"
"Kyc8L2Rpdj4nOwogICAgICAgIGgrPSc8L2Rpdj4nOwogICAgICB9KTsKICAgICAgaCs9JzwvZGl2Pic7"
"CgogICAgICAvLyBJbXBhY3QKICAgICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLWltcGFjdCI+PGRpdiBj"
"bGFzcz0iY2hhaW4taW1wYWN0LXRpdGxlIj7imqEgQVRUQUNLIElNUEFDVDwvZGl2Pic7CiAgICAgIGgr"
"PSc8ZGl2IGNsYXNzPSJjaGFpbi1pbXBhY3QtdGV4dCI+JytjLmltcGFjdCsnPC9kaXY+PC9kaXY+JzsK"
"CiAgICAgIC8vIEJ1c2luZXNzIEltcGFjdCArIENvc3QKICAgICAgaCs9JzxkaXYgY2xhc3M9ImNoYWlu"
"LWJ1c2luZXNzIj48ZGl2IGNsYXNzPSJjaGFpbi1idXNpbmVzcy10aXRsZSI+8J+SvCBCVVNJTkVTUyBJ"
"TVBBQ1Q8L2Rpdj4nOwogICAgICBoKz0nPGRpdiBjbGFzcz0iY2hhaW4taW1wYWN0LXRleHQiPicrYy5i"
"dXNpbmVzc19pbXBhY3QrJzwvZGl2Pic7CiAgICAgIGgrPSc8ZGl2IGNsYXNzPSJjaGFpbi1jb3N0Ij5F"
"c3RpbWF0ZWQgQ29zdDogJytjLmNvc3RfZXN0aW1hdGUrJzwvZGl2PjwvZGl2Pic7CgogICAgICAvLyBG"
"aXgKICAgICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLWZpeCI+PGRpdiBjbGFzcz0iY2hhaW4tZml4LXRp"
"dGxlIj7wn5uhIFJFTUVESUFUSU9OIENPTU1BTkRTPC9kaXY+JzsKICAgICAgaCs9JzxkaXYgY2xhc3M9"
"ImNoYWluLWZpeC1jbWQiPicrYy5maXgrJzwvZGl2PjwvZGl2Pic7CgogICAgICAvLyBDb21wbGlhbmNl"
"CiAgICAgIGlmKGMuY29tcGxpYW5jZSAmJiBPYmplY3Qua2V5cyhjLmNvbXBsaWFuY2UpLmxlbmd0aCl7"
"CiAgICAgICAgaCs9JzxkaXYgY2xhc3M9ImNoYWluLWNvbXBsaWFuY2UiPic7CiAgICAgICAgT2JqZWN0"
"LmtleXMoYy5jb21wbGlhbmNlKS5mb3JFYWNoKGZ1bmN0aW9uKGZ3KXsKICAgICAgICAgIGgrPSc8ZGl2"
"IGNsYXNzPSJjaGFpbi1jb21wLXRhZyI+JytmdysnOiAnK2MuY29tcGxpYW5jZVtmd10rJzwvZGl2Pic7"
"CiAgICAgICAgfSk7CiAgICAgICAgaCs9JzwvZGl2Pic7CiAgICAgIH0KCiAgICAgIGgrPSc8L2Rpdj4n"
"OwogICAgfSk7CgogICAgY29udGFpbmVyLmlubmVySFRNTD1oOwogIH0pLmNhdGNoKGZ1bmN0aW9uKCl7"
"fSk7Cn0KCi8qID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT0KICAgQURWQU5DRUQgUkVQT1JUIERPV05MT0FEICgzLUF1ZGllbmNlKQogICA9"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09ICovCmZ1bmN0aW9uIGRvd25sb2FkQWR2YW5jZWRSZXBvcnQoKXsKICBmZXRjaCgnL2FkdmFuY2Vk"
"X3JlcG9ydCcpLnRoZW4oZnVuY3Rpb24ocil7cmV0dXJuIHIuanNvbigpfSkudGhlbihmdW5jdGlvbihy"
"cHQpewogICAgaWYocnB0LmVycm9yKXtub3RpZnkoJ05vIHJlcG9ydCBkYXRhIHlldC4gUnVuIHNjYW5z"
"IGZpcnN0LicpO3JldHVybn0KCiAgICB2YXIgY3NzID0gJ2JvZHl7Zm9udC1mYW1pbHk6SGVsdmV0aWNh"
"LEFyaWFsLHNhbnMtc2VyaWY7Y29sb3I6IzNhM2E0NDtwYWRkaW5nOjQwcHg7bWF4LXdpZHRoOjExMDBw"
"eDttYXJnaW46YXV0bztmb250LXNpemU6MTNweDtsaW5lLWhlaWdodDoxLjZ9JwogICAgICArICdoMXtj"
"b2xvcjojZTYzOTQ2O2ZvbnQtc2l6ZToyOHB4O3RleHQtYWxpZ246Y2VudGVyO21hcmdpbi1ib3R0b206"
"NXB4fScKICAgICAgKyAnaDJ7Y29sb3I6I2U2Mzk0Njtmb250LXNpemU6MTZweDtib3JkZXItYm90dG9t"
"OjJweCBzb2xpZCAjZTYzOTQ2O3BhZGRpbmctYm90dG9tOjZweDttYXJnaW4tdG9wOjMwcHh9JwogICAg"
"ICArICdoM3tjb2xvcjojMGEwYTBjO2ZvbnQtc2l6ZToxM3B4O21hcmdpbi10b3A6MThweH0nCiAgICAg"
"ICsgJy5tZXRhe3RleHQtYWxpZ246Y2VudGVyO2NvbG9yOiM4YThhOTY7Zm9udC1zaXplOjExcHg7bWFy"
"Z2luLWJvdHRvbTozMHB4fScKICAgICAgKyAnLnNjb3JlLWJveHt0ZXh0LWFsaWduOmNlbnRlcjtwYWRk"
"aW5nOjMwcHg7Ym9yZGVyOjNweCBzb2xpZCAnK3JwdC5yaXNrX2xldmVsKyc7Ym9yZGVyLXJhZGl1czox"
"NnB4O21hcmdpbjoyMHB4IGF1dG87bWF4LXdpZHRoOjMwMHB4fScKICAgICAgKyAnLnNjb3JlLW51bXtm"
"b250LXNpemU6NjRweDtmb250LXdlaWdodDo5MDA7Y29sb3I6JysoJyNkOTA0MjknKSsnO30nCiAgICAg"
"ICsgJy5zY29yZS1sYWJlbHtmb250LXNpemU6MThweDtmb250LXdlaWdodDo3MDA7Y29sb3I6IzNhM2E0"
"NH0nCiAgICAgICsgJy5jYXJke2JvcmRlci1sZWZ0OjRweCBzb2xpZCAjZDkwNDI5O3BhZGRpbmc6MTJw"
"eCAxNnB4O21hcmdpbjoxMHB4IDA7YmFja2dyb3VuZDojZjdmN2Y4O2JvcmRlci1yYWRpdXM6OHB4fScK"
"ICAgICAgKyAnLmNhcmQuSElHSHtib3JkZXItbGVmdC1jb2xvcjojZTg1ZDA0fS5jYXJkLk1FRElVTXti"
"b3JkZXItbGVmdC1jb2xvcjojZTA5ZjNlfS5jYXJkLkxPV3tib3JkZXItbGVmdC1jb2xvcjojMmQ2YTRm"
"fScKICAgICAgKyAnLmZpeHtiYWNrZ3JvdW5kOiNmMGZkZjQ7Ym9yZGVyOjFweCBzb2xpZCAjYmJmN2Qw"
"O3BhZGRpbmc6MTJweDtib3JkZXItcmFkaXVzOjhweDttYXJnaW46OHB4IDA7Zm9udC1mYW1pbHk6bW9u"
"b3NwYWNlO2ZvbnQtc2l6ZToxMXB4O3doaXRlLXNwYWNlOnByZS13cmFwfScKICAgICAgKyAnLmNvbXB7"
"ZGlzcGxheTppbmxpbmUtYmxvY2s7YmFja2dyb3VuZDojZjFmNWY5O2JvcmRlcjoxcHggc29saWQgI2Uy"
"ZThmMDtwYWRkaW5nOjNweCA4cHg7Ym9yZGVyLXJhZGl1czo0cHg7Zm9udC1zaXplOjEwcHg7bWFyZ2lu"
"OjJweH0nCiAgICAgICsgJ3RhYmxle3dpZHRoOjEwMCU7Ym9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlO21h"
"cmdpbjoxMHB4IDB9dGgsdGR7cGFkZGluZzo2cHggMTBweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCAj"
"ZWNlY2VmO3RleHQtYWxpZ246bGVmdDtmb250LXNpemU6MTFweH10aHtiYWNrZ3JvdW5kOiNmN2Y3Zjg7"
"Zm9udC13ZWlnaHQ6NzAwfScKICAgICAgKyAnLnNldntwYWRkaW5nOjJweCA4cHg7Ym9yZGVyLXJhZGl1"
"czoxMHB4O2ZvbnQtc2l6ZToxMHB4O2ZvbnQtd2VpZ2h0OjcwMH0nCiAgICAgICsgJy5zZXYuQ1JJVElD"
"QUx7YmFja2dyb3VuZDojZmRkO2NvbG9yOiNkOTA0Mjl9LnNldi5ISUdIe2JhY2tncm91bmQ6I2ZlZDtj"
"b2xvcjojZTg1ZDA0fS5zZXYuTUVESVVNe2JhY2tncm91bmQ6I2ZmZDtjb2xvcjojYjg4NjBifS5zZXYu"
"TE9Xe2JhY2tncm91bmQ6I2RmZDtjb2xvcjojMmQ2YTRmfScKICAgICAgKyAnLnNlY3Rpb257cGFnZS1i"
"cmVhay1pbnNpZGU6YXZvaWR9JwogICAgICArICdAbWVkaWEgcHJpbnR7Ym9keXtwYWRkaW5nOjIwcHh9"
"fSc7CgogICAgdmFyIGIgPSAnPCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PG1ldGEgY2hhcnNldD0i"
"VVRGLTgiPjx0aXRsZT5IQVJTSEEgdjcuMCBBZHZhbmNlZCBWQVBUIFJlcG9ydDwvdGl0bGU+PHN0eWxl"
"PicrY3NzKyc8L3N0eWxlPjwvaGVhZD48Ym9keT4nOwoKICAgIC8vIEhFQURFUgogICAgYiArPSAnPGgx"
"PkhBUlNIQSB2Ny4wPC9oMT4nOwogICAgYiArPSAnPGRpdiBzdHlsZT0idGV4dC1hbGlnbjpjZW50ZXI7"
"Zm9udC1zaXplOjE2cHg7Y29sb3I6IzhhOGE5NjttYXJnaW4tYm90dG9tOjVweCI+QURWQU5DRUQgVkFQ"
"VCBSRVBPUlQ8L2Rpdj4nOwogICAgYiArPSAnPGRpdiBjbGFzcz0ibWV0YSI+VGFyZ2V0OiAnK3JwdC50"
"YXJnZXQrJyB8IEdlbmVyYXRlZDogJytycHQuZ2VuZXJhdGVkKyc8L2Rpdj4nOwoKICAgIC8vIFJJU0sg"
"U0NPUkUKICAgIGIgKz0gJzxkaXYgY2xhc3M9InNjb3JlLWJveCI+PGRpdiBjbGFzcz0ic2NvcmUtbnVt"
"Ij4nK3JwdC5yaXNrX3Njb3JlKyc8L2Rpdj4nOwogICAgYiArPSAnPGRpdiBjbGFzcz0ic2NvcmUtbGFi"
"ZWwiPicrcnB0LnJpc2tfbGV2ZWwrJyBSSVNLPC9kaXY+PC9kaXY+JzsKCiAgICAvLyA9PT09PT09PT09"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgIC8vIFNFQ1RJT04gMTogRVhFQ1VUSVZF"
"IFNVTU1BUlkKICAgIC8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQog"
"ICAgYiArPSAnPGgyPvCfk4sgU0VDVElPTiAxOiBFWEVDVVRJVkUgU1VNTUFSWTwvaDI+JzsKICAgIGIg"
"Kz0gJzxkaXYgc3R5bGU9ImJhY2tncm91bmQ6I2ZmZjhmODtib3JkZXI6MXB4IHNvbGlkICNmZWNhY2E7"
"cGFkZGluZzoxNnB4O2JvcmRlci1yYWRpdXM6OHB4O21hcmdpbjoxMnB4IDAiPic7CiAgICBiICs9ICc8"
"cCBzdHlsZT0iZm9udC1zaXplOjE0cHg7Zm9udC13ZWlnaHQ6NjAwIj4nK3JwdC5leGVjdXRpdmUuaGVh"
"ZGxpbmUrJzwvcD4nOwogICAgYiArPSAnPHA+JytycHQuZXhlY3V0aXZlLnJpc2tfc3VtbWFyeSsnPC9w"
"Pic7CiAgICBiICs9ICc8L2Rpdj4nOwoKICAgIGIgKz0gJzxoMz5LZXkgQnVzaW5lc3MgUmlza3M8L2gz"
"Pic7CiAgICBpZihycHQuZXhlY3V0aXZlLmJ1c2luZXNzX3Jpc2tzLmxlbmd0aCl7CiAgICAgIHJwdC5l"
"eGVjdXRpdmUuYnVzaW5lc3Nfcmlza3MuZm9yRWFjaChmdW5jdGlvbihyLGkpewogICAgICAgIGIgKz0g"
"JzxkaXYgY2xhc3M9ImNhcmQgQ1JJVElDQUwiPjxiPlJpc2sgJysoaSsxKSsnOjwvYj4gJytyKyc8L2Rp"
"dj4nOwogICAgICB9KTsKICAgIH0KCiAgICBiICs9ICc8aDM+Q29zdCBFeHBvc3VyZTwvaDM+JzsKICAg"
"IGlmKHJwdC5leGVjdXRpdmUuY29zdF9leHBvc3VyZS5sZW5ndGgpewogICAgICBycHQuZXhlY3V0aXZl"
"LmNvc3RfZXhwb3N1cmUuZm9yRWFjaChmdW5jdGlvbihjLGkpewogICAgICAgIGIgKz0gJzxkaXYgY2xh"
"c3M9ImNhcmQgSElHSCI+PGI+Q2hhaW4gJysoaSsxKSsnOjwvYj4gJytjKyc8L2Rpdj4nOwogICAgICB9"
"KTsKICAgIH0KCiAgICBiICs9ICc8aDM+UHJpb3JpdHkgQWN0aW9uczwvaDM+JzsKICAgIGIgKz0gJzx0"
"YWJsZT48dHI+PHRoPiM8L3RoPjx0aD5BdHRhY2sgQ2hhaW48L3RoPjx0aD5Qcmlvcml0eTwvdGg+PHRo"
"PkltbWVkaWF0ZSBBY3Rpb248L3RoPjwvdHI+JzsKICAgIHJwdC5leGVjdXRpdmUudG9wX3JlY29tbWVu"
"ZGF0aW9ucy5mb3JFYWNoKGZ1bmN0aW9uKHIsaSl7CiAgICAgIGIgKz0gJzx0cj48dGQ+JysoaSsxKSsn"
"PC90ZD48dGQ+JytyLmNoYWluKyc8L3RkPjx0ZD48c3BhbiBjbGFzcz0ic2V2ICcrci5wcmlvcml0eSsn"
"Ij4nK3IucHJpb3JpdHkrJzwvc3Bhbj48L3RkPjx0ZD4nK3IuYWN0aW9uKyc8L3RkPjwvdHI+JzsKICAg"
"IH0pOwogICAgYiArPSAnPC90YWJsZT4nOwoKICAgIC8vID09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT09PT09PT09PQogICAgLy8gU0VDVElPTiAyOiBURUNITklDQUwgRklORElOR1MKICAgIC8v"
"ID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQogICAgYiArPSAnPGgyPvCf"
"lKcgU0VDVElPTiAyOiBURUNITklDQUwgRklORElOR1M8L2gyPic7CgogICAgLy8gQXR0YWNrIENoYWlu"
"cwogICAgdmFyIGNoYWlucyA9IHJwdC50ZWNobmljYWwuY2hhaW5zIHx8IFtdOwogICAgaWYoY2hhaW5z"
"Lmxlbmd0aCl7CiAgICAgIGIgKz0gJzxoMz5BdHRhY2sgQ2hhaW5zICgnK2NoYWlucy5sZW5ndGgrJyBm"
"b3VuZCk8L2gzPic7CiAgICAgIGNoYWlucy5mb3JFYWNoKGZ1bmN0aW9uKGMsaSl7CiAgICAgICAgYiAr"
"PSAnPGRpdiBjbGFzcz0ic2VjdGlvbiI+PGRpdiBjbGFzcz0iY2FyZCAnK2Muc2V2ZXJpdHkrJyI+PGI+"
"Q2hhaW4gJysoaSsxKSsnOiAnK2MubmFtZSsnPC9iPiA8c3BhbiBjbGFzcz0ic2V2ICcrYy5zZXZlcml0"
"eSsnIj4nK2Muc2V2ZXJpdHkrJzwvc3Bhbj4gKCcrYy5jb25maWRlbmNlKyclIGNvbmZpZGVuY2UpJzsK"
"ICAgICAgICBiICs9ICc8YnI+PHNtYWxsIHN0eWxlPSJjb2xvcjojOGE4YTk2Ij5LaWxsIENoYWluOiAn"
"K2Mua2lsbF9jaGFpbisnPC9zbWFsbD4nOwogICAgICAgIGIgKz0gJzxicj48YnI+PGI+SW1wYWN0Ojwv"
"Yj4gJytjLmltcGFjdDsKICAgICAgICBiICs9ICc8YnI+PGJyPjxiPlN0ZXBzOjwvYj48b2wgc3R5bGU9"
"Im1hcmdpbjo2cHggMCI+JzsKICAgICAgICBjLnN0ZXBzLmZvckVhY2goZnVuY3Rpb24ocyl7CiAgICAg"
"ICAgICB2YXIgaWNvbiA9IHMuc3RhdHVzPT09J2NvbmZpcm1lZCcgPyAn4pyFJyA6ICfinZMnOwogICAg"
"ICAgICAgYiArPSAnPGxpPicraWNvbisnIFsnK3MucGhhc2UrJ10gJytzLmxhYmVsKyc8L2xpPic7CiAg"
"ICAgICAgfSk7CiAgICAgICAgYiArPSAnPC9vbD4nOwogICAgICAgIGIgKz0gJzxkaXYgY2xhc3M9ImZp"
"eCI+JytjLmZpeCsnPC9kaXY+JzsKICAgICAgICBiICs9ICc8L2Rpdj48L2Rpdj4nOwogICAgICB9KTsK"
"ICAgIH0KCiAgICAvLyBPcGVuIFBvcnRzCiAgICB2YXIgcG9ydHMgPSBycHQudGVjaG5pY2FsLnBvcnRz"
"IHx8IFtdOwogICAgaWYocG9ydHMubGVuZ3RoKXsKICAgICAgYiArPSAnPGgzPk9wZW4gUG9ydHMgKCcr"
"cG9ydHMubGVuZ3RoKycpPC9oMz4nOwogICAgICBiICs9ICc8dGFibGU+PHRyPjx0aD5Qb3J0PC90aD48"
"dGg+U2VydmljZTwvdGg+PHRoPlJpc2s8L3RoPjx0aD5EZXNjcmlwdGlvbjwvdGg+PHRoPlJlbWVkaWF0"
"aW9uPC90aD48L3RyPic7CiAgICAgIHBvcnRzLmZvckVhY2goZnVuY3Rpb24ocCl7CiAgICAgICAgYiAr"
"PSAnPHRyPjx0ZD4nK3AucG9ydCsnLycrcC5wcm90bysnPC90ZD48dGQ+JytwLnNlcnZpY2UrJzwvdGQ+"
"PHRkPjxzcGFuIGNsYXNzPSJzZXYgJytwLnNldmVyaXR5KyciPicrcC5zZXZlcml0eSsnPC9zcGFuPjwv"
"dGQ+PHRkPicrcC5kZXNjKyc8L3RkPjx0ZCBzdHlsZT0iZm9udC1zaXplOjEwcHgiPicrcC5maXgrJzwv"
"dGQ+PC90cj4nOwogICAgICB9KTsKICAgICAgYiArPSAnPC90YWJsZT4nOwogICAgfQoKICAgIC8vIFRo"
"cmVhdHMKICAgIHZhciB0aHJlYXRzID0gcnB0LnRlY2huaWNhbC50aHJlYXRzIHx8IFtdOwogICAgaWYo"
"dGhyZWF0cy5sZW5ndGgpewogICAgICBiICs9ICc8aDM+VnVsbmVyYWJpbGl0aWVzICgnK3RocmVhdHMu"
"bGVuZ3RoKycpPC9oMz4nOwogICAgICB0aHJlYXRzLmZvckVhY2goZnVuY3Rpb24odCxpKXsKICAgICAg"
"ICBiICs9ICc8ZGl2IGNsYXNzPSJjYXJkICcrdC5zZXZlcml0eSsnIj48Yj4nKyhpKzEpKycuICcrdC5u"
"YW1lKyc8L2I+IDxzcGFuIGNsYXNzPSJzZXYgJyt0LnNldmVyaXR5KyciPicrdC5zZXZlcml0eSsnPC9z"
"cGFuPic7CiAgICAgICAgYiArPSAnPGJyPicrdC5kZXNjOwogICAgICAgIGIgKz0gJzxkaXYgY2xhc3M9"
"ImZpeCI+RklYOiAnK3QuZml4Kyc8L2Rpdj48L2Rpdj4nOwogICAgICB9KTsKICAgIH0KCiAgICAvLyA9"
"PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0KICAgIC8vIFNFQ1RJT04gMzog"
"Q09NUExJQU5DRSBNQVBQSU5HCiAgICAvLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09"
"PT09PT09PT0KICAgIGIgKz0gJzxoMj7wn5OcIFNFQ1RJT04gMzogQ09NUExJQU5DRSBNQVBQSU5HPC9o"
"Mj4nOwogICAgdmFyIGZ3ID0gcnB0LmNvbXBsaWFuY2UuZnJhbWV3b3JrcyB8fCB7fTsKICAgIHZhciBm"
"d0tleXMgPSBPYmplY3Qua2V5cyhmdyk7CiAgICBpZihmd0tleXMubGVuZ3RoKXsKICAgICAgZndLZXlz"
"LmZvckVhY2goZnVuY3Rpb24oZmspewogICAgICAgIGIgKz0gJzxoMz4nK2ZrKyc8L2gzPic7CiAgICAg"
"ICAgYiArPSAnPHRhYmxlPjx0cj48dGg+Q29udHJvbDwvdGg+PHRoPklzc3VlIEZvdW5kPC90aD48dGg+"
"U2V2ZXJpdHk8L3RoPjwvdHI+JzsKICAgICAgICBmd1tma10uZm9yRWFjaChmdW5jdGlvbihpdGVtKXsK"
"ICAgICAgICAgIGIgKz0gJzx0cj48dGQ+PHNwYW4gY2xhc3M9ImNvbXAiPicraXRlbS5jb250cm9sKyc8"
"L3NwYW4+PC90ZD48dGQ+JytpdGVtLmlzc3VlKyc8L3RkPjx0ZD48c3BhbiBjbGFzcz0ic2V2ICcraXRl"
"bS5zZXZlcml0eSsnIj4nK2l0ZW0uc2V2ZXJpdHkrJzwvc3Bhbj48L3RkPjwvdHI+JzsKICAgICAgICB9"
"KTsKICAgICAgICBiICs9ICc8L3RhYmxlPic7CiAgICAgIH0pOwogICAgfSBlbHNlIHsKICAgICAgYiAr"
"PSAnPHAgc3R5bGU9ImNvbG9yOiM4YThhOTYiPk5vIGNvbXBsaWFuY2UgZGF0YSBhdmFpbGFibGUgeWV0"
"LiBSdW4gbW9yZSBzY2FucyB0byBnZW5lcmF0ZSBjb21wbGlhbmNlIG1hcHBpbmcuPC9wPic7CiAgICB9"
"CgogICAgLy8gRk9PVEVSCiAgICBiICs9ICc8ZGl2IHN0eWxlPSJtYXJnaW4tdG9wOjQwcHg7cGFkZGlu"
"Zy10b3A6MjBweDtib3JkZXItdG9wOjJweCBzb2xpZCAjZWNlY2VmO3RleHQtYWxpZ246Y2VudGVyO2Nv"
"bG9yOiM4YThhOTY7Zm9udC1zaXplOjEwcHgiPic7CiAgICBiICs9ICdIQVJTSEEgdjcuMCBWQVBUIFN1"
"aXRlIOKAlCBBZHZhbmNlZCBTZWN1cml0eSBSZXBvcnQ8YnI+JzsKICAgIGIgKz0gJ0dlbmVyYXRlZDog"
"JytycHQuZ2VuZXJhdGVkKycgfCBDbGFzc2lmaWNhdGlvbjogQ09ORklERU5USUFMJzsKICAgIGIgKz0g"
"JzwvZGl2Pic7CgogICAgYiArPSAnPC9ib2R5PjwvaHRtbD4nOwoKICAgIHZhciBhID0gZG9jdW1lbnQu"
"Y3JlYXRlRWxlbWVudCgnYScpOwogICAgYS5ocmVmID0gVVJMLmNyZWF0ZU9iamVjdFVSTChuZXcgQmxv"
"YihbYl0se3R5cGU6J3RleHQvaHRtbCd9KSk7CiAgICBhLmRvd25sb2FkID0gJ0hBUlNIQV92N19BZHZh"
"bmNlZF9WQVBUX1JlcG9ydC5odG1sJzsKICAgIGEuY2xpY2soKTsKICAgIG5vdGlmeSgnQWR2YW5jZWQg"
"cmVwb3J0IGRvd25sb2FkZWQhJyk7CiAgfSkuY2F0Y2goZnVuY3Rpb24oZSl7bm90aWZ5KCdFcnJvciBn"
"ZW5lcmF0aW5nIHJlcG9ydDogJytlLm1lc3NhZ2UpfSk7Cn0KCi8qIFJlZnJlc2ggY2hhaW5zIHdoZW4g"
"c3dpdGNoaW5nIHRvIHRoZSB0YWIgKi8KdmFyIF9vcmlnU3dpdGNoVGFiID0gc3dpdGNoVGFiOwpzd2l0"
"Y2hUYWIgPSBmdW5jdGlvbih0YWIsIGJ0bikgewogIF9vcmlnU3dpdGNoVGFiKHRhYiwgYnRuKTsKICBp"
"Zih0YWIgPT09ICdjaGFpbnMnKSByZWZyZXNoQXR0YWNrQ2hhaW5zKCk7Cn07CgovKiBBbHNvIHJlZnJl"
"c2ggYWZ0ZXIgZWFjaCBzY2FuIGNvbXBsZXRlcyAqLwp2YXIgY2hhaW5Qb2xsQ291bnQgPSAwOwpzZXRJ"
"bnRlcnZhbChmdW5jdGlvbigpewogIGlmKGxhc3RQaGFzZSA9PT0gJ2NvbXBsZXRlJyAmJiBjaGFpblBv"
"bGxDb3VudCA8IDMpewogICAgcmVmcmVzaEF0dGFja0NoYWlucygpOwogICAgY2hhaW5Qb2xsQ291bnQr"
"KzsKICB9CiAgaWYobGFzdFBoYXNlICE9PSAnY29tcGxldGUnKSBjaGFpblBvbGxDb3VudCA9IDA7Cn0s"
"IDIwMDApOwoKLyogS0VZQk9BUkQgU0hPUlRDVVRTICovCmRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIo"
"J2tleWRvd24nLGZ1bmN0aW9uKGUpewogIGlmKGUuY3RybEtleSYmZS5rZXk9PT0nLycpe2UucHJldmVu"
"dERlZmF1bHQoKTtkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndG9vbC1zZWFyY2gnKS5mb2N1cygpfQp9"
"KTsKPC9zY3JpcHQ+Cgo8L2JvZHk+CjwvaHRtbD4K"
)


# ═══════════════════════════════════════════════════════
# EMBEDDED UI — SINGLE FILE, NO EXTERNAL DEPENDENCIES
# ═══════════════════════════════════════════════════════
def get_html():
    import base64
    html = base64.b64decode(_HTML_B64).decode("utf-8")
    # Keep branding consistent even when legacy labels exist inside embedded UI payload.
    html = re.sub(r"harsha", "FG", html, flags=re.IGNORECASE)
    html = re.sub(r'(<div class="s-logo-mark">\s*)H(\s*</div>)', r'\1F\2', html, flags=re.IGNORECASE)
    html = re.sub(r'(<div class="s-avatar">\s*)HA(\s*</div>)', r'\1FG\2', html, flags=re.IGNORECASE)
    return html

@app.route("/")
def index():
    return Response(get_html(), mimetype="text/html")

if __name__ == "__main__":
    print("""
================================================================
    FG AI v7.0 - FULL VAPT SUITE
  Web VAPT + Network VAPT + Infrastructure VAPT
================================================================
  Open browser: http://localhost:5000
  TIP: chmod +s /usr/bin/nmap
  TIP: pip install wafw00f sqlmap
================================================================
    """)
    app.run(debug=False, host="0.0.0.0", port=5000)
