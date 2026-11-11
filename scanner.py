"""CyberAI - evidence-based assessment for the fixed authorised training lab.

Run: py scanner.py
Tests: py scanner.py --self-test
Report file: py scanner.py --report assessment.txt

NVD records are candidates, not confirmed target vulnerabilities. Python owns
all classifications. Ollama is optional explanatory prose and cannot override it.
"""
from __future__ import annotations
import argparse, getpass, html, ipaddress, json, os, re, socket, time, unittest
import urllib.error, urllib.parse, urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from typing import Any, Optional
import paramiko

# Preserved, isolated lab environment. This scanner accepts no arbitrary target.
SSH_HOST, SSH_PORT, SSH_USERNAME = "192.168.56.10", 22, "ciren"
TARGET_IP = "192.168.77.20"
OLLAMA_URL, OLLAMA_MODEL = "http://localhost:11434/api/chat", "llama3.2:3b"
NVD_API, NVD_RESULTS_PER_QUERY, NVD_REQUEST_DELAY_SECONDS = "https://services.nvd.nist.gov/rest/json/cves/2.0", 10, 1.5
NVD_API_KEY_ENVIRONMENT_VARIABLE = "NVD_API_KEY"  # optional; never hardcode a key

@dataclass(frozen=True)
class Settings:
    ssh_host: str = SSH_HOST; ssh_port: int = SSH_PORT; ssh_username: str = SSH_USERNAME
    authorized_target: str = TARGET_IP; ollama_url: str = OLLAMA_URL; ollama_model: str = OLLAMA_MODEL
    nvd_api: str = NVD_API; nvd_page_size: int = NVD_RESULTS_PER_QUERY; nvd_max_results_per_query: int = 100
    nvd_request_delay_seconds: float = NVD_REQUEST_DELAY_SECONDS; nvd_retries: int = 2; nvd_timeout_seconds: int = 30
    ssh_timeout_seconds: int = 15; nmap_timeout_seconds: int = 300; ollama_timeout_seconds: int = 120
SETTINGS = Settings()
class ScanError(RuntimeError): pass
class NvdRequestError(RuntimeError): pass

@dataclass
class ServiceRecord:
    ip_address: str; port: str; protocol: str; state: str; service_name: str
    product: str; version: str; extra_info: str; detection_source: str; version_confidence: str
    nmap_confidence: Optional[int] = None
    def display_name(self) -> str: return f"{self.ip_address}:{self.port}/{self.protocol} ({self.service_name})"
    def to_dict(self) -> dict[str, Any]: return asdict(self)

@dataclass(frozen=True)
class ProductProfile:
    canonical_name: str; aliases: tuple[str, ...]; search_name: str
    cpe_vendors: tuple[str, ...]; cpe_products: tuple[str, ...]
PROFILES = (
    ProductProfile("OpenSSH", ("openssh",), "OpenSSH", ("openbsd",), ("openssh",)),
    ProductProfile("ProFTPD", ("proftpd",), "ProFTPD", ("proftpd", "proftpd_project"), ("proftpd",)),
    ProductProfile("vsftpd", ("vsftpd",), "vsftpd", ("vsftpd", "vsftpd_project"), ("vsftpd",)),
    ProductProfile("Apache HTTP Server", ("apache httpd", "apache http server"), "Apache HTTP Server", ("apache", "apache_software_foundation"), ("http_server",)),
    ProductProfile("ISC BIND", ("isc bind", "bind"), "ISC BIND", ("isc", "internet_systems_consortium"), ("bind",)),
    ProductProfile("Samba", ("samba", "samba smbd"), "Samba", ("samba",), ("samba",)),
    ProductProfile("MySQL", ("mysql",), "MySQL", ("oracle", "mysql"), ("mysql",)),
    ProductProfile("PostgreSQL", ("postgresql", "postgresql db"), "PostgreSQL", ("postgresql", "postgres"), ("postgresql",)),
    ProductProfile("Apache Tomcat", ("apache tomcat", "tomcat"), "Apache Tomcat", ("apache", "apache_software_foundation"), ("tomcat",)),
)
def norm(value: str) -> str: return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", value.lower())).strip()
def profile_for(product: str) -> Optional[ProductProfile]:
    return next((p for p in PROFILES if norm(product) in {norm(a) for a in p.aliases}), None)
def confidence(raw: Optional[str]) -> tuple[str, Optional[int]]:
    if not raw or not raw.isdigit(): return "Nmap confidence not supplied", None
    n = int(raw); return ("high" if n >= 8 else "medium" if n >= 4 else "low") + f" (Nmap service confidence {n}/10)", n

# SSH-based fixed target scan.
def parse_nmap_xml(xml_data: str, target: str) -> list[ServiceRecord]:
    if not xml_data.strip(): raise ScanError("Nmap returned no XML output.")
    try: root = ET.fromstring(xml_data)
    except ET.ParseError as error: raise ScanError(f"Nmap XML could not be parsed: {error}") from error
    if root.tag != "nmaprun": raise ScanError(f"Unexpected Nmap XML root: {root.tag!r}")
    hosts = [h for h in root.findall("host") if target in [a.get("addr", "") for a in h.findall("address")]]
    if not hosts: raise ScanError(f"Nmap XML did not contain authorised target {target}.")
    output = []
    for host in hosts:
        if (host.find("status") is not None and host.find("status").get("state") == "down"): continue
        for port in host.findall("./ports/port"):
            state, service = port.find("state"), port.find("service")
            conf, conf_number = confidence(service.get("conf") if service is not None else None)
            output.append(ServiceRecord(target, port.get("portid", "unknown"), port.get("protocol", "unknown"), state.get("state", "unknown") if state is not None else "unknown", service.get("name", "unknown") if service is not None else "unknown", service.get("product", "") if service is not None else "", service.get("version", "") if service is not None else "", service.get("extrainfo", "") if service is not None else "", "Nmap -sV XML", conf, conf_number))
    return output

def run_scan(password: str, settings: Settings = SETTINGS) -> list[ServiceRecord]:
    try: target = ipaddress.ip_address(settings.authorized_target)
    except ValueError as error: raise ScanError(f"Configured target is invalid: {error}") from error
    if str(target) != TARGET_IP: raise ScanError("Target is outside the configured lab scope.")
    ssh = paramiko.SSHClient(); ssh.load_system_host_keys(); ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        print("\nConnecting to the configured Ubuntu lab scanner...")
        ssh.connect(hostname=settings.ssh_host, port=settings.ssh_port, username=settings.ssh_username, password=password, timeout=settings.ssh_timeout_seconds, allow_agent=False, look_for_keys=False, banner_timeout=settings.ssh_timeout_seconds, auth_timeout=settings.ssh_timeout_seconds)
        print("Connected. Running authorised Nmap service discovery...")
        _stdin, stdout, stderr = ssh.exec_command(f"nmap -sV -oX - -- {target}", timeout=settings.nmap_timeout_seconds, get_pty=False)
        stdout.channel.settimeout(settings.nmap_timeout_seconds)
        xml, diagnostics, code = stdout.read().decode("utf-8", errors="replace"), stderr.read().decode("utf-8", errors="replace"), stdout.channel.recv_exit_status()
        if code != 0: raise ScanError(f"Nmap failed with exit code {code}: {diagnostics.strip() or 'no diagnostics'}")
        records = parse_nmap_xml(xml, str(target)); print(f"Scan completed. Parsed {len(records)} port records."); return records
    except (paramiko.SSHException, socket.error, OSError) as error: raise ScanError(f"SSH/Nmap connection failed: {error}") from error
    finally: ssh.close(); print("SSH connection closed.")

# NVD record parsing.
def english(cve: dict[str, Any]) -> str:
    return next((x["value"] for x in cve.get("descriptions", []) if isinstance(x, dict) and x.get("lang") == "en" and isinstance(x.get("value"), str)), "")
def cvss(cve: dict[str, Any]) -> dict[str, Any]:
    metrics = cve.get("metrics", {}) if isinstance(cve.get("metrics", {}), dict) else {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key, [])
        if isinstance(values, list) and values and isinstance(values[0], dict):
            metric = values[0]; data = metric.get("cvssData", {}) if isinstance(metric.get("cvssData"), dict) else {}
            return {"score": data.get("baseScore"), "severity": metric.get("baseSeverity") or data.get("baseSeverity") or "Not provided", "version": data.get("version", "Unknown")}
    return {"score": None, "severity": "Not provided", "version": "Unknown"}
def split_cpe(criteria: str) -> Optional[list[str]]:
    if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"): return None
    result, current, escaped = [], [], False
    for char in criteria:
        if escaped: current.append(char); escaped = False
        elif char == "\\": current.append(char); escaped = True
        elif char == ":": result.append("".join(current)); current = []
        else: current.append(char)
    result.append("".join(current)); return result if len(result) == 13 and result[:2] == ["cpe", "2.3"] else None
def cpe_short(criteria: str) -> str:
    fields = split_cpe(criteria); return criteria if not fields else f"part={fields[2]}, vendor={fields[3]}, product={fields[4]}, version={fields[5]}"
def condition_state(nodes: Any) -> tuple[bool, list[str]]:
    if not isinstance(nodes, list): return False, []
    uncertain, notes = False, []
    for node in nodes:
        if not isinstance(node, dict): continue
        matches = node.get("cpeMatch", []) if isinstance(node.get("cpeMatch", []), list) else []
        other = [x for x in matches if isinstance(x, dict) and not x.get("vulnerable", False)]
        if node.get("negate"): uncertain = True; notes.append("configuration contains a negated CPE condition")
        if str(node.get("operator", "OR")).upper() == "AND" and other: uncertain = True; notes.append("configuration has additional AND CPE conditions")
        for x in other:
            fields = split_cpe(str(x.get("criteria", "")))
            if fields and fields[2] in {"o", "h"}: uncertain = True; notes.append("platform/hardware condition: " + cpe_short(str(x.get("criteria", ""))))
        child_state, child_notes = condition_state(node.get("nodes", node.get("children", []))); uncertain = uncertain or child_state; notes.extend(child_notes)
    return uncertain, list(dict.fromkeys(notes))
def affected_products(cve: dict[str, Any]) -> list[dict[str, Any]]:
    output = []
    for index, configuration in enumerate(cve.get("configurations", [])):
        if not isinstance(configuration, dict) or not isinstance(configuration.get("nodes"), list): continue
        roots = configuration["nodes"]; unchecked, notes = condition_state(roots)
        def visit(node: dict[str, Any], path: str) -> None:
            for match in node.get("cpeMatch", []) if isinstance(node.get("cpeMatch", []), list) else []:
                if isinstance(match, dict) and match.get("vulnerable", False): output.append({"criteria": str(match.get("criteria", "")), "version_start_including": match.get("versionStartIncluding"), "version_start_excluding": match.get("versionStartExcluding"), "version_end_including": match.get("versionEndIncluding"), "version_end_excluding": match.get("versionEndExcluding"), "configuration_index": index, "configuration_path": path, "unchecked_conditions": unchecked, "condition_notes": notes})
            for child_i, child in enumerate(node.get("nodes", node.get("children", [])) if isinstance(node.get("nodes", node.get("children", [])), list) else []):
                if isinstance(child, dict): visit(child, f"{path}.{child_i}")
        for root_i, root in enumerate(roots):
            if isinstance(root, dict): visit(root, str(root_i))
    return output
def candidate(cve: dict[str, Any]) -> dict[str, Any]:
    return {"cve_id": cve.get("id", "Unknown"), "description": english(cve), "cvss": cvss(cve), "affected_products": affected_products(cve), "published": cve.get("published"), "last_modified": cve.get("lastModified"), "source": "NVD CVE API 2.0", "verification_status": "Candidate only; target applicability not verified", "search_queries": []}

class RateLimiter:
    def __init__(self, delay: float) -> None: self.delay, self.last = delay, 0.0
    def wait(self) -> None:
        remaining = self.delay - (time.monotonic() - self.last)
        if remaining > 0: time.sleep(remaining)
        self.last = time.monotonic()
@dataclass
class Search:
    label: str; parameters: dict[str, str]; kind: str; status: str; total_results: Optional[int]; retrieved_results: int
    candidates: list[dict[str, Any]]; error: Optional[str] = None; attempts: int = 0
def nvd_headers() -> dict[str, str]:
    output = {"User-Agent": "CyberAI-Lab/2.0", "Accept": "application/json"}; key = os.environ.get(NVD_API_KEY_ENVIRONMENT_VARIABLE, "").strip()
    if key: output["apiKey"] = key
    return output
def read_nvd(url: str, limiter: RateLimiter, settings: Settings) -> tuple[dict[str, Any], int]:
    last_error = "Unknown NVD error"
    for attempt in range(1, settings.nvd_retries + 2):
        try:
            limiter.wait()
            with urllib.request.urlopen(urllib.request.Request(url, headers=nvd_headers()), timeout=settings.nvd_timeout_seconds) as response: data = json.loads(response.read().decode("utf-8"))
            if not isinstance(data, dict): raise NvdRequestError("NVD response root was not a JSON object.")
            return data, attempt
        except urllib.error.HTTPError as error:
            last_error = f"HTTP {error.code}: {error.read().decode('utf-8', errors='replace')[:300] or error.reason}"; retryable = error.code in {429, 500, 502, 503, 504}
        except (urllib.error.URLError, TimeoutError, socket.timeout, json.JSONDecodeError, UnicodeDecodeError, NvdRequestError) as error: last_error, retryable = str(error), True
        if not retryable or attempt > settings.nvd_retries: break
        time.sleep(min(2 ** (attempt - 1), 4))
    raise NvdRequestError(last_error)
def query_nvd(label: str, parameters: dict[str, str], kind: str, limiter: RateLimiter, settings: Settings = SETTINGS) -> Search:
    results, start, total, attempts = [], 0, None, 0
    while len(results) < settings.nvd_max_results_per_query:
        params = dict(parameters, resultsPerPage=str(settings.nvd_page_size), startIndex=str(start)); url = settings.nvd_api + "?" + urllib.parse.urlencode(params)
        try:
            data, tries = read_nvd(url, limiter, settings); attempts += tries; page, total = data.get("vulnerabilities", []), int(data.get("totalResults", 0))
            if not isinstance(page, list): raise TypeError("vulnerabilities was not a list")
        except (NvdRequestError, TypeError, ValueError) as error: return Search(label, parameters, kind, "failed", total, len(results), results, f"Could not process NVD response: {error}", attempts)
        for wrapper in page:
            cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
            if isinstance(cve, dict) and isinstance(cve.get("id"), str): results.append(candidate(cve))
            if len(results) >= settings.nvd_max_results_per_query: break
        if not page or len(results) >= total or len(results) >= settings.nvd_max_results_per_query: break
        start += len(page)
    return Search(label, parameters, kind, "success", total, len(results), results, attempts=attempts)

# Strict version semantics. Distro package revisions are never treated as upstream versions.
SIMPLE_VERSION = re.compile(r"^(\d+(?:\.\d+)*)(?:([a-z]+)|(p\d+))?$", re.I)
DISTRO_BUILD = re.compile(r"(?:-|[+~.])(ubuntu|debian|rhel|centos|fedora|suse|amzn|kali)\b|-[0-9]+(?:ubuntu|deb|el|rhel|fc|suse)", re.I)
def is_distro(value: str) -> bool: return bool(DISTRO_BUILD.search(value.strip()))
def parse_version(value: str) -> Optional[tuple[tuple[int, ...], int, str]]:
    value = value.strip().lower()
    if not value or is_distro(value): return None
    match = SIMPLE_VERSION.fullmatch(value)
    if not match: return None
    numeric, letters, patch = match.groups(); nums = tuple(int(x) for x in numeric.split("."))
    return (nums, int(patch[1:]), "p") if patch else (nums, sum(ord(x)-ord("a")+1 for x in letters), "letter") if letters else (nums, 0, "bare")
def compare_version(installed: str, boundary: str) -> Optional[int]:
    a, b = parse_version(installed), parse_version(boundary)
    if a is None or b is None: return None
    an, ax, ak = a; bn, bx, bk = b
    if ak != bk and "bare" not in {ak, bk}: return None
    length = max(len(an), len(bn)); an += (0,) * (length-len(an)); bn += (0,) * (length-len(bn))
    if an != bn: return (an > bn) - (an < bn)
    return ((0 if ak == "bare" else ax) > (0 if bk == "bare" else bx)) - ((0 if ak == "bare" else ax) < (0 if bk == "bare" else bx))
def range_match(installed: str, item: dict[str, Any]) -> tuple[str, str]:
    rules = (("version_start_including", "start inclusive", lambda x:x<0), ("version_start_excluding", "start exclusive", lambda x:x<=0), ("version_end_including", "end inclusive", lambda x:x>0), ("version_end_excluding", "end exclusive", lambda x:x>=0))
    found = [(k,l,r) for k,l,r in rules if item.get(k) not in (None, "")]
    if not found: return "UNCERTAIN", "No explicit NVD version boundary was supplied."
    for key, label, reject in found:
        boundary = item[key]; comparison = compare_version(installed, boundary) if isinstance(boundary, str) else None
        if comparison is None: return "UNCERTAIN", f"Cannot safely compare detected version {installed!r} with {label} boundary {boundary!r}."
        if reject(comparison): return "NOT MATCHED", f"Detected version does not satisfy the {label} boundary {boundary}."
    return "POTENTIAL MATCH", "Detected version satisfies every supplied NVD range boundary."
def with_conditions(status: str, evidence: str, item: dict[str, Any]) -> tuple[str, str]:
    if status == "POTENTIAL MATCH" and item.get("unchecked_conditions"):
        return "UNCERTAIN", evidence + " However, " + ("; ".join(item.get("condition_notes", [])) or "unevaluated CPE conditions") + "; this scan cannot verify it."
    return status, evidence
def match_candidate_to_service(cve: dict[str, Any], service: ServiceRecord) -> dict[str, str]:
    if not service.product.strip() or not service.version.strip(): return {"status":"UNCERTAIN", "evidence":"Detected product or version is missing; CPE applicability cannot be evaluated."}
    profile = profile_for(service.product)
    if not profile: return {"status":"UNCERTAIN", "evidence":f"Nmap product {service.product!r} has no trusted CPE identity mapping; automatic matching is withheld."}
    uncertain, rejected, vendor_mismatch = [], [], False
    for item in cve.get("affected_products", []):
        fields = split_cpe(str(item.get("criteria", ""))) if isinstance(item, dict) else None
        if not fields: continue
        part, vendor, product, cpe_version = (x.lower() for x in fields[2:6])
        if part != "a" or product not in profile.cpe_products: continue
        if vendor not in profile.cpe_vendors: vendor_mismatch = True; continue
        identity = f"CPE vendor={vendor}, product={product}"
        has_range = any(item.get(k) not in (None, "") for k in ("version_start_including", "version_start_excluding", "version_end_including", "version_end_excluding"))
        if has_range: status, evidence = range_match(service.version, item); status, evidence = with_conditions(status, identity + "; " + evidence, item)
        elif cpe_version in {"*", "-", ""}: status, evidence = "UNCERTAIN", identity + "; wildcard/unspecified CPE version has no range."
        elif service.version.casefold() == cpe_version.casefold(): status, evidence = with_conditions("POTENTIAL MATCH", identity + f", version={cpe_version}; exact detected-version string match.", item)
        elif compare_version(service.version, cpe_version) is None: status, evidence = "UNCERTAIN", identity + f", CPE version={cpe_version}; detected version {service.version!r} cannot be safely compared."
        else: status, evidence = "NOT MATCHED", identity + f", CPE version={cpe_version}; detected version is not that exact version."
        if status == "POTENTIAL MATCH": return {"status":status, "evidence":evidence + " Vendor backports and service configuration remain unverified."}
        (uncertain if status == "UNCERTAIN" else rejected).append(evidence)
    if uncertain: return {"status":"UNCERTAIN", "evidence":uncertain[0]}
    if rejected: return {"status":"NOT MATCHED", "evidence":rejected[0]}
    if vendor_mismatch: return {"status":"NO PRODUCT/VERSION MATCH IDENTIFIED", "evidence":"A similarly named CPE had a different vendor identity, so it was not associated with this service."}
    return {"status":"NO PRODUCT/VERSION MATCH IDENTIFIED", "evidence":"No CPE entry with the expected vendor and product identity was found. This does not prove the service is safe."}

@dataclass
class Assessment:
    service: ServiceRecord; searches: list[Search]; candidates: list[dict[str, Any]]; lookup_status: str; lookup_note: str
def cpe_version(value: str) -> Optional[str]: return value.lower() if parse_version(value) is not None and not is_distro(value) and not any(x in value for x in (":", "\\", "*", "?")) else None
def cpe_name(vendor: str, product: str, version: str) -> str: return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
def search_copy(label: str, params: dict[str,str], kind: str, cache: dict[Any,Search], limiter: RateLimiter, settings: Settings) -> Search:
    key = kind, tuple(sorted(params.items()))
    if key not in cache: cache[key] = query_nvd(label, params, kind, limiter, settings)
    s = cache[key]; return Search(s.label, dict(s.parameters), s.kind, s.status, s.total_results, s.retrieved_results, [dict(x) for x in s.candidates], s.error, s.attempts)
def deduplicate(searches: list[Search]) -> list[dict[str,Any]]:
    result: dict[str,dict[str,Any]] = {}
    for search in searches:
        for item in search.candidates:
            key = str(item.get("cve_id", "Unknown"))
            if key not in result: result[key] = dict(item); result[key]["search_queries"] = []
            result[key]["search_queries"].append({"label":search.label, "kind":search.kind, "parameters":search.parameters})
    return list(result.values())
def lookup_vulnerabilities(findings: list[ServiceRecord], settings: Settings = SETTINGS) -> list[Assessment]:
    cache: dict[Any,Search] = {}; limiter = RateLimiter(settings.nvd_request_delay_seconds); reports = []
    for service in [x for x in findings if x.state == "open"]:
        if not service.product or not service.version: reports.append(Assessment(service, [], [], "NOT QUERIED", "Nmap did not provide both product and version.")); continue
        profile, searches = profile_for(service.product), []
        name = profile.search_name if profile else service.product; version = cpe_version(service.version)
        if profile and version:
            for vendor in profile.cpe_vendors:
                for product in profile.cpe_products:
                    cpe = cpe_name(vendor, product, version); searches.append(search_copy("CPE name: " + cpe, {"cpeName":cpe}, "cpeName", cache, limiter, settings))
        else: searches.append(search_copy("Keyword: " + name + " " + service.version, {"keywordSearch":name + " " + service.version}, "keyword", cache, limiter, settings))
        has_candidates = any(x.status == "success" and x.candidates for x in searches); specific = name + " " + service.version
        if not has_candidates and not any(x.kind == "keyword" and x.parameters.get("keywordSearch") == specific for x in searches): searches.append(search_copy("Keyword: " + specific, {"keywordSearch":specific}, "keyword", cache, limiter, settings))
        if not any(x.status == "success" and x.candidates for x in searches) and any(x.status == "success" and not x.candidates for x in searches): searches.append(search_copy("Broad keyword fallback: " + name, {"keywordSearch":name}, "broad_keyword", cache, limiter, settings))
        candidates = deduplicate(searches)
        for item in candidates:
            matched = match_candidate_to_service(item, service); item.update({"service":service.display_name(), "port":service.port, "detected_product":service.product, "detected_version":service.version, "match_status":matched["status"], "match_evidence":matched["evidence"]})
        status, note = ("CANDIDATES RETRIEVED", "Candidates were filtered by structured CPE/vendor/version evidence.") if candidates else ("LOOKUP FAILED", "At least one NVD request failed; this is not a clean result.") if any(x.status == "failed" for x in searches) else ("NO CANDIDATES RETURNED", "Completed NVD searches returned no candidates; this does not establish security.")
        reports.append(Assessment(service, searches, candidates, status, note))
    return reports

# Report has fixed authoritative sections; only a separate explanatory section uses AI.
def cvss_text(item: dict[str,Any]) -> str:
    data = item.get("cvss", {}) if isinstance(item.get("cvss", {}), dict) else {}; return f"{data.get('score') if data.get('score') is not None else 'Not provided'} ({data.get('severity','Not provided')}; CVSS {data.get('version','Unknown')})"
def heading(lines: list[str], text: str) -> None: lines.extend(["", text, "-" * len(text)])
def recommendation(item: dict[str,Any]) -> str:
    return "Verify installed package/build and vendor/distribution advisory, check configuration conditions, patch where appropriate, then retest." if item.get("match_status") == "POTENTIAL MATCH" else "Collect package revision and platform/configuration evidence, then compare vendor and distribution advisories." if item.get("match_status") == "UNCERTAIN" else "Do not base remediation on this candidate alone; validate vendor information if relevant."
def show_candidate(lines: list[str], item: dict[str,Any], show_description: bool=True) -> None:
    lines.extend([f"{item.get('cve_id','Unknown')} | CVSS: {cvss_text(item)}", f"  Affected product / detected version: {item.get('detected_product','Unknown')} {item.get('detected_version','')}".rstrip(), f"  Python classification: {item.get('match_status','UNCERTAIN')}", f"  Matching evidence: {item.get('match_evidence','Not available')}"])
    if show_description and item.get("description"): lines.append("  NVD description: " + item["description"])
    if item.get("search_queries"): lines.append("  Originating search(es): " + "; ".join(x["label"] for x in item["search_queries"]))
    lines.append("  Recommended verification: " + recommendation(item))
def build_report(findings: list[ServiceRecord], reports: list[Assessment]) -> str:
    open_services = [x for x in findings if x.state == "open"]; searches = [x for r in reports for x in r.searches]; candidates = [x for r in reports for x in r.candidates]
    potential, uncertain, unmatched = [x for x in candidates if x.get("match_status") == "POTENTIAL MATCH"], [x for x in candidates if x.get("match_status") == "UNCERTAIN"], [x for x in candidates if x.get("match_status") in {"NOT MATCHED", "NO PRODUCT/VERSION MATCH IDENTIFIED"}]
    potential.sort(key=lambda x:float(x.get("cvss",{}).get("score") or -1), reverse=True)
    lines = ["CYBERAI — EVIDENCE-BASED LAB SECURITY ASSESSMENT", "="*55]; heading(lines, "A. Scan Summary")
    lines.extend([f"Target IP: {TARGET_IP}", "Scan completion status: COMPLETED", f"Open ports: {len(open_services)}", f"Detected open services: {len(open_services)}", f"Successful NVD searches: {sum(x.status == 'success' for x in searches)}", f"Failed NVD searches: {sum(x.status == 'failed' for x in searches)}", f"Candidate CVEs retrieved (deduplicated per service): {len(candidates)}"])
    heading(lines,"B. Detected Services")
    if open_services:
        for s in open_services: lines.append(f"{s.port}/{s.protocol} | service={s.service_name or 'unknown'} | product={s.product or 'not detected'} | version={s.version or 'not detected'} | version confidence={s.version_confidence}"); lines.extend(["  Additional version information: " + s.extra_info] if s.extra_info else [])
    else: lines.append("No open ports were present in completed Nmap XML. This is not a proof of security.")
    for title, items, description, empty in (("C. Priority Findings",potential,True,"No candidate met the conservative Python rules for a POTENTIAL MATCH."),("D. Uncertain Findings",uncertain,True,"No retrieved candidate required an UNCERTAIN classification."),("E. Unmatched Candidates",unmatched,False,"No candidates were classified as NOT MATCHED or NO PRODUCT/VERSION MATCH IDENTIFIED.")):
        heading(lines,title)
        if items:
            for item in items: show_candidate(lines,item,description)
        else: lines.append(empty)
    heading(lines,"F. Services With No Candidates"); empty_reports = [r for r in reports if r.lookup_status == "NO CANDIDATES RETURNED"]
    if empty_reports:
        for r in empty_reports: lines.append(r.service.display_name() + ": " + r.lookup_note)
    else: lines.append("None.")
    heading(lines,"G. Failed Searches"); failed = [x for x in searches if x.status == "failed"]
    if failed:
        for x in failed: lines.append(x.label + ": " + (x.error or "Unknown NVD error"))
    else: lines.append("None.")
    heading(lines,"H. Recommended Defensive Actions"); lines.extend(["1. Verify exact installed package versions and revisions directly on the target; Nmap information can be incomplete.","2. Review vendor and distribution-specific security advisories, including possible backported fixes.","3. Patch or upgrade only after confirming applicability and following the operational change process; retest afterward.","4. Disable or firewall unnecessary exposed services and review authentication, encryption, and least-privilege configuration.","5. Do not use exploitation as routine verification; use package/configuration evidence, advisories, and retesting."])
    heading(lines,"I. Limitations"); lines.extend(["NVD searches discover candidates, not confirmed target vulnerabilities.","The scanner never infers upstream versions from distribution package suffixes or treats CPE wildcards as exact matches.","Platform, hardware, negation, and other CPE conditions not observable through service scanning remain uncertain.","CVSS severity describes potential impact, not target applicability.","No candidates, unmatched candidates, and failed lookups must not be interpreted as a clean result."])
    return "\n".join(lines)

def ai_explanation(findings: list[ServiceRecord], reports: list[Assessment], settings: Settings=SETTINGS) -> tuple[bool,str]:
    evidence = {"target":TARGET_IP,"services":[x.to_dict() for x in findings if x.state=="open"],"classifications":[{"service":r.service.display_name(),"lookup_status":r.lookup_status,"candidates":[{"cve_id":x.get("cve_id"),"classification":x.get("match_status"),"evidence":x.get("match_evidence")} for x in r.candidates]} for r in reports]}
    prompt = "Explain this authorised training-lab context in 2-5 short paragraphs with headings Plain-language context and Defensive next steps. Python evidence is authoritative. Explain services generally and defensive verification. Do not include CVE IDs, scores, product-version pairs, classifications, or words vulnerable, confirmed, exploitable, or safe. Do not recommend exploitation.\n\n" + json.dumps(evidence,ensure_ascii=False)
    request = urllib.request.Request(settings.ollama_url,data=json.dumps({"model":settings.ollama_model,"messages":[{"role":"system","content":"Explain only supplied context. Never classify or add findings."},{"role":"user","content":prompt}],"stream":False}).encode(),headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(request,timeout=settings.ollama_timeout_seconds) as response: data = json.loads(response.read().decode())
        text = data.get("message",{}).get("content") if isinstance(data,dict) else None; bad = ("cve-","potential match","not matched","uncertain","no product/version match identified","confirmed vulnerable","is vulnerable","exploitable","vulnerability-free"," safe")
        if not isinstance(text,str) or not text.strip(): return False,"Ollama returned an empty explanation."
        hit = next((x for x in bad if x in text.casefold()),None)
        return (False,f"Ollama explanation used restricted classification language ({hit!r}).") if hit else (True,text.strip())
    except (urllib.error.URLError,TimeoutError,socket.timeout,json.JSONDecodeError,UnicodeDecodeError,AttributeError,KeyError) as error: return False,f"Ollama explanation unavailable: {error}"
def append_ai(report: str, result: tuple[bool,str]) -> str:
    available,text = result; return report + "\n\nJ. Optional Local AI Explanation (Non-Authoritative)\n" + "-"*48 + "\n" + ("Python classifications above remain controlling.\n\n" + text if available else text + "\nThe complete evidence-based Python report remains available above.")

# Offline unit tests: no network, SSH, Nmap, or Ollama.
def fake_service(product: str, version: str) -> ServiceRecord: return ServiceRecord(TARGET_IP,"22","tcp","open","ssh",product,version,"","test","test")
def fake_cve(criteria: str, **ranges: Any) -> dict[str,Any]:
    item = {"criteria":criteria,"unchecked_conditions":False,"condition_notes":[]}; item.update(ranges); return {"cve_id":"CVE-2099-0001","affected_products":[item]}
class MatchingTests(unittest.TestCase):
    def test_boundaries(self):
        c = fake_cve("cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",version_start_including="12.0",version_end_excluding="13.0"); self.assertEqual(match_candidate_to_service(c,fake_service("PostgreSQL","12.0"))["status"],"POTENTIAL MATCH"); self.assertEqual(match_candidate_to_service(c,fake_service("PostgreSQL","13.0"))["status"],"NOT MATCHED")
    def test_exact_openssh(self): self.assertEqual(match_candidate_to_service(fake_cve("cpe:2.3:a:openbsd:openssh:4.7p1:*:*:*:*:*:*:*"),fake_service("OpenSSH","4.7p1"))["status"],"POTENTIAL MATCH")
    def test_distro_version_uncertain(self): self.assertEqual(match_candidate_to_service(fake_cve("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",version_end_including="5.0.51a"),fake_service("Apache httpd","5.0.51a-3ubuntu5"))["status"],"UNCERTAIN")
    def test_unsupported_uncertain(self): self.assertEqual(match_candidate_to_service(fake_cve("cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*",version_end_including="9.9.9"),fake_service("ISC BIND","9.X - 10.X"))["status"],"UNCERTAIN")
    def test_product_vendor_mismatch(self):
        self.assertEqual(match_candidate_to_service(fake_cve("cpe:2.3:a:oracle:mysql:8.0:*:*:*:*:*:*:*"),fake_service("PostgreSQL","12.0"))["status"],"NO PRODUCT/VERSION MATCH IDENTIFIED"); self.assertEqual(match_candidate_to_service(fake_cve("cpe:2.3:a:other:postgresql:12.0:*:*:*:*:*:*:*"),fake_service("PostgreSQL","12.0"))["status"],"NO PRODUCT/VERSION MATCH IDENTIFIED")
    def test_wildcard_not_exact(self): self.assertEqual(match_candidate_to_service(fake_cve("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"),fake_service("OpenSSH","9.0"))["status"],"UNCERTAIN")
    def test_conditions_uncertain(self):
        c=fake_cve("cpe:2.3:a:openbsd:openssh:9.0:*:*:*:*:*:*:*"); c["affected_products"][0].update({"unchecked_conditions":True,"condition_notes":["platform condition"]}); self.assertEqual(match_candidate_to_service(c,fake_service("OpenSSH","9.0"))["status"],"UNCERTAIN")
    def test_dedup(self):
        a,b=Search("a",{},"keyword","success",1,1,[{"cve_id":"CVE-2099-1"}]),Search("b",{},"keyword","success",1,1,[{"cve_id":"CVE-2099-1"}]); self.assertEqual(len(deduplicate([a,b])),1)

def assessment_counts(findings: list[ServiceRecord], reports: list[Assessment]) -> dict[str, int]:
    candidates = [item for report in reports for item in report.candidates]
    searches = [search for report in reports for search in report.searches]
    return {
        "open_services": sum(service.state == "open" for service in findings),
        "potential": sum(item.get("match_status") == "POTENTIAL MATCH" for item in candidates),
        "uncertain": sum(item.get("match_status") == "UNCERTAIN" for item in candidates),
        "unmatched": sum(item.get("match_status") in {"NOT MATCHED", "NO PRODUCT/VERSION MATCH IDENTIFIED"} for item in candidates),
        "candidates": len(candidates),
        "search_success": sum(search.status == "success" for search in searches),
        "search_failed": sum(search.status == "failed" for search in searches),
        "services_without_candidates": sum(report.lookup_status == "NO CANDIDATES RETURNED" for report in reports),
    }

def print_simple_summary(findings: list[ServiceRecord], reports: list[Assessment]) -> None:
    counts = assessment_counts(findings, reports)
    candidates = [item for report in reports for item in report.candidates]
    potential = sorted((x for x in candidates if x.get("match_status") == "POTENTIAL MATCH"), key=lambda x: float((x.get("cvss") or {}).get("score") or -1), reverse=True)
    uncertain = [x for x in candidates if x.get("match_status") == "UNCERTAIN"]
    print("\n" + "=" * 58)
    print("CYBERAI — SIMPLE SCAN SUMMARY")
    print("=" * 58)
    print(f"Target: {TARGET_IP}  |  Scan: COMPLETED")
    print(f"Open services found: {counts['open_services']}")
    print(f"Potential matches to investigate: {counts['potential']}")
    print(f"Findings needing verification: {counts['uncertain']}")
    print(f"NVD searches failed: {counts['search_failed']}")
    print("\nIMPORTANT: These are automated candidate matches, not confirmed vulnerabilities.")
    if potential:
        print("\nTOP ITEMS TO REVIEW (up to 5):")
        for item in potential[:5]:
            score = (item.get("cvss") or {}).get("score")
            score_text = f", CVSS {score}" if score is not None else ""
            print(f" - {item.get('cve_id', 'Unknown')} — {item.get('detected_product', 'Unknown')} {item.get('detected_version', '')}{score_text}")
    elif uncertain:
        print("\nNo potential matches were identified. Some results need manual verification.")
    else:
        print("\nNo potential matches were identified by the current rules.")
    print("\nNEXT STEPS:")
    print("  1. Open the HTML report in your browser.")
    print("  2. Verify important findings against vendor/distribution advisories.")
    print("  3. Do not treat missing results or failed lookups as proof of security.")

def _html_escape(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)

def build_html_report(findings: list[ServiceRecord], reports: list[Assessment], ai_result: tuple[bool, str]) -> str:
    counts = assessment_counts(findings, reports)
    candidates = [item for report in reports for item in report.candidates]
    potential = sorted((x for x in candidates if x.get("match_status") == "POTENTIAL MATCH"), key=lambda x: float((x.get("cvss") or {}).get("score") or -1), reverse=True)
    uncertain = [x for x in candidates if x.get("match_status") == "UNCERTAIN"]
    open_services = [x for x in findings if x.state == "open"]

    def finding_rows(items: list[dict[str, Any]], limit: Optional[int] = None) -> str:
        shown = items if limit is None else items[:limit]
        if not shown:
            return '<tr><td colspan="5">No findings in this category.</td></tr>'
        rows = []
        for item in shown:
            cvss_data = item.get("cvss") or {}
            cvss_value = cvss_data.get("score")
            description = item.get("description") or "No description supplied by NVD."
            evidence = item.get("match_evidence") or "No matching evidence supplied."
            rows.append("<tr>" + "".join([
                f"<td>{_html_escape(item.get('cve_id', 'Unknown'))}</td>",
                f"<td>{_html_escape(item.get('detected_product', 'Unknown'))} {_html_escape(item.get('detected_version', ''))}</td>",
                f"<td>{_html_escape(cvss_value if cvss_value is not None else 'N/A')}</td>",
                f"<td>{_html_escape(evidence)}<details><summary>Plain record description</summary><p>{_html_escape(description)}</p></details></td>",
                f"<td>{_html_escape(recommendation(item))}</td>",
            ]) + "</tr>")
        return "\n".join(rows)

    service_rows = "\n".join(
        f"<tr><td>{_html_escape(s.port)}/{_html_escape(s.protocol)}</td><td>{_html_escape(s.service_name or 'unknown')}</td><td>{_html_escape(s.product or 'Not detected')}</td><td>{_html_escape(s.version or 'Not detected')}</td></tr>"
        for s in open_services
    ) or '<tr><td colspan="4">No open services were reported by the completed scan.</td></tr>'
    lookup_rows = "\n".join(
        f"<tr><td>{_html_escape(r.service.display_name())}</td><td>{_html_escape(r.lookup_status)}</td><td>{_html_escape(r.lookup_note)}</td></tr>"
        for r in reports if r.lookup_status != "CANDIDATES RETRIEVED"
    ) or '<tr><td colspan="3">No services reported an empty or failed lookup.</td></tr>'
    ai_available, ai_text = ai_result
    ai_section = f"<section><h2>Optional AI explanation</h2><p class='note'>This text is explanatory only. Python classifications above remain authoritative.</p><p>{_html_escape(ai_text)}</p></section>" if ai_available else ""
    detailed_text = build_report(findings, reports)
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberAI — Lab Security Assessment</title>
<style>
:root {{ color-scheme: light; --ink:#172033; --muted:#5d687a; --line:#dce2eb; --panel:#f5f7fb; --blue:#2457a7; }}
* {{ box-sizing:border-box; }} body {{ margin:0; background:#f3f5f9; color:var(--ink); font:16px/1.5 system-ui,-apple-system,Segoe UI,Arial,sans-serif; }}
main {{ max-width:1120px; margin:0 auto; padding:28px 18px 56px; }} header {{ background:#172033; color:white; padding:26px; border-radius:16px; }} h1 {{ margin:0 0 8px; font-size:clamp(1.6rem,4vw,2.2rem); }} header p {{ margin:4px 0; color:#e1e8f5; }} section {{ background:white; margin-top:18px; padding:22px; border:1px solid var(--line); border-radius:14px; }} h2 {{ margin:0 0 14px; font-size:1.25rem; }} .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-top:18px; }} .card {{ background:var(--panel); border:1px solid var(--line); padding:16px; border-radius:12px; }} .card strong {{ display:block; font-size:1.8rem; }} .card span {{ color:var(--muted); font-size:.92rem; }} .note {{ color:var(--muted); }} .warning {{ background:#fff8e6; border-left:4px solid #d79a12; padding:12px 14px; border-radius:6px; }} .table-wrap {{ overflow-x:auto; }} table {{ width:100%; border-collapse:collapse; font-size:.94rem; }} th,td {{ padding:11px 10px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }} th {{ background:var(--panel); }} details {{ margin-top:8px; }} summary {{ color:var(--blue); cursor:pointer; }} code {{ background:var(--panel); padding:2px 5px; border-radius:4px; }} footer {{ color:var(--muted); padding:18px 2px; font-size:.9rem; }}
</style></head><body><main>
<header><h1>CyberAI — Lab Security Assessment</h1><p><strong>Target:</strong> {_html_escape(TARGET_IP)} &nbsp; | &nbsp; <strong>Scan status:</strong> Completed</p><p>Simple overview of services and potential findings from your authorised training lab.</p></header>
<div class="cards">
<div class="card"><strong>{counts['open_services']}</strong><span>Open services</span></div>
<div class="card"><strong>{counts['potential']}</strong><span>Potential matches to investigate</span></div>
<div class="card"><strong>{counts['uncertain']}</strong><span>Findings needing verification</span></div>
<div class="card"><strong>{counts['search_failed']}</strong><span>Failed NVD searches</span></div>
</div>
<section><h2>How to read these results</h2><p class="warning"><strong>Important:</strong> A potential match is not a confirmed vulnerability. Nmap version information and NVD records alone cannot prove that the installed software is affected. A result may also be missing because a lookup failed or the scanner could not safely compare the version.</p><p>Start with the potential matches, verify the installed package/build and vendor advisory, and treat uncertain results as questions to investigate—not as proof of a problem.</p></section>
<section><h2>Priority findings</h2><p class="note">Showing up to 10 potential matches, ordered by CVSS score when available.</p><div class="table-wrap"><table><thead><tr><th>CVE</th><th>Detected software</th><th>CVSS</th><th>Why it was listed</th><th>Suggested next step</th></tr></thead><tbody>{finding_rows(potential, 10)}</tbody></table></div>{'<details><summary>Show all potential matches</summary><div class="table-wrap"><table><thead><tr><th>CVE</th><th>Detected software</th><th>CVSS</th><th>Evidence</th><th>Next step</th></tr></thead><tbody>'+finding_rows(potential)+'</tbody></table></div></details>' if len(potential) > 10 else ''}</section>
<section><h2>Needs further verification</h2><p class="note">These results could not be evaluated confidently with the available evidence.</p><div class="table-wrap"><table><thead><tr><th>CVE</th><th>Detected software</th><th>CVSS</th><th>Why it is uncertain</th><th>Suggested next step</th></tr></thead><tbody>{finding_rows(uncertain, 10)}</tbody></table></div>{'<details><summary>Show all uncertain findings</summary><div class="table-wrap"><table><thead><tr><th>CVE</th><th>Detected software</th><th>CVSS</th><th>Evidence</th><th>Next step</th></tr></thead><tbody>'+finding_rows(uncertain)+'</tbody></table></div></details>' if len(uncertain) > 10 else ''}</section>
<section><h2>Services discovered</h2><div class="table-wrap"><table><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version reported by Nmap</th></tr></thead><tbody>{service_rows}</tbody></table></div></section>
<section><h2>Lookups needing attention</h2><p class="note">Includes services with no candidates and searches that failed. Neither means the service is secure.</p><div class="table-wrap"><table><thead><tr><th>Service</th><th>Status</th><th>Details</th></tr></thead><tbody>{lookup_rows}</tbody></table></div></section>
{ai_section}
<section><h2>Recommended next steps</h2><ol><li>Verify the exact installed package version and revision on the target.</li><li>Compare it with the software vendor's or Linux distribution's security advisory.</li><li>Review configuration and platform conditions before deciding whether a finding applies.</li><li>Patch or reconfigure only after checking applicability, then rescan.</li><li>Do not treat an empty result or failed lookup as proof of security.</li></ol></section>
<section><h2>Technical details</h2><p>The complete technical report is included below for reference. Most users only need the summary and findings sections above.</p><details><summary>Open full technical report</summary><pre style="white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.5 ui-monospace,Consolas,monospace">{_html_escape(detailed_text)}</pre></details></section>
<footer>CyberAI internship prototype · NVD records are candidates, not confirmed target vulnerabilities.</footer>
</main></body></html>'''

def main(argv: Optional[list[str]]=None) -> int:
    parser = argparse.ArgumentParser(description="CyberAI authorised lab vulnerability assessment")
    parser.add_argument("--self-test", action="store_true", help="run offline unit tests only")
    parser.add_argument("--report", metavar="PATH", help="also save the full technical text report")
    parser.add_argument("--html-report", metavar="PATH", default="cyberai_report.html", help="HTML report path (default: cyberai_report.html)")
    args = parser.parse_args(argv)
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(MatchingTests))
        return 0 if result.wasSuccessful() else 1
    print("=" * 58 + "\nCYBERAI — LAB SECURITY ASSESSMENT\n" + "=" * 58)
    password = getpass.getpass("\nEnter your Ubuntu password: ")
    try:
        findings = run_scan(password)
    except ScanError as error:
        print(f"\nSCAN FAILED: {error}\nNo assessment report was generated because scan evidence was unavailable.")
        return 1
    except Exception as error:
        print(f"\nUNEXPECTED SCAN ERROR: {type(error).__name__}: {error}")
        return 1
    print("\nSearching NVD for product/version candidates...")
    reports = lookup_vulnerabilities(findings)
    ai_result = ai_explanation(findings, reports)
    print_simple_summary(findings, reports)
    try:
        html_report = build_html_report(findings, reports, ai_result)
        with open(args.html_report, "w", encoding="utf-8", newline="\n") as output:
            output.write(html_report)
        print(f"\nHTML report saved: {os.path.abspath(args.html_report)}")
    except OSError as error:
        print(f"\nHTML REPORT WRITE ERROR: {error}")
        return 1
    if args.report:
        try:
            full_report = append_ai(build_report(findings, reports), ai_result)
            with open(args.report, "w", encoding="utf-8", newline="\n") as output:
                output.write(full_report)
            print(f"Full technical report saved: {os.path.abspath(args.report)}")
        except OSError as error:
            print(f"\nTECHNICAL REPORT WRITE ERROR: {error}")
            return 1
    print("\nAssessment complete. NVD candidates are not confirmed target vulnerabilities.")
    return 0
if __name__ == "__main__": raise SystemExit(main())
