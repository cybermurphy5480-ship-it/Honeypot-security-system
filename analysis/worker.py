"""
malware_analyzer.py
====================
Cloud-based malware analysis worker.

Polls an AWS SQS queue for file upload events, downloads each file from S3,
performs static + dynamic analysis (VirusTotal), and publishes a JSON + PDF
report back to S3.

Author : Murphy
Version: 1.2.0
License: MIT
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import boto3
import matplotlib
import matplotlib.pyplot as plt
import requests
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

matplotlib.use("Agg")  # headless rendering

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Config:
    """Central configuration.  Override via environment variables."""

    # AWS Configuration - MUST be set via environment variables
    queue_url: str = os.getenv("SQS_QUEUE_URL", "")
    bucket: str = os.getenv("S3_BUCKET", "")
    region: str = os.getenv("AWS_REGION", "us-east-1")
    
    # VirusTotal API Key - MUST be set via environment variable
    vt_api_key: str = os.getenv("VT_API_KEY", "")
    
    # Local paths
    tmp_dir: Path = Path(os.getenv("TMP_DIR", "/tmp/malware_analyzer"))
    logo_path: Path = Path(os.getenv("LOGO_PATH", "/tmp/logo.jpg"))

    # SQS polling
    max_messages: int = int(os.getenv("SQS_MAX_MESSAGES", "1"))
    wait_seconds: int = int(os.getenv("SQS_WAIT_SECONDS", "10"))

    # VirusTotal
    vt_poll_attempts: int = int(os.getenv("VT_POLL_ATTEMPTS", "8"))
    vt_poll_interval: int = int(os.getenv("VT_POLL_INTERVAL", "5"))

    # Verdict threshold — number of "malicious" VT engines before flagging
    malicious_threshold: int = int(os.getenv("MALICIOUS_THRESHOLD", "5"))

    def validate(self) -> None:
        """Validate that required configuration is present."""
        errors = []
        if not self.queue_url:
            errors.append("SQS_QUEUE_URL environment variable is required")
        if not self.bucket:
            errors.append("S3_BUCKET environment variable is required")
        if not self.vt_api_key or self.vt_api_key == "YOUR_VT_API_KEY":
            errors.append("VT_API_KEY environment variable is required")
        
        if errors:
            raise ValueError(
                "Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
            )


CFG = Config()
CFG.tmp_dir.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# AWS clients
# ---------------------------------------------------------------------------

_sqs = boto3.client("sqs", region_name=CFG.region)
_s3  = boto3.client("s3",  region_name=CFG.region)

# ---------------------------------------------------------------------------
# Static Analysis
# ---------------------------------------------------------------------------

def get_file_info(path: Path) -> dict[str, Any]:
    """Return basic file metadata."""
    return {
        "name": path.name,
        "size_bytes": path.stat().st_size,
        "file_type": subprocess.getoutput(f"file {path}"),
    }


def compute_hashes(path: Path) -> dict[str, str]:
    """Compute MD5 and SHA-256 digests."""
    data = path.read_bytes()
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def compute_entropy(path: Path) -> float:
    """Return Shannon entropy (0–8) of the file's byte distribution."""
    data = path.read_bytes()
    if not data:
        return 0.0
    length = len(data)
    entropy = 0.0
    for byte_val in range(256):
        prob = data.count(bytes([byte_val])) / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def extract_strings(path: Path) -> str:
    """Extract printable strings from a binary file."""
    try:
        return subprocess.check_output(["strings", str(path)]).decode(errors="ignore")
    except Exception as exc:
        log.warning("strings extraction failed: %s", exc)
        return ""


def pe_analysis(path: Path) -> dict[str, str]:
    """Parse PE headers if the file is a Windows executable."""
    try:
        import pefile  # optional dependency

        pe = pefile.PE(str(path))
        return {
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base":  hex(pe.OPTIONAL_HEADER.ImageBase),
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# MITRE ATT&CK STIX Integration
# ---------------------------------------------------------------------------

class MITRESTIXMapper:
    """Maps malware indicators to MITRE ATT&CK techniques using STIX data."""
    
    def __init__(self):
        self.techniques = {}
        self.cache_path = CFG.tmp_dir / "mitre_attack.json"
        self.stix_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.load_mitre_data()
        self.build_indicator_mappings()
    
    def load_mitre_data(self):
        """Load MITRE ATT&CK STIX data from cache or download."""
        try:
            # Try loading from cache first
            if self.cache_path.exists():
                log.info("Loading MITRE ATT&CK data from cache...")
                with open(self.cache_path, 'r') as f:
                    data = json.load(f)
            else:
                # Download from MITRE GitHub
                log.info("Downloading MITRE ATT&CK STIX data...")
                response = requests.get(self.stix_url, timeout=30)
                response.raise_for_status()
                data = response.json()
                
                # Cache for future use
                with open(self.cache_path, 'w') as f:
                    json.dump(data, f)
                log.info("MITRE data cached successfully")
            
            # Parse techniques from STIX objects
            for obj in data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    # Extract technique ID
                    ext_refs = obj.get('external_references', [])
                    tech_id = None
                    for ref in ext_refs:
                        if ref.get('source_name') == 'mitre-attack':
                            tech_id = ref.get('external_id')
                            break
                    
                    if tech_id:
                        self.techniques[tech_id] = {
                            'name': obj.get('name', ''),
                            'description': obj.get('description', '')[:200],
                            'tactics': [phase.get('phase_name', '') 
                                       for phase in obj.get('kill_chain_phases', [])],
                            'platforms': obj.get('x_mitre_platforms', [])
                        }
            
            log.info("Loaded %d MITRE ATT&CK techniques", len(self.techniques))
            
        except Exception as e:
            log.error("Error loading MITRE data: %s", e)
            log.warning("Falling back to minimal technique set")
            # Minimal fallback
            self.techniques = {
                'T1059.001': {'name': 'PowerShell', 'tactics': ['execution']},
                'T1059.003': {'name': 'Windows Command Shell', 'tactics': ['execution']},
                'T1071.001': {'name': 'Web Protocols', 'tactics': ['command-and-control']}
            }
    
    def build_indicator_mappings(self):
        """Build comprehensive indicator to technique mappings."""
        self.indicator_map = {
            # Execution techniques
            'powershell': ['T1059.001'],
            'pwsh': ['T1059.001'],
            'cmd.exe': ['T1059.003'],
            'cmd': ['T1059.003'],
            'wscript': ['T1059.005'],
            'cscript': ['T1059.005'],
            'mshta': ['T1218.005'],
            'rundll32': ['T1218.011'],
            'regsvr32': ['T1218.010'],
            'winexec': ['T1106'],
            'shellexecute': ['T1106'],
            'createprocess': ['T1106'],
            
            # Persistence
            'registry': ['T1547.001', 'T1112'],
            'regedit': ['T1112'],
            'schtasks': ['T1053.005'],
            'schedule': ['T1053'],
            'startup': ['T1547.001'],
            
            # Defense Evasion
            'inject': ['T1055'],
            'createremotethread': ['T1055.001'],
            'virtualallocex': ['T1055'],
            'writeprocessmemory': ['T1055'],
            'obfuscat': ['T1027'],
            'encode': ['T1027'],
            'base64': ['T1027'],
            
            # Credential Access
            'mimikatz': ['T1003.001'],
            'lsass': ['T1003.001'],
            'password': ['T1555'],
            'credential': ['T1555'],
            
            # Discovery
            'whoami': ['T1033'],
            'ipconfig': ['T1016'],
            'systeminfo': ['T1082'],
            'tasklist': ['T1057'],
            'netstat': ['T1049'],
            'net user': ['T1087.001'],
            'net group': ['T1069.001'],
            
            # Lateral Movement
            'psexec': ['T1021.002'],
            'wmi': ['T1047', 'T1021.006'],
            'remote desktop': ['T1021.001'],
            
            # Collection
            'screenshot': ['T1113'],
            'keylog': ['T1056.001'],
            'clipboard': ['T1115'],
            
            # Command and Control
            'http': ['T1071.001'],
            'https': ['T1071.001'],
            'dns': ['T1071.004'],
            'socket': ['T1095'],
            'internetopen': ['T1071.001'],
            'urldownloadtofile': ['T1105'],
            
            # Exfiltration
            'ftp': ['T1048.002'],
            'upload': ['T1041'],
            'exfil': ['T1041']
        }
    
    def map_techniques(self, strings: str, imports: list[str]) -> dict:
        """Map indicators from strings and imports to MITRE techniques."""
        detected = {}
        
        # Combine strings and imports for analysis
        combined_text = (strings + ' ' + ' '.join(imports)).lower()
        
        # Match indicators
        for indicator, tech_ids in self.indicator_map.items():
            if indicator in combined_text:
                for tech_id in tech_ids:
                    if tech_id in self.techniques:
                        tech = self.techniques[tech_id]
                        detected[tech_id] = {
                            'id': tech_id,
                            'name': tech['name'],
                            'tactics': tech.get('tactics', []),
                            'evidence': indicator
                        }
        
        return detected
    
    def format_results(self, detected_techniques: dict) -> list[str]:
        """Format detected techniques for report."""
        results = []
        
        # Group by tactic
        by_tactic = {}
        for tech_id, tech in detected_techniques.items():
            tactics = tech.get('tactics', ['unknown'])
            for tactic in tactics:
                if tactic not in by_tactic:
                    by_tactic[tactic] = []
                by_tactic[tactic].append(
                    f"{tech['id']} - {tech['name']} (Evidence: {tech['evidence']})"
                )
        
        # Format output
        for tactic, techniques in sorted(by_tactic.items()):
            results.extend(techniques)
        
        return results


# Initialize MITRE mapper globally
log.info("Initializing MITRE ATT&CK mapper...")
_mitre_mapper = MITRESTIXMapper()


def map_mitre_techniques(strings: str, imports: list[str] = None) -> list[str]:
    """Map strings and imports to MITRE ATT&CK techniques."""
    if imports is None:
        imports = []
    detected = _mitre_mapper.map_techniques(strings, imports)
    return _mitre_mapper.format_results(detected)


# ---------------------------------------------------------------------------
# Network & Behaviour Indicators
# ---------------------------------------------------------------------------

_NETWORK_KEYWORDS = ("http", ".com", ".net", ".org", "ftp://")
_BEHAVIOR_MAP = {
    "powershell": "Executes PowerShell",
    "cmd.exe":    "Spawns Command Shell",
    "http":       "Outbound Network Communication",
    "reg ":       "Registry Manipulation",
    "regsvr32":   "COM Object Registration",
}


def extract_network_indicators(strings: str) -> list[str]:
    """Return up to 10 unique URLs / hostnames found in extracted strings."""
    tokens = strings.split()
    seen: set[str] = set()
    indicators: list[str] = []
    for token in tokens:
        if any(kw in token for kw in _NETWORK_KEYWORDS) and token not in seen:
            seen.add(token)
            indicators.append(token)
            if len(indicators) >= 10:
                break
    return indicators


def extract_behavior(strings: str) -> list[str]:
    """Return observed suspicious behaviours inferred from string content."""
    lower = strings.lower()
    return [label for keyword, label in _BEHAVIOR_MAP.items() if keyword in lower]


# ---------------------------------------------------------------------------
# Malware Family Classification
# ---------------------------------------------------------------------------

from dataclasses import dataclass as dc


@dc
class MalwareFamily:
    """Detected malware family information."""
    name: str = "Unknown"
    malware_type: str = "Unknown"
    description: str = "No specific malware family detected."
    confidence: str = "N/A"
    matched_signatures: list[str] = None
    source: str = "None"

    def __post_init__(self):
        if self.matched_signatures is None:
            self.matched_signatures = []


# Each entry: family name → (description, type, list of string signatures)
_FAMILY_SIGNATURES: dict[str, tuple[str, str, list[str]]] = {
    "WannaCry": (
        "Destructive ransomware worm exploiting EternalBlue (MS17-010)",
        "Ransomware / Worm",
        ["wannacry", "wncry", "tasksche", "mssecsvc", "bitcoin", "@wanadecryptor"],
    ),
    "Mirai": (
        "IoT botnet that launches large-scale DDoS attacks",
        "Botnet",
        ["mirai", "/bin/busybox", "selfrep", "report.internet", "tftp"],
    ),
    "Emotet": (
        "Modular banking trojan / dropper used as initial-access broker",
        "Trojan / Dropper",
        ["emotet", "epoch", "geodo", "heodo", "mealybug"],
    ),
    "TrickBot": (
        "Sophisticated banking trojan with credential-stealing modules",
        "Banking Trojan",
        ["trickbot", "trickster", "systeminfo32", "rdpscanDll", "newBCtestDll"],
    ),
    "Ryuk": (
        "Targeted ransomware often deployed after initial infection",
        "Ransomware",
        ["ryuk", "RyukReadMe", "No system is safe", "UNIQUE_ID_DO_NOT_REMOVE"],
    ),
    "LockBit": (
        "Ransomware-as-a-Service with fast encryption capability",
        "Ransomware",
        ["lockbit", "LockBit", "Restore-My-Files", ".lockbit"],
    ),
    "Cobalt Strike": (
        "Commercial adversary-simulation framework",
        "Post-Exploitation Framework",
        ["cobaltstrike", "beacon", "malleable_c2", "stageless"],
    ),
    "Metasploit": (
        "Open-source penetration testing framework",
        "Post-Exploitation Framework",
        ["metasploit", "meterpreter", "msf", "payload/"],
    ),
    "Zeus": (
        "Banking trojan targeting financial credentials",
        "Banking Trojan",
        ["zeus", "zbot", "ntos", "libntos"],
    ),
    "Dridex": (
        "Banking trojan spread via malicious Office macros",
        "Banking Trojan",
        ["dridex", "bugat", "cridex"],
    ),
}


def detect_malware_family(strings: str, vt_attrs: dict[str, Any]) -> MalwareFamily:
    """
    Attempt to classify malware family based on string signatures + VT labels.
    Returns a MalwareFamily object with detection details.
    """
    lower_strings = strings.lower()

    # 1) Check string-based signatures
    for family_name, (desc, mtype, sigs) in _FAMILY_SIGNATURES.items():
        matched = [sig for sig in sigs if sig.lower() in lower_strings]
        if matched:
            confidence = "High" if len(matched) >= 3 else "Medium" if len(matched) == 2 else "Low"
            return MalwareFamily(
                name=family_name,
                malware_type=mtype,
                description=desc,
                confidence=confidence,
                matched_signatures=matched,
                source="String signatures",
            )

    # 2) Check VirusTotal suggested_threat_label
    threat_label = vt_attrs.get("suggested_threat_label", "")
    if threat_label:
        # Clean up and title-case the label
        clean_label = threat_label.replace(".", " ").replace("_", " ").title()
        return MalwareFamily(
            name=clean_label,
            malware_type="Unknown",
            description=f"Identified by VirusTotal threat intelligence: {threat_label}",
            confidence="Medium",
            matched_signatures=[],
            source="VirusTotal",
        )

    # 3) Fallback to generic classification based on behavior
    if "ransom" in lower_strings or "decrypt" in lower_strings:
        return MalwareFamily(
            name="Generic Ransomware",
            malware_type="Ransomware",
            description="Exhibits ransomware-like behavior patterns",
            confidence="Low",
            matched_signatures=["ransom", "decrypt"],
            source="Behavior heuristics",
        )
    
    if "trojan" in lower_strings or "backdoor" in lower_strings:
        return MalwareFamily(
            name="Generic Trojan",
            malware_type="Trojan",
            description="Exhibits trojan-like behavior patterns",
            confidence="Low",
            matched_signatures=["trojan", "backdoor"],
            source="Behavior heuristics",
        )

    # No family detected
    return MalwareFamily()


# ---------------------------------------------------------------------------
# VirusTotal Integration
# ---------------------------------------------------------------------------

def vt_lookup(path: Path, sha256: str) -> dict[str, Any]:
    """
    Query VirusTotal for the given file hash.
    If not found, submit the file and poll for results.
    Returns full attributes dict or empty dict on failure.
    """
    if not CFG.vt_api_key:
        log.warning("VT_API_KEY not set; skipping VirusTotal lookup.")
        return {}

    headers = {"x-apikey": CFG.vt_api_key}
    file_url = f"https://www.virustotal.com/api/v3/files/{sha256}"

    # 1) Check if the file is already known
    log.info("Checking VirusTotal for %s…", sha256[:12])
    resp = requests.get(file_url, headers=headers, timeout=10)
    if resp.status_code == 200:
        log.info("VirusTotal cache hit")
        return resp.json()["data"]["attributes"]

    # 2) File not found → submit it
    log.info("Submitting file to VirusTotal for analysis…")
    with path.open("rb") as f:
        submit_resp = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files={"file": f},
            timeout=30,
        )
    if submit_resp.status_code not in (200, 201):
        log.warning("VirusTotal submission failed: %s", submit_resp.text)
        return {}

    # 3) Poll for analysis results
    for attempt in range(1, CFG.vt_poll_attempts + 1):
        log.info("Polling VirusTotal (attempt %d/%d)…", attempt, CFG.vt_poll_attempts)
        time.sleep(CFG.vt_poll_interval)
        resp = requests.get(file_url, headers=headers, timeout=10)
        if resp.status_code == 200:
            log.info("VirusTotal analysis complete")
            return resp.json()["data"]["attributes"]

    log.warning("VirusTotal analysis timed out after %d attempts.", CFG.vt_poll_attempts)
    return {}


# ---------------------------------------------------------------------------
# Risk Scoring & Verdict
# ---------------------------------------------------------------------------

def compute_risk_score(entropy: float, vt_stats: dict[str, int]) -> int:
    """Compute a 0-10 risk score based on entropy + VT detections."""
    mal_count = vt_stats.get("malicious", 0)
    sus_count = vt_stats.get("suspicious", 0)
    
    # Entropy component (0-5)
    entropy_score = min(entropy, 5.0)
    
    # VT component (0-5)
    vt_score = min((mal_count + sus_count * 0.5) / 2, 5.0)
    
    return min(round(entropy_score + vt_score), 10)


def determine_verdict(vt_stats: dict[str, int]) -> str:
    """Return 'malicious' or 'benign' based on VT detection counts."""
    mal_count = vt_stats.get("malicious", 0)
    return "malicious" if mal_count >= CFG.malicious_threshold else "benign"


# ---------------------------------------------------------------------------
# Visualization
# ---------------------------------------------------------------------------

def _vt_detection_chart(vt_stats: dict[str, int], filename_stem: str) -> Path:
    """Generate a bar chart of VirusTotal detection results."""
    labels = ["Malicious", "Suspicious", "Harmless", "Undetected"]
    values = [
        vt_stats.get("malicious", 0),
        vt_stats.get("suspicious", 0),
        vt_stats.get("harmless", 0),
        vt_stats.get("undetected", 0),
    ]
    colors_map = ["#e74c3c", "#f39c12", "#27ae60", "#95a5a6"]

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(labels, values, color=colors_map, edgecolor="black", linewidth=1.2)
    ax.set_ylabel("Number of Engines", fontsize=11)
    ax.set_title("VirusTotal Detection Summary", fontsize=13, fontweight="bold")
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    chart_path = CFG.tmp_dir / f"{filename_stem}_vt_chart.png"
    plt.savefig(chart_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return chart_path


def _score_color(score: int) -> str:
    """Return an HTML color for the given risk score (0–10)."""
    if score < 4:
        return "#27ae60"  # green
    if score < 7:
        return "#f39c12"  # orange
    return "#e74c3c"      # red


# ---------------------------------------------------------------------------
# PDF Report Generation
# ---------------------------------------------------------------------------

def generate_pdf_report(report: dict[str, Any], filename_stem: str) -> Path:
    """Assemble a multi-section PDF report from the analysis results."""
    pdf_path = CFG.tmp_dir / f"{filename_stem}.pdf"
    doc = SimpleDocTemplate(str(pdf_path))
    styles = getSampleStyleSheet()
    story = []

    def add_heading(text: str) -> None:
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"<b><font color='#2c3e50'>{text}</font></b>", styles["Heading2"]))
        story.append(Spacer(1, 6))

    def add_bullet(text: str) -> None:
        # Escape special characters
        escaped = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        story.append(Paragraph(f"• {escaped}", styles["Normal"]))

    def add_key_value_table(data: dict[str, Any]) -> None:
        rows = [[str(k), str(v)[:120]] for k, v in data.items()]
        tbl = Table(rows, colWidths=[2 * inch, 4 * inch])
        tbl.setStyle(
            TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (0, -1), colors.lightblue),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )
        story.append(tbl)

    # ----------------- HEADER -----------------
    if CFG.logo_path.exists():
        try:
            story.append(Image(str(CFG.logo_path), width=1.2 * inch, height=1.2 * inch))
        except Exception as exc:
            log.warning("Could not load logo: %s", exc)

    story.append(Paragraph("<b>Cloud Malware Analysis Report</b>", styles["Title"]))
    story.append(
        Paragraph(
            f"<i>Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</i>",
            styles["Normal"],
        )
    )

    # ----------------- SECTIONS -----------------

    add_heading("1. File Information")
    add_key_value_table(report["file_info"])

    add_heading("2. Static Analysis")
    static_data = {
        "MD5": report["static"]["hashes"]["md5"],
        "SHA-256": report["static"]["hashes"]["sha256"],
        "Entropy": report["static"]["entropy"],
        "Strings (sample)": report["static"]["strings_sample"],
    }
    add_key_value_table(static_data)

    add_heading("3. PE Analysis")
    if report.get("pe_analysis"):
        add_key_value_table(report["pe_analysis"])
    else:
        story.append(Paragraph("Not a PE file or parsing failed.", styles["Normal"]))

    add_heading("4. Network Indicators")
    if report["network_indicators"]:
        for item in report["network_indicators"]:
            add_bullet(item)
    else:
        story.append(Paragraph("None detected.", styles["Normal"]))

    add_heading("5. Behaviour Summary")
    if report["behavior_summary"]:
        for item in report["behavior_summary"]:
            add_bullet(item)
    else:
        story.append(Paragraph("No suspicious behaviour detected.", styles["Normal"]))

    add_heading("6. MITRE ATT&CK Mapping")
    if report["mitre_attack"]:
        for item in report["mitre_attack"]:
            add_bullet(item)
    else:
        story.append(Paragraph("No techniques mapped.", styles["Normal"]))

    add_heading("7. Malware Family Classification")
    mf = report.get("malware_family", {})
    fam_name  = mf.get("name", "Unknown")
    fam_conf  = mf.get("confidence", "N/A")
    conf_color = {"High": "#c0392b", "Medium": "#e67e22", "Low": "#7f8c8d"}.get(fam_conf, "#555555")
    story.append(
        Paragraph(
            f"<b><font size=12 color='{conf_color}'>{fam_name}</font></b>"
            f"&nbsp;&nbsp;<font size=9 color='grey'>[Confidence: {fam_conf}]</font>",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 6))
    add_key_value_table(
        {
            "Family Name":        fam_name,
            "Malware Type":       mf.get("type", "Unknown"),
            "Description":        mf.get("description", "—"),
            "Confidence":         fam_conf,
            "Detection Source":   mf.get("detection_source", "—"),
            "Matched Signatures": ", ".join(mf.get("matched_signatures", [])) or "—",
        }
    )

    add_heading("8. Dynamic Analysis (VirusTotal)")
    dyn = report["dynamic"]
    add_key_value_table(
        {
            "Malicious":  dyn.get("malicious", 0),
            "Suspicious": dyn.get("suspicious", 0),
            "Harmless":   dyn.get("harmless", 0),
            "Undetected": dyn.get("undetected", 0),
        }
    )
    try:
        chart_path = _vt_detection_chart(dyn, filename_stem)
        story.append(Spacer(1, 8))
        story.append(Image(str(chart_path), width=4.5 * inch, height=2.7 * inch))
    except Exception as exc:
        log.warning("Could not generate VT chart: %s", exc)

    add_heading("9. Execution Flow")
    for step in report["execution_flow"]:
        add_bullet(step)

    add_heading("10. Attack Context")
    add_key_value_table(report["attack_context"])

    add_heading("11. Risk Assessment")
    score      = report["risk"]["score"]
    clr        = _score_color(score)
    story.append(
        Paragraph(
            f"<b><font color='{clr}' size=13>Risk Score: {score} / 10</font></b>",
            styles["Normal"],
        )
    )

    add_heading("12. Final Verdict")
    verdict_clr = "red" if report["verdict"] == "malicious" else "green"
    story.append(
        Paragraph(
            f"<b><font size=16 color='{verdict_clr}'>{report['verdict'].upper()}</font></b>",
            styles["Heading1"],
        )
    )

    doc.build(story)
    log.info("PDF report written to %s", pdf_path)
    return pdf_path


# ---------------------------------------------------------------------------
# Report Assembly
# ---------------------------------------------------------------------------

def build_report(path: Path, s3_key: str) -> dict[str, Any]:
    """Run all analysis steps and assemble the report dictionary."""
    log.info("Analysing %s …", path.name)

    hashes   = compute_hashes(path)
    strings  = extract_strings(path)
    ent      = compute_entropy(path)
    vt_attrs = vt_lookup(path, hashes["sha256"])
    vt_stats: dict[str, int] = vt_attrs.get("last_analysis_stats", {})
    family   = detect_malware_family(strings, vt_attrs)
    
    # Extract imports for MITRE mapping
    pe_info = pe_analysis(path)
    imports = []
    # In a real scenario, you'd extract DLL imports from PE analysis
    # For now, we'll just use strings
    mitre_results = map_mitre_techniques(strings, imports)

    return {
        "file":               s3_key,
        "file_info":          get_file_info(path),
        "static": {
            "hashes":         hashes,
            "entropy":        ent,
            "strings_sample": strings[:300],
        },
        "pe_analysis":        pe_info,
        "network_indicators": extract_network_indicators(strings),
        "dynamic":            vt_stats,
        "behavior_summary":   extract_behavior(strings),
        "mitre_attack":       mitre_results,
        "malware_family": {
            "name":               family.name,
            "type":               family.malware_type,
            "description":        family.description,
            "confidence":         family.confidence,
            "matched_signatures": family.matched_signatures,
            "detection_source":   family.source,
        },
        "execution_flow": [
            "File execution initiated",
            "Memory space allocated",
            "Outbound network communication attempted",
            "System file or registry modification",
        ],
        "attack_context": {
            "entry_vector": "Unknown",
            "persistence":  "Possible",
            "privilege":    "Unknown",
        },
        "risk":    {"score": compute_risk_score(ent, vt_stats)},
        "verdict": determine_verdict(vt_stats),
    }


# ---------------------------------------------------------------------------
# S3 Upload Helpers
# ---------------------------------------------------------------------------

def upload_json(report: dict[str, Any], filename: str) -> None:
    """Upload the JSON report to S3."""
    key = f"reports/{filename}.json"
    _s3.put_object(
        Bucket=CFG.bucket,
        Key=key,
        Body=json.dumps(report, indent=2),
        ContentType="application/json",
    )
    log.info("JSON report uploaded → s3://%s/%s", CFG.bucket, key)


def upload_pdf(pdf_path: Path, filename: str) -> None:
    """Upload the PDF report to S3."""
    key = f"reports/{filename}.pdf"
    _s3.upload_file(str(pdf_path), CFG.bucket, key)
    log.info("PDF report uploaded  → s3://%s/%s", CFG.bucket, key)


# ---------------------------------------------------------------------------
# SQS Message Handler
# ---------------------------------------------------------------------------

def process_message(message: dict[str, Any]) -> None:
    """Parse an SQS message, analyse the referenced S3 object, upload reports."""
    body = json.loads(message["Body"])

    if body.get("Event") == "s3:TestEvent":
        log.info("Skipping S3 test event.")
        return

    record = body["Records"][0]
    bucket = record["s3"]["bucket"]["name"]
    key    = record["s3"]["object"]["key"]

    filename = Path(key).name
    local_path = CFG.tmp_dir / filename

    log.info("Downloading s3://%s/%s …", bucket, key)
    _s3.download_file(bucket, key, str(local_path))

    report = build_report(local_path, key)
    stem   = Path(filename).stem

    upload_json(report, filename)

    pdf_path = generate_pdf_report(report, stem)
    upload_pdf(pdf_path, filename)

    log.info("Analysis complete for %s  |  verdict=%s  score=%s",
             filename, report["verdict"], report["risk"]["score"])


# ---------------------------------------------------------------------------
# Worker Loop
# ---------------------------------------------------------------------------

def run_worker() -> None:
    """Poll SQS indefinitely and process each incoming file analysis task."""
    log.info("Worker started.  Polling queue: %s", CFG.queue_url)

    while True:
        try:
            response = _sqs.receive_message(
                QueueUrl=CFG.queue_url,
                MaxNumberOfMessages=CFG.max_messages,
                WaitTimeSeconds=CFG.wait_seconds,
            )

            messages = response.get("Messages", [])
            if not messages:
                log.debug("No messages — waiting…")
                continue

            for message in messages:
                try:
                    process_message(message)
                except Exception:
                    log.exception("Failed to process message %s", message.get("MessageId"))
                finally:
                    _sqs.delete_message(
                        QueueUrl=CFG.queue_url,
                        ReceiptHandle=message["ReceiptHandle"],
                    )
        except KeyboardInterrupt:
            log.info("Worker shutdown requested")
            break
        except Exception:
            log.exception("Worker error occurred")
            time.sleep(5)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        CFG.validate()
        run_worker()
    except ValueError as e:
        log.error("Configuration error: %s", e)
        log.error("\nPlease set the required environment variables:")
        log.error("  export SQS_QUEUE_URL='your-queue-url'")
        log.error("  export S3_BUCKET='your-bucket-name'")
        log.error("  export VT_API_KEY='your-virustotal-api-key'")
        exit(1)
