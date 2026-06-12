#!/usr/bin/env python3
"""
WinIntel v1.0.0 — Windows Exploit Intelligence Tool
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Parses systeminfo.txt → maps missing KBs → CVEs with exploit intel.
118 CVEs: XP → Win11 24H2 (2003-2026) | Watson + WES-NG accuracy
Author: github.com/drgoteee | MIT license
"""
import argparse, sys, os, re, json, csv
import urllib.request, urllib.error
from datetime import datetime
from pathlib import Path

# Windows consoles default to cp1252, which can't encode characters like the
# arrow or en-dash used in output. Force UTF-8 so output is consistent across
# platforms. Safe no-op on Linux/macOS (already UTF-8).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass  # older Python without reconfigure, or already-wrapped stream

try:
    from rich.console import Console
    from rich.panel   import Panel
    from rich.rule    import Rule
    from rich         import box as rbox
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


VERSION        = "1.0.0"
GITHUB_DEF_URL = "https://raw.githubusercontent.com/drgoteee/winintel/main/definitions.json"
CACHE_DIR  = Path.home() / ".winintel"
CACHE_FILE = CACHE_DIR / "definitions.json"

BANNER = r"""
 ██╗    ██╗██╗███╗   ██╗██╗███╗   ██╗████████╗███████╗██╗
 ██║    ██║██║████╗  ██║██║████╗  ██║╚══██╔══╝██╔════╝██║
 ██║ █╗ ██║██║██╔██╗ ██║██║██╔██╗ ██║   ██║   █████╗  ██║
 ██║███╗██║██║██║╚██╗██║██║██║╚██╗██║   ██║   ██╔══╝  ██║
 ╚███╔███╔╝██║██║ ╚████║██║██║ ╚████║   ██║   ███████╗███████╗
  ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝"""

SECWIKI_BASE = "https://github.com/SecWiki/windows-kernel-exploits/tree/master/"
NVD_BASE     = "https://nvd.nist.gov/vuln/detail/"
EDB_BASE     = "https://www.exploit-db.com/exploits/"

WIN10_11_BUILDS = [
    (26100,"Windows 11 24H2 / Server 2025"),(22631,"Windows 11 23H2"),
    (22621,"Windows 11 22H2"),(22000,"Windows 11 21H2"),
    (20348,"Windows Server 2022"),
    (19045,"Windows 10 22H2"),(19044,"Windows 10 21H2"),(19043,"Windows 10 21H1"),
    (19042,"Windows 10 20H2"),(19041,"Windows 10 2004"),(18363,"Windows 10 1909"),
    (18362,"Windows 10 1903"),(17763,"Windows 10 1809 / Server 2019"),
    (17134,"Windows 10 1803"),(16299,"Windows 10 1709"),(15063,"Windows 10 1703"),
    (14393,"Windows 10 1607 / Server 2016"),(10586,"Windows 10 1511"),(10240,"Windows 10 1507"),
]
WIN_MAJOR_LABELS = {
    "5.1":"Windows XP","5.2":"Windows Server 2003",
    "6.0":"Windows Vista / Server 2008","6.1":"Windows 7 / Server 2008 R2",
    "6.2":"Windows 8 / Server 2012","6.3":"Windows 8.1 / Server 2012 R2",
}
RELIABILITY_COLOR = {"Excellent":"bold green","Great":"green","Good":"yellow","Average":"yellow","Low":"red","Unknown":"dim white"}
RELIABILITY_BADGE = {"Excellent":"★★★★★","Great":"★★★★☆","Good":"★★★☆☆","Average":"★★☆☆☆","Low":"★☆☆☆☆","Unknown":"?????"}
SEV_COLOR  = {"CRITICAL":"bold red","HIGH":"bold yellow","MEDIUM":"bold blue","LOW":"dim white"}
TIER_COLOR = {"CONFIRMED":"bold green","LIKELY":"bold yellow","MANUAL":"dim white"}
CATEGORY_LABEL = {
    "kernel_driver":"Kernel Driver","kernel_pool":"Kernel Pool","kernel_race":"Kernel Race",
    "service_lpe":"Service LPE","print_spooler":"Print Spooler","ntlm_relay":"NTLM Relay",
    "kerberos_abuse":"Kerberos","rce_smb":"SMB RCE","rce_rdp":"RDP RCE","rce_iis":"IIS/Web RCE",
    "installer_lpe":"Installer LPE","cred_access":"Cred Access","rce_network":"Network RCE",
}

def detect_os_label(os_major, os_build):
    if os_major == "10.0" and os_build:
        for build_min, label in WIN10_11_BUILDS:
            if os_build >= build_min: return label
        return "Windows 10 (early)"
    return WIN_MAJOR_LABELS.get(os_major, f"Windows ({os_major})")

def is_win11(os_major, os_build):
    return os_major == "10.0" and (os_build or 0) >= 22000



RELIABILITY_COLOR = {
    "Excellent": "bold green",
    "Great":     "green",
    "Good":      "yellow",
    "Average":   "yellow",
    "Low":       "red",
    "Unknown":   "dim white",
}
RELIABILITY_BADGE = {
    "Excellent": "★★★★★",
    "Great":     "★★★★☆",
    "Good":      "★★★☆☆",
    "Average":   "★★☆☆☆",
    "Low":       "★☆☆☆☆",
    "Unknown":   "?????",
}
SEV_COLOR = {
    "CRITICAL":"bold red","HIGH":"bold yellow",
    "MEDIUM":"bold blue","LOW":"dim white",
}
TIER_COLOR = {
    "CONFIRMED":"bold green","LIKELY":"bold yellow","MANUAL":"dim white",
}

WINDOWS_VERSIONS = {
    "5.1":"Windows XP","5.2":"Windows Server 2003",
    "6.0":"Windows Vista / Server 2008","6.1":"Windows 7 / Server 2008 R2",
    "6.2":"Windows 8 / Server 2012","6.3":"Windows 8.1 / Server 2012 R2",
    "10.0":"Windows 10 / Server 2016/2019/2022",
}


# ════════════════════════════════════════════════════════════════
#  CVE DATABASE
#
#  kb          : KB that patches this CVE (None = no KB / unknown)
#  ms          : Microsoft Security Bulletin
#  cvss        : CVSS v2 base score
#  severity    : CRITICAL / HIGH / MEDIUM / LOW
#  type        : LPE / RCE / Info / DoS / AuthBypass
#  desc        : one-line description
#  msf         : exact Metasploit module path or None
#  edb         : ExploitDB ID or None
#  secwiki     : SecWiki folder name (MS## or CVE-####-####)
#  requires    : service/context needed
#                  local          = needs existing shell (LPE)
#                  smb            = SMB 445/139 reachable
#                  rdp            = RDP 3389 reachable
#                  iis            = IIS web server running
#                  kerberos       = AD domain + DC reachable
#                  print          = Print Spooler service running
#                  rpc            = RPC endpoint reachable
#                  webdav         = WebDAV client service (local)
#                  bits           = BITS service running (local)
#                  user_interact  = needs user to open a file
#  arch        : ["x86"] / ["x64"] / ["any"]
#  affected    : Windows OS major version strings
#  confidence  : "kb"     -> use KB presence check (CONFIRMED)
#                "build"  -> use build-range check (LIKELY)
#                "manual" -> cannot verify from systeminfo (MANUAL)
#  vuln_builds : {os_major: (min_build_inclusive, max_build_inclusive)}
#                only used when confidence == "build"
#                None means all builds of that OS version
# ════════════════════════════════════════════════════════════════



CVE_META = {
    # ── XP / 2003 era ─────────────────────────────────────────────────
    "CVE-2003-0352": {
        "itw": True, "reliability": "Excellent",
        "notes": "Blaster worm — unauthenticated, no creds needed, fire-and-forget",
        "poc_urls": [], "tags": ["worm","rce"],
    },
    "CVE-2008-4250": {
        "itw": True, "reliability": "Excellent",
        "notes": "Conficker — extremely reliable against unpatched XP/2003/Vista",
        "poc_urls": ["https://github.com/andyk/ms08-067"],
        "tags": ["worm","rce","no-auth"],
    },
    "CVE-2008-4037": {
        "itw": True, "reliability": "Great",
        "notes": "NTLM relay via SMB reflection. Pair with Responder.",
        "poc_urls": [], "tags": ["relay"],
    },
    # ── 2010 ──────────────────────────────────────────────────────────
    "CVE-2010-0232": {
        "itw": True, "reliability": "Excellent",
        "notes": "KiTrap0D — most reliable Win7/Vista x86 LPE. Works pre- and post-SP1. First try this.",
        "poc_urls": [
            "https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-015",
        ],
        "tags": ["x86-only","ctf-common","first-try"],
    },
    "CVE-2010-3338": {
        "itw": False, "reliability": "Excellent",
        "notes": "Task Scheduler schelevator — stable MSF module, works on Win Vista/7",
        "poc_urls": [], "tags": ["ctf-common"],
    },
    "CVE-2010-2554": {
        "itw": False, "reliability": "Good",
        "notes": "Tracing race condition — requires SeImpersonatePrivilege or service context",
        "poc_urls": ["https://www.exploit-db.com/exploits/15609"], "tags": [],
    },
    # ── 2011 ──────────────────────────────────────────────────────────
    "CVE-2011-1249": {
        "itw": False, "reliability": "Great",
        "notes": "AFD.sys — reliable x86 LPE, EDB PoC compiles cleanly with mingw",
        "poc_urls": ["https://www.exploit-db.com/exploits/40564"], "tags": ["x86-only"],
    },
    # ── 2012 ──────────────────────────────────────────────────────────
    "CVE-2012-0002": {
        "itw": True, "reliability": "Average",
        "notes": "MS12-020 RDP RCE — BSoD-level crash risk. No public reliable exec PoC.",
        "poc_urls": [], "tags": ["crash-risk","rdp"],
    },
    "CVE-2012-0178": {
        "itw": False, "reliability": "Great",
        "notes": "SYSRET — x64 only. Very reliable on Win7/2008R2 SP1 x64 with MSF module.",
        "poc_urls": [], "tags": ["x64-only"],
    },
    # ── 2014 ──────────────────────────────────────────────────────────
    "CVE-2014-1767": {
        "itw": False, "reliability": "Great",
        "notes": "AFD.sys double-free — reliable MSF module for x86 targets",
        "poc_urls": [], "tags": ["x86-only"],
    },
    "CVE-2014-4113": {
        "itw": True, "reliability": "Great",
        "notes": "Win32k UAF — exploited ITW by APT groups. Reliable MSF module.",
        "poc_urls": [], "tags": ["itw","ctf-common"],
    },
    "CVE-2014-6321": {
        "itw": False, "reliability": "Low",
        "notes": "Schannel — no reliable public exploit. DoS-level PoC only.",
        "poc_urls": [], "tags": ["no-public-rce"],
    },
    "CVE-2014-6324": {
        "itw": True, "reliability": "Excellent",
        "notes": "MS14-068 Kerberos PAC bypass — domain admin in one shot if domain joined. Requires low-priv domain account.",
        "poc_urls": [
            "https://github.com/gentilkiwi/kekeo",
            "https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068",
        ],
        "tags": ["domain-only","da-escalation","kerberos"],
    },
    # ── 2015 ──────────────────────────────────────────────────────────
    "CVE-2015-1701": {
        "itw": True, "reliability": "Great",
        "notes": "Win32k UAF — exploited ITW, reliable MSF module for x86",
        "poc_urls": [], "tags": ["itw","x86-only"],
    },
    "CVE-2015-2546": {
        "itw": True, "reliability": "Great",
        "notes": "Win32k — exploited ITW by APT, affects Win8.1+",
        "poc_urls": [], "tags": ["itw"],
    },
    "CVE-2015-0003": {
        "itw": False, "reliability": "Good",
        "notes": "AppCompat cache — rarely has prebuilt binary, may need to compile",
        "poc_urls": [], "tags": [],
    },
    "CVE-2015-0057": {
        "itw": False, "reliability": "Good",
        "notes": "Win32k scrollbar UAF — check SecWiki for prebuilt binary",
        "poc_urls": [], "tags": [],
    },
    # ── 2016 ──────────────────────────────────────────────────────────
    "CVE-2016-0051": {
        "itw": False, "reliability": "Great",
        "notes": "WebDAV client LPE — reliable MSF module, x86 targets only",
        "poc_urls": [], "tags": ["x86-only"],
    },
    "CVE-2016-0099": {
        "itw": False, "reliability": "Excellent",
        "notes": "MS16-032 Secondary Logon — PowerShell PoC public + MSF module. First try on Win7/8/10.",
        "poc_urls": [
            "https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032",
            "https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1",
        ],
        "tags": ["ctf-common","ps-poc","first-try"],
    },
    "CVE-2016-3225": {
        "itw": False, "reliability": "Great",
        "notes": "Hot Potato / RottenPotato NTLM relay — local SYSTEM via NBNS spoof + NTLM relay",
        "poc_urls": [
            "https://github.com/foxglovesec/RottenPotato",
            "https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-075",
        ],
        "tags": ["potato","ctf-common"],
    },
    "CVE-2016-3309": {
        "itw": False, "reliability": "Great",
        "notes": "MS16-098 Win32k LPE — x64 binary on SecWiki works well on 8.1/2012R2",
        "poc_urls": [
            "https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-098",
            "https://www.exploit-db.com/exploits/41020",
        ],
        "tags": ["x64-only","ctf-common","binary-available"],
    },
    "CVE-2016-7255": {
        "itw": True, "reliability": "Good",
        "notes": "Win32k UAF — exploited ITW by APT28 (Fancy Bear), SecWiki binary available",
        "poc_urls": [], "tags": ["itw","apt"],
    },
    "CVE-2016-0167": {
        "itw": False, "reliability": "Good",
        "notes": "Win32k UAF — SecWiki binary available, works on Win Vista–10",
        "poc_urls": [], "tags": [],
    },
    # ── 2017 ──────────────────────────────────────────────────────────
    "CVE-2017-0144": {
        "itw": True, "reliability": "Excellent",
        "notes": "EternalBlue (NSA/WannaCry) — fire-and-forget SYSTEM. Most famous Windows exploit.",
        "poc_urls": [
            "https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS17-010",
            "https://github.com/worawit/MS17-010",
        ],
        "tags": ["nsa","worm","no-auth","smb","legendary"],
    },
    "CVE-2017-0145": {
        "itw": True, "reliability": "Excellent",
        "notes": "EternalRomance/Synergy — works on XP through Server 2016 (pre-SMBv1 fix)",
        "poc_urls": ["https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS17-010"],
        "tags": ["nsa","no-auth","smb"],
    },
    "CVE-2017-0213": {
        "itw": False, "reliability": "Great",
        "notes": "COM marshaler LPE — widely used in CTFs. SecWiki binary works without recompile.",
        "poc_urls": [
            "https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2017-0213",
            "https://www.exploit-db.com/exploits/42020",
        ],
        "tags": ["ctf-common","binary-available"],
    },
    "CVE-2017-8464": {
        "itw": True, "reliability": "Average",
        "notes": "LNK RCE — requires user interaction (browsing a folder). Phishing vector.",
        "poc_urls": [], "tags": ["phishing","user-interaction"],
    },
    # ── 2018 ──────────────────────────────────────────────────────────
    "CVE-2018-8120": {
        "itw": False, "reliability": "Great",
        "notes": "Win32k null-ptr — Win7 SP1 x86/x64. SecWiki binary available.",
        "poc_urls": [
            "https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2018-8120",
        ],
        "tags": ["win7-sp1-only","binary-available"],
    },
    "CVE-2018-8440": {
        "itw": True, "reliability": "Great",
        "notes": "ALPC LPE — all Windows before Sep 2018. Public PoC reliable.",
        "poc_urls": [
            "https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2018-8440",
            "https://www.exploit-db.com/exploits/45053",
        ],
        "tags": ["itw","alpc"],
    },
    "CVE-2018-8453": {
        "itw": True, "reliability": "Good",
        "notes": "Win32k UAF — exploited ITW by FruityArmor APT. Win8.1+ targets.",
        "poc_urls": ["https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2018-8453"],
        "tags": ["itw","apt"],
    },
    "CVE-2018-8639": {
        "itw": False, "reliability": "Good",
        "notes": "Win32k UAF — pre-Dec 2018 Windows. SecWiki binary available.",
        "poc_urls": ["https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2018-8639"],
        "tags": [],
    },
    # ── 2019 ──────────────────────────────────────────────────────────
    "CVE-2019-1458": {
        "itw": True, "reliability": "Great",
        "notes": "Win32k LPE — exploited ITW by WizardOpium APT. SecWiki binary available.",
        "poc_urls": [
            "https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2019-1458",
        ],
        "tags": ["itw","apt"],
    },
    "CVE-2019-0859": {
        "itw": True, "reliability": "Great",
        "notes": "Win32k UAF — ITW by SandCat APT. Reliable on Win7 SP1 through early Win10. SecWiki binary available.",
        "poc_urls": [
            "https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2019-0859",
        ],
        "tags": ["itw","apt","win32k"],
    },
    "CVE-2019-1132": {
        "itw": True, "reliability": "Good",
        "notes": "Win32k null-deref — ITW by Buhtrap APT (Eastern Europe espionage). Win7/2008 R2 only.",
        "poc_urls": [],
        "tags": ["itw","apt","win7"],
    },
    "CVE-2019-0803": {
        "itw": False, "reliability": "Good",
        "notes": "Win32k LPE — SecWiki binary works on most Win7/10 targets",
        "poc_urls": ["https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2019-0803"],
        "tags": [],
    },
    # ── 2020 ──────────────────────────────────────────────────────────
    "CVE-2020-0787": {
        "itw": False, "reliability": "Good",
        "notes": "BITS service EoP — requires BITS running. SecWiki binary available.",
        "poc_urls": ["https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2020-0787"],
        "tags": ["bits-required"],
    },
    "CVE-2020-0796": {
        "itw": True, "reliability": "Great",
        "notes": "SMBGhost — pre-auth SYSTEM on Win10 1903/1909. MSF module reliable.",
        "poc_urls": [
            "https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2020-0796",
        ],
        "tags": ["itw","smb","no-auth","win10-only"],
    },
    "CVE-2020-1472": {
        "itw": True, "reliability": "Excellent",
        "notes": "ZeroLogon — domain takeover with 0 creds. Requires DC access. Extremely impactful.",
        "poc_urls": ["https://github.com/SecuraBV/CVE-2020-1472"],
        "tags": ["itw","domain-only","da-instant","dc-required"],
    },
    # ── 2021 ──────────────────────────────────────────────────────────
    "CVE-2021-1675": {
        "itw": True, "reliability": "Great",
        "notes": "PrintNightmare — RCE via Print Spooler. Requires Spooler running.",
        "poc_urls": [
            "https://github.com/cube0x0/CVE-2021-1675",
            "https://github.com/calebstewart/CVE-2021-1675",
        ],
        "tags": ["itw","print-spooler","ctf-common"],
    },
    "CVE-2021-34527": {
        "itw": True, "reliability": "Great",
        "notes": "PrintNightmare v2 — Spooler RCE. Bypass for initial patch. Same PoC works.",
        "poc_urls": ["https://github.com/cube0x0/CVE-2021-1675"],
        "tags": ["itw","print-spooler"],
    },
    "CVE-2021-36934": {
        "itw": False, "reliability": "Good",
        "notes": "HiveNightmare — read SAM/SYSTEM as low-priv user. Dump hashes → pass-the-hash.",
        "poc_urls": ["https://github.com/GossiTheDog/HiveNightmare"],
        "tags": ["cred-dump","win10-only"],
    },
    "CVE-2021-40449": {
        "itw": True, "reliability": "Good",
        "notes": "Win32k UAF — ITW by MysterySnail/IronHusky APT (Kaspersky). Works Win7 through Win10 21H1. SecWiki binary available.",
        "poc_urls": ["https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2021-40449"],
        "tags": ["itw","apt","win32k","mysterysnail"],
    },
"CVE-2025-21333":{"itw":True,"reliability":"Good","notes":"Hyper-V VSP 0day — exploited before patch, affects Win10/11 even without Hyper-V role installed","poc_urls":[],"tags":["itw","hyper-v","0day"]},
    "CVE-2025-21334":{"itw":True,"reliability":"Good","notes":"Hyper-V VSP 0day — triplet of ITW zero-days in Jan 2025, same component as 21333/21335","poc_urls":[],"tags":["itw","hyper-v","0day"]},
    "CVE-2025-21335":{"itw":True,"reliability":"Good","notes":"Hyper-V VSP 0day — triplet of ITW zero-days in Jan 2025","poc_urls":[],"tags":["itw","hyper-v","0day"]},
    "CVE-2025-21275":{"itw":False,"reliability":"Good","notes":"App Package Installer LPE — publicly known before patch, similar chain to CVE-2021-41379","poc_urls":[],"tags":["installer","disclosed"]},
    "CVE-2025-21418":{"itw":True,"reliability":"Good","notes":"AFD.sys 0day — same driver class as MS11-046/CVE-2024-38193. Exploited ITW Feb 2025.","poc_urls":[],"tags":["itw","afd","0day"]},
    "CVE-2025-21391":{"itw":True,"reliability":"Average","notes":"Windows Storage EoP via file deletion — unusual primitive, ITW Feb 2025. No public PoC.","poc_urls":[],"tags":["itw","storage"]},
    "CVE-2025-24983":{"itw":True,"reliability":"Great","notes":"Win32k UAF — exploited since 2023 via PipeMagic before patched in Mar 2025 (ESET). 2-year ITW window.","poc_urls":["https://github.com/ESET/research"],"tags":["itw","pipemagic","eset","win32k"]},
    "CVE-2025-24984":{"itw":True,"reliability":"Low","notes":"Physical access required (USB). Unusual ITW use — likely targeted/espionage rather than opportunistic.","poc_urls":[],"tags":["itw","physical-access","ntfs"]},
    "CVE-2025-24985":{"itw":True,"reliability":"Good","notes":"Fast FAT RCE via VHD mount — pair with LPE for full chain. Exploited ITW Mar 2025.","poc_urls":[],"tags":["itw","ntfs","vhd-mount"]},
    "CVE-2025-24991":{"itw":True,"reliability":"Low","notes":"NTFS info disclosure — exploited ITW likely as part of chain. Low direct impact alone.","poc_urls":[],"tags":["itw","ntfs","info-disclosure"]},
    "CVE-2025-24993":{"itw":True,"reliability":"Good","notes":"NTFS heap overflow RCE via VHD — pair with LPE for full code exec + SYSTEM chain.","poc_urls":[],"tags":["itw","ntfs","vhd-rce"]},
    "CVE-2025-29824":{"itw":True,"reliability":"Great","notes":"CLFS 0day used by Storm-2460 (PipeMagic → CLFS exploit → LSASS dump → RansomEXX). MSTIC + BI.ZONE analysis.","poc_urls":["https://github.com/AfanPan/CVE-2025-29824-Exploit"],"tags":["itw","clfs","pipemagic","ransomware","storm-2460","ransomEXX"]},
    "CVE-2025-30400":{"itw":True,"reliability":"Good","notes":"DWM 0day — 7th DWM EoP of 2025. Exploited ITW before patch May 2025.","poc_urls":[],"tags":["itw","dwm","0day"]},
    "CVE-2025-32701":{"itw":True,"reliability":"Great","notes":"CLFS UAF 0day — MSTIC discovered ITW exploitation. Part of ongoing CLFS attack dynasty (follows 2023/2024 ITW).","poc_urls":[],"tags":["itw","clfs","mstic","0day"]},
    "CVE-2025-32706":{"itw":True,"reliability":"Great","notes":"CLFS heap overflow 0day — discovered by CrowdStrike Counter Adversary Ops in late Apr 2025, reported to Microsoft.","poc_urls":[],"tags":["itw","clfs","crowdstrike","0day"]},
    "CVE-2025-32709":{"itw":False,"reliability":"Good","notes":"AFD.sys EoP — same driver family as CVE-2025-21418 and MS11-046. Watch for PoC.","poc_urls":[],"tags":["afd","winsock"]},
    "CVE-2025-33073":{"itw":False,"reliability":"Good","notes":"DWM Core Library EoP — exploitation more likely per Microsoft. Jun 2025 patch.","poc_urls":[],"tags":["dwm"]},
    "CVE-2025-38140":{"itw":True,"reliability":"Good","notes":"Windows Kernel 0day — exploited ITW Jul 2025. Limited public details.","poc_urls":[],"tags":["itw","kernel","0day"]},
    "CVE-2025-47981":{"itw":True,"reliability":"Good","notes":"Windows Kernel 0day — exploited ITW Aug 2025. Limited public details.","poc_urls":[],"tags":["itw","kernel","0day"]},
    "CVE-2025-57853":{"itw":False,"reliability":"Good","notes":"Win32k EoP — exploitation more likely. Sep 2025.","poc_urls":[],"tags":["win32k"]},
    "CVE-2025-24990":{"itw":True,"reliability":"Average","notes":"Legacy modem driver 0day (ltmdm64.sys) — shipped with Windows but rarely used. Likely used for EDR evasion. Oct 2025.","poc_urls":[],"tags":["itw","legacy-driver","edr-evasion","0day"]},
    "CVE-2025-59230":{"itw":True,"reliability":"Good","notes":"Windows kernel access control 0day — exploited ITW Oct 2025 alongside CVE-2025-24990.","poc_urls":[],"tags":["itw","0day","kernel"]},
    "CVE-2025-62215":{"itw":True,"reliability":"Good","notes":"Kernel race condition + double-free — CISA KEV. MSTIC internal discovery. All current Windows versions. Nov 2025.","poc_urls":[],"tags":["itw","kernel-race","cisa-kev","0day","mstic"]},
    "CVE-2025-62221":{"itw":True,"reliability":"Good","notes":"Cloud Files Mini Filter Driver 0day — final ITW of 2025. Dec Patch Tuesday. All Windows 10/11.","poc_urls":[],"tags":["itw","cloud-files","0day"]},
    "CVE-2026-26132":{"itw":False,"reliability":"Unknown","notes":"Windows kernel EoP Jan 2026 — limited public details. Apply patches immediately.","poc_urls":[],"tags":["kernel","2026"]},
}

META_DEFAULT = {
    "itw":False,"reliability":"Unknown","notes":"",
    "poc_urls":[],"tags":[]
}

def get_meta(cve_id):
    m = {**META_DEFAULT, **CVE_META.get(cve_id, {})}
    # Infer reliability when not hand-rated, so the scoring engine isn't blind.
    # Heuristic: precompiled binary / MSF presence + ITW status imply field-proven.
    if m.get("reliability","Unknown") == "Unknown":
        db = CVE_DB.get(cve_id, {})
        has_msf  = bool(db.get("msf"))
        has_swk  = bool(db.get("secwiki"))
        has_edb  = bool(db.get("edb"))
        is_itw   = m.get("itw", False)
        if has_msf:
            m["reliability"] = "Great" if is_itw else "Good"
        elif has_swk or has_edb:
            m["reliability"] = "Good"
        elif is_itw:
            m["reliability"] = "Good"   # exploited in wild → known-workable
        else:
            m["reliability"] = "Average"
    return m


CVE_DB = {

    # ── 2003 ──────────────────────────────────────────────────────────
    "CVE-2003-0352": {
        "kb":"KB823980","ms":"MS03-026","cvss":7.5,"severity":"HIGH","type":"RCE","category":"rce_network",
        "desc":"RPC DCOM buffer overrun (Blaster) — remote unauthenticated SYSTEM",
        "msf":"exploit/windows/dcerpc/ms03_026_dcom","edb":None,"secwiki":"MS03-026",
        "requires":["rpc"],"arch":["any"],"affected":["5.1","5.2"],
        "confidence":"kb","vuln_builds":None,
    },
    # ── 2005 ──────────────────────────────────────────────────────────
    "CVE-2005-1983": {
        "kb":"KB899588","ms":"MS05-039","cvss":7.5,"severity":"HIGH","type":"RCE","category":"rce_smb",
        "desc":"PnP Service buffer overflow — unauthenticated remote SYSTEM",
        "msf":"exploit/windows/smb/ms05_039_pnp","edb":None,"secwiki":"MS05-039",
        "requires":["smb"],"arch":["any"],"affected":["5.1","5.2"],
        "confidence":"kb","vuln_builds":None,
    },
    # ── 2006 ──────────────────────────────────────────────────────────
    "CVE-2006-3439": {
        "kb":"KB921883","ms":"MS06-040","cvss":10.0,"severity":"CRITICAL","type":"RCE","category":"rce_smb",
        "desc":"Server service RPC buffer overflow — unauthenticated remote SYSTEM",
        "msf":"exploit/windows/smb/ms06_040_netapi","edb":None,"secwiki":"MS06-040",
        "requires":["smb"],"arch":["any"],"affected":["5.1","5.2"],
        "confidence":"kb","vuln_builds":None,
    },
    # ── 2008 ──────────────────────────────────────────────────────────
    "CVE-2008-4250": {
        "kb":"KB958644","ms":"MS08-067","cvss":10.0,"severity":"CRITICAL","type":"RCE","category":"rce_smb",
        "desc":"Server service netapi stack overflow — unauthenticated remote SYSTEM",
        "msf":"exploit/windows/smb/ms08_067_netapi","edb":None,"secwiki":"MS08-067",
        "requires":["smb"],"arch":["any"],"affected":["5.1","5.2","6.0"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2008-4037": {
        "kb":"KB957097","ms":"MS08-068","cvss":9.3,"severity":"CRITICAL","type":"RCE","category":"ntlm_relay",
        "desc":"SMB NTLM credential reflection — relay to code execution",
        "msf":"exploit/windows/smb/smb_relay","edb":None,"secwiki":"MS08-068",
        "requires":["smb"],"arch":["any"],"affected":["5.1","5.2","6.0"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2008-1084": {
        "kb":"KB941693","ms":"MS08-025","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32.sys kernel driver LPE via crafted IOCTL — local SYSTEM",
        "msf":None,"edb":None,"secwiki":"MS08-025",
        "requires":["local"],"arch":["x86"],"affected":["5.1","5.2","6.0"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2008-3464": {
        "kb":"KB956803","ms":"MS08-066","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"AFD.sys ancillary function driver LPE — local SYSTEM",
        "msf":None,"edb":5704,"secwiki":"MS08-066",
        "requires":["local"],"arch":["x86"],"affected":["5.1","5.2"],
        "confidence":"kb","vuln_builds":None,
    },
    # ── 2009 ──────────────────────────────────────────────────────────
    "CVE-2009-1535": {
        "kb":"KB970483","ms":"MS09-020","cvss":5.0,"severity":"MEDIUM","type":"AuthBypass","category":"rce_iis",
        "desc":"IIS 6.0 WebDAV authentication bypass — unauthorized file access",
        "msf":"exploit/windows/iis/iis_webdav_scstoragepathfromurl","edb":None,"secwiki":"MS09-020",
        "requires":["iis"],"arch":["any"],"affected":["5.2","6.0"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2009-2532": {
        "kb":"KB975517","ms":"MS09-050","cvss":10.0,"severity":"CRITICAL","type":"RCE","category":"rce_smb",
        "desc":"SMBv2 negotiate function index — unauthenticated remote SYSTEM (Vista/2008)",
        "msf":"exploit/windows/smb/ms09_050_smb2_negotiate_func_index","edb":None,"secwiki":"MS09-050",
        "requires":["smb"],"arch":["any"],"affected":["6.0"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2009-0079": {
        "kb":"KB959454","ms":"MS09-012","cvss":7.2,"severity":"HIGH","type":"LPE","category":"service_lpe",
        "desc":"Task Scheduler churraskito — local SYSTEM",
        "msf":None,"edb":None,"secwiki":"MS09-012",
        "requires":["local"],"arch":["any"],"affected":["6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    # ── 2010 ──────────────────────────────────────────────────────────
    "CVE-2010-0232": {
        "kb":"KB977165","ms":"MS10-015","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"KiTrap0D — kernel BIOS call via 16-bit app support, local SYSTEM (x86)",
        "msf":"exploit/windows/local/ms10_015_kitrap0d","edb":11199,"secwiki":"MS10-015",
        "requires":["local"],"arch":["x86"],"affected":["5.1","5.2","6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2010-0233": {
        "kb":"KB978706","ms":"MS10-021","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Kernel double-free in object manager — local SYSTEM",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["local"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2010-2554": {
        "kb":"KB982799","ms":"MS10-059","cvss":6.9,"severity":"MEDIUM","type":"LPE","category":"service_lpe",
        "desc":"Tracing Feature for Services race condition — local SYSTEM",
        "msf":None,"edb":15609,"secwiki":"MS10-059",
        "requires":["local"],"arch":["any"],"affected":["6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2010-2555": {
        "kb":"KB982799","ms":"MS10-059","cvss":6.9,"severity":"MEDIUM","type":"LPE","category":"service_lpe",
        "desc":"Tracing Feature for Services impersonation — local SYSTEM",
        "msf":None,"edb":15609,"secwiki":"MS10-059",
        "requires":["local"],"arch":["any"],"affected":["6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2010-3338": {
        "kb":"KB2305420","ms":"MS10-092","cvss":6.9,"severity":"MEDIUM","type":"LPE","category":"service_lpe",
        "desc":"Task Scheduler .job privilege escalation — local SYSTEM",
        "msf":"exploit/windows/local/ms10_092_schelevator","edb":None,"secwiki":"MS10-092",
        "requires":["local"],"arch":["any"],"affected":["6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2010-3961": {
        "kb":"KB2393802","ms":"MS10-098","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k.sys buffer overflow via crafted app — local SYSTEM",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["local"],"arch":["x86"],"affected":["5.1","5.2","6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2010-4398": {
        "kb":"KB2393802","ms":"MS11-011","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Kernel stack overflow via RtlQueryRegistryValues — local SYSTEM",
        "msf":None,"edb":None,"secwiki":"MS11-011",
        "requires":["local"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    # ── 2011 ──────────────────────────────────────────────────────────
    "CVE-2011-0043": {
        "kb":"KB2524375","ms":"MS11-013","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kerberos_abuse",
        "desc":"Kerberos unkeyed checksum — PAC forging LPE (domain joined only)",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["kerberos"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2011-0045": {
        "kb":"KB2479628","ms":"MS11-012","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Windows kernel driver object handling — local SYSTEM",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["local"],"arch":["x86"],"affected":["5.1","5.2","6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2011-1249": {
        "kb":"KB2503665","ms":"MS11-046","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"AFD.sys socket validation (afd.sys) — local SYSTEM",
        "msf":None,"edb":40564,"secwiki":"MS11-046",
        "requires":["local"],"arch":["x86"],"affected":["5.1","5.2","6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2011-2018": {
        "kb":"KB2567680","ms":"MS11-097","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"CSRSS improper message handling — local SYSTEM",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["local"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2011-3408": {
        "kb":"KB2507938","ms":"MS11-010","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"CSRSS logon process LPE — local SYSTEM",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["local"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2011-3414": {
        "kb":"KB2656351","ms":"MS11-100","cvss":5.0,"severity":"MEDIUM","type":"DoS","category":"rce_iis",
        "desc":"ASP.NET hash table collision DoS via crafted POST — requires IIS+.NET",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["iis"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2011-3416": {
        "kb":"KB2656351","ms":"MS11-100","cvss":6.0,"severity":"MEDIUM","type":"AuthBypass","category":"rce_iis",
        "desc":"ASP.NET Forms Authentication bypass — account hijack via padding attack",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["iis"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2"],
        "confidence":"kb","vuln_builds":None,
    },
    # ── 2012 ──────────────────────────────────────────────────────────
    "CVE-2012-0002": {
        "kb":"KB2621440","ms":"MS12-020","cvss":9.3,"severity":"CRITICAL","type":"RCE","category":"rce_rdp",
        "desc":"RDP pre-auth remote code execution — unauthenticated SYSTEM via port 3389",
        "msf":None,"edb":None,"secwiki":"MS12-020",
        "requires":["rdp"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2012-0178": {
        "kb":"KB2724197","ms":"MS12-042","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"SYSRET kernel handler flaw — local SYSTEM (x64 only)",
        "msf":"exploit/windows/local/ms12_042_sysret","edb":None,"secwiki":"MS12-042",
        "requires":["local"],"arch":["x64"],"affected":["5.2","6.0","6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    # ── 2013 ──────────────────────────────────────────────────────────
    "CVE-2013-0002": {
        "kb":"KB2756918","ms":"MS13-004","cvss":9.3,"severity":"CRITICAL","type":"RCE","category":"rce_iis",
        "desc":".NET WinForms memory corruption — RCE via hosted .NET app or IIS",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["iis"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2013-0003": {
        "kb":"KB2756918","ms":"MS13-004","cvss":9.3,"severity":"CRITICAL","type":"RCE","category":"rce_iis",
        "desc":".NET object serialization buffer overflow — RCE via hosted .NET app",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["iis"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2013-0008": {
        "kb":"KB2778930","ms":"MS13-005","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k window station message handling — local SYSTEM",
        "msf":None,"edb":None,"secwiki":"MS13-005",
        "requires":["local"],"arch":["any"],"affected":["5.2","6.0","6.1","6.2"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2013-0073": {
        "kb":"KB2800088","ms":"MS13-015","cvss":10.0,"severity":"CRITICAL","type":"RCE","category":"rce_iis",
        "desc":".NET CAS check bypass — full privilege escalation / RCE via .NET app",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["iis"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2013-0076": {
        "kb":"KB2790113","ms":"MS13-019","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"CSRSS use-after-free in CreateProcess — local SYSTEM (Win7 only)",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["local"],"arch":["any"],"affected":["6.1"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2013-1283": {
        "kb":"KB2813170","ms":"MS13-031","cvss":6.9,"severity":"MEDIUM","type":"LPE","category":"kernel_race",
        "desc":"Kernel race condition in object manager — local LPE",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["local"],"arch":["any"],"affected":["6.0","6.1","6.2"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2013-1285": {
        "kb":"KB2807986","ms":"MS13-027","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"USB descriptor integer overflow in usbhub.sys — local SYSTEM via USB device",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["local"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2013-1291": {
        "kb":"KB2813170","ms":"MS13-031","cvss":7.1,"severity":"HIGH","type":"LPE","category":"kernel_race",
        "desc":"Kernel race condition in thread object — local LPE",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["local"],"arch":["any"],"affected":["6.0","6.1","6.2"],
        "confidence":"kb","vuln_builds":None,
    },
    # ── 2014 ──────────────────────────────────────────────────────────
    "CVE-2014-1767": {
        "kb":"KB2957189","ms":"MS14-040","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"AFD.sys double-free — local SYSTEM",
        "msf":"exploit/windows/local/ms14_040_afd_bypass","edb":None,"secwiki":"MS14-040",
        "requires":["local"],"arch":["x86"],"affected":["5.1","5.2","6.0","6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2014-4113": {
        "kb":"KB3000061","ms":"MS14-058","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k.sys use-after-free (track popup menu) — local SYSTEM, exploited ITW",
        "msf":"exploit/windows/local/ms14_058_track_popup_menu","edb":None,"secwiki":"MS14-058",
        "requires":["local"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2014-6321": {
        "kb":"KB2992611","ms":"MS14-066","cvss":10.0,"severity":"CRITICAL","type":"RCE","category":"rce_network",
        "desc":"Schannel pre-auth RCE via malformed TLS packets — remote SYSTEM",
        "msf":None,"edb":None,"secwiki":"MS14-066",
        "requires":["rdp","smb"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2014-6324": {
        "kb":"KB3011780","ms":"MS14-068","cvss":9.0,"severity":"CRITICAL","type":"LPE","category":"kerberos_abuse",
        "desc":"Kerberos PAC validation bypass — domain privilege escalation to DA",
        "msf":"exploit/windows/kerberos/ms14_068_kerberos_checksum","edb":None,"secwiki":"MS14-068",
        "requires":["kerberos"],"arch":["any"],"affected":["5.2","6.0","6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2014-4076": {
        "kb":"KB2989935","ms":"MS14-070","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"TCP/IP kernel driver LPE — local SYSTEM (Server 2003 only)",
        "msf":"exploit/windows/local/ms14_070_tcpip_ioctl","edb":None,"secwiki":"MS14-070",
        "requires":["local"],"arch":["x86"],"affected":["5.2"],
        "confidence":"kb","vuln_builds":None,
    },
    # ── 2015 ──────────────────────────────────────────────────────────
    "CVE-2015-0003": {
        "kb":"KB3023266","ms":"MS15-001","cvss":7.2,"severity":"HIGH","type":"LPE","category":"service_lpe",
        "desc":"Application compatibility cache LPE — local SYSTEM",
        "msf":None,"edb":None,"secwiki":"MS15-001",
        "requires":["local"],"arch":["any"],"affected":["6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2015-0057": {
        "kb":"KB3036220","ms":"MS15-010","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k.sys scrollbar use-after-free — local SYSTEM",
        "msf":None,"edb":None,"secwiki":"MS15-010",
        "requires":["local"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2015-0062": {
        "kb":"KB3031432","ms":"MS15-015","cvss":7.2,"severity":"HIGH","type":"LPE","category":"service_lpe",
        "desc":"CreateProcess impersonation token LPE — local SYSTEM",
        "msf":None,"edb":None,"secwiki":"MS15-015",
        "requires":["local"],"arch":["any"],"affected":["6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2015-1701": {
        "kb":"KB3057191","ms":"MS15-051","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k.sys use-after-free (client copy image) — local SYSTEM, exploited ITW",
        "msf":"exploit/windows/local/ms15_051_client_copy_image","edb":None,"secwiki":"MS15-051",
        "requires":["local"],"arch":["x86"],"affected":["5.1","5.2","6.0","6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2015-2387": {
        "kb":"KB3057839","ms":"MS15-061","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k.sys font parsing — local SYSTEM",
        "msf":None,"edb":None,"secwiki":"MS15-061",
        "requires":["local"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2015-2426": {
        "kb":"KB3077657","ms":"MS15-077","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Adobe Type Manager (ATM) font driver LPE — local SYSTEM",
        "msf":None,"edb":None,"secwiki":"MS15-077",
        "requires":["local"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2015-2370": {
        "kb":"KB3067505","ms":"MS15-076","cvss":7.2,"severity":"HIGH","type":"LPE","category":"service_lpe",
        "desc":"RPC elevation of privilege via impersonation — local SYSTEM",
        "msf":None,"edb":None,"secwiki":"MS15-076",
        "requires":["local"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2015-2546": {
        "kb":"KB3089656","ms":"MS15-097","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k.sys memory corruption — local SYSTEM, exploited ITW",
        "msf":None,"edb":None,"secwiki":"MS15-097",
        "requires":["local"],"arch":["any"],"affected":["6.2","6.3","10.0"],
        "confidence":"kb","vuln_builds":None,"build_cap":{"10.0": 10240},
    },
    # ── 2016 ──────────────────────────────────────────────────────────
    "CVE-2016-0051": {
        "kb":"KB3136041","ms":"MS16-016","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"WebDAV client driver LPE (abuses local WebDAV client) — local SYSTEM",
        "msf":"exploit/windows/local/ms16_016_webdav","edb":None,"secwiki":"MS16-016",
        "requires":["local"],"arch":["x86"],"affected":["6.0","6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2016-0099": {
        "kb":"KB3143141","ms":"MS16-032","cvss":7.2,"severity":"HIGH","type":"LPE","category":"service_lpe",
        "desc":"Secondary Logon service handle LPE — local SYSTEM (PowerShell PoC public)",
        "msf":"exploit/windows/local/ms16_032_secondary_logon_handle_privesc","edb":None,"secwiki":"MS16-032",
        "requires":["local"],"arch":["any"],"affected":["6.0","6.1","6.2","6.3","10.0"],
        "confidence":"kb","vuln_builds":None,"build_cap":{"10.0": 10586},
    },
    "CVE-2016-0167": {
        "kb":"KB3143145","ms":"MS16-034","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k.sys use-after-free — local SYSTEM",
        "msf":None,"edb":None,"secwiki":"MS16-034",
        "requires":["local"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2","6.3","10.0"],
        "confidence":"kb","vuln_builds":None,"build_cap":{"10.0": 14393},
    },
    "CVE-2016-3225": {
        "kb":"KB3164038","ms":"MS16-075","cvss":7.2,"severity":"HIGH","type":"LPE","category":"ntlm_relay",
        "desc":"Hot Potato / RottenPotato NTLM relay — local SYSTEM",
        "msf":"exploit/windows/local/ms16_075_reflection_juicy","edb":None,"secwiki":"MS16-075",
        "requires":["local"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2016-3309": {
        "kb":"KB3178466","ms":"MS16-098","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k.sys kernel driver LPE — local SYSTEM (Win 8.1 x64)",
        "msf":None,"edb":41020,"secwiki":"MS16-098",
        "requires":["local"],"arch":["x64"],"affected":["6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2016-7255": {
        "kb":"KB3199135","ms":"MS16-135","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k.sys use-after-free — local SYSTEM (exploited ITW by APT28)",
        "msf":None,"edb":None,"secwiki":"MS16-135",
        "requires":["local"],"arch":["any"],"affected":["6.0","6.1","6.2","6.3","10.0"],
        "confidence":"kb","vuln_builds":None,"build_cap":{"10.0": 14393},
    },
    "CVE-2016-3371": {
        "kb":"KB3186973","ms":"MS16-111","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Windows kernel API LPE — local SYSTEM (Win 10 10586)",
        "msf":None,"edb":None,"secwiki":"MS16-111",
        "requires":["local"],"arch":["any"],"affected":["10.0"],
        "confidence":"kb","vuln_builds":None,"build_cap":{"10.0": 14393},
    },
    # ── 2017 ──────────────────────────────────────────────────────────
    "CVE-2017-0144": {
        "kb":"KB4013389","ms":"MS17-010","cvss":9.3,"severity":"CRITICAL","type":"RCE","category":"rce_smb",
        "desc":"EternalBlue SMBv1 — unauthenticated remote SYSTEM via port 445",
        "msf":"exploit/windows/smb/ms17_010_eternalblue","edb":42315,"secwiki":"MS17-010",
        "requires":["smb"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2","6.3","10.0"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2017-0145": {
        "kb":"KB4013389","ms":"MS17-010","cvss":9.3,"severity":"CRITICAL","type":"RCE","category":"rce_smb",
        "desc":"EternalRomance/Synergy SMBv1 — unauthenticated remote SYSTEM via port 445",
        "msf":"exploit/windows/smb/ms17_010_psexec","edb":None,"secwiki":"MS17-010",
        "requires":["smb"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2","6.3"],
        "confidence":"kb","vuln_builds":None,
    },
    "CVE-2017-0101": {
        "kb":"KB4013081","ms":"MS17-017","cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"GDI palette objects kernel race condition — local SYSTEM (Win7/8)",
        "msf":None,"edb":None,"secwiki":"MS17-017",
        "requires":["local"],"arch":["any"],"affected":["6.1","6.2"],
        "confidence":"kb","vuln_builds":None,
    },
    # ── No KB - build-range confirmed ─────────────────────────────────
    "CVE-2017-0213": {
        "kb":None,"ms":None,"cvss":7.2,"severity":"HIGH","type":"LPE","category":"service_lpe",
        "desc":"Windows COM aggregate marshaler LPE — local SYSTEM",
        "msf":None,"edb":42020,"secwiki":"CVE-2017-0213",
        "requires":["local"],"arch":["any"],"affected":["6.0","6.1","6.2","6.3","10.0"],
        "confidence":"build",
        "vuln_builds":{"6.0":(6000,9999),"6.1":(7600,17134),"6.2":(9200,9999),
                       "6.3":(9600,9999),"10.0":(10240,16299)},
    },
    "CVE-2017-8464": {
        "kb":None,"ms":None,"cvss":9.3,"severity":"CRITICAL","type":"RCE","category":"rce_network",
        "desc":"LNK shortcut RCE — requires user to open folder with crafted .lnk file",
        "msf":"exploit/windows/fileformat/ms10_046_shortcut_icon_dllloader","edb":None,"secwiki":"CVE-2017-8464",
        "requires":["user_interact"],"arch":["any"],"affected":["5.1","5.2","6.0","6.1","6.2","6.3","10.0"],
        "confidence":"build",
        "vuln_builds":{"5.1":(2600,9999),"5.2":(3790,9999),"6.0":(6000,9999),
                       "6.1":(7600,17134),"6.2":(9200,9999),"6.3":(9600,9999),
                       "10.0":(10240,16299)},
    },
    "CVE-2018-8120": {
        "kb":None,"ms":None,"cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k NtUserSetImeInfoEx null pointer dereference — local SYSTEM (Win7 SP1 x86/x64)",
        "msf":None,"edb":None,"secwiki":"CVE-2018-8120",
        "requires":["local"],"arch":["any"],"affected":["6.1"],
        "confidence":"build",
        "vuln_builds":{"6.1":(7601,7601)},   # Win7 SP1 only (build 7601)
    },
    "CVE-2018-8440": {
        "kb":None,"ms":None,"cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Windows ALPC LPE — local SYSTEM (all Windows before Sep 2018 patch)",
        "msf":None,"edb":45053,"secwiki":"CVE-2018-8440",
        "requires":["local"],"arch":["any"],"affected":["6.0","6.1","6.2","6.3","10.0"],
        "confidence":"build",
        "vuln_builds":{"6.1":(7600,17134),"6.2":(9200,9999),"6.3":(9600,9999),
                       "10.0":(10240,17134)},
    },
    "CVE-2018-8453": {
        "kb":None,"ms":None,"cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k use-after-free EoP — local SYSTEM (Win8.1+, exploited ITW)",
        "msf":None,"edb":None,"secwiki":"CVE-2018-8453",
        "requires":["local"],"arch":["any"],"affected":["6.3","10.0"],
        "confidence":"build",
        "vuln_builds":{"6.3":(9600,9999),"10.0":(10240,17763)},
    },
    "CVE-2018-8639": {
        "kb":None,"ms":None,"cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k use-after-free — local SYSTEM (Win7/8/10, before Dec 2018 patch)",
        "msf":None,"edb":None,"secwiki":"CVE-2018-8639",
        "requires":["local"],"arch":["any"],"affected":["6.1","6.2","6.3","10.0"],
        "confidence":"build",
        "vuln_builds":{"6.1":(7600,17763),"6.2":(9200,9999),"6.3":(9600,9999),
                       "10.0":(10240,17763)},
    },
    "CVE-2019-0803": {
        "kb":None,"ms":None,"cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k object handling LPE — local SYSTEM",
        "msf":None,"edb":None,"secwiki":"CVE-2019-0803",
        "requires":["local"],"arch":["any"],"affected":["6.1","6.2","6.3","10.0"],
        "confidence":"build",
        "vuln_builds":{"6.1":(7600,17763),"10.0":(10240,17763)},
    },
    "CVE-2019-0836": {
        "kb":None,"ms":None,"cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Windows kernel call gate LPE — local SYSTEM (Win10 only)",
        "msf":None,"edb":46718,"secwiki":None,
        "requires":["local"],"arch":["x64"],"affected":["10.0"],
        "confidence":"build",
        "vuln_builds":{"10.0":(10240,17763)},
    },
    "CVE-2019-1458": {
        "kb":None,"ms":None,"cvss":7.2,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k EoP — local SYSTEM (Win7/8/10, exploited ITW before Jan 2020)",
        "msf":None,"edb":None,"secwiki":"CVE-2019-1458",
        "requires":["local"],"arch":["any"],"affected":["6.1","6.2","6.3","10.0"],
        "confidence":"build",
        "vuln_builds":{"6.1":(7600,18363),"6.2":(9200,9999),"6.3":(9600,9999),
                       "10.0":(10240,18362)},
    },
    "CVE-2019-0859": {
        "kb":None,"ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k use-after-free EoP — local SYSTEM, exploited ITW by SandCat/APT (Apr 2019)",
        "msf":None,"edb":None,"secwiki":"CVE-2019-0859",
        "requires":["local"],"arch":["any"],"affected":["6.1","6.2","6.3","10.0"],
        "confidence":"build",
        "vuln_builds":{"6.1":(7600,18362),"6.2":(9200,9999),"6.3":(9600,9999),
                       "10.0":(10240,17763)},
    },
    "CVE-2019-1132": {
        "kb":None,"ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k null-deref EoP — local SYSTEM, exploited ITW by Buhtrap APT (Jul 2019)",
        "msf":None,"edb":None,"secwiki":None,
        "requires":["local"],"arch":["any"],"affected":["6.1","6.2","6.3"],
        "confidence":"build",
        "vuln_builds":{"6.1":(7600,7601),"6.2":(9200,9999),"6.3":(9600,9999)},
    },
    "CVE-2020-0787": {
        "kb":None,"ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"service_lpe",
        "desc":"BITS service EoP — local SYSTEM (requires BITS service running)",
        "msf":None,"edb":None,"secwiki":"CVE-2020-0787",
        "requires":["local","bits"],"arch":["any"],"affected":["6.1","6.2","6.3","10.0"],
        "confidence":"build",
        "vuln_builds":{"6.1":(7600,18362),"10.0":(10240,18362)},
    },
    "CVE-2020-0796": {
        "kb":None,"ms":None,"cvss":10.0,"severity":"CRITICAL","type":"RCE","category":"rce_smb",
        "desc":"SMBGhost SMBv3 — unauthenticated remote SYSTEM via port 445 (Win10 1903/1909)",
        "msf":"exploit/windows/smb/smbghost_auth_bypass","edb":None,"secwiki":"CVE-2020-0796",
        "requires":["smb"],"arch":["x64"],"affected":["10.0"],
        "confidence":"build",
        "vuln_builds":{"10.0":(18362,18363)},
    },
    "CVE-2020-1472": {
        "kb":None,"ms":None,"cvss":10.0,"severity":"CRITICAL","type":"LPE","category":"kerberos_abuse",
        "desc":"ZeroLogon Netlogon — domain takeover without credentials (DC only)",
        "msf":"exploit/windows/dcerpc/cve_2020_1472_zerologon","edb":None,"secwiki":None,
        "requires":["kerberos","rpc"],"arch":["any"],"affected":["6.1","6.2","6.3","10.0"],
        "confidence":"build",
        "vuln_builds":{"6.1":(7600,18362),"6.2":(9200,9999),"6.3":(9600,9999),
                       "10.0":(10240,19041)},
    },
    "CVE-2021-1675": {
        "kb":None,"ms":None,"cvss":8.8,"severity":"HIGH","type":"RCE","category":"print_spooler",
        "desc":"PrintNightmare — SYSTEM via Print Spooler (RCE remote / LPE local)",
        "msf":"exploit/windows/dcerpc/cve_2021_1675_printnightmare","edb":None,"secwiki":None,
        "requires":["print","rpc"],"arch":["any"],"affected":["6.1","6.2","6.3","10.0"],
        "confidence":"build",
        "vuln_builds":{"6.1":(7600,19042),"10.0":(10240,19041)},
    },
    "CVE-2021-1732": {
        "kb":None,"ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k EoP — local SYSTEM (Win10 20H2, exploited ITW)",
        "msf":None,"edb":None,"secwiki":"CVE-2021-1732",
        "requires":["local"],"arch":["any"],"affected":["10.0"],
        "confidence":"build",
        "vuln_builds":{"10.0":(19041,19042)},
    },
    "CVE-2021-33739": {
        "kb":None,"ms":None,"cvss":8.4,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Microsoft DWM Core Library EoP — local SYSTEM (Win10/Server 20H2)",
        "msf":None,"edb":None,"secwiki":"CVE-2021-33739",
        "requires":["local"],"arch":["any"],"affected":["10.0"],
        "confidence":"build",
        "vuln_builds":{"10.0":(19041,19042)},
    },
    "CVE-2021-40449": {
        "kb":None,"ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver",
        "desc":"Win32k use-after-free EoP (CallNextHookEx) — local SYSTEM, exploited ITW by MysterySnail/IronHusky APT (Oct 2021)",
        "msf":None,"edb":None,"secwiki":"CVE-2021-40449",
        "requires":["local"],"arch":["any"],"affected":["6.1","6.2","6.3","10.0"],
        "confidence":"build",
        "vuln_builds":{"6.1":(7600,7601),"6.2":(9200,9999),"6.3":(9600,9999),
                       "10.0":(10240,19043)},
    },
    "CVE-2021-34527": {
        "kb":None,"ms":None,"cvss":8.8,"severity":"HIGH","type":"RCE","category":"print_spooler",
        "desc":"PrintNightmare v2 — SYSTEM via Print Spooler (RCE remote / LPE local)",
        "msf":"exploit/windows/dcerpc/cve_2021_1675_printnightmare","edb":None,"secwiki":None,
        "requires":["print","rpc"],"arch":["any"],"affected":["6.1","6.2","6.3","10.0"],
        "confidence":"build",
        "vuln_builds":{"6.1":(7600,19042),"10.0":(10240,19041)},
    },
    "CVE-2021-36934": {
        "kb":None,"ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"cred_access",
        "desc":"HiveNightmare/SeriousSam — SAM file read as low-priv user, credential dump",
        "msf":None,"edb":50070,"secwiki":None,
        "requires":["local"],"arch":["any"],"affected":["10.0"],
        "confidence":"build",
        "vuln_builds":{"10.0":(19041,19041)},
    },
    "CVE-2022-21999":{"kb":"KB5010386","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"print_spooler","desc":"Windows Print Spooler LPE — local SYSTEM (requires Spooler running)","msf":None,"edb":None,"secwiki":None,"requires":["local","print"],"arch":["any"],"affected":["6.1","6.2","6.3","10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2022-24521":{"kb":"KB5012647","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"CLFS driver LPE — local SYSTEM, exploited ITW by ransomware operators (Win10+Win11)","msf":None,"edb":None,"secwiki":"CVE-2022-24521","requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2022-37969":{"kb":"KB5017316","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"CLFS driver LPE — local SYSTEM, exploited ITW by Nokoyawa and other ransomware groups","msf":None,"edb":None,"secwiki":"CVE-2022-37969","requires":["local"],"arch":["any"],"affected":["6.3","10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2022-38028":{"kb":"KB5018410","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"print_spooler","desc":"Print Spooler LPE — local SYSTEM, exploited ITW by Forest Blizzard (APT28/GRU)","msf":None,"edb":None,"secwiki":None,"requires":["local","print"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2022-41073":{"kb":"KB5019959","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"print_spooler","desc":"Windows Print Spooler LPE — local SYSTEM, exploited ITW (Oct 2022)","msf":None,"edb":None,"secwiki":None,"requires":["local","print"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2023 ─────────────────────────────────────────────────────────
    "CVE-2023-21674":{"kb":"KB5022282","ms":None,"cvss":8.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Windows ALPC LPE — local SYSTEM, exploited ITW by Nokoyawa ransomware (Jan 2023)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2023-23397":{"kb":"KB5023322","ms":None,"cvss":9.8,"severity":"CRITICAL","type":"RCE","category":"ntlm_relay","desc":"Outlook NTLM relay — Net-NTLMv2 leak via calendar invite, zero clicks, exploited ITW by APT28","msf":None,"edb":None,"secwiki":None,"requires":["user_interact"],"arch":["any"],"affected":["6.1","6.2","6.3","10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2023-28252":{"kb":"KB5025221","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"CLFS driver LPE — local SYSTEM, exploited ITW by Nokoyawa ransomware (Apr 2023, ZDI)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2023-36802":{"kb":"KB5030219","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"MSKSSRV.sys Microsoft Streaming Service proxy LPE — local SYSTEM, exploited ITW (Sep 2023)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2023-36874":{"kb":"KB5028185","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"service_lpe","desc":"Windows Error Reporting service LPE — local SYSTEM, exploited ITW by Storm-0978 (Jul 2023)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2024 ─────────────────────────────────────────────────────────
    "CVE-2024-21338":{"kb":"KB5034765","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"appid.sys kernel driver LPE — local SYSTEM, exploited ITW by Lazarus/DPRK (Feb 2024)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2024-26169":{"kb":"KB5036893","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"service_lpe","desc":"Windows Error Reporting LPE — local SYSTEM, exploited ITW by Black Basta ransomware (Mar 2024)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2024-26229":{"kb":"KB5037771","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Windows kernel LPE via csc.sys — local SYSTEM (public PoC available)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2024-30088":{"kb":"KB5039212","ms":None,"cvss":7.0,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Windows kernel LPE — local SYSTEM, exploited ITW by Storm-0978/RomCom (Jun 2024)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2024-38106":{"kb":"KB5041587","ms":None,"cvss":7.0,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Windows kernel LPE — local SYSTEM, exploited ITW by multiple threat actors (Aug 2024)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2024-38193":{"kb":"KB5041580","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"AFD.sys LPE — local SYSTEM, exploited ITW by Lazarus/DPRK (ESET+Microsoft Aug 2024), Win10+Win11","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},

    # ── 2025 Jan ─────────────────────────────────────────────────────
    "CVE-2025-21333":{"kb":"KB5049981","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Hyper-V NT Kernel VSP heap buffer overflow — local SYSTEM (Win10/11/Server 2022/2025), exploited ITW Jan 2025","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2025-21334":{"kb":"KB5049981","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Hyper-V NT Kernel VSP use-after-free — local SYSTEM (Win10/11/Server), exploited ITW Jan 2025","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2025-21335":{"kb":"KB5049981","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Hyper-V NT Kernel VSP use-after-free — local SYSTEM (Win10/11/Server), exploited ITW Jan 2025","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2025-21275":{"kb":"KB5049981","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"installer_lpe","desc":"Windows App Package Installer EoP — local SYSTEM (publicly disclosed before patch, Jan 2025)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2025 Feb ─────────────────────────────────────────────────────
    "CVE-2025-21418":{"kb":"KB5051987","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"AFD.sys (Ancillary Function Driver for WinSock) EoP — local SYSTEM, exploited ITW as 0day Feb 2025","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2025-21391":{"kb":"KB5051987","ms":None,"cvss":7.1,"severity":"HIGH","type":"LPE","category":"service_lpe","desc":"Windows Storage EoP — local deletion of files leading to privilege escalation, exploited ITW Feb 2025","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2025 Mar ─────────────────────────────────────────────────────
    "CVE-2025-24983":{"kb":"KB5053606","ms":None,"cvss":7.0,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Win32k use-after-free — local SYSTEM, exploited ITW since Mar 2023 via PipeMagic backdoor (ESET, patched Mar 2025)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2025-24984":{"kb":"KB5053606","ms":None,"cvss":4.6,"severity":"MEDIUM","type":"Info","category":"cred_access","desc":"Windows NTFS info disclosure via USB device — partial heap memory leak, exploited ITW (requires physical access)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2025-24985":{"kb":"KB5053606","ms":None,"cvss":7.8,"severity":"HIGH","type":"RCE","category":"rce_network","desc":"Windows Fast FAT File System Driver integer overflow — RCE via mounting crafted VHD, exploited ITW Mar 2025","msf":None,"edb":None,"secwiki":None,"requires":["user_interact"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2025-24991":{"kb":"KB5053606","ms":None,"cvss":5.5,"severity":"MEDIUM","type":"Info","category":"cred_access","desc":"Windows NTFS info disclosure — heap memory leak via crafted VHD mount, exploited ITW Mar 2025","msf":None,"edb":None,"secwiki":None,"requires":["user_interact"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2025-24993":{"kb":"KB5053606","ms":None,"cvss":7.8,"severity":"HIGH","type":"RCE","category":"rce_network","desc":"Windows NTFS heap buffer overflow — RCE via mounting crafted VHD, exploited ITW Mar 2025","msf":None,"edb":None,"secwiki":None,"requires":["user_interact"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2025 Apr ─────────────────────────────────────────────────────
    "CVE-2025-29824":{"kb":"KB5055523","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"CLFS driver use-after-free — local SYSTEM, exploited ITW by Storm-2460 via PipeMagic to deploy RansomEXX (Apr 2025)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2025 May ─────────────────────────────────────────────────────
    "CVE-2025-30400":{"kb":"KB5058411","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Desktop Window Manager (DWM) Core Library EoP — local SYSTEM, exploited ITW as 0day (May 2025)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2025-32701":{"kb":"KB5058411","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"CLFS driver use-after-free EoP — local SYSTEM, exploited ITW (MSTIC discovery, May 2025)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2025-32706":{"kb":"KB5058411","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"CLFS driver heap buffer overflow EoP — local SYSTEM, exploited ITW (discovered by CrowdStrike, May 2025)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2025-32709":{"kb":"KB5058411","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Windows Ancillary Function Driver for WinSock EoP — local SYSTEM (May 2025 patch Tuesday)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2025 Jun ─────────────────────────────────────────────────────
    "CVE-2025-33073":{"kb":"KB5061768","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"service_lpe","desc":"Windows DWM Core Library EoP — local SYSTEM (Jun 2025 patch, exploitation more likely)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2025 Jul ─────────────────────────────────────────────────────
    "CVE-2025-38140":{"kb":"KB5064627","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Windows Kernel EoP — local SYSTEM, exploited ITW as 0day (Jul 2025 Patch Tuesday)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2025 Aug ─────────────────────────────────────────────────────
    "CVE-2025-47981":{"kb":"KB5067691","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Windows Kernel EoP — local SYSTEM, exploited ITW (Aug 2025 Patch Tuesday)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2025 Sep ─────────────────────────────────────────────────────
    "CVE-2025-57853":{"kb":"KB5068121","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Windows Win32k EoP — local SYSTEM (Sep 2025 patch, exploitation more likely)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2025 Oct ─────────────────────────────────────────────────────
    "CVE-2025-24990":{"kb":"KB5068823","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Agere Modem ltmdm64.sys driver EoP — admin privileges, exploited ITW (EDR evasion vector, Oct 2025)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["x64"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    "CVE-2025-59230":{"kb":"KB5068823","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"service_lpe","desc":"Windows improper access control EoP — local SYSTEM, exploited ITW as 0day (Oct 2025)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2025 Nov ─────────────────────────────────────────────────────
    "CVE-2025-62215":{"kb":"KB5068861","ms":None,"cvss":7.0,"severity":"HIGH","type":"LPE","category":"kernel_race","desc":"Windows Kernel race condition + double-free EoP — local SYSTEM, exploited ITW (CISA KEV, MSTIC discovery, Nov 2025)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2025 Dec ─────────────────────────────────────────────────────
    "CVE-2025-62221":{"kb":"KB5073520","ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Windows Cloud Files Mini Filter Driver EoP — local SYSTEM, exploited ITW (final 0day of 2025, Dec)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"kb","vuln_builds":None},
    # ── 2026 ─────────────────────────────────────────────────────────
    "CVE-2026-26132":{"kb":None,"ms":None,"cvss":7.8,"severity":"HIGH","type":"LPE","category":"kernel_driver","desc":"Windows kernel EoP — local SYSTEM (Jan 2026 disclosure, limited public detail, all modern Windows)","msf":None,"edb":None,"secwiki":None,"requires":["local"],"arch":["any"],"affected":["10.0"],"confidence":"build","vuln_builds":{"10.0":(19041,99999)}},
}


# ══════════════════════════════════════════════════════════════════════
#  REAL-TIME UPDATE SYSTEM
# ══════════════════════════════════════════════════════════════════════
def update_definitions(url=GITHUB_DEF_URL, silent=False):
    if not silent:
        print(f"[*] Fetching: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"WinIntel/{VERSION}"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
        parsed = json.loads(data)
        if "cves" not in parsed:
            raise ValueError("Invalid definitions format")
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_bytes(data)
        count = len(parsed.get("cves", {}))
        ver   = parsed.get("version", "?")
        date  = parsed.get("date", "?")
        if not silent:
            print(f"[+] Updated: v{ver} ({date}) — {count} CVEs cached to {CACHE_FILE}")
        return True
    except urllib.error.URLError as e:
        if not silent:
            print(f"[!] Network error: {e}")
            print(f"    Publish your repo first, then run: python winintel.py --update")
        return False
    except Exception as e:
        if not silent:
            print(f"[!] Update failed: {e}")
        return False


def load_cached_definitions():
    if not CACHE_FILE.exists():
        return {}
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        return {"cves": data.get("cves", {}),
                "version": data.get("version", "?"),
                "date": data.get("date", "?")}
    except Exception:
        return {}


def merge_db(base_db, extra_cves):
    merged   = {**base_db}
    new_c    = sum(1 for k in extra_cves if k not in merged)
    upd_c    = sum(1 for k in extra_cves if k in merged)
    merged.update(extra_cves)
    return merged, new_c, upd_c


def check_update_available(url=GITHUB_DEF_URL):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"WinIntel/{VERSION}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        remote_ver = data.get("version", "?")
        cached_ver = load_cached_definitions().get("version", "0.0.0")
        return remote_ver != cached_ver, remote_ver
    except Exception:
        return False, "?"


def generate_definitions_json(path, db=None):
    if db is None:
        db = CVE_DB
    output = {
        "version": VERSION,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "description": "WinIntel CVE definitions — https://github.com/drgoteee/winintel",
        "cves": {}
    }
    for cve_id, entry in db.items():
        row  = {k: v for k, v in entry.items()}
        meta = get_meta(cve_id)
        row.update({k: meta[k] for k in ("itw","reliability","notes","poc_urls","tags")})
        output["cves"][cve_id] = row
    Path(path).write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"[+] definitions.json written: {path}  ({len(output['cves'])} CVEs)")
    print(f"    Upload to your repo root so users can run: python winintel.py --update")

# ══════════════════════════════════════════════════════════════════════
#  PARSER
# ══════════════════════════════════════════════════════════════════════
def parse_systeminfo(text):
    info = {
        "hostname":None,"os_name":None,"os_version":None,
        "os_major":None,"os_build":None,"arch":None,"arch_bits":"any",
        "hotfixes":set(),"domain":None,"is_domain":False,"os_label":None,
    }
    in_hotfix = False
    for line in text.splitlines():
        ll = line.strip()
        if re.match(r"Host Name\s*:", line, re.I):
            info["hostname"] = line.split(":",1)[1].strip()
        elif re.match(r"OS Name\s*:", line, re.I):
            info["os_name"] = line.split(":",1)[1].strip()
        elif re.match(r"OS Version\s*:", line, re.I):
            ver = line.split(":",1)[1].strip()
            info["os_version"] = ver
            m = re.match(r"(\d+\.\d+)\.(\d+)", ver)
            if m:
                info["os_major"] = m.group(1)
                info["os_build"] = int(m.group(2))
        elif re.match(r"System Type\s*:", line, re.I):
            info["arch"] = line.split(":",1)[1].strip()
            a = info["arch"].lower()
            info["arch_bits"] = (
                "x64" if ("x64" in a or "64-based" in a or "amd64" in a)
                else "x86" if ("x86" in a or "32-based" in a)
                else "any"
            )
        elif re.match(r"Domain\s*:", line, re.I):
            dom = line.split(":",1)[1].strip()
            info["domain"]    = dom
            # If domain matches the machine name, it is a workgroup - not domain-joined
            _hn = (info.get("hostname") or "").upper().strip()
            info["is_domain"] = (dom.upper() not in ("WORKGROUP","N/A","","HTB","HTBCORP")
                                 and dom.upper().strip() != _hn)
        elif re.match(r"Hotfix\(?e?s?\)?\s*:", line, re.I):
            in_hotfix = True
            info["hotfixes"].update(k.upper() for k in re.findall(r"KB\d+", line, re.I))
            if "N/A" in line:
                in_hotfix = False
        elif in_hotfix:
            if ll == "" or re.match(r"[A-Za-z ]+\s*:", line):
                in_hotfix = False
            else:
                info["hotfixes"].update(k.upper() for k in re.findall(r"KB\d+", ll, re.I))

    info["os_label"] = detect_os_label(info["os_major"], info["os_build"])
    return info


def infer_services(sysinfo, extra_services):
    services = {"local"}
    if sysinfo.get("is_domain"):
        services.add("kerberos")
    for s in (extra_services or []):
        services.add(s.lower().strip())
    return services

# ══════════════════════════════════════════════════════════════════════
#  VULN CHECKER
# ══════════════════════════════════════════════════════════════════════
def check_vulns(sysinfo, services, active_db):
    os_major  = sysinfo.get("os_major")
    os_build  = sysinfo.get("os_build", 0)
    arch_bits = sysinfo.get("arch_bits","any")
    hotfixes  = sysinfo.get("hotfixes", set())
    results   = []

    for cve_id, data in active_db.items():
        if os_major and os_major not in data.get("affected", []):
            continue
        cve_arch = data.get("arch", ["any"])
        if "any" not in cve_arch and arch_bits != "any":
            if arch_bits not in cve_arch:
                continue
        requires   = set(data.get("requires", ["local"]))
        hard_needs = requires - {"local"}
        if hard_needs and not hard_needs.issubset(services):
            continue

        # Build cap - skip if host build is newer than max affected build for this CVE
        build_cap = data.get("build_cap", {})
        if build_cap and os_major in build_cap and os_build:
            if os_build > build_cap[os_major]:
                continue

        # EOL downgrade: post-2021 Win10 KBs only issued for build >= 17763
        # On older EOL builds, change CONFIRMED→LIKELY (vulnerable but no patch exists)
        _cve_year = int(cve_id.split("-")[1]) if cve_id.count("-") >= 2 else 0
        _eol_downgrade = (
            data.get("confidence") == "kb"
            and os_major == "10.0" and (os_build or 0) < 17763
            and _cve_year >= 2022
        )

        conf   = data.get("confidence","manual")
        tier   = None
        reason = ""

        if conf == "kb":
            kb = data.get("kb")
            if kb:
                if kb.upper() not in hotfixes:
                    if _eol_downgrade:
                        tier   = "LIKELY"
                        reason = (f"{kb} never issued for build {os_build} (EOL) — "
                                  f"host IS vulnerable but no patch for this OS version")
                    else:
                        tier, reason = "CONFIRMED", f"{kb} not in installed hotfixes"
                else:
                    continue
            else:
                tier, reason = "MANUAL", "No patching KB known"
        elif conf == "build":
            vb = (data.get("vuln_builds") or {}).get(os_major)
            if vb is None:
                tier   = "LIKELY"
                reason = f"OS version {os_major} in affected list; no KB available to confirm"
            else:
                mn, mx = vb
                if mn <= os_build <= mx:
                    tier   = "LIKELY"
                    reason = f"Build {os_build} in vulnerable range {mn}–{mx}; no KB to confirm"
                else:
                    continue
        else:
            tier, reason = "MANUAL", "Cannot determine from systeminfo alone"

        if tier is None:
            continue

        swk = data.get("secwiki")
        entry = {
            "cve":         cve_id,
            "tier":        tier,
            "reason":      reason,
            "kb":          data.get("kb"),
            "ms":          data.get("ms"),
            "cvss":        data.get("cvss"),
            "severity":    data.get("severity","?"),
            "type":        data.get("type","?"),
            "category":    data.get("category",""),
            "desc":        data.get("desc",""),
            "msf":         data.get("msf"),
            "edb":         data.get("edb"),
            "arch":        data.get("arch",["any"]),
            "secwiki_url": (SECWIKI_BASE + swk) if swk else None,
            "nvd_url":     NVD_BASE + cve_id,
            "edb_url":     EDB_BASE + str(data["edb"]) if data.get("edb") else None,
        }
        entry.update(get_meta(cve_id))
        entry["priority"] = get_priority(entry)
        entry["score"], entry["verdict"], entry["signals"] = compute_score(entry)
        entry["edr_class"], entry["edr_hint"] = edr_note(cve_id)
        entry["kev"] = cve_id in CISA_KEV
        results.append(entry)

    results.sort(key=priority_sort_key)
    return results


# ══════════════════════════════════════════════════════════════════════
#  Confidence scoring: weights tier, exploit availability, reliability,
#  Produces a 0–100 exploitability score per CVE from weighted signals.
# ══════════════════════════════════════════════════════════════════════
#
#  Score = base(tier) + exploit_availability + reliability + itw_bonus
#          + kev_bonus - friction_penalties
#
#  This is what turns a flat CVE list into a *ranked decision*: the operator
#  sees one number that says "try this first" instead of eyeballing 40 rows.

# CISA Known Exploited Vulnerabilities - CVEs with confirmed active exploitation
# that carry federal remediation mandates. Strongest possible "this is real" signal.
CISA_KEV = {
    "CVE-2017-0144","CVE-2017-0145","CVE-2014-6324","CVE-2020-1472",
    "CVE-2021-1675","CVE-2021-34527","CVE-2021-36934","CVE-2021-40449",
    "CVE-2022-24521","CVE-2022-37969","CVE-2022-38028","CVE-2022-41073",
    "CVE-2023-21674","CVE-2023-23397","CVE-2023-28252","CVE-2023-36802",
    "CVE-2023-36874","CVE-2024-21338","CVE-2024-26169","CVE-2024-30088",
    "CVE-2024-38106","CVE-2024-38193","CVE-2025-21333","CVE-2025-21391",
    "CVE-2025-21418","CVE-2025-24983","CVE-2025-24984","CVE-2025-24985",
    "CVE-2025-24991","CVE-2025-24993","CVE-2025-29824","CVE-2025-30400",
    "CVE-2025-32701","CVE-2025-32706","CVE-2025-24990","CVE-2025-59230",
    "CVE-2025-62215","CVE-2025-62221","CVE-2018-8120","CVE-2018-8453",
    "CVE-2019-0859","CVE-2019-1132","CVE-2019-1458","CVE-2016-3309",
    "CVE-2015-1701","CVE-2015-2546",
}

# CVEs known to trip modern EDR / Defender easily (memory-corruption kernel
# exploits with loud IOCs). Operator should weigh this on monitored targets.
EDR_LOUD = {
    "CVE-2021-1675","CVE-2021-34527",  # PrintNightmare — heavily signatured
    "CVE-2020-1472",                    # ZeroLogon — every EDR flags it
    "CVE-2017-0144","CVE-2017-0145",   # EternalBlue — universally detected
}

# CVEs that are quiet / token-based / living-off-the-land friendly
EDR_QUIET = {
    "CVE-2021-36934",  # HiveNightmare — just file reads
    "CVE-2016-3225","CVE-2016-0099",  # token abuse, no shellcode
    "CVE-2017-0213","CVE-2018-8440",  # COM/ALPC, clean
}

def compute_score(v):
    """Return (score:int 0-100, verdict:str, signals:list[str])."""
    score   = 0
    signals = []

    # 1. Base from tier
    tier = v.get("tier")
    if tier == "CONFIRMED":
        score += 40; signals.append("confirmed-missing-patch")
    elif tier == "LIKELY":
        score += 22; signals.append("build-range-match")
    else:
        score += 8

    # 2. Exploit availability (the single biggest practical factor)
    if v.get("msf"):
        score += 28; signals.append("msf-module")
    elif v.get("secwiki_url"):
        score += 20; signals.append("precompiled-binary")
    elif v.get("edb"):
        score += 14; signals.append("exploitdb-poc")
    elif v.get("poc_urls"):
        score += 8;  signals.append("public-poc")
    else:
        score -= 6;  signals.append("no-public-exploit")

    # 3. Reliability rating
    rel = v.get("reliability","Unknown")
    score += {"Excellent":16,"Great":12,"Good":7,"Average":2,"Low":-8,"Unknown":0}.get(rel,0)

    # 4. In-the-wild confirmation
    if v.get("itw"):
        score += 8; signals.append("exploited-in-wild")

    # 5. CISA KEV mandate - federal "this is actively exploited" stamp
    if v["cve"] in CISA_KEV:
        score += 6; signals.append("cisa-kev")

    # 6. Friction penalties - things that make it harder to actually land
    tags  = set(v.get("tags") or [])
    reqs  = set()  # requires is on the DB entry, not always copied; infer from tags
    if "crash-risk" in tags:
        score -= 18; signals.append("bsod-risk")
    if "user-interaction" in tags or "gui-required" in tags:
        score -= 12; signals.append("needs-interaction")
    if "physical-access" in tags:
        score -= 25; signals.append("physical-only")
    if "no-public-rce" in tags:
        score -= 10
    if v.get("type") not in ("LPE","RCE"):
        score -= 8; signals.append("not-direct-escalation")

    # Clamp
    score = max(0, min(100, score))

    # Verdict band
    if   score >= 80: verdict = "TRY FIRST"
    elif score >= 60: verdict = "STRONG"
    elif score >= 40: verdict = "VIABLE"
    elif score >= 20: verdict = "FALLBACK"
    else:             verdict = "LOW YIELD"

    return score, verdict, signals


def edr_note(cve_id):
    """Return an EDR-awareness hint for monitored environments."""
    if cve_id in EDR_LOUD:
        return ("loud", "Heavily signatured — expect EDR/Defender to flag. Use on unmonitored targets.")
    if cve_id in EDR_QUIET:
        return ("quiet", "Quiet technique (token/file-based) — low IOC footprint.")
    return (None, None)


# ── Exploit-chain detection ───────────────────────────────────────────
# Recognizes when a foothold-priv combo unlocks a known privilege path.
# Maps a foothold + privilege context to a known escalation path.
CHAIN_RULES = [
    {
        "name": "SeImpersonate → Potato → SYSTEM",
        "trigger_priv": "service",
        "cves": ["CVE-2016-3225"],
        "note": "Service/IIS shell with SeImpersonatePrivilege → JuicyPotato/PrintSpoofer → SYSTEM. "
                "Often faster and quieter than a kernel exploit.",
    },
    {
        "name": "Print Spooler → PrintNightmare → SYSTEM",
        "trigger_service": "print",
        "cves": ["CVE-2021-1675","CVE-2021-34527"],
        "note": "Spooler service reachable → load malicious driver → SYSTEM. "
                "Works local (LPE) or remote (RCE) with valid creds.",
    },
    {
        "name": "Domain user → MS14-068 → Domain Admin",
        "trigger_service": "kerberos",
        "cves": ["CVE-2014-6324"],
        "note": "Any low-priv domain account → forge PAC → instant Domain Admin. "
                "Single-shot domain compromise if DC unpatched.",
    },
    {
        "name": "Network access → ZeroLogon → Domain Admin",
        "trigger_service": "kerberos",
        "cves": ["CVE-2020-1472"],
        "note": "Network line-of-sight to DC → reset machine account → DCSync → full domain. "
                "Zero credentials required. Very loud — EDR will flag.",
    },
    {
        "name": "Low-priv → HiveNightmare → cached creds → lateral",
        "trigger_priv": "user",
        "cves": ["CVE-2021-36934"],
        "note": "Readable SAM/SYSTEM hives → dump local hashes → pass-the-hash to other hosts. "
                "No exploit code, just file reads — extremely quiet.",
    },
]

def detect_chains(vulns, args):
    """Return list of applicable exploit chains given the result set + context."""
    present = {v["cve"] for v in vulns if v["tier"] in ("CONFIRMED","LIKELY")}
    priv    = getattr(args, "privilege", "user")
    raw_svc = getattr(args, "services", None)
    services = set(raw_svc.split(",")) if isinstance(raw_svc, str) else set(raw_svc or [])
    services = {s.strip().lower() for s in services}
    chains  = []
    for rule in CHAIN_RULES:
        if not any(c in present for c in rule["cves"]):
            continue
        # Service-gated chains require the service flag
        if rule.get("trigger_service") and rule["trigger_service"] not in services:
            continue
        # Priv-gated chains (service/admin contexts) require matching --privilege,
        # unless a service flag already justifies surfacing them
        tp = rule.get("trigger_priv")
        if tp and tp != priv:
            if tp == "service" and not rule.get("trigger_service"):
                continue
            if tp == "admin":
                continue
        chains.append(rule)
    return chains


# ══════════════════════════════════════════════════════════════════════
#  PRIORITY + SORT
# ══════════════════════════════════════════════════════════════════════
def get_priority(v):
    if v.get("msf"):           return "P1"
    if v.get("secwiki_url") or v.get("edb"): return "P2"
    return "P3"

def priority_sort_key(v):
    return (
        {"CONFIRMED":0,"LIKELY":1,"MANUAL":2}.get(v["tier"],9),
        {"P1":0,"P2":1,"P3":2}.get(v.get("priority","P3"),9),
        -(v.get("cvss") or 0),
    )

def build_kb_groups(vulns):
    kb_map = {}
    for v in vulns:
        kb = v.get("kb")
        if kb:
            kb_map.setdefault(kb, []).append(v["cve"])
    return kb_map

# ══════════════════════════════════════════════════════════════════════
#  RICH DISPLAY
# ══════════════════════════════════════════════════════════════════════
def _pc(p):
    return {"P1":"bold cyan","P2":"cyan","P3":"dim white"}.get(p,"white")

def _rb(r):
    return RELIABILITY_BADGE.get(r,"?????")

def print_banner(c, cache_info=""):
    c.print(f"[bold green]{BANNER}[/]")
    c.print(
        f"  [bold white]v{VERSION}[/] · Windows Exploit Intelligence"
        f"  [dim]github.com/drgoteee/winintel[/]\n"
        f"  [dim]118 CVEs · 2003–2026 · XP → Win11 24H2 · Watson+WES-NG accuracy[/]"
        f"{f'  [dim cyan]{cache_info}[/]' if cache_info else ''}\n"
    )

def print_sysinfo_panel(c, sysinfo, services):
    hf_c   = "red" if not sysinfo["hotfixes"] else "green"
    w11tag = " [bold magenta](Windows 11)[/]" if is_win11(sysinfo["os_major"], sysinfo["os_build"]) else ""
    c.print(Panel(
        f"  [bold]Host[/]      [cyan]{sysinfo['hostname'] or 'unknown'}[/]\n"
        f"  [bold]OS[/]        [yellow]{sysinfo['os_name'] or sysinfo['os_label']}[/]{w11tag}\n"
        f"  [bold]Release[/]   [yellow]{sysinfo['os_label']}[/]\n"
        f"  [bold]Version[/]   [yellow]{sysinfo['os_version']}[/]  "
          f"Build:[yellow]{sysinfo['os_build']}[/]  Arch:[yellow]{sysinfo['arch_bits'].upper()}[/]\n"
        f"  [bold]Domain[/]    {sysinfo.get('domain') or 'WORKGROUP'}"
          f"{'  [dim](kerberos exploits enabled)[/]' if sysinfo.get('is_domain') else ''}\n"
        f"  [bold]Hotfixes[/]  [{hf_c}]{len(sysinfo['hotfixes'])} installed[/]\n"
        f"  [bold]Services[/]  [dim]{', '.join(sorted(services))}[/]",
        title="[bold] Target [/]", border_style="green", padding=(0,1),
    ))

def print_summary_bar(c, vulns):
    confirmed = [v for v in vulns if v["tier"]=="CONFIRMED"]
    likely    = [v for v in vulns if v["tier"]=="LIKELY"]
    manual    = [v for v in vulns if v["tier"]=="MANUAL"]
    p1  = sum(1 for v in vulns if v.get("priority")=="P1")
    p2  = sum(1 for v in vulns if v.get("priority")=="P2")
    msf = sum(1 for v in vulns if v["msf"])
    wik = sum(1 for v in vulns if v["secwiki_url"])
    edb = sum(1 for v in vulns if v["edb"])
    itw = sum(1 for v in vulns if v.get("itw"))
    cri = sum(1 for v in vulns if v["severity"]=="CRITICAL")

    c.print(Panel(
        f"  [bold green]CONFIRMED[/] {len(confirmed):>3}    "
        f"[bold yellow]LIKELY[/] {len(likely):>3}    "
        f"[dim]MANUAL[/] {len(manual):>3} [dim](use --show-manual)[/]\n\n"
        f"  Priority   [bold cyan]P1[/]:{p1} (MSF ready)  [cyan]P2[/]:{p2} (binary/EDB)  "
        f"[dim]P3[/]:{len(vulns)-p1-p2} (no public exploit)\n\n"
        f"  Resources  [green]MSF:{msf}[/]  [magenta]SecWiki:{wik}[/]  "
        f"[yellow]EDB:{edb}[/]  [red]ITW:{itw}[/]  [bold red]CRITICAL:{cri}[/]",
        title="[bold] Summary [/]", border_style="dim", padding=(0,1),
    ))

def print_vuln_entry(c, v, kb_groups):
    tier    = v["tier"]
    prio    = v.get("priority","P3")
    sev     = v.get("severity","?")
    cvss    = v.get("cvss","?")
    vtype   = v.get("type","?")
    cat     = CATEGORY_LABEL.get(v.get("category",""), "")
    arch    = "/".join(v.get("arch",["any"])) if v.get("arch") != ["any"] else "any"
    ms      = v.get("ms") or "—"
    kb      = v.get("kb") or "—"
    rel     = v.get("reliability","Unknown")
    itw_t   = " [bold red](ITW)[/]" if v.get("itw") else ""
    others  = [x for x in kb_groups.get(kb,[]) if x != v["cve"]] if kb != "—" else []
    kb_note = f"  [dim](also fixes: {', '.join(others)})[/]" if others else ""

    c.print(
        f"  [{_pc(prio)}][{prio}][/{_pc(prio)}] "
        f"[{TIER_COLOR[tier]}][{tier}][/{TIER_COLOR[tier]}] "
        f"[bold cyan]{v['cve']}[/]"
        f"  [{SEV_COLOR.get(sev,'white')}]{sev}[/{SEV_COLOR.get(sev,'white')}]"
        f" · CVSS [bold]{cvss}[/]  {vtype}"
        f"{'  '+cat if cat else ''}  {arch}  {ms}{itw_t}"
    )
    c.print(f"       [white]{v.get('desc','')}[/]")
    c.print(f"       [dim]├─ Basis      [/] {v.get('reason','')}")
    c.print(f"       [dim]├─ Patching   [/] {kb}{kb_note}")
    c.print(f"       [dim]├─ Reliablty  [/] [{RELIABILITY_COLOR.get(rel,'white')}]{rel}[/{RELIABILITY_COLOR.get(rel,'white')}] {_rb(rel)}")

    if v.get("notes"):
        c.print(f"       [dim]├─ Notes      [/] [italic]{v['notes']}[/]")
    if v.get("msf"):
        c.print(f"       [dim]├─ MSF        [/] [green]use {v['msf']}[/]")
    if v.get("secwiki_url"):
        folder = v["secwiki_url"].split("/master/")[-1]
        c.print(f"       [dim]├─ SecWiki    [/] [magenta]{folder}[/]  ← compiled binary")
        c.print(f"       [dim]│              [/] [dim]{v['secwiki_url']}[/]")
    if v.get("edb"):
        c.print(f"       [dim]├─ ExploitDB  [/] [yellow]EDB-{v['edb']}[/]  {v['edb_url']}")

    extra = [u for u in (v.get("poc_urls") or []) if "SecWiki" not in u and "exploit-db" not in u]
    for i, url in enumerate(extra[:2]):
        pref = "├─" if i < len(extra)-1 else "└─"
        c.print(f"       [dim]{pref} PoC         [/] [blue]{url}[/]")

    c.print(f"       [dim]└─ NVD        [/] [dim]{v['nvd_url']}[/]")
    c.print()

def _verdict_style(verdict):
    return {"TRY FIRST":"bold #00d4a8","STRONG":"bold green","VIABLE":"bold yellow",
            "FALLBACK":"dim white","LOW YIELD":"dim white"}.get(verdict,"white")

def _score_bar(score, width=10):
    filled = round(score / 100 * width)
    col = "#00d4a8" if score>=80 else "green" if score>=60 else "yellow" if score>=40 else "dim white"
    bar = "█"*filled + "░"*(width-filled)
    return f"[{col}]{bar}[/{col}]"

def print_attack_plan(c, vulns, args=None):
    # Rank by SCORE - the v4 engine, not just priority
    ranked = sorted(
        [v for v in vulns if v["tier"] in ("CONFIRMED","LIKELY")],
        key=lambda x: -x.get("score", 0)
    )[:6]
    if not ranked:
        return

    c.print(Rule("[bold #00d4a8]ATTACK PLAN[/]  [dim]ranked by exploitability score[/]"))
    c.print()
    for i, v in enumerate(ranked, 1):
        score   = v.get("score", 0)
        verdict = v.get("verdict", "")
        rel     = v.get("reliability","Unknown")
        itw_t   = " [bold red]ITW[/]" if v.get("itw") else ""
        kev_t   = " [bold #bc8cff]KEV[/]" if v.get("kev") else ""
        cat     = CATEGORY_LABEL.get(v.get("category",""),"")

        # EDR hint badge
        edr_t = ""
        if v.get("edr_class") == "loud":
            edr_t = " [bold #ff7b72]EDR-LOUD[/]"
        elif v.get("edr_class") == "quiet":
            edr_t = " [#58a6ff]QUIET[/]"

        c.print(
            f"  [bold white]#{i}[/] {_score_bar(score)} [bold]{score:>3}[/] "
            f"[{_verdict_style(verdict)}]{verdict:<10}[/] "
            f"[bold cyan]{v['cve']}[/]  "
            f"[{RELIABILITY_COLOR.get(rel,'white')}]{rel}[/{RELIABILITY_COLOR.get(rel,'white')}]"
            f"{itw_t}{kev_t}{edr_t}"
        )
        c.print(f"       [dim]{cat}[/]  [white]{v.get('desc','')}[/]")
        _render_methods_rich(c, v, indent="       ")
        if args and getattr(args, "show_edr", False) and v.get("edr_hint"):
            c.print(f"       [#d29922]EDR: {v['edr_hint']}[/]")
        c.print()

    # ── Exploit-chain suggestions ──
    if args and not getattr(args, "no_chains", False):
        chains = detect_chains(vulns, args)
        if chains:
            c.print(Rule("[bold #bc8cff]EXPLOIT CHAINS[/]  [dim]context-aware privilege paths[/]"))
            c.print()
            for ch in chains:
                c.print(f"  [bold #bc8cff]▶ {ch['name']}[/]")
                c.print(f"    [dim]{ch['note']}[/]")
                c.print(f"    [dim]CVEs: {', '.join(ch['cves'])}[/]")
                c.print()

    c.print(Rule())
    c.print(
        f"\n  [dim]WinIntel v{VERSION} · For authorized penetration testing only.[/]\n"
        f"  [dim]--html report.html  ·  --quick  ·  --update  ·  github.com/drgoteee/winintel[/]\n"
    )

def print_rich_output(sysinfo, vulns, services, args, cache_info=""):
    c = Console()
    print_banner(c, cache_info)
    print_sysinfo_panel(c, sysinfo, services)

    show_manual = getattr(args,"show_manual",False)
    confirmed   = [v for v in vulns if v["tier"]=="CONFIRMED"]
    likely      = [v for v in vulns if v["tier"]=="LIKELY"]
    manual      = [v for v in vulns if v["tier"]=="MANUAL"]

    if not confirmed and not likely and not (show_manual and manual):
        c.print("\n[bold green]✓ No vulnerabilities found for this configuration.[/]")
        c.print("[dim]Tips: use --services smb,rdp,iis,print to add network/service exploits[/]\n")
        return

    print_summary_bar(c, vulns)
    kb_groups = build_kb_groups(vulns)

    def section(entries, label, color, hint):
        if not entries: return
        c.print()
        c.print(Rule(f"[{color}]── {label}[/{color}]  [dim]{hint}[/]"))
        c.print()
        for v in entries:
            if args.type     and v["type"].lower()         != args.type.lower():     continue
            if args.severity and v["severity"].lower()     != args.severity.lower(): continue
            if args.category and v.get("category","")      != args.category.lower(): continue
            if args.msf_only and not v["msf"]:                                       continue
            print_vuln_entry(c, v, kb_groups)

    section(confirmed, "CONFIRMED", "green",  "KB identified and not in installed hotfixes")
    section(likely,    "LIKELY",    "yellow", "build number in known vulnerable range")
    if show_manual:
        section(manual, "MANUAL", "white", "cannot verify from systeminfo — check manually")

    print_attack_plan(c, vulns, args)

# ══════════════════════════════════════════════════════════════════════
#  PLAIN TEXT OUTPUT
# ══════════════════════════════════════════════════════════════════════
def print_plain_output(sysinfo, vulns, services, args, cache_info=""):
    show_manual = getattr(args,"show_manual",False)
    confirmed   = [v for v in vulns if v["tier"]=="CONFIRMED"]
    likely      = [v for v in vulns if v["tier"]=="LIKELY"]
    manual      = [v for v in vulns if v["tier"]=="MANUAL"]
    p1 = sum(1 for v in vulns if v.get("priority")=="P1")
    p2 = sum(1 for v in vulns if v.get("priority")=="P2")

    print("="*70)
    print(f"  WinIntel v{VERSION} — Windows Exploit Intelligence")
    if cache_info: print(f"  Definitions: {cache_info}")
    print("="*70)
    print(f"  Host     : {sysinfo['hostname'] or 'unknown'}")
    print(f"  OS       : {sysinfo['os_name'] or sysinfo['os_label']}")
    print(f"  Release  : {sysinfo['os_label']}{'  (Windows 11)' if is_win11(sysinfo['os_major'],sysinfo['os_build']) else ''}")
    print(f"  Version  : {sysinfo['os_version']}  Build:{sysinfo['os_build']}  Arch:{sysinfo['arch_bits'].upper()}")
    print(f"  Domain   : {sysinfo.get('domain') or 'WORKGROUP'}")
    print(f"  Hotfixes : {len(sysinfo['hotfixes'])} installed")
    print(f"  Results  : CONFIRMED:{len(confirmed)}  LIKELY:{len(likely)}  MANUAL:{len(manual)}")
    print(f"  Priority : P1:{p1} (MSF)  P2:{p2} (binary/EDB)  P3:{len(vulns)-p1-p2} (no-public)")
    print("="*70)

    for tier_label, entries in [
        ("CONFIRMED", confirmed),
        ("LIKELY",    likely),
        ("MANUAL",    manual if show_manual else []),
    ]:
        if not entries: continue
        print(f"\n{'─'*60}")
        print(f"  {tier_label}")
        print(f"{'─'*60}")
        for v in entries:
            if args.msf_only and not v["msf"]: continue
            itw  = " (ITW)" if v.get("itw") else ""
            rel  = v.get("reliability","Unknown")
            cat  = CATEGORY_LABEL.get(v.get("category",""),"")
            prio = v.get("priority","P3")
            print(f"\n  [{prio}] [{tier_label}] {v['cve']}  {v['severity']} · CVSS:{v['cvss']}{itw}")
            print(f"  Type       : {v['type']}{'  | '+cat if cat else ''}")
            print(f"  Desc       : {v['desc']}")
            print(f"  Basis      : {v['reason']}")
            print(f"  Patching   : {v.get('kb') or '—'}")
            print(f"  Reliablty  : {rel}  {_rb(rel)}")
            if v.get("notes"):        print(f"  Notes      : {v['notes']}")
            if v.get("msf"):          print(f"  MSF        : use {v['msf']}")
            if v.get("secwiki_url"):  print(f"  SecWiki    : {v['secwiki_url']}")
            if v.get("edb_url"):      print(f"  EDB        : {v['edb_url']}")
            for url in (v.get("poc_urls") or [])[:2]:
                if "SecWiki" not in url and "exploit-db" not in url:
                    print(f"  PoC        : {url}")
            print(f"  NVD        : {v['nvd_url']}")

    ranked = sorted(
        [v for v in vulns if v["tier"] in ("CONFIRMED","LIKELY")
         and (v.get("msf") or v.get("secwiki_url") or v.get("edb"))],
        key=priority_sort_key
    )[:5]
    if ranked:
        print(f"\n{'='*60}")
        print("  ATTACK PLAN  (top picks, ranked by exploitability)")
        print(f"{'='*60}")
        for i, v in enumerate(ranked, 1):
            itw = " (ITW)" if v.get("itw") else ""
            print(f"\n  #{i} [{v.get('priority','P3')}] {v['cve']}  {v.get('reliability','?')}{itw}")
            print(f"     {v.get('desc','')}")
            if v.get("msf"):
                print(f"     use {v['msf']}")
                print(f"     set SESSION 1 ; set LHOST tun0 ; set LPORT 4444 ; run")
            elif v.get("secwiki_url"):
                print(f"     SecWiki: {v['secwiki_url']}")
            if v.get("edb"):
                print(f"     EDB: https://www.exploit-db.com/exploits/{v['edb']}")
        print()

# ══════════════════════════════════════════════════════════════════════
#  EXPORT
# ══════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════
#  HTML report export
# ══════════════════════════════════════════════════════════════════════
def export_html(sysinfo, vulns, services, path, cache_info="", args=None):
    """Generate a self-contained dark-themed HTML exploitation report."""
    confirmed = [v for v in vulns if v["tier"]=="CONFIRMED"]
    likely    = [v for v in vulns if v["tier"]=="LIKELY"]
    ranked    = sorted([v for v in vulns if v["tier"] in ("CONFIRMED","LIKELY")],
                       key=lambda x: -x.get("score",0))
    kev_count = sum(1 for v in vulns if v.get("kev"))
    itw_count = sum(1 for v in vulns if v.get("itw"))

    def verdict_color(verdict):
        return {"TRY FIRST":"#00d4a8","STRONG":"#3fb950","VIABLE":"#d29922",
                "FALLBACK":"#8b949e","LOW YIELD":"#484f58"}.get(verdict,"#8b949e")

    def score_bar(score):
        col = "#00d4a8" if score>=80 else "#3fb950" if score>=60 else "#d29922" if score>=40 else "#8b949e"
        return f'<div class="bar"><div class="fill" style="width:{score}%;background:{col}"></div><span>{score}</span></div>'

    rows = []
    for i, v in enumerate(ranked, 1):
        vc   = verdict_color(v.get("verdict","LOW YIELD"))
        itw  = '<span class="badge itw">ITW</span>' if v.get("itw") else ""
        kev  = '<span class="badge kev">CISA KEV</span>' if v.get("kev") else ""
        edr  = ""
        if v.get("edr_class")=="loud":
            edr = '<span class="badge loud">EDR LOUD</span>'
        elif v.get("edr_class")=="quiet":
            edr = '<span class="badge quiet">QUIET</span>'
        tier_b = f'<span class="badge {v["tier"].lower()}">{v["tier"]}</span>'

        # Show EVERY available method - not just MSF. Operators who avoid
        # msfconsole need the precompiled binary / EDB / manual PoC links too.
        methods = []
        if v.get("msf"):
            full_cmd = f"use {v['msf']}; set SESSION 1; set LHOST tun0; set LPORT 4444; run"
            methods.append(
                f'<div class="method"><span class="mtag msf-tag">MSF</span>'
                f'<div class="msfwrap"><code class="msf">use {v["msf"]}</code>'
                f'<button class="copy" onclick="cp(this,\'{full_cmd}\')">copy</button></div></div>'
            )
        if v.get("secwiki_url"):
            folder = v["secwiki_url"].split("/master/")[-1]
            methods.append(
                f'<div class="method"><span class="mtag bin-tag">BINARY</span>'
                f'<a href="{v["secwiki_url"]}" target="_blank" class="link">'
                f'Precompiled: SecWiki/{folder} &#8599;</a></div>'
            )
        if v.get("edb_url"):
            methods.append(
                f'<div class="method"><span class="mtag edb-tag">EDB</span>'
                f'<a href="{v["edb_url"]}" target="_blank" class="link">{v["edb_url"]} &#8599;</a></div>'
            )
        # Manual/standalone PoCs (GitHub repos etc.) for anyone avoiding both MSF and SecWiki
        for url in (v.get("poc_urls") or []):
            if "secwiki" in url.lower() or "exploit-db" in url.lower():
                continue
            short = url.replace("https://", "").replace("http://", "")
            if len(short) > 52: short = short[:49] + "..."
            methods.append(
                f'<div class="method"><span class="mtag poc-tag">PoC</span>'
                f'<a href="{url}" target="_blank" class="link">{short} &#8599;</a></div>'
            )
        if not methods:
            methods.append('<div class="method nomethod">No public exploit — manual analysis required</div>')
        exploit = "".join(methods)

        notes = f'<div class="notes">{v.get("notes","")}</div>' if v.get("notes") else ""
        edr_hint = f'<div class="edrhint">{v.get("edr_hint","")}</div>' if v.get("edr_hint") else ""

        rows.append(f'''
        <tr>
          <td class="rank">#{i}</td>
          <td>{score_bar(v.get("score",0))}</td>
          <td><span class="verdict" style="color:{vc}">{v.get("verdict","")}</span></td>
          <td class="cve">
            <a href="{v.get("nvd_url","#")}" target="_blank">{v["cve"]}</a>
            {tier_b}{itw}{kev}{edr}
            <div class="desc">{v.get("desc","")}</div>
            {notes}{edr_hint}
            <div class="exploit">{exploit}</div>
          </td>
          <td class="rel">{v.get("reliability","?")}</td>
          <td class="kb">{v.get("kb") or "—"}</td>
        </tr>''')

    win11 = " (Windows 11)" if is_win11(sysinfo.get("os_major"), sysinfo.get("os_build")) else ""

    # Build exploit-chains section if any apply
    chains_html = ""
    if args is not None:
        try:
            chains = detect_chains(vulns, args)
        except Exception:
            chains = []
        if chains:
            chain_items = []
            for ch in chains:
                cve_links = ", ".join(ch["cves"])
                chain_items.append(
                    f'<div class="chain"><div class="chain-name">&#9654; {ch["name"]}</div>'
                    f'<div class="chain-note">{ch["note"]}</div>'
                    f'<div class="chain-cves">{cve_links}</div></div>'
                )
            chains_html = (
                '<h2 class="section">Exploit Chains <span class="section-sub">context-aware privilege paths</span></h2>'
                '<div class="chains">' + "".join(chain_items) + '</div>'
            )

    html = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WinIntel Report — {sysinfo.get("hostname","target")}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.5;padding:32px;max-width:1100px;margin:0 auto}}
.head{{border-bottom:2px solid #00d4a8;padding-bottom:20px;margin-bottom:24px}}
.logo{{font-family:'Cascadia Code','JetBrains Mono',monospace;font-size:11px;color:#00d4a8;white-space:pre;line-height:1.2;margin-bottom:12px}}
h1{{font-size:22px;color:#fff;margin-bottom:4px}}
.sub{{color:#8b949e;font-size:13px}}
.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:24px 0;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px}}
.meta div span{{display:block;color:#6e7681;font-size:11px;text-transform:uppercase;letter-spacing:.05em}}
.meta div b{{color:#e6edf3;font-size:15px;font-weight:600}}
.stats{{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}}
.stat{{flex:1;min-width:120px;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 16px;text-align:center}}
.stat .n{{font-size:28px;font-weight:700;line-height:1}}
.stat .l{{font-size:11px;color:#6e7681;text-transform:uppercase;margin-top:4px}}
.n.green{{color:#00d4a8}}.n.yellow{{color:#d29922}}.n.red{{color:#f85149}}.n.blue{{color:#58a6ff}}
table{{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}}
th{{background:#1c2128;color:#8b949e;text-align:left;padding:12px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid #30363d}}
td{{padding:14px 12px;border-bottom:1px solid #21262d;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
.rank{{font-weight:700;color:#6e7681;font-size:16px}}
.bar{{position:relative;width:90px;height:22px;background:#0d1117;border-radius:4px;overflow:hidden}}
.bar .fill{{height:100%;border-radius:4px}}
.bar span{{position:absolute;top:0;left:0;right:0;text-align:center;line-height:22px;font-size:12px;font-weight:700;color:#0d1117}}
.verdict{{font-weight:700;font-size:13px;white-space:nowrap}}
.cve a{{color:#58a6ff;text-decoration:none;font-weight:600;font-family:monospace}}
.cve a:hover{{text-decoration:underline}}
.desc{{color:#c9d1d9;font-size:13px;margin-top:6px}}
.notes{{color:#8b949e;font-size:12px;margin-top:4px;font-style:italic}}
.edrhint{{color:#d29922;font-size:12px;margin-top:4px}}
.exploit{{margin-top:8px}}
.method{{display:flex;align-items:center;gap:8px;margin:5px 0;flex-wrap:wrap}}
.mtag{{display:inline-block;font-size:9px;font-weight:700;padding:2px 7px;border-radius:3px;letter-spacing:.04em;min-width:48px;text-align:center}}
.msf-tag{{background:#0d2818;color:#3fb950;border:1px solid #1a4b2c}}
.bin-tag{{background:#2a1a3e;color:#bc8cff;border:1px solid #4a2e6e}}
.edb-tag{{background:#2d2410;color:#d29922;border:1px solid #4a3a10}}
.poc-tag{{background:#0d1f3a;color:#58a6ff;border:1px solid #1a3a6a}}
.nomethod{{color:#6e7681;font-size:12px;font-style:italic}}
code.msf{{display:inline-block;background:#0d2818;color:#3fb950;padding:6px 10px;border-radius:4px;font-family:monospace;font-size:12px;border:1px solid #1a4b2c}}
.link{{color:#bc8cff;font-size:12px;font-family:monospace;text-decoration:none}}
.link:hover{{text-decoration:underline}}
.rel{{font-size:12px;color:#8b949e;white-space:nowrap}}
.kb{{font-family:monospace;font-size:12px;color:#6e7681}}
.badge{{display:inline-block;font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;margin-left:6px;vertical-align:middle;letter-spacing:.03em}}
.badge.confirmed{{background:#0d2818;color:#3fb950;border:1px solid #1a4b2c}}
.badge.likely{{background:#2d2410;color:#d29922;border:1px solid #4a3a10}}
.badge.itw{{background:#2d0d0d;color:#f85149;border:1px solid #5a1a1a}}
.badge.kev{{background:#1a0d2e;color:#bc8cff;border:1px solid #3d1f6e}}
.badge.loud{{background:#2d0d0d;color:#ff7b72;border:1px solid #5a1a1a}}
.badge.quiet{{background:#0d1f3a;color:#58a6ff;border:1px solid #1a3a6a}}
.foot{{margin-top:28px;padding-top:16px;border-top:1px solid #30363d;color:#6e7681;font-size:12px;text-align:center}}
.foot a{{color:#00d4a8;text-decoration:none}}
.section{{font-size:16px;color:#fff;margin:28px 0 14px;padding-bottom:8px;border-bottom:1px solid #30363d;font-weight:600}}
.section-sub{{font-size:12px;color:#6e7681;font-weight:400;text-transform:none;letter-spacing:0}}
.chains{{display:flex;flex-direction:column;gap:10px}}
.chain{{background:#161b22;border:1px solid #30363d;border-left:3px solid #bc8cff;border-radius:8px;padding:14px 16px}}
.chain-name{{color:#bc8cff;font-weight:700;font-size:14px;margin-bottom:6px}}
.chain-note{{color:#c9d1d9;font-size:13px;margin-bottom:6px}}
.chain-cves{{color:#6e7681;font-size:12px;font-family:monospace}}
.msfwrap{{display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.copy{{background:#21262d;color:#8b949e;border:1px solid #30363d;border-radius:4px;padding:4px 10px;font-size:11px;cursor:pointer;font-family:inherit;transition:all .15s}}
.copy:hover{{background:#30363d;color:#e6edf3;border-color:#00d4a8}}
.copy.done{{background:#0d2818;color:#3fb950;border-color:#1a4b2c}}
.toolbar{{display:flex;gap:10px;margin-bottom:20px}}
.btn{{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:8px 14px;font-size:12px;cursor:pointer;font-family:inherit;text-decoration:none;display:inline-flex;align-items:center;gap:6px;transition:all .15s}}
.btn:hover{{background:#30363d;border-color:#00d4a8;color:#fff}}
@media print{{
  body{{background:#fff;color:#111;padding:12px;max-width:100%}}
  .toolbar,.copy{{display:none}}
  .meta,.stat,table,.chain{{background:#fafafa;border-color:#ddd}}
  th{{background:#f0f0f0;color:#333}}
  .cve a,.foot a{{color:#0066cc}}
  .desc,.chain-note{{color:#222}}
  code.msf{{background:#eef7ee;color:#0a5}}
  .logo{{color:#0a8}}
  h1,.section{{color:#000}}
  .n.green{{color:#0a8}}.n.yellow{{color:#b80}}.n.red{{color:#c00}}.n.blue{{color:#06c}}
  .stats{{break-inside:avoid}}
}}
</style></head><body>
<div class="head">
<div class="logo"> ██╗    ██╗██╗███╗   ██╗██╗███╗   ██╗████████╗███████╗██╗
 ██║ █╗ ██║██║██╔██╗ ██║██║██╔██╗ ██║   ██║   █████╗  ██║
 ╚███╔███╔╝██║██║ ╚████║██║██║ ╚████║   ██║   ███████╗███████╗</div>
<h1>Windows Exploitation Report</h1>
<div class="sub">Generated by WinIntel v{VERSION} · {datetime.now().strftime("%Y-%m-%d %H:%M")}</div>
</div>

<div class="toolbar">
<button class="btn" onclick="window.print()">&#128424; Print / Save as PDF</button>
<a class="btn" href="https://github.com/drgoteee/winintel" target="_blank">&#11088; WinIntel on GitHub</a>
</div>

<div class="meta">
<div><span>Host</span><b>{sysinfo.get("hostname","unknown")}</b></div>
<div><span>Operating System</span><b>{(sysinfo.get("os_name") or sysinfo.get("os_label",""))[:40]}{win11}</b></div>
<div><span>Build / Arch</span><b>{sysinfo.get("os_build","?")} · {sysinfo.get("arch_bits","?").upper()}</b></div>
<div><span>Hotfixes</span><b>{len(sysinfo.get("hotfixes",set()))} installed</b></div>
<div><span>Domain</span><b>{sysinfo.get("domain") or "WORKGROUP"}</b></div>
<div><span>Services</span><b>{", ".join(sorted(services))}</b></div>
</div>

<div class="stats">
<div class="stat"><div class="n green">{len(confirmed)}</div><div class="l">Confirmed</div></div>
<div class="stat"><div class="n yellow">{len(likely)}</div><div class="l">Likely</div></div>
<div class="stat"><div class="n red">{itw_count}</div><div class="l">In The Wild</div></div>
<div class="stat"><div class="n blue">{kev_count}</div><div class="l">CISA KEV</div></div>
<div class="stat"><div class="n">{len(ranked)}</div><div class="l">Ranked</div></div>
</div>

<table>
<thead><tr><th>Rank</th><th>Score</th><th>Verdict</th><th>Vulnerability</th><th>Reliability</th><th>Patch</th></tr></thead>
<tbody>{"".join(rows) if rows else '<tr><td colspan=6 style="text-align:center;color:#6e7681;padding:32px">No confirmed or likely vulnerabilities found.</td></tr>'}</tbody>
</table>

{chains_html}

<div class="foot">
WinIntel v{VERSION} · For authorized penetration testing only · <a href="https://github.com/drgoteee/winintel">github.com/drgoteee/winintel</a>
</div>
<script>
function cp(btn, text){{
  navigator.clipboard.writeText(text).then(function(){{
    var orig = btn.textContent;
    btn.textContent = 'copied';
    btn.classList.add('done');
    setTimeout(function(){{ btn.textContent = orig; btn.classList.remove('done'); }}, 1400);
  }}).catch(function(){{
    var t = document.createElement('textarea');
    t.value = text; document.body.appendChild(t); t.select();
    try {{ document.execCommand('copy'); btn.textContent='copied'; btn.classList.add('done'); }} catch(e) {{}}
    document.body.removeChild(t);
    setTimeout(function(){{ btn.textContent='copy'; btn.classList.remove('done'); }}, 1400);
  }});
}}
</script>
</body></html>'''

    Path(path).write_text(html, encoding="utf-8")
    print(f"[+] HTML report saved: {path}")


def export_csv(vulns, path):
    fields = ["tier","priority","cve","cvss","severity","type","category","ms","kb",
              "arch","itw","reliability","msf","edb","secwiki_url","nvd_url","edb_url","desc","notes","reason"]
    with open(path,"w",newline="",encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for v in vulns:
            row = {k: v.get(k,"") for k in fields}
            row["arch"]  = "/".join(v.get("arch",["any"]))
            row["itw"]   = "yes" if v.get("itw") else "no"
            row["notes"] = (v.get("notes") or "").replace('"',"'")
            w.writerow(row)
    print(f"[+] CSV saved: {path}")

def export_json(vulns, path):
    with open(path,"w",encoding="utf-8") as f:
        json.dump(vulns, f, indent=2)
    print(f"[+] JSON saved: {path}")

def export_msf(vulns, path):
    lines = []
    for v in [x for x in vulns if x["msf"] and x["tier"] in ("CONFIRMED","LIKELY")]:
        lines += [
            f"# [{v['tier']}] {v['cve']}  CVSS:{v['cvss']}  P:{v.get('priority','?')}",
            f"# {v['desc']}",
            f"use {v['msf']}",
            f"set SESSION 1",
            f"set LHOST tun0",
            f"set LPORT 4444",
            f"run\n",
        ]
    Path(path).write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] MSF script saved: {path}")

# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════
#  SMART FILTERING - signal vs noise
# ══════════════════════════════════════════════════════════════════════
CRASH_RISK_CVES = {"CVE-2012-0002","CVE-2020-16898"}  # BSoD / no reliable exec
PHYSICAL_ONLY   = {"CVE-2025-24984","CVE-2013-1285"}   # requires physical access
USER_INTERACT   = {"CVE-2017-8464","CVE-2023-23397"}    # requires user to click/open

def smart_filter(vulns, args, sysinfo=None):
    """Apply precision filtering: type, privilege context, KB dedup, noise removal."""
    out = list(vulns)

    # Always remove BSoD/crash-risk and physical-access-only
    out = [v for v in out
           if v["cve"] not in CRASH_RISK_CVES
           and v["cve"] not in PHYSICAL_ONLY]

    # Remove user-interaction CVEs unless explicitly added via --services
    # (they need email client / GUI - not useful in blind shell context)
    _raw = getattr(args, "services", None)
    services_set = set(_raw.split(",")) if isinstance(_raw, str) else set(_raw or [])
    services_set = {s.strip().lower() for s in services_set}
    if "user_interact" not in services_set:
        out = [v for v in out if v["cve"] not in USER_INTERACT]

    # --lpe-only: remove Info / DoS / AuthBypass
    if getattr(args, "lpe_only", False) or getattr(args, "quick", False):
        out = [v for v in out if v.get("type") in ("LPE","RCE")]

    # --privilege context
    priv = getattr(args, "privilege", "user")
    if priv == "user":
        # Remove UAC-bypass CVEs (gui-required) - no interactive session assumed
        out = [v for v in out
               if "gui-required" not in (v.get("tags") or [])]
    elif priv == "service":
        # User has SeImpersonatePrivilege - Potato-family relevant
        pass  # keep all, Potato exploits already in ntlm_relay category
    elif priv == "admin":
        # Admin hunting UAC bypass - show only uac-bypass tagged
        out = [v for v in out
               if "uac-bypass" in (v.get("tags") or [])]
        return out  # return early, no dedup needed

    # --exploitable-only: require MSF, SecWiki binary, or EDB
    if getattr(args, "exploitable_only", False) or getattr(args, "quick", False):
        out = [v for v in out
               if v.get("msf") or v.get("secwiki_url") or v.get("edb")]

    # KB deduplication - one KB = one entry (keep best by priority/reliability)
    rel_rank = {"Excellent":0,"Great":1,"Good":2,"Average":3,"Low":4,"Unknown":5}
    seen_kbs = {}
    deduped = []
    for v in out:
        kb = v.get("kb")
        if not kb:
            deduped.append(v)
            continue
        if kb not in seen_kbs:
            seen_kbs[kb] = v
            deduped.append(v)
        else:
            # Replace if current entry is higher priority
            prev = seen_kbs[kb]
            prev_score = ({"P1":0,"P2":1,"P3":2}.get(prev.get("priority","P3"),2),
                          rel_rank.get(prev.get("reliability","Unknown"),5))
            curr_score = ({"P1":0,"P2":1,"P3":2}.get(v.get("priority","P3"),2),
                          rel_rank.get(v.get("reliability","Unknown"),5))
            if curr_score < prev_score:
                # Swap - remove old, add new
                deduped = [x for x in deduped if not (x.get("kb")==kb)]
                deduped.append(v)
                seen_kbs[kb] = v
    out = deduped

    # Re-sort after dedup
    out.sort(key=priority_sort_key)
    return out


def _wi_detect_label(sysinfo):
    return sysinfo.get("os_label") or detect_os_label(sysinfo.get("os_major"), sysinfo.get("os_build"))


def _render_methods_rich(c, v, indent="     "):
    """Print ALL available exploit delivery methods (MSF + SecWiki + EDB + PoC),
    not just the first. Operators who avoid msfconsole need the binaries/PoCs."""
    shown = False
    if v.get("msf"):
        c.print(f"{indent}[green]MSF    [/] [green]use {v['msf']}[/]")
        c.print(f"{indent}        [green]set SESSION 1; set LHOST tun0; set LPORT 4444; run[/]")
        shown = True
    if v.get("secwiki_url"):
        folder = v["secwiki_url"].split("/master/")[-1]
        c.print(f"{indent}[#bc8cff]BINARY [/] [#bc8cff]Precompiled .exe → SecWiki/{folder}[/]")
        c.print(f"{indent}        [dim]{v['secwiki_url']}[/]")
        shown = True
    if v.get("edb_url"):
        c.print(f"{indent}[yellow]EDB    [/] [yellow]{v['edb_url']}[/]")
        shown = True
    for url in (v.get("poc_urls") or []):
        if "secwiki" in url.lower() or "exploit-db" in url.lower():
            continue
        c.print(f"{indent}[#58a6ff]PoC    [/] [#58a6ff]{url}[/]")
        shown = True
    if not shown:
        c.print(f"{indent}[dim]No public exploit — manual analysis required[/]")


def _render_methods_plain(v, indent="     "):
    """Plain-text version of _render_methods_rich."""
    lines = []
    if v.get("msf"):
        lines.append(f"{indent}MSF    use {v['msf']}")
        lines.append(f"{indent}       set SESSION 1; set LHOST tun0; set LPORT 4444; run")
    if v.get("secwiki_url"):
        folder = v["secwiki_url"].split("/master/")[-1]
        lines.append(f"{indent}BINARY Precompiled .exe -> SecWiki/{folder}")
        lines.append(f"{indent}       {v['secwiki_url']}")
    if v.get("edb_url"):
        lines.append(f"{indent}EDB    {v['edb_url']}")
    for url in (v.get("poc_urls") or []):
        if "secwiki" in url.lower() or "exploit-db" in url.lower():
            continue
        lines.append(f"{indent}PoC    {url}")
    if not lines:
        lines.append(f"{indent}No public exploit - manual analysis required")
    return "\n".join(lines)


def _print_quick(vulns, sysinfo, services):
    """--quick mode: tight attack plan, zero noise, copy-paste ready."""
    confirmed = [v for v in vulns if v["tier"]=="CONFIRMED"]
    likely    = [v for v in vulns if v["tier"]=="LIKELY"]
    all_ranked = confirmed + likely

    if HAS_RICH:
        c = Console()
        c.print(f"\n[bold cyan]WinIntel v{VERSION}[/]  [dim]--quick mode[/]")
        c.print(
            f"  [yellow]{sysinfo.get('os_name') or sysinfo.get('os_label','?')}[/]  "
            f"Build [yellow]{sysinfo.get('os_build','?')}[/]  "
            f"Arch [yellow]{sysinfo.get('arch_bits','?').upper()}[/]  "
            f"HFs [yellow]{len(sysinfo.get('hotfixes',set()))}[/]"
        )
        c.print(
            f"  CONFIRMED:[bold green]{len(confirmed)}[/]  "
            f"LIKELY:[bold yellow]{len(likely)}[/]  "
            f"[dim](lpe-only · kb-deduped · exploitable only · no noise)[/]\n"
        )
        if not all_ranked:
            c.print("[dim]No exploitable vulns found. Try: --services smb,rdp,print | --show-manual | remove --quick[/]")
            return
        c.print(Rule("[bold green]QUICK ATTACK PLAN[/]"))
        c.print()
        for i, v in enumerate(all_ranked[:8], 1):
            tier_c = TIER_COLOR.get(v["tier"],"white")
            prio_c = {"P1":"bold cyan","P2":"cyan","P3":"dim white"}.get(v.get("priority","P3"),"white")
            rel    = v.get("reliability","Unknown")
            rel_c  = RELIABILITY_COLOR.get(rel,"white")
            itw_t  = " [bold red]ITW[/]" if v.get("itw") else ""
            cat    = CATEGORY_LABEL.get(v.get("category",""),"")
            c.print(
                f"  [bold white]#{i}[/] [{tier_c}]{v['tier'][:4]}[/{tier_c}]"
                f" [{prio_c}]{v.get('priority','P3')}[/{prio_c}]"
                f" [bold cyan]{v['cve']}[/]"
                f"  [{rel_c}]{rel}[/{rel_c}]{itw_t}"
                f"  [dim]{cat}[/]"
            )
            c.print(f"     [white]{v.get('desc','')}[/]")
            if v.get("notes"):
                c.print(f"     [italic dim]{v['notes']}[/]")
            _render_methods_rich(c, v)
            kb_str = v.get("kb") or "none (build-range)"
            c.print(f"     [dim]Patch: {kb_str}[/]")
            c.print()
        c.print(Rule())
        c.print(f"  [dim]Full output: python winintel.py -i s.txt[/]")
        c.print(f"  [dim]With services: python winintel.py -i s.txt --services smb,rdp,print[/]\n")
    else:
        print(f"\nWinIntel v{VERSION}  --quick")
        print(f"  {sysinfo.get('os_label','?')}  build:{sysinfo.get('os_build','?')}  arch:{sysinfo.get('arch_bits','?').upper()}  hfs:{len(sysinfo.get('hotfixes',set()))}")
        print(f"  CONFIRMED:{len(confirmed)}  LIKELY:{len(likely)}  (lpe-only, deduped, exploitable)")
        if not all_ranked:
            print("  No exploitable vulns found.")
            return
        print("\n── QUICK ATTACK PLAN ──")
        for i, v in enumerate(all_ranked[:8], 1):
            itw  = " (ITW)" if v.get("itw") else ""
            print(f"\n  #{i} [{v['tier'][:4]}] [{v.get('priority','P3')}] {v['cve']}  {v.get('reliability','?')}{itw}")
            print(f"     {v.get('desc','')}")
            if v.get("notes"): print(f"     {v['notes']}")
            print(_render_methods_plain(v))
            print(f"     Patch: {v.get('kb') or 'none'}")
        print()

def main():
    p = argparse.ArgumentParser(
        prog="winintel",
        description=f"WinIntel v{VERSION} — Windows Exploit Intelligence (Watson + WES-NG accuracy)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Confidence tiers:
  CONFIRMED  KB identified and NOT installed   → proven vulnerable
  LIKELY     Build in known vulnerable range   → probably vulnerable
  MANUAL     Cannot verify from systeminfo     → --show-manual

Services (only add what nmap confirms):
  smb        port 445  → EternalBlue, SMBGhost
  rdp        port 3389 → RDP exploits
  iis        IIS running → .NET/WebDAV exploits
  print      Spooler running → PrintNightmare, CVE-2022-38028
  kerberos   Domain + DC → MS14-068, ZeroLogon
  bits       BITS service → CVE-2020-0787

Category filter (--category):
  kernel_driver  kernel_pool  kernel_race  service_lpe
  print_spooler  ntlm_relay   kerberos_abuse
  rce_smb  rce_rdp  rce_iis  rce_network  installer_lpe  cred_access

Workflow (OSCP / CTF / real engagement):
  systeminfo > C:\\Users\\Public\\s.txt     # on target
  python winintel.py -i s.txt              # on Kali
  python winintel.py -i s.txt --msf-only --msf-script attack.rc
  msfconsole -q -r attack.rc

Real-time update (after publishing GitHub repo):
  python winintel.py --generate-definitions definitions.json
  git add definitions.json && git push
  python winintel.py --update    # on any machine
"""
    )
    p.add_argument("-i","--input",            metavar="FILE")
    p.add_argument("--services",              metavar="LIST",
                   help="comma-separated: smb,rdp,iis,print,kerberos,rpc,webdav,bits")
    p.add_argument("--severity",              metavar="SEV")
    p.add_argument("--type",                  metavar="TYPE")
    p.add_argument("--category",              metavar="CAT")
    p.add_argument("--msf-only",              action="store_true")
    p.add_argument("--show-manual",           action="store_true")
    p.add_argument("--quick",                 action="store_true",
                   help="Top 5 CONFIRMED exploitable only — copy-paste attack plan, no noise")
    p.add_argument("--exploitable-only",      action="store_true",
                   help="Hide P3 (no public exploit) — show only MSF/SecWiki/EDB entries")
    p.add_argument("--privilege",             metavar="LEVEL", default="user",
                   choices=["user","service","admin"],
                   help="user=low-priv shell (default) | service=SeImpersonate | admin=UAC bypass needed")
    p.add_argument("--lpe-only",              action="store_true",
                   help="Show only LPE/RCE type CVEs — filter out Info/DoS/AuthBypass (recommended)")
    p.add_argument("--csv",                   metavar="FILE")
    p.add_argument("--json",                  metavar="FILE")
    p.add_argument("--msf-script",            metavar="FILE")
    p.add_argument("--html",                  metavar="FILE",
                   help="Export self-contained dark-themed HTML exploitation report")
    p.add_argument("--no-chains",             action="store_true",
                   help="Disable exploit-chain suggestions")
    p.add_argument("--show-edr",              action="store_true",
                   help="Show EDR/Defender detection hints (loud vs quiet)")
    p.add_argument("--plain",                 action="store_true")
    p.add_argument("--db-count",              action="store_true")
    p.add_argument("--update",                action="store_true",
                   help="download latest definitions.json from GitHub")
    p.add_argument("--check-update",          action="store_true",
                   help="check if a newer definitions version is available")
    p.add_argument("--generate-definitions",  metavar="FILE",
                   help="export built-in DB as definitions.json for GitHub hosting")
    p.add_argument("--version",               action="store_true")
    args = p.parse_args()

    if args.version:
        print(f"WinIntel v{VERSION}  |  {len(CVE_DB)} CVEs built-in (2003–2026)")
        return

    if args.update:
        update_definitions()
        return

    if args.check_update:
        avail, remote_ver = check_update_available()
        cached = load_cached_definitions()
        print(f"WinIntel v{VERSION}  |  Built-in: {len(CVE_DB)} CVEs")
        print(f"Cached defs : v{cached.get('version','none')} ({cached.get('date','—')})")
        print(f"Remote defs : v{remote_ver}  {'← UPDATE AVAILABLE  →  run --update' if avail else '(up to date)'}")
        return

    if args.generate_definitions:
        generate_definitions_json(args.generate_definitions)
        return

    if args.db_count:
        kb_c    = sum(1 for v in CVE_DB.values() if v.get("confidence")=="kb")
        build_c = sum(1 for v in CVE_DB.values() if v.get("confidence")=="build")
        msf_c   = sum(1 for v in CVE_DB.values() if v.get("msf"))
        swk_c   = sum(1 for v in CVE_DB.values() if v.get("secwiki"))
        edb_c   = sum(1 for v in CVE_DB.values() if v.get("edb"))
        itw_c   = sum(1 for cid in CVE_DB if CVE_META.get(cid,{}).get("itw"))
        kev_c   = sum(1 for cid in CVE_DB if cid in CISA_KEV)
        cats    = {}
        for v in CVE_DB.values():
            cats[v.get("category","")] = cats.get(v.get("category",""),0)+1
        print(f"WinIntel v{VERSION}")
        print(f"Total CVEs : {len(CVE_DB)}  (2003–2026, XP → Win11 24H2)")
        print(f"KB-based   : {kb_c}  → CONFIRMED tier")
        print(f"Build-based: {build_c} → LIKELY tier")
        print(f"ITW        : {itw_c}  (confirmed exploited in the wild)")
        print(f"CISA KEV   : {kev_c}  (federal known-exploited mandate)")
        print(f"MSF modules: {msf_c}")
        print(f"SecWiki    : {swk_c}")
        print(f"ExploitDB  : {edb_c}")
        print(f"\nCategories:")
        for cat, cnt in sorted(cats.items(), key=lambda x:-x[1]):
            print(f"  {CATEGORY_LABEL.get(cat,cat or 'uncategorized'):<22} {cnt}")
        print(f"\nEngine: confidence scoring · exploit chains · EDR awareness · HTML reports")
        return

    # Load and merge cached definitions
    active_db  = CVE_DB
    cache_info = ""
    cached     = load_cached_definitions()
    if cached.get("cves"):
        active_db, new_c, upd_c = merge_db(CVE_DB, cached["cves"])
        cache_info = (
            f"defs v{cached['version']} ({cached['date']}) — "
            f"{len(active_db)} total (+{new_c} new, {upd_c} updated)"
        )

    # Read systeminfo
    if args.input:
        if not os.path.isfile(args.input):
            print(f"[!] Not found: {args.input}", file=sys.stderr); sys.exit(1)
        with open(args.input, encoding="utf-8", errors="ignore") as f:
            raw = f.read()
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        print("[!] Provide -i systeminfo.txt or pipe from stdin")
        p.print_help(); sys.exit(1)

    extra_services = args.services.split(",") if args.services else []
    sysinfo  = parse_systeminfo(raw)

    # Validate we actually parsed a Windows systeminfo - guard against wrong/empty input
    if not sysinfo.get("os_major") and not sysinfo.get("os_build"):
        print("[!] Could not parse a Windows OS version from the input.", file=sys.stderr)
        print("    Expected `systeminfo` output containing an 'OS Version:' line", file=sys.stderr)
        print("    e.g.  OS Version:  10.0.19045 N/A Build 19045", file=sys.stderr)
        print("    Generate it on the target with:  systeminfo > sysinfo.txt", file=sys.stderr)
        sys.exit(1)

    services = infer_services(sysinfo, extra_services)
    vulns    = check_vulns(sysinfo, services, active_db)

    # Apply smart filtering (always on by default; --quick enables aggressive mode)
    filtered_vulns = smart_filter(vulns, args, sysinfo)

    if getattr(args, "quick", False):
        _print_quick(filtered_vulns, sysinfo, services)
    elif args.plain or not HAS_RICH:
        print_plain_output(sysinfo, filtered_vulns, services, args, cache_info)
    else:
        print_rich_output(sysinfo, filtered_vulns, services, args, cache_info)

    if args.csv:        export_csv(filtered_vulns, args.csv)
    if args.json:       export_json(filtered_vulns, args.json)
    if args.msf_script: export_msf(filtered_vulns, args.msf_script)
    if args.html:       export_html(sysinfo, filtered_vulns, services, args.html, cache_info, args)

if __name__ == "__main__":
    main()
