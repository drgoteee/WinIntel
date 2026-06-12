# Publishing WinIntel to GitHub

Step-by-step to get WinIntel live on your GitHub with an auto-built `.exe`.

---

## 1. Create the repository

Go to https://github.com/new

- **Repository name:** `winintel`
- **Description:** `Windows Exploit Intelligence — systeminfo.txt to ranked LPE/RCE attack plan with MSF modules, precompiled binaries, ITW markers, and HTML reports`
- **Visibility:** Public
- **Initialize:** leave ALL checkboxes empty (no README, no .gitignore, no license)

Click **Create repository**.

---

## 2. Push the files

On your machine:

```bash
mkdir -p ~/tools/winintel/.github/workflows
cd ~/tools/winintel

# Copy these files into this folder:
#   winintel.py
#   definitions.json
#   README.md
#   DEMO.md
#   build.py
#   requirements.txt
#   report_grandpa.html  report_optimum.html  report_support.html  report_domain_chains.html
#   .github/workflows/build.yml   (into the workflows subfolder)

# .gitignore
cat > .gitignore << 'GITIGNORE'
__pycache__/
*.py[cod]
dist/
build/
*.spec
.winintel/
*systeminfo*.txt
*_sysinfo.txt
*.csv
*.rc
GITIGNORE

git init
git add winintel.py definitions.json README.md DEMO.md build.py requirements.txt .gitignore
git add .github/workflows/build.yml report_*.html
git commit -m "WinIntel v1.0.0 — 118 CVEs, scoring engine, exploit chains, EDR awareness, HTML reports"
git branch -M main
git remote add origin https://github.com/drgoteee/winintel.git
git push -u origin main
```

If `git push` asks for a password, use a **Personal Access Token**, not your account password:
GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens → generate one with repo write access for `winintel`.

---

## 3. Add topics (makes it discoverable)

On the repo page, click the gear next to **About**, paste into Topics:

```
pentest privilege-escalation windows oscp cve exploit lpe watson wesng ctf windows-kernel post-exploitation kernel-exploit
```

---

## 4. Trigger the .exe build

```bash
git tag v1.0.0
git push origin v1.0.0
```

This fires the GitHub Actions workflow. Watch it at:
`https://github.com/drgoteee/winintel/actions`

In ~3 minutes, two jobs finish (Windows .exe + Linux binary) and both are
automatically attached to a release at:
`https://github.com/drgoteee/winintel/releases/tag/v1.0.0`

---

## 5. Verify

Anyone can now download `winintel.exe` and run it on a Windows target:

```cmd
winintel.exe -i systeminfo.txt --quick
systeminfo | winintel.exe --lpe-only
```

Or run the Python version directly (sidesteps any Defender false-positive on the .exe):

```bash
python winintel.py -i systeminfo.txt --quick
```

---

## Future updates

To ship a new version later:

```bash
# edit winintel.py, bump VERSION, regenerate definitions:
python winintel.py --generate-definitions definitions.json
git add -A && git commit -m "..." && git push
git tag v1.1.0 && git push origin v1.1.0   # builds + publishes new .exe
```

Users pull updated CVE definitions without reinstalling via:
```bash
python winintel.py --update
```
