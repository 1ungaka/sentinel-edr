#!/usr/bin/env python3
"""build-lab-corpus.py — build the local "lab" recall/specificity corpus.

The held-out MalwareBazaar corpus (corpus/heldout) needs an API key and live
malware. This one needs neither: it measures the engine against the real
offensive tooling a Kali host already ships, plus payloads msfvenom generates,
and against benign files from the same machine. It reads and hashes files; it
never executes one. Nothing it produces is committed (see .gitignore).

The split is what makes the number mean something:

  * Positives are split by GROUP (a tool, or an msfvenom payload), stratified
    by class, so no sibling of a dev sample sits in heldout. Measuring heldout
    therefore asks "does this catch a tool the rules were not written from?".
  * Benign files are split per file.
  * The assignment is a pure function of the group name, so it is reproducible
    and cannot be nudged after seeing a result.

Rule: author and tune against manifest-dev.json only. Read aggregate numbers
from manifest-heldout.json, never its per-sample misses, and only to report.

Usage:
  scripts/build-lab-corpus.py generate     # msfvenom payloads (minutes)
  scripts/build-lab-corpus.py manifest     # write the two manifests
  scripts/build-lab-corpus.py wide         # large benign sweep, heldout excluded
  scripts/build-lab-corpus.py sources DIR  # revshells, LOLBAS and GTFOBins data in DIR

Dual-use programs (netcat, debuggers, VNC viewers, wget) are in neither
population: they are not malware and not a fair benign control.
"""

import concurrent.futures
import hashlib
import json
import os
import random
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LAB = REPO / "corpus" / "lab"
GEN = LAB / "generated"
LHOST = "192.0.2.1"  # RFC 5737 TEST-NET-1: routes nowhere.
LPORT = "8443"
MAX_SIZE = 64 << 20
RETRIEVED = "2026-11-06T00:00:00Z"

WIN_PAYLOADS = [
    ("windows/meterpreter/reverse_tcp", "x86"),
    ("windows/meterpreter/reverse_https", "x86"),
    ("windows/shell_reverse_tcp", "x86"),
    ("windows/shell_bind_tcp", "x86"),
    ("windows/x64/meterpreter/reverse_tcp", "x64"),
    ("windows/x64/meterpreter/reverse_https", "x64"),
    ("windows/x64/shell_reverse_tcp", "x64"),
    ("windows/x64/shell_bind_tcp", "x64"),
]
WIN_FORMATS = [
    ("exe", "msf-exe"),
    ("exe-service", "msf-exe"),
    ("dll", "msf-exe"),
    ("raw", "msf-shellcode"),
    ("psh", "msf-script"),
    ("psh-cmd", "msf-script"),
    ("psh-reflection", "msf-script"),
    ("vba", "msf-script"),
    ("vbs", "msf-script"),
    ("hta-psh", "msf-script"),
    ("aspx", "msf-script"),
    ("c", "msf-script"),
]
LINUX_PAYLOADS = [
    "linux/x64/shell_reverse_tcp",
    "linux/x64/shell_bind_tcp",
    "linux/x64/meterpreter/reverse_tcp",
    "linux/x86/shell_reverse_tcp",
    "linux/x86/shell_bind_tcp",
    "linux/x86/meterpreter/reverse_tcp",
]
SCRIPT_PAYLOADS = [
    ("php/meterpreter/reverse_tcp", "raw", "php"),
    ("php/reverse_php", "raw", "php"),
    ("python/meterpreter/reverse_tcp", "raw", "py"),
    ("python/shell_reverse_tcp", "raw", "py"),
    ("cmd/unix/reverse_bash", "raw", "sh"),
    ("cmd/unix/reverse_perl", "raw", "sh"),
    ("cmd/unix/reverse_python", "raw", "sh"),
    ("cmd/unix/reverse_netcat", "raw", "sh"),
    ("java/jsp_shell_reverse_tcp", "raw", "jsp"),
]


def slug(s):
    return s.replace("/", "_")


def jobs():
    """Every msfvenom invocation as (class, group, path, argv)."""
    base = ["msfvenom", f"LHOST={LHOST}", f"LPORT={LPORT}"]
    out = []
    for payload, arch in WIN_PAYLOADS:
        for fmt, cls in WIN_FORMATS:
            p = GEN / cls / f"{slug(payload)}.{fmt}"
            out.append((cls, payload, p, base + ["-p", payload, "-f", fmt, "-o", str(p)]))
        enc = "x86/shikata_ga_nai" if arch == "x86" else "x64/xor_dynamic"
        for fmt, cls in (("exe", "msf-exe"), ("raw", "msf-shellcode")):
            p = GEN / cls / f"{slug(payload)}.enc.{fmt}"
            out.append((cls, payload, p, base + ["-p", payload, "-e", enc, "-i", "3", "-f", fmt, "-o", str(p)]))
    for payload in LINUX_PAYLOADS:
        for fmt, cls, ext in (("elf", "msf-elf", "elf"), ("elf-so", "msf-elf", "so"), ("raw", "msf-shellcode", "linux.raw")):
            p = GEN / cls / f"{slug(payload)}.{ext}"
            out.append((cls, payload, p, base + ["-p", payload, "-f", fmt, "-o", str(p)]))
    for payload, fmt, ext in SCRIPT_PAYLOADS:
        p = GEN / "msf-script" / f"{slug(payload)}.{ext}"
        out.append(("msf-script", payload, p, base + ["-p", payload, "-f", fmt, "-o", str(p)]))
    return out


def run_job(job):
    _, _, path, argv = job
    if path.exists() and path.stat().st_size:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    if r.returncode or not path.exists():
        return f"{path.name}: {r.stderr.strip().splitlines()[-1:] or 'failed'}"
    path.chmod(0o644)
    return None


def generate():
    if not shutil.which("msfvenom"):
        sys.exit("msfvenom not found")
    js = jobs()
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        failures = [f for f in ex.map(run_job, js) if f]
    for f in failures:
        print("FAILED", f, file=sys.stderr)
    print(f"{len(js) - len(failures)}/{len(js)} payloads present under {GEN}")

    # UPX variants of the real PE hacktools are a packed-evasion control.
    upx = GEN / "upx"
    upx.mkdir(parents=True, exist_ok=True)
    if shutil.which("upx"):
        for src in tool_binaries():
            dst = upx / src.name
            if dst.exists():
                continue
            shutil.copyfile(src, dst)
            r = subprocess.run(["upx", "-q", "-q", str(dst)], capture_output=True)
            if r.returncode:
                dst.unlink(missing_ok=True)
            else:
                dst.chmod(0o644)


def tool_binaries():
    wr = Path("/usr/share/windows-resources")
    wb = Path("/usr/share/windows-binaries")
    picks = [wr / "mimikatz/Win32/mimikatz.exe", wr / "mimikatz/x64/mimikatz.exe",
             wr / "wce/wce32.exe", wr / "wce/wce64.exe", wb / "fgdump/fgdump.exe",
             wb / "fgdump/PwDump.exe", wb / "klogger.exe"]
    return [p for p in picks if p.is_file()]


def walk(root, exts=None, exclude=()):
    root = Path(root)
    if not root.exists():
        return
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not any(x in f"{dirpath}/{d}" for x in exclude))
        for name in sorted(files):
            p = Path(dirpath) / name
            if exts is not None and p.suffix.lower() not in exts:
                continue
            try:
                st = p.lstat()
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and 0 < st.st_size <= MAX_SIZE:
                yield p


def positives():
    """Yield (class, group, path, source) for every malicious sample."""
    web = {".php", ".php3", ".asp", ".aspx", ".jsp", ".jspx", ".cfm", ".cgi", ".pl", ".war"}
    for root in ("/usr/share/webshells", "/usr/share/laudanum"):
        for p in walk(root, web):
            yield "webshell", f"webshell:{p.stem}", p, "kali:webshells"
    ps = {".ps1", ".psm1"}
    nishang = Path("/usr/share/windows-resources/nishang")
    for p in walk(nishang, ps):
        yield "offensive-powershell", f"nishang:{p.relative_to(nishang).parts[0]}", p, "kali:nishang"
    ps_root = Path("/usr/share/windows-resources/powersploit")
    for p in walk(ps_root, ps):
        yield "offensive-powershell", f"powersploit:{p.relative_to(ps_root).parts[0]}", p, "kali:powersploit"
    emp = Path("/usr/share/windows-resources/powershell-empire")
    for p in walk(emp, ps, exclude=("/test",)):
        yield "offensive-powershell", f"empire:{p.parent.name}", p, "kali:powershell-empire"

    wr = Path("/usr/share/windows-resources")
    wb = Path("/usr/share/windows-binaries")
    for tool, root in (("mimikatz", wr / "mimikatz"), ("wce", wr / "wce"),
                       ("fgdump", wb / "fgdump"), ("sbd", wr / "sbd"), ("dbd", wr / "dbd")):
        for p in walk(root, {".exe", ".dll", ".sys"}):
            yield "pe-hacktool", f"tool:{tool}", p, f"kali:{tool}"
    if (wb / "klogger.exe").is_file():
        yield "pe-hacktool", "tool:klogger", wb / "klogger.exe", "kali:windows-binaries"
    for p in walk("/usr/share/peass/winpeas", {".exe"}):
        yield "pe-hacktool", "tool:winpeas", p, "kali:peass"
    for p in walk("/usr/share/peass/linpeas"):
        if "darwin" not in p.name:
            yield "linux-hacktool", "tool:linpeas", p, "kali:peass"

    for cls, group, path, _ in jobs():
        if path.is_file():
            yield cls, f"msf:{group}", path, "msfvenom"
    for p in walk(GEN / "upx"):
        yield "packed-hacktool", f"upx:{p.name}", p, "upx-of-kali-tool"


BENIGN_EXCLUDE = (
    "metasploit", "exploitdb", "seclists", "webshells", "laudanum", "powersploit",
    "nishang", "peass", "windows-resources", "windows-binaries", "impacket", "responder",
    "sqlmap", "set/", "beef", "armitage", "/wordlists", "powershell-empire", "crackmapexec",
    "netexec", "nxc", "/cau", "/.cache", "/.local/share/Trash", "/.msf4", "lsassy", "pypykatz",
    "evil_winrm", "evil-winrm", "/go/pkg", "/ghidra", "kali-defaults", "pwntools", "pwnlib",
)
BENIGN_QUOTAS = [
    # (bucket, roots, extensions or None for "the ELF sniff", quota)
    ("elf", ("/usr/bin", "/usr/sbin", "/usr/lib/x86_64-linux-gnu", "/usr/libexec"), "elf", 1500),
    ("pe", ("/usr/x86_64-w64-mingw32", "/usr/lib/gcc/x86_64-w64-mingw32", "/usr/lib/dotnet", "/usr/share/dotnet", "/usr/lib/python3"), {".dll", ".exe"}, 900),
    ("shell", ("/usr/bin", "/usr/lib", "/usr/share", "/etc"), {".sh", ".bash"}, 800),
    ("python", ("/usr/lib/python3", "/usr/lib/python3.13"), {".py"}, 900),
    ("perl", ("/usr/share/perl", "/usr/lib/x86_64-linux-gnu/perl"), {".pl", ".pm"}, 400),
    ("js", ("/usr/share/javascript", "/usr/lib/node_modules", "/usr/share/nodejs"), {".js"}, 400),
    ("php", ("/usr/share", "/usr/lib", "/home/kali"), {".php"}, 400),
    ("powershell", ("/home/kali", "/usr/share/dotnet", "/usr/lib/dotnet", "/etc/skel"), {".ps1", ".psm1"}, 300),
    ("web", ("/usr/share", "/home/kali"), {".jsp", ".asp", ".aspx"}, 100),
]


def is_elf(p):
    try:
        with open(p, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def benign():
    for bucket, roots, kind, quota in BENIGN_QUOTAS:
        pool = {}
        for root in roots:
            for p in walk(root, None if kind == "elf" else kind, BENIGN_EXCLUDE):
                if any(x in str(p) for x in BENIGN_EXCLUDE):
                    continue
                if kind == "elf" and not is_elf(p):
                    continue
                pool[str(p)] = p
        keys = sorted(pool)
        random.Random(f"cau-lab-{bucket}").shuffle(keys)
        for k in keys[:quota]:
            yield bucket, pool[k]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def assign_groups(groups_by_class):
    """Stratified, deterministic 50/50: within a class, order groups by a hash
    of their name and alternate. Keeps both splits populated in small classes."""
    split = {}
    for cls, groups in groups_by_class.items():
        ordered = sorted(groups, key=lambda g: hashlib.sha256(g.encode()).hexdigest())
        for i, g in enumerate(ordered):
            split[g] = "dev" if i % 2 == 0 else "heldout"
    return split


def manifest():
    seen = {}
    rows = []
    for cls, group, path, source in positives():
        digest = sha256(path)
        if digest in seen:  # the same bytes under two paths: one sample, one group
            continue
        seen[digest] = group
        rows.append((cls, group, path, source, digest))

    by_class = {}
    for cls, group, *_ in rows:
        by_class.setdefault(cls, set()).add(group)
    split = assign_groups(by_class)

    out = {"dev": [], "heldout": []}
    for cls, group, path, source, digest in rows:
        out[split[group]].append({
            "id": f"{cls}/{digest[:16]}",
            "path": str(path).lstrip("/"),
            "label": cls,
            "sha256": digest,
            "tags": [f"group:{group}"],
            "provenance": {"source": source, "license": "as-shipped", "retrieved": RETRIEVED},
        })
    n_mal = {k: len(v) for k, v in out.items()}

    for bucket, path in benign():
        try:
            digest = sha256(path)
        except OSError:
            continue
        if digest in seen:
            continue
        seen[digest] = "benign"
        s = "dev" if int(hashlib.sha256(str(path).encode()).hexdigest(), 16) % 2 == 0 else "heldout"
        out[s].append({
            "id": f"clean-{bucket}/{digest[:16]}",
            "path": str(path).lstrip("/"),
            "label": "clean",
            "sha256": digest,
            "tags": [f"bucket:{bucket}"],
            "provenance": {"source": "local-install", "license": "as-shipped", "retrieved": RETRIEVED},
        })

    LAB.mkdir(parents=True, exist_ok=True)
    for name, samples in out.items():
        doc = {
            "schema_version": "1",
            "name": f"lab-{name}",
            "description": f"Local lab corpus, {name} split. Generated by scripts/build-lab-corpus.py.",
            "root": "/",
            "samples": samples,
        }
        (LAB / f"manifest-{name}.json").write_text(json.dumps(doc, indent=1) + "\n")
        print(f"{name}: {n_mal[name]} malicious, {len(samples) - n_mal[name]} benign")
    summary = {}
    for name, samples in out.items():
        for s in samples:
            k = s["label"]
            summary.setdefault(k, {"dev": 0, "heldout": 0})[name] += 1
    for k in sorted(summary):
        print(f"  {k:24s} dev {summary[k]['dev']:5d}  heldout {summary[k]['heldout']:5d}")


def js_strings(text, section, stop):
    """Pull name/command pairs out of one array in revshells' data.js.

    The file is parsed as text, never run: it is third-party JavaScript.
    """
    start = text.index(section)
    body = text[start:text.index(stop, start)]
    out = []
    for m in re.finditer(r'"name":\s*("(?:[^"\\]|\\.)*"),\s*"command":\s*("(?:[^"\\]|\\.)*")', body):
        try:
            out.append((json.loads(m.group(1), strict=False), json.loads(m.group(2), strict=False)))
        except ValueError:
            continue
    return out


def tool_of(name):
    """The tool a template belongs to: 'nc mkfifo' and 'nc -e' are one group."""
    t = re.sub(r"[^a-z0-9+#.]", " ", name.lower()).split()
    return t[0] if t else "x"


def fill(cmd):
    return (cmd.replace("{ip}", LHOST).replace("{port}", LPORT).replace("{shell}", "/bin/sh")
            .replace("{payload}", "id"))


def gtfobin_blocks(text, function):
    """The `code` blocks of one function in a GTFOBins entry, by indentation."""
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        if line != f"  {function}:":
            continue
        for j in range(i + 1, len(lines)):
            if lines[j] and not lines[j].startswith("   ") and not lines[j].startswith("  -"):
                break
            if lines[j].lstrip().startswith("- code: |-") or lines[j].strip() == "code: |-":
                indent = len(lines[j]) - len(lines[j].lstrip()) + 2
                block = []
                for k in range(j + 1, len(lines)):
                    if lines[k].strip() and len(lines[k]) - len(lines[k].lstrip()) < indent:
                        break
                    block.append(lines[k].strip())
                out.append("\n".join(block).strip())
    return out


def sources(root):
    """Turn the public catalogues into samples.

    revshells keeps a real split: vectors are written from its dev half. LOLBAS
    and GTFOBins are catalogues the detection content is derived from, so their
    manifest measures coverage of the catalogue, not a detection rate.
    """
    root = Path(root)
    written = []

    def emit(cls, group, name, body, source):
        d = GEN / cls
        d.mkdir(parents=True, exist_ok=True)
        p = d / (re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:80] + ".txt")
        n = 1
        while p.exists() and p.read_text() != body:
            p = d / (re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:76] + f"_{n}.txt")
            n += 1
        p.write_text(body)
        written.append((cls, group, p, source))

    text = (root / "revshells/data.js").read_text(errors="replace")
    for section, stop in (("reverseShellCommands = ", "bindShellCommands = "), ("bindShellCommands = ", "msfvenomCommands = ")):
        for name, cmd in js_strings(text, section, stop):
            emit("revshell-oneliner", f"rev:{tool_of(name)}", name, fill(cmd) + "\n", "revshells")

    for entry in json.loads((root / "lolbas/lolbas.json").read_text()):
        for i, c in enumerate(entry.get("Commands") or []):
            if c.get("Category") in ("Download", "Execute", "AWL Bypass", "UAC Bypass", "Dump", "Tamper"):
                cmd = re.sub(r"\{REMOTEURL(?::([^}]*))?\}", lambda m: "http://192.0.2.1/x" + (m.group(1) or ""), c.get("Command") or "")
                cmd = re.sub(r"\{PATH_SMB(?::([^}]*))?\}", lambda m: "\\\\192.0.2.1\\share\\x" + (m.group(1) or ""), cmd)
                emit("lolbin-command", f"lolbas:{entry['Name']}", f"{entry['Name']}_{i}", cmd + "\n", "lolbas")

    gt = next((root / "gtfobins/x").iterdir()) / "_gtfobins"
    for f in sorted(gt.iterdir()):
        body = f.read_text(errors="replace")
        for fn in ("reverse-shell", "bind-shell"):
            for i, code in enumerate(gtfobin_blocks(body, fn)):
                code = code.replace("attacker.com", LHOST).replace("12345", LPORT)
                emit("gtfobin-netshell", f"gtfo:{f.name}", f"{f.name}_{fn}_{i}", code + "\n", "gtfobins")

    rows = []
    for cls, group, p, source in written:
        rows.append((cls, group, p, source, sha256(p)))
    by_class = {}
    for cls, group, *_ in rows:
        by_class.setdefault(cls, set()).add(group)
    split = assign_groups({"revshell-oneliner": by_class.get("revshell-oneliner", set())})

    def sample(cls, group, p, source, digest):
        return {"id": f"{cls}/{digest[:16]}", "path": str(p).lstrip("/"), "label": cls, "sha256": digest,
                "tags": [f"group:{group}"], "provenance": {"source": source, "license": "see-upstream", "retrieved": RETRIEVED}}

    out = {"revshell-dev": [], "revshell-heldout": [], "catalog": []}
    seen = set()
    for row in rows:
        if row[4] in seen:
            continue
        seen.add(row[4])
        key = "catalog" if row[0] != "revshell-oneliner" else f"revshell-{split[row[1]]}"
        out[key].append(sample(*row))
    for key, samples in out.items():
        doc = {"schema_version": "1", "name": f"lab-{key}", "description": f"{key}: generated by scripts/build-lab-corpus.py sources.",
               "root": "/", "samples": samples}
        (LAB / f"manifest-{key}.json").write_text(json.dumps(doc, indent=1) + "\n")
        print(f"{key}: {len(samples)}")


def wide(limit=25000):
    """A large benign sweep for false positives, kept apart from the score.

    Heldout's benign files are excluded so triaging a hit here cannot leak into
    tuning. Offensive trees are excluded exactly as for the benign split.
    """
    held = {s["sha256"] for s in json.loads((LAB / "manifest-heldout.json").read_text())["samples"]}
    roots = ("/usr", "/etc", "/opt", "/home/kali/.nuget", "/home/kali/.cargo", "/home/kali/.local/lib")
    keep = {".py", ".pl", ".pm", ".rb", ".sh", ".bash", ".js", ".php", ".ps1", ".psm1", ".java", ".jsp", ".asp",
            ".aspx", ".cfm", ".cgi", ".c", ".h", ".cs", ".vb", ".lua", ".dll", ".exe", ".so", ".conf", ".md", ".txt", ""}
    pool = []
    for root in roots:
        for p in walk(root, keep, BENIGN_EXCLUDE):
            if not any(x in str(p) for x in BENIGN_EXCLUDE):
                pool.append(p)
    random.Random("cau-lab-wide").shuffle(pool)
    samples, seen = [], set()
    for p in pool:
        if len(samples) >= limit:
            break
        try:
            digest = sha256(p)
        except OSError:
            continue
        if digest in held or digest in seen:
            continue
        seen.add(digest)
        samples.append({"id": f"wide/{digest[:16]}", "path": str(p).lstrip("/"), "label": "clean", "sha256": digest,
                        "provenance": {"source": "local-install", "license": "as-shipped", "retrieved": RETRIEVED}})
    doc = {"schema_version": "1", "name": "lab-wide",
           "description": "Wide benign sweep, heldout excluded. Generated by scripts/build-lab-corpus.py.",
           "root": "/", "samples": samples}
    (LAB / "manifest-wide.json").write_text(json.dumps(doc, indent=1) + "\n")
    print(f"wide: {len(samples)} benign (from {len(pool)} candidates)")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "generate":
        generate()
    elif cmd == "manifest":
        manifest()
    elif cmd == "wide":
        wide()
    elif cmd == "sources":
        sources(sys.argv[2])
    else:
        sys.exit(__doc__)
