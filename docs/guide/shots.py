#!/usr/bin/env python3
"""Regenerate the user guide's terminal screenshots from real vault runs.

Every screenshot is the genuine output of the vault binary built from this
checkout, run in a throwaway home directory. The cosmetic touches are: the
sandbox path and file owner are shown as /home/sam and "sam sam", key lines
are highlighted in amber for the reader, and "moment" frames show a prompt
with a cursor, exactly as vault prints it before you type.

Needs: cargo (with the pinned toolchain), cargo-zigbuild and zig for the
build screenshot, python3, and Chrome or Chromium (set CHROME=/path if not
found).
Output: docs/guide/img/*.png
"""

import getpass
import glob
import grp
import html
import os
import pty
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
IMG = os.path.join(HERE, "img")
TOOLS = os.path.join(HERE, ".tools")
FONT_URL = "https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip"
SHOWN_HOME = "/home/sam"
PROMPT_USER = "sam@laptop"


def find_chrome():
    if os.environ.get("CHROME"):
        return os.environ["CHROME"]
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        if shutil.which(name):
            return shutil.which(name)
    found = sorted(glob.glob(os.path.expanduser("~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome")))
    mac = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if found:
        return found[-1]
    if os.path.exists(mac):
        return mac
    sys.exit("shots: no Chrome or Chromium found; set CHROME=/path/to/chrome")


def font_dir():
    target = os.path.join(TOOLS, "jetbrains-mono")
    if not os.path.exists(os.path.join(target, "JetBrainsMono-Regular.ttf")):
        os.makedirs(target, exist_ok=True)
        zpath = os.path.join(TOOLS, "jbm.zip")
        print("shots: fetching JetBrains Mono")
        urllib.request.urlretrieve(FONT_URL, zpath)
        with zipfile.ZipFile(zpath) as z:
            for n in z.namelist():
                base = os.path.basename(n)
                if n.startswith("fonts/ttf/") and base in ("JetBrainsMono-Regular.ttf", "JetBrainsMono-Bold.ttf"):
                    with open(os.path.join(target, base), "wb") as f:
                        f.write(z.read(n))
        os.remove(zpath)
    return target


class Sandbox:
    """A fake home with vault on PATH. Commands run through bash."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="vault-shots-")
        self.home = os.path.join(self.root, "sam")
        self.bin = os.path.join(self.root, "bin")
        os.makedirs(self.home)
        os.makedirs(self.bin)
        subprocess.run(["cargo", "build", "--release", "--locked", "--quiet"], cwd=REPO, check=True)
        shutil.copy2(os.path.join(REPO, "target", "release", "vault"), os.path.join(self.bin, "vault"))

    def env(self, extra=None):
        e = {
            "HOME": self.home,
            "PATH": self.bin + os.pathsep + os.environ["PATH"],
            "LANG": "C.UTF-8",
            "TZ": "Europe/London",
        }
        e.update(extra or {})
        return e

    def run(self, command, passphrase=None, extra_env=None):
        env = self.env(extra_env)
        if passphrase is not None:
            env["VAULT_PASSPHRASE"] = passphrase
        p = subprocess.run(["bash", "-c", command], cwd=self.home, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return self.tidy(p.stdout)

    def run_tty(self, command, passphrase, answer):
        """Run on a pseudo-terminal, typing answer at vault's [y/N] question."""
        env = self.env({"VAULT_PASSPHRASE": passphrase})
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(self.home)
            os.execve("/bin/bash", ["bash", "-c", command], env)
        out = b""
        while b"[y/N]" not in out:
            out += os.read(fd, 1024)
        os.write(fd, answer.encode() + b"\n")
        try:
            while True:
                chunk = os.read(fd, 1024)
                if not chunk:
                    break
                out += chunk
        except OSError:
            pass
        os.waitpid(pid, 0)
        return self.tidy(out.decode().replace("\r\n", "\n"))

    def tidy(self, text):
        owner = " %s %s " % (getpass.getuser(), grp.getgrgid(os.getgid()).gr_name)
        return text.replace(self.home, SHOWN_HOME).replace(owner, " sam sam ").rstrip("\n")

    def write(self, rel, content):
        path = os.path.join(self.home, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(path, mode) as f:
            f.write(content)


# ---- rendering -------------------------------------------------------------

CSS = """
@font-face { font-family: JBM; src: url('file://%(fonts)s/JetBrainsMono-Regular.ttf'); }
@font-face { font-family: JBM; font-weight: bold; src: url('file://%(fonts)s/JetBrainsMono-Bold.ttf'); }
html, body { margin: 0; background: transparent; }
body { padding: 22px 48px 64px; display: flex; gap: 28px; align-items: flex-start; }
.win { width: %(width)dpx; border-radius: 12px; overflow: hidden; background: #0d1326;
       box-shadow: 0 18px 40px rgba(6, 10, 30, .45), 0 0 0 1px rgba(255,255,255,.06); }
.bar { height: 34px; background: linear-gradient(#1b2340, #151c35); display: flex;
       align-items: center; padding: 0 14px; position: relative; }
.dot { width: 12px; height: 12px; border-radius: 50%%; margin-right: 8px; }
.r { background: #ff5f57; } .y { background: #febc2e; } .g { background: #28c840; }
.title { position: absolute; left: 0; right: 0; text-align: center; color: #8b95b7;
         font: 12.5px JBM, monospace; pointer-events: none; }
pre { margin: 0; padding: 16px 20px 18px; font: 14px/21px JBM, monospace; color: #d6ddf2;
      white-space: pre; }
.u { color: #3ee0c5; font-weight: bold; } .p { color: #7aa2ff; font-weight: bold; }
.c { color: #ffffff; font-weight: bold; } .dim { color: #6f7a9c; }
.cur { background: #3ee0c5; color: #0d1326; }
.hl { color: #ffcc66; }
"""


def prompt(cwd="~"):
    return ('<span class="u">%s</span> <span class="p">%s</span> <span class="dim">$</span> '
            % (PROMPT_USER, html.escape(cwd)))


def window(lines, title, width):
    body = "\n".join(lines)
    return ('<div class="win"><div class="bar"><span class="dot r"></span><span class="dot y"></span>'
            '<span class="dot g"></span><div class="title">%s</div></div><pre>%s</pre></div>'
            % (html.escape(title), body))


class Term:
    """Accumulates one terminal window's contents."""

    def __init__(self, box, title="sam@laptop: ~", width=860):
        self.box, self.title, self.width, self.lines = box, title, width, []

    def cmd(self, command, passphrase=None, extra_env=None, shown=None, cwd="~", highlight=()):
        self.lines.append(prompt(cwd) + '<span class="c">%s</span>' % html.escape(shown or command))
        out = self.box.run(command, passphrase, extra_env)
        for line in out.split("\n") if out else []:
            esc = html.escape(line)
            if any(h in line for h in highlight):
                esc = '<span class="hl">%s</span>' % esc
            self.lines.append(esc)
        return out

    def moment(self, command, prompt_text, cwd="~"):
        """A frame captured while vault waits for typed input (no echo)."""
        self.lines.append(prompt(cwd) + '<span class="c">%s</span>' % html.escape(command))
        self.lines.append(html.escape(prompt_text) + ' <span class="cur"> </span>')

    def raw(self, text):
        self.lines.append(text)

    def idle(self, cwd="~"):
        self.lines.append(prompt(cwd) + '<span class="cur"> </span>')

    def html(self):
        return window(self.lines, self.title, self.width)

    def height(self):
        return 34 + 16 + 18 + 21 * max(1, len(self.lines))


def shoot(name, *terms):
    chrome = find_chrome()
    fonts = font_dir()
    total_w = sum(t.width for t in terms) + 28 * (len(terms) - 1) + 96
    total_h = max(t.height() for t in terms) + 22 + 64
    page = "<!doctype html><meta charset=utf-8><style>%s</style><body>%s</body>" % (
        CSS % {"fonts": fonts, "width": terms[0].width}, "".join(t.html() for t in terms))
    if len({t.width for t in terms}) > 1:
        sys.exit("shots: side-by-side windows must share a width")
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
        f.write(page)
    out = os.path.join(IMG, name + ".png")
    subprocess.run([chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-sandbox",
                    "--force-device-scale-factor=2", "--default-background-color=00000000",
                    "--window-size=%d,%d" % (total_w, total_h), "--screenshot=" + out,
                    "file://" + f.name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.remove(f.name)
    print("shots: wrote img/%s.png" % name)


# ---- scenes ----------------------------------------------------------------

def main():
    os.makedirs(IMG, exist_ok=True)
    box = Sandbox()
    P = "correct horse battery staple"
    D = "shopping list 42"

    box.write("Documents/tax-return-2025.pdf", os.urandom(183_402))
    box.write("Documents/passport-scan.jpg", os.urandom(1_204_551))
    box.write("Documents/letters/landlord.txt", "Dear landlord,\n")
    box.write("Documents/letters/bank.txt", "Dear bank,\n")
    box.write("notes.md", "# ideas\n")
    box.write("recipes/pancakes.txt", "flour, eggs, milk\n")
    box.write("recipes/curry.txt", "spices\n")

    t = Term(box)
    t.cmd("vault help")
    shoot("help", t)

    t = Term(box)
    t.moment("vault genkey", "Enter passphrase:")
    shoot("genkey-prompt", t)

    t = Term(box)
    t.moment("vault genkey", "Enter decoy passphrase (empty for none):")
    shoot("genkey-decoy-prompt", t)

    t = Term(box)
    t.cmd("vault genkey", passphrase=P, extra_env={"VAULT_DECOY_PASSPHRASE": D})
    t.cmd("ls -l ~/.vault/")
    shoot("genkey", t)

    t = Term(box)
    t.cmd("vault init")
    t.cmd("ls -A ~/.vault/store/")
    t.cmd("find ~/.vault/store/records -type f | wc -l")
    shoot("init", t)

    t = Term(box)
    t.cmd("vault add Documents/tax-return-2025.pdf", P)
    t.cmd("vault add Documents/passport-scan.jpg id", P)
    t.cmd("vault add Documents/letters", P)
    t.cmd("vault add notes.md", P)
    shoot("add", t)

    t = Term(box)
    t.cmd("vault ls", P)
    t.cmd("vault ls letters", P)
    t.cmd("vault list", P)
    shoot("list", t)

    t = Term(box)
    t.cmd("mkdir -p restored && cd restored && vault get id/passport-scan.jpg", P)
    t.cmd("vault get tax-return-2025.pdf -o restored/tax.pdf", P)
    t.cmd("vault get notes.md", P, highlight=("already exists",))
    shoot("get", t)

    t = Term(box)
    t.cmd("echo '# more ideas' >> notes.md && vault add notes.md", P, highlight=("replaced",))
    t.cmd("vault mv notes.md ideas/notes.md", P)
    t.cmd("vault rm letters/bank.txt", P)
    t.cmd("vault list", P)
    shoot("mv-rm", t)

    t = Term(box, title="sam@laptop: ~/.vault/store")
    t.cmd("cd .vault/store && ls -l records/*/* | head -5", cwd="~/.vault/store", shown="ls -l records/*/* | head -5")
    shoot("on-disk", t)

    # decoy: fill the decoy side, then show both views side by side
    box.run("vault add recipes", D)
    box.run("vault add notes.md shopping", D)
    real = Term(box, title="real passphrase", width=600)
    real.cmd("vault list", P)
    decoy = Term(box, title="decoy passphrase", width=600)
    decoy.cmd("vault list", D)
    shoot("decoy-views", real, decoy)

    t = Term(box)
    t.cmd("vault get ideas/notes.md -o /tmp/x.md", D, highlight=("not in the vault",))
    t.cmd("find ~/.vault/store/records -type f | wc -l")
    shoot("decoy-hidden", t)

    # migrate: one file is already in the vault, so it asks first
    box.write("Scans/receipts/march.pdf", os.urandom(48_113))
    box.write("Scans/receipts/april.pdf", os.urandom(51_870))
    box.run("vault add Scans/receipts/march.pdf receipts", P)
    t = Term(box)
    t.lines.append(prompt() + '<span class="c">vault migrate Scans/receipts</span>')
    for line in box.run_tty("vault migrate Scans/receipts", P, "y").split("\n"):
        esc = html.escape(line)
        if "[y/N]" in line:
            esc = '<span class="hl">%s</span>' % esc
        t.lines.append(esc)
    t.cmd("ls Scans")
    shoot("migrate", t)

    # rm -r: lists the folder, asks, then frees the space
    t = Term(box)
    t.cmd("vault ls", P)
    t.lines.append(prompt() + '<span class="c">vault rm -r receipts</span>')
    for line in box.run_tty("vault rm -r receipts", P, "y").split("\n"):
        esc = html.escape(line)
        if "[y/N]" in line:
            esc = '<span class="hl">%s</span>' % esc
        t.lines.append(esc)
    t.cmd("vault ls", P)
    shoot("rm-r", t)

    # absorb: a tar archive piped in, here pulled from a gzipped tarball
    box.write("Projects/website/index.html", "<h1>hello</h1>\n")
    box.write("Projects/website/css/site.css", "body{}\n")
    box.write("Projects/website/img/logo.png", os.urandom(24_311))
    t = Term(box)
    t.cmd("tar -czf website.tar.gz -C Projects website")
    t.cmd("vault absorb backups < website.tar.gz", P)
    t.cmd("tar -c recipes | vault absorb old", P)
    t.cmd("vault list backups", P)
    shoot("absorb", t)

    # mirror: a tiny local site, served on localhost
    site = os.path.join(box.root, "site")
    for rel, body in {"index.html": '<a href="/about.html">About</a> <link href="/style.css">',
                      "about.html": '<a href="/">Home</a> <img src="/img/me.png">',
                      "style.css": "body{background:url(/img/bg.png)}",
                      "img/me.png": "png", "img/bg.png": "png"}.items():
        os.makedirs(os.path.dirname(os.path.join(site, rel)), exist_ok=True)
        with open(os.path.join(site, rel), "w") as f:
            f.write(body)
    srv = subprocess.Popen([sys.executable, "-m", "http.server", "8000", "--bind", "127.0.0.1"],
                           cwd=site, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    t = Term(box)
    t.cmd("vault mirror http://localhost:8000/ sites", P)
    t.cmd("vault get sites/localhost:8000/about.html && cat about.html", P)
    shoot("mirror", t)
    srv.terminate()

    # errors
    t = Term(box)
    t.cmd("vault list", "hunter2", highlight=("incorrect",))
    t.cmd("vault get does-not-exist.txt", P, highlight=("not in",))
    t.cmd("vault add notes.md ../escape", P, highlight=("invalid",))
    t.cmd("vault list --vault ~/Desktop", P, highlight=("not a vault",))
    t.cmd("vault init", highlight=("already",))
    shoot("errors", t)

    # locking: start a big add, then a second writer while it runs
    box.write("big-video.mkv", os.urandom(600 << 20))
    first = Term(box, title="terminal 1", width=600)
    second = Term(box, title="terminal 2", width=600)
    env = box.env({"VAULT_PASSPHRASE": P})
    a = subprocess.Popen(["bash", "-c", "vault add big-video.mkv"], cwd=box.home, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.5)
    second.cmd("vault add recipes/curry.txt", P, highlight=("waiting",))
    first.lines.append(prompt() + '<span class="c">vault add big-video.mkv</span>')
    first.lines += [html.escape(box.tidy(l)) for l in a.communicate()[0].rstrip("\n").split("\n")]
    shoot("locking", first, second)
    os.remove(os.path.join(box.home, "big-video.mkv"))

    # automation
    t = Term(box)
    t.cmd("export VAULT_PASSPHRASE='correct horse battery staple'", shown="export VAULT_PASSPHRASE=…")
    t.cmd("vault list ideas", P)
    t.cmd("vault get nope 2>/dev/null; echo \"exit code: $?\"", P)
    shoot("scripting", t)

    # cp, folder mv, get -r
    t = Term(box)
    t.cmd("vault cp -r letters archive/2025", P)
    t.cmd("vault mv ideas/notes.md archive/", P)
    t.cmd("vault ls archive", P)
    t.cmd("vault get -r archive -o restored/archive", P)
    shoot("cp-mv", t)

    # unlock: one passphrase, then commands stop asking until lock
    t = Term(box)
    t.cmd("vault unlock", P)
    t.cmd("vault ls")
    t.cmd("vault get archive/notes.md -o /tmp/notes.md")
    t.cmd("vault lock")
    t.moment("vault ls", "Enter passphrase:")
    shoot("unlock", t)

    # building, into a temporary OUT so an existing dist/ is left alone
    rel = tempfile.mkdtemp(prefix="vault-release-")
    targets = "linux/amd64 linux/arm64 linux/armv7 windows/amd64"
    t = Term(box, title="sam@laptop: ~/src/vault")
    out = subprocess.run(["./build.sh"], cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, env=dict(os.environ, TARGETS=targets, OUT=rel)).stdout
    sums = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=rel,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout
    t.lines.append(prompt("~/src/vault") + '<span class="c">export TARGETS="%s"</span>' % targets)
    t.lines.append(prompt("~/src/vault") + '<span class="c">OUT=/tmp/release ./build.sh</span>')
    t.lines += [html.escape(l.replace(rel, "/tmp/release")) for l in out.rstrip("\n").split("\n")]
    t.lines.append(prompt("~/src/vault") + '<span class="c">cd /tmp/release &amp;&amp; sha256sum -c SHA256SUMS</span>')
    t.lines += [html.escape(l) for l in sums.rstrip("\n").split("\n")]
    shoot("build", t)
    shutil.rmtree(rel, ignore_errors=True)

    shutil.rmtree(box.root, ignore_errors=True)


if __name__ == "__main__":
    main()
