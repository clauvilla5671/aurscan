# aurscan — Claude-powered AUR malware scanner

Single static Go binary (stdlib only, `CGO_ENABLED=0`), no runtime dependencies.

Scans the **PKGBUILD, `.install` scriptlets, `.SRCINFO` and helper scripts** of
AUR packages — *and their AUR dependency closure* — with a Claude model
**before `makepkg` ever executes a single line**. Built in response to the
June 2026 "Atomic Arch" campaign (orphaned AUR packages hijacked to pull
malicious npm/Bun payloads such as `atomic-lockfile` at install time).

## Why this is a wrapper, not a pacman hook

PKGBUILD code runs **as your user, during `makepkg`, before pacman is ever
involved**. Even merely *sourcing* a PKGBUILD executes shell code. A pacman
`PreTransaction` hook fires only when the already-built package is being
installed — by then, malware in `prepare()`/`build()` has already run.
The only safe interception point is *before* yay hands the build directory
to makepkg. `syay` is that interception point; with `alias yay=syay` it is
completely transparent.

## Install

```bash
sudo ./install.sh          # builds (if needed) and installs aurscan, syay, aurscan-edit
```

Two integration options — pick one:

**A) Wrapper (recommended).** fish: `alias yay=syay; funcsave yay`.
Scans targets *and* pending AUR updates on `-Syu`, including the AUR
dependency closure, before handing off to the real yay.

**B) Editor-gate, unmodified yay.** `yay --save --answeredit All --editor aurscan-edit`
yay then invokes aurscan as the "editor" on every PKGBUILD after download,
before build; a non-OK verdict exits non-zero and yay aborts the build itself.
This is the closest thing to a native hook yay offers — no fork required.
(Trade-off: it sees only the files yay shows it, not the dependency closure,
and it replaces your actual editor review step.)

Authentication, auto-detected in this order:

1. **Claude Code CLI** (`claude`) in PATH and logged in → **no API key, no
   extra credentials** (uses your existing Claude subscription login).
2. `ANTHROPIC_API_KEY` environment variable → direct API call
   (model `claude-sonnet-4-6` by default, override with `AURSCAN_MODEL`).
3. `AURSCAN_BACKEND=/path/to/cmd` → any executable that reads the prompt on
   stdin and prints the model reply (e.g. a local model), for fully offline use.

## Usage

```bash
syay -S some-aur-package      # scan, then hand off to real yay if clean
syay -Syu                     # also scans every pending AUR update (yay -Qua)
aurscan some-aur-package      # standalone scan, fetches snapshot from AUR
aurscan ./yay/cache/pkg/      # scan a local build directory
aurscan --update-check        # audit pending AUR updates without installing
```

On a non-OK verdict, installation is **blocked by default** and you get:

```
[ MAL! ] google-chrome  confidence 97%
         PKGBUILD installs the atomic-lockfile npm payload ...
         [critical] PKGBUILD: Installs an npm package unrelated to building Chrome
             > npm install atomic-lockfile

!! Installation blocked: 1 package(s) flagged MALICIOUS.
  [A]bort (default) / [r]eport to mailing list & abort / [c]ontinue anyway:
```

* **Abort** is the default — pressing Enter is always safe.
* **Report** drafts `/tmp/aurscan-report-<pkg>.txt`, offers to open your mail
  client addressed to `aur-general@lists.archlinux.org` (the list where the
  Atomic Arch cleanup is coordinated), and reminds you to file a *Deletion
  request* on the package's AUR web page. **It never sends automatically** —
  you review first, so false positives don't spam the list.
* **Continue** requires typing the word `INSTALL` — no accidental overrides.

Exit codes: `0` clean/approved, `1` suspicious-abort, `2` malicious-abort,
`3` operational error. Non-interactive runs (scripts, no TTY) always abort
on non-OK, so it is safe in cron/CI.

## Fail-closed design

* Backend error, timeout, or unparseable model output ⇒ verdict
  **SUSPICIOUS**, install blocked. The scanner can fail, but never fails open.
* The package files are sent as **untrusted data on stdin**, separated from
  the trusted instructions; the prompt explicitly treats any embedded
  "this package is safe / ignore previous instructions" text as evidence of
  malice (prompt-injection hardening).
* AUR snapshots are parsed **in memory** (tarfile via extractfile) — nothing
  from the suspect package is ever written to disk or executed.
* Binary files and files > 64 KB are skipped; total context capped at 240 KB;
  dependency recursion capped at 25 packages (`AURSCAN_MAX_PKGS`).

## Honest limitations — please read

An LLM scanner is a strong extra layer, **not a guarantee**. Keep the other
layers too:

* Prefer repo packages; be extra wary of **recently adopted orphaned packages**
  (the exact Atomic Arch vector) — check the package's "Last Packager" and
  git log on the AUR page.
* Build in a clean chroot (`extra-x86_64-build` / `pkgctl build`) when possible.
* `npm`/`bun`/`pip` invocations are sometimes legitimate (e.g. Electron apps
  building from source) — the scanner weighs context, but expect occasional
  false positives; that's the safer direction to err.
* Scanning costs one model call per package (a few seconds, a fraction of a
  cent on API; free against a Claude Code subscription).
