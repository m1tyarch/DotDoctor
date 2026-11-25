# DotDoctor

CLI tool for Arch Linux and CachyOS diagnostics, system upgrades, and maintenance.

Arch Linux / CachyOS · Python 3.11+ · MIT · [Reference](docs/reference.md) · [Releases](https://github.com/m1tyarch/DotDoctor/releases)

https://github.com/user-attachments/assets/8a176002-5070-47a3-a2e8-a789da28a998

<sub>Illustrative report. Checks depend on your installed tools and configuration.</sub>

## Install

Requires an Arch-based Linux distribution with `pacman`, `systemd`, and Python 3.11+.

### Arch package (recommended)

Installs `/usr/bin/dotdoctor`, Bash/Zsh/Fish completions, and tracks dependencies via `pacman` (see [packaging/aur/README.md](packaging/aur/README.md)):

```bash
git clone https://github.com/m1tyarch/DotDoctor.git
cd DotDoctor/packaging/aur/dotdoctor-git
makepkg -si
```

### Isolated install (`pipx`)

```bash
pipx install git+https://github.com/m1tyarch/DotDoctor.git
```

## Usage

| Command | Behavior | Privileges |
| --- | --- | --- |
| `dotdoctor` | Parallel read-only scan across enabled checks. On TTY, prompts to run upgrades or fixes when findings exist (`[y/N]`). | Regular user |
| `dotdoctor --sysup` (`-u`) | Pre-flight checks → snapshot (`snapper`/`timeshift`) → mirrors → keyring → `paru`/`yay`/`pacman -Syu` → Flatpak → `paccache` → Oh-My-Zsh → `fwupd` → `.pacnew` and post-flight checks. | `sudo` (cached up front) |
| `dotdoctor --fix` (`-f`) | Interactive remediation (`[y/N]`) for cache, orphans, unused Flatpaks, `.pacnew`, journal, failed units, TRIM, Btrfs scrub, timers, backups, and missing package files. | `sudo` per action |

Flags:

* `-a`, `--all` — include `PASS` checks in output.
* `-v`, `--verbose` — print detailed findings, package version lists, and per-check timings.
* `-d`, `--disable-check <id>` — skip a check for this run (repeatable, e.g. `-d sys.firmware`).
* `-c`, `--config <path>` — use a specific YAML config file.
* `--json` / `--json-output <path>` — emit structured JSON to stdout or a file.
* `-V`, `--version` — print version and exit.

## Checks

Runs up to **26 modular checks** concurrently based on installed tools and configuration:

| Category | Coverage | Tools |
| --- | --- | --- |
| **Updates** | Official packages, AUR, Flatpak, firmware, Oh-My-Zsh | `checkupdates`, `paru`/`yay`, `flatpak`, `fwupdmgr`, `git` |
| **Integrity & Security** | Local DB consistency, signing keyrings, missing package files, unread Arch news, CVEs, foreign library ABI rebuilds | `pacman -Dk`/`-Qkq`, `arch-audit`, `checkrebuild` |
| **Hygiene** | Orphan packages, pacman cache, unused Flatpak runtimes, `.pacnew`/`.pacsave` files, journal disk usage | `pacman`, `paccache`, `flatpak`, `pacdiff`, `journalctl` |
| **Hardware & Storage** | Disk space (`/` and `/boot`), mount capacity/inodes/read-only state, S.M.A.R.T. (cached `sudo` only), TRIM, Btrfs errors & scrub age | `findmnt`, `lsblk`, `smartctl`, `btrfs` |
| **Services & Runtime** | Failed system/user units, maintenance timers, reboot detection (kernel mismatch, `pacman.log`, deleted libraries in `/proc/*/maps`), backup freshness | `systemctl`, `journalctl` |

`sys.backup` is opt-in and omitted unless configured. `sys.network` is reported only when HTTPS connectivity checks fail.

## Automation

```bash
dotdoctor --json                     # structured report to stdout
dotdoctor --json-output report.json  # save report to file
```

JSON fields: `schema_version` (`"1.0"`), `dotdoctor_version`, `profile`, `summary` (`PASS`, `OUTD`, `WARN`, `FAIL`, `SKIP`), `exit_code`, and `results`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clean scan (`PASS`/`SKIP` only), or `--sysup` completed without errors. |
| `1` | One or more `WARN` or `OUTD` findings, or pre-flight network/disk check failed in `--sysup`. |
| `2` | One or more `FAIL` findings, or snapshot/preflight/package transaction failed in `--sysup`. |
| `3` | Configuration error or `sudo` authentication failure/timeout. |

## Configuration

Works out of the box with built-in defaults. To customize thresholds, disabled checks, timers, or backup monitoring:

```bash
mkdir -p ~/.config/dotdoctor
cp dotdoctor.example.yml ~/.config/dotdoctor/config.yml
```

Search order: `-c`/`--config` → `DOTDOCTOR_CONFIG` → `$XDG_CONFIG_HOME/dotdoctor/config.yml` (or `.yaml`) → `/etc/dotdoctor/config.yml` (or `.yaml`) → built-in defaults.

## Documentation

* [Reference](docs/reference.md) — check IDs, JSON schema, configuration schema, and backup adapter examples.
* [Example config](dotdoctor.example.yml) — all 26 check IDs and config keys.
* [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [MIT License](LICENSE)
