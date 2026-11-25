# Systemd User Timer for DotDoctor

Example user-level `systemd` units for running a quiet, read-only weekly audit and exporting the latest JSON report to `~/.local/state/dotdoctor/last-audit.json`.

## Install (user session)

```bash
mkdir -p ~/.config/systemd/user
cp dotdoctor-audit.service dotdoctor-audit.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now dotdoctor-audit.timer
```

Inspect status and latest run:

```bash
systemctl --user status dotdoctor-audit.timer
journalctl --user -u dotdoctor-audit.service -n 20
```
