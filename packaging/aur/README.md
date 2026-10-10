# Arch package

`dotdoctor-git/PKGBUILD` builds the current `main` branch as `dotdoctor-git`.
The command remains `dotdoctor`. This is a development package, not a tagged release.
It provides and conflicts with `dotdoctor`, so a future release package can replace it.

The package has not been published to AUR. AUR publication requires an existing
account with an SSH public key registered in its profile. New account registration
was closed when this recipe was prepared.

## Build locally

On Arch Linux or CachyOS, install `base-devel` and `git`, then:

```bash
git clone https://github.com/m1tyarch/DotDoctor.git
cd DotDoctor/packaging/aur/dotdoctor-git
makepkg -si
dotdoctor --help
```

Run `makepkg` as your regular user. It builds a wheel with the distribution's
Python libraries, runs the mocked test suite, and installs through pacman.
`pacman-contrib` and `fakeroot` are runtime dependencies so `checkupdates` works
on a fresh Arch installation. Extra managers, snapshot tools, and hardware
readers are optional dependencies; the package does not enable timers or services.
The example configuration is installed under `/usr/share/doc/dotdoctor-git/`;
it is not copied into an active configuration location.

## Publish to AUR

After an AUR account and SSH key are configured, use a separate AUR checkout:

```bash
git -c init.defaultBranch=master clone ssh://aur@aur.archlinux.org/dotdoctor-git.git
```

Copy `PKGBUILD` and `.gitignore` from this directory into that checkout, then
build and inspect the package before publication:

```bash
makepkg -s
namcap PKGBUILD ./*.pkg.tar.zst
makepkg --printsrcinfo > .SRCINFO
git add PKGBUILD .SRCINFO .gitignore
git commit -m "Initial dotdoctor-git package"
git push origin master
```

Only the packaging files belong in the AUR repository. Check the Git author
name and email before committing; AUR commit history is public. Regenerate
`.SRCINFO` after metadata changes. For this VCS package, new upstream commits
are picked up at build time; do not push changes that only bump `pkgver`.

See the official [submission guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines)
and [Python packaging guidelines](https://wiki.archlinux.org/title/Python_package_guidelines).

After a successful push, verify the AUR package page and replace the pending
publication notices in this document and the root README with installation
instructions for the published package.

## Validation recorded on 2026-10-10

- All 368 tests passed with Rich 14.3.4 and again with Rich 15.0.0 on Python 3.14.7.
- The current Arch library versions were exercised in an isolated environment:
  Typer 0.27.3, Rich 15.0.0, Pydantic 2.13.5, and PyYAML 6.0.3. All 368 tests
  also passed with Arch's current pytest 9.1.1.
- `makepkg` built an `any` package, including its mocked `check()` step. The
  validation used a local source checkout and preprovisioned Python libraries;
  `--nodeps --noextract --holdver` and `PACMAN=/usr/bin/false` prevented package
  manager operations. This was not a clean-chroot dependency-resolution test.
- The archive contained `/usr/bin/dotdoctor`, the Python modules, MIT license,
  reference, and example configuration. Its script uses `/usr/bin/python`;
  extracted `--help`, `version`, and imports passed without installing the package.
- Bash syntax and generated `.SRCINFO` were checked. Ruff, Black, and mypy passed.

Before public AUR submission, also run `namcap` and validate a normal dependency-
resolved build in a disposable Arch environment. Neither was performed locally.
