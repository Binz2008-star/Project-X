# OpenCode on a Windows PC — Project X

**Purpose:** connect the existing [Project X GitHub repository](https://github.com/Binz2008-star/Project-X) to a real local Windows workspace and open OpenCode with the **same project and handoffs**. OpenCode is already visible in the user's Windows terminal screenshot; do not reinstall it without checking first.

## Prerequisites and boundaries

- Windows PowerShell or Windows Terminal, Git for Windows, OpenCode, and (for Python test runs) Python 3.12+.
- Do not paste credentials, Neon database URLs, access tokens, IPA binaries, or private keys into OpenCode messages or the public repository.
- The most complete implementation is in **stacked draft feature branches**, not `main`. This onboarding PR's development branch is `chore/opencode-workstation-setup`.
- Commands below do not merge, deploy, create cloud database tables, modify Neon or push commits. They clone/fetch and change only the local working checkout when it is clean.

## First-time PC setup or safe re-open

Exit the current OpenCode session in Windows Terminal (`Ctrl+C`, if supported) or open a **new PowerShell tab**. Run from ordinary **non-administrator** PowerShell:

```powershell
git --version
opencode --version
$repoUrl = "https://github.com/Binz2008-star/Project-X.git"
$folder = Join-Path $HOME "Projects\Project-X"
$parent = Split-Path $folder -Parent

New-Item -ItemType Directory -Force -Path $parent | Out-Null

if (-not (Test-Path $folder)) {
    git clone $repoUrl $folder
    if ($LASTEXITCODE -ne 0) { throw "Git clone failed" }
} elseif (-not (Test-Path (Join-Path $folder ".git"))) {
    throw "A non-Git folder already exists at $folder; do not overwrite it"
}

Set-Location $folder
$origin = git remote get-url origin
$allowed = @(
    "https://github.com/Binz2008-star/Project-X.git",
    "https://github.com/Binz2008-star/Project-X",
    "git@github.com:Binz2008-star/Project-X.git"
)
if ($origin -notin $allowed) { throw "Unexpected Git origin; stop and inspect" }
if (git status --porcelain) { throw "Uncommitted local changes exist; stop and review them before switching branches" }

git fetch origin --prune
if ($LASTEXITCODE -ne 0) { throw "Git fetch failed" }
$branch = "chore/opencode-workstation-setup"
git show-ref --verify --quiet "refs/heads/$branch"
if ($LASTEXITCODE -eq 0) {
    git switch $branch
    if ($LASTEXITCODE -ne 0) { throw "Branch switch failed" }
    git pull --ff-only origin $branch
    if ($LASTEXITCODE -ne 0) { throw "Fast-forward pull failed; do not reset or force push" }
} else {
    git switch --track "origin/$branch"
    if ($LASTEXITCODE -ne 0) { throw "Branch checkout failed" }
}

git status -sb
opencode
```

**Important:** Run `opencode` *after* entering the cloned `Project-X` directory. Running it from `~` (as in the initial screenshot) does not automatically load repository instructions. OpenCode reads root `AGENTS.md` on startup.

If Git is not installed, install [Git for Windows](https://git-scm.com/download/win) and restart the terminal. If `opencode --version` fails, follow the [official OpenCode documentation](https://opencode.ai/docs/), but the screenshot indicates it is already installed. GitHub HTTPS pushing may request interactive browser authentication; do not share passwords or paste PATs into chats.

## First prompt *inside OpenCode*

> You are working in the local Project X repository. Read AGENTS.md, docs/PROJECT_HANDOFF.md, docs/ENGINEERING_HANDOFF.md, docs/API_STATUS.md, and docs/NEON_STAGING.md. Check the current directory, git status, origin and branch; confirm the current code and tests. Give me a concise status and propose the smallest safe next engineering task. Read-only first: do not edit files, merge, deploy, run cloud migrations or access Neon production. Use only the owned demo product.

## Optional local Python tests (offline / SQLite)

In a **separate PowerShell tab** within the Project-X directory, assuming Python 3.12 is installed:

```powershell
py -3.12 --version
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q tests/test_api.py tests/test_neon_staging_check.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_licensing.py -v
.\.venv\Scripts\python.exe -m scripts.export_openapi --check
```

The integration suite skips PostgreSQL cases when `PROJECT_X_TEST_POSTGRESQL_URL` is unset. Such a skip is **not** proof PostgreSQL works; the last known PostgreSQL CI evidence is recorded in `docs/ENGINEERING_HANDOFF.md`. Do not use a production DB URL.

## Future work: GitHub ⇄ PC workflow

1. In PowerShell, `git fetch origin` and `git status -sb` to inspect changes; `git pull --ff-only` only on a clean branch which tracks the correct remote.
2. Ask OpenCode to work on **one scoped issue at a time** in a dedicated branch. Review changed files and tests before any commit.
3. If authorized, push **that feature branch only** (`git push -u origin feature/your-topic`); open a Draft PR targeted at the actual stacked development branch, not `main`.
4. Keep production and any real users' data isolated. No merge, release or destructive cloud action without explicit approval.

**Do not run `/init` to overwrite the repository's reviewed `AGENTS.md`.** Verify local files and GitHub state independently.
