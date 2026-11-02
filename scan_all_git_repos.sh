#!/bin/bash
# Move the secret values in every .env under the given git repositories into
# the OS keychain, using the securikey plugin's `skey import`.
#
# The plugin keeps secrets in the keychain, so this script has no encryption
# key to set, no vault file to write, and nothing to copy into the repositories
# it scans. What it leaves behind is a reference: the .env keeps the names, the
# values move to the keychain.
#
# Usage:
#   scan_all_git_repos.sh --dir PATH [--dir PATH ...] [--apply] [--all]
#
#   --dir PATH   search PATH for git repositories (repeatable, required)
#   --apply      rewrite the .env files; without it every change is only shown
#   --all        import every value, not only the secret-looking ones
#   --skey PATH    path to the skey executable (default: this repository's plugin/bin/skey)
#
# Exits 0 when every repository was processed, 1 when any failed.
set -uo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SKEY_BIN="${SCRIPT_DIR}/plugin/bin/skey"
DIRS=()
APPLY=0
IMPORT_ALL=0

usage() {
    cat <<'EOF'
Usage: scan_all_git_repos.sh --dir PATH [--dir PATH ...] [--apply] [--all]

  --dir PATH   search PATH for git repositories (repeatable, required)
  --apply      rewrite the .env files; without it every change is only shown
  --all        import every value, not only the secret-looking ones
  --skey PATH    path to the skey executable (default: this repository's plugin/bin/skey)
EOF
}

die() {
    echo "scan_all_git_repos: $*" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dir)
            [ $# -ge 2 ] || die "--dir needs a path"
            DIRS+=("$2"); shift 2 ;;
        --dir=*)
            DIRS+=("${1#--dir=}"); shift ;;
        --apply)
            APPLY=1; shift ;;
        --all)
            IMPORT_ALL=1; shift ;;
        --skey)
            [ $# -ge 2 ] || die "--skey needs a path"
            SKEY_BIN="$2"; shift 2 ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            die "unknown argument: $1 (try --help)" ;;
    esac
done

[ ${#DIRS[@]} -gt 0 ] || die "no --dir given, so there is nothing to scan (try --help)"

for dir in "${DIRS[@]}"; do
    [ -d "$dir" ] || die "not a directory: $dir"
done

if [ ! -x "$SKEY_BIN" ]; then
    if command -v skey >/dev/null 2>&1; then
        SKEY_BIN=$(command -v skey)
    else
        die "skey not found at $SKEY_BIN and not on PATH (pass --skey PATH)"
    fi
fi

if [ "${SKEY_BIN}" = "${SCRIPT_DIR}/plugin/bin/skey" ] && ! command -v uv >/dev/null 2>&1; then
    die "uv is required to run ${SKEY_BIN} (https://docs.astral.sh/uv/)"
fi

# Directories that never hold a repository of their own and are expensive to
# walk.
PRUNE='( -name node_modules -o -name .venv -o -name venv -o -name __pycache__ -o -name dist -o -name build )'

# --- collect the repositories -------------------------------------------------
# The repository list stays an array. Assigning the joined text back to the
# array name turns it into one string, which the old loop then treated as a
# single (multi-line) path.
found=()
for dir in "${DIRS[@]}"; do
    while IFS= read -r gitdir; do
        found+=("$(dirname -- "$gitdir")")
    done < <(find "$dir" $PRUNE -prune -o -name .git -prune -print 2>/dev/null)
done

if [ ${#found[@]} -eq 0 ]; then
    echo "No git repositories found under: ${DIRS[*]}"
    exit 0
fi

# One repository can sit under several of the given directories; sort -u works
# on whole lines, so paths with spaces survive it.
repos=()
while IFS= read -r line; do
    repos+=("$line")
done < <(printf '%s\n' "${found[@]}" | sort -u)

if [ ${#repos[@]} -eq 0 ]; then
    echo "No git repositories found under: ${DIRS[*]}"
    exit 0
fi

echo "Found ${#repos[@]} git repository/ies under: ${DIRS[*]}"
if [ "$APPLY" -eq 0 ]; then
    echo "Dry run. Nothing will be written. Re-run with --apply to make the changes."
fi
echo

# --- the .env files of one repository ----------------------------------------
# `.tv-backup-` is the pre-3.0.0 backup suffix: old backups are still skipped.
env_files_of() {
    find "$1" $PRUNE -prune -o -name .git -prune -o -type f \
        \( -name '.env' -o -name '.env.*' \) -print 2>/dev/null \
        | grep -v -E '\.(example|sample|template|dist)$' \
        | grep -v -E '\.(skey|tv)-backup-'
}

failed=0
changed=0
backups_left=0

for repo in "${repos[@]}"; do
    echo "=== $repo ==="
    env_files=()
    while IFS= read -r line; do
        env_files+=("$line")
    done < <(env_files_of "$repo")

    if [ ${#env_files[@]} -eq 0 ]; then
        echo "  no .env files"
        echo
        continue
    fi

    for env_file in "${env_files[@]}"; do
        all_flag=""
        [ "$IMPORT_ALL" -eq 1 ] && all_flag="--all"

        echo "  -- $env_file"
        if [ "$APPLY" -eq 0 ]; then
            if ! "$SKEY_BIN" import $all_flag --dry-run "$env_file"; then
                echo "  !! failed: $env_file"
                failed=$((failed + 1))
            fi
            continue
        fi

        # Keep the plaintext until the keychain copy is in place. The backup
        # is a plaintext copy of a secret, so it is created mode 0600 (no window at the original mode) and it is deleted
        # once the import succeeds. Nothing keeps it out of the scanned
        # repository: add *.skey-backup-* to that repository's .gitignore if you
        # are worried about committing it.
        backup="${env_file}.skey-backup-$(date +%Y%m%d-%H%M%S)"
        if ! (umask 077 && cp -- "$env_file" "$backup"); then
            echo "  !! could not back up $env_file"
            failed=$((failed + 1))
            continue
        fi
        # A backup that already existed (same name, same second) keeps its own mode when
        # cp overwrites it, so the mode is set again on the file that is there now.
        if ! chmod 0600 -- "$backup" 2>/dev/null; then
            echo "  !! could not set the mode of $backup to 0600; it still holds plaintext, check it by hand" >&2
        fi

        if ! "$SKEY_BIN" import $all_flag "$env_file"; then
            echo "  !! failed: $env_file (the original is still in $backup)"
            failed=$((failed + 1))
            backups_left=$((backups_left + 1))
            continue
        fi
        # Only count a file that actually changed: an import that found
        # nothing secret-looking leaves it as it was.
        if ! cmp -s -- "$env_file" "$backup"; then
            changed=$((changed + 1))
        fi
        # The value is in the keychain now, so the plaintext copy has no
        # reason to stay on disk.
        rm -f -- "$backup"
    done
    echo
done

if [ "$APPLY" -eq 0 ]; then
    echo "Dry run finished. No file was changed."
else
    echo "Done. $changed file(s) now hold securikey:<name> references."
    echo "Each file was backed up to <name>.skey-backup-<timestamp> until the import succeeded."
    if [ "$backups_left" -gt 0 ]; then
        echo "$backups_left backup(s) still hold plaintext: they are the files whose import failed."
        echo "They are skipped on the next run. Delete them once the import works."
    fi
fi

if [ "$failed" -gt 0 ]; then
    echo "$failed file(s) failed." >&2
    exit 1
fi
exit 0
