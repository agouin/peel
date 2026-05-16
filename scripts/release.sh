#!/usr/bin/env bash
# scripts/release.sh — cut a new peel release.
#
# Invoked via `mise run release [VERSION]`. With no argument, prompts for
# the new version and defaults to the next patch bump from the current
# Cargo.toml version. Updates every file that carries the version, then
# commits, tags, and pushes to origin.
#
# Preconditions enforced:
#   1. Working tree is clean (no staged or unstaged changes).
#   2. HEAD is on `main`.
#   3. `main` matches `origin/main` after a `git fetch`.
#   4. The target tag does not already exist locally or remotely.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# --- output helpers ----------------------------------------------------------

if [ -t 1 ]; then
    BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
    BLUE=$'\033[34m'; RESET=$'\033[0m'
else
    BOLD=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""
fi

info()  { printf '%s==>%s %s\n'      "$BLUE"  "$RESET" "$*"; }
ok()    { printf '%s ok%s %s\n'       "$GREEN" "$RESET" "$*"; }
warn()  { printf '%swarn%s %s\n'      "$YELLOW" "$RESET" "$*" >&2; }
die()   { printf '%serror%s %s\n'     "$RED"   "$RESET" "$*" >&2; exit 1; }

# --- argument / version handling --------------------------------------------

current_version() {
    # Grab `version = "X.Y.Z"` from the [package] section of Cargo.toml. We
    # match only the first occurrence because the workspace package's
    # version is the first `version =` after `[package]`.
    awk '
        /^\[package\]/ { in_pkg = 1; next }
        /^\[/          { in_pkg = 0 }
        in_pkg && /^version[[:space:]]*=/ {
            match($0, /"[^"]+"/);
            print substr($0, RSTART + 1, RLENGTH - 2);
            exit
        }
    ' Cargo.toml
}

next_patch() {
    # 0.6.12 -> 0.6.13
    local v="$1"
    local major minor patch
    IFS='.' read -r major minor patch <<<"$v"
    printf '%s.%s.%s' "$major" "$minor" "$((patch + 1))"
}

validate_version() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Version must be X.Y.Z, got: $1"
}

CUR="$(current_version)"
[ -n "$CUR" ] || die "Could not parse current version from Cargo.toml"
SUGGESTED="$(next_patch "$CUR")"

if [ $# -ge 1 ] && [ -n "${1:-}" ]; then
    NEW="$1"
else
    printf '%sCurrent version:%s %s\n' "$BOLD" "$RESET" "$CUR"
    printf '%sNew version%s [%s]: ' "$BOLD" "$RESET" "$SUGGESTED"
    read -r NEW
    NEW="${NEW:-$SUGGESTED}"
fi

validate_version "$NEW"
[ "$NEW" != "$CUR" ] || die "New version equals current version ($CUR)"

TAG="v$NEW"
info "Releasing ${BOLD}$CUR${RESET} → ${BOLD}$NEW${RESET} (tag: $TAG)"

# --- preconditions ----------------------------------------------------------

info "Checking git state"

# Working tree clean.
if ! git diff --quiet || ! git diff --cached --quiet; then
    git status --short >&2
    die "Working tree has uncommitted changes — commit or stash first"
fi

# On main.
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[ "$BRANCH" = "main" ] || die "Must be on 'main', currently on '$BRANCH'"

# In sync with origin/main.
info "Fetching origin"
git fetch --quiet origin main

LOCAL_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse origin/main)"
if [ "$LOCAL_SHA" != "$REMOTE_SHA" ]; then
    die "Local main ($LOCAL_SHA) does not match origin/main ($REMOTE_SHA) — pull/push first"
fi

# Tag does not already exist (local or remote).
if git rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null; then
    die "Local tag $TAG already exists"
fi
if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
    die "Remote tag $TAG already exists on origin"
fi

ok "Git state clean, on main, in sync with origin"

# --- file edits -------------------------------------------------------------

# Use these for changelog headers in their respective formats.
FEDORA_DATE="$(date -u +"%a %b %d %Y")"      # e.g. "Fri May 15 2026"
DEBIAN_DATE="$(date -uR)"                     # e.g. "Fri, 15 May 2026 13:00:00 +0000"
AUTHOR_NAME="$(git config user.name)"
AUTHOR_EMAIL="$(git config user.email)"
AUTHOR="${AUTHOR_NAME} <${AUTHOR_EMAIL}>"

info "Updating version-bearing files"

# Cargo.toml — the [package] version (first `version = ` after `[package]`).
# Using a portable awk to rewrite only the workspace-package version.
awk -v new="$NEW" '
    BEGIN { in_pkg = 0; done = 0 }
    /^\[package\]/ { in_pkg = 1; print; next }
    /^\[/          { in_pkg = 0 }
    {
        if (in_pkg && !done && $0 ~ /^version[[:space:]]*=/) {
            sub(/"[^"]+"/, "\"" new "\"")
            done = 1
        }
        print
    }
' Cargo.toml > Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml

# Cargo.lock — bump the peel-rs package entry. `name = "peel-rs"` is unique
# (it's the workspace root crate), and the next `version = "..."` line is
# always its version.
sed -i '/^name = "peel-rs"$/{n;s/^version = ".*"$/version = "'"$NEW"'"/;}' Cargo.lock

# Fedora spec — Version field and a new %changelog entry at the top of the
# changelog section.
awk -v new="$NEW" -v date="$FEDORA_DATE" -v author="$AUTHOR" '
    BEGIN { ver_done = 0; cl_done = 0 }
    !ver_done && /^Version:[[:space:]]/ {
        print "Version:        " new
        ver_done = 1
        next
    }
    !cl_done && /^%changelog/ {
        print
        print "* " date " " author " - " new "-1"
        print "- Release v" new "."
        print ""
        cl_done = 1
        next
    }
    { print }
' packaging/fedora/peel.spec > packaging/fedora/peel.spec.tmp \
    && mv packaging/fedora/peel.spec.tmp packaging/fedora/peel.spec

# Debian changelog — prepend a new stanza at the top of the file.
{
    printf 'peel (%s-1) unstable; urgency=medium\n\n' "$NEW"
    printf '  * New upstream release.\n\n'
    printf ' -- %s  %s\n\n' "$AUTHOR" "$DEBIAN_DATE"
    cat packaging/debian/changelog
} > packaging/debian/changelog.tmp \
    && mv packaging/debian/changelog.tmp packaging/debian/changelog

# Alpine APKBUILD — pkgver only. (pkgrel is left alone; bump manually if the
# packaging itself changed without an upstream version bump.)
sed -i -E "s/^pkgver=.*$/pkgver=$NEW/" packaging/alpine/APKBUILD

# AUR PKGBUILDs — pkgver only, same rationale.
sed -i -E "s/^pkgver=.*$/pkgver=$NEW/" packaging/aur/peel/PKGBUILD
sed -i -E "s/^pkgver=.*$/pkgver=$NEW/" packaging/aur/peel-bin/PKGBUILD

ok "Files updated"

# Sanity check: Cargo.toml and Cargo.lock agree (catches a botched sed).
info "Verifying Cargo metadata is coherent"
cargo metadata --format-version 1 --offline --no-deps >/dev/null \
    || die "cargo metadata failed — Cargo.toml / Cargo.lock may be inconsistent"
ok "cargo metadata ok"

# --- review & confirm -------------------------------------------------------

info "Pending changes:"
git --no-pager diff --stat

printf '\n%sProceed?%s Will commit "%s", tag %s, and push origin main + tag. [y/N] ' \
    "$BOLD" "$RESET" "$TAG" "$TAG"
read -r reply
case "${reply,,}" in
    y|yes) ;;
    *)
        warn "Aborted. File edits are still on disk — review with 'git diff', then commit manually or 'git checkout -- .' to discard."
        exit 1
        ;;
esac

# --- commit, tag, push ------------------------------------------------------

info "Committing"
git add Cargo.toml Cargo.lock packaging/fedora/peel.spec \
    packaging/debian/changelog packaging/alpine/APKBUILD \
    packaging/aur/peel/PKGBUILD packaging/aur/peel-bin/PKGBUILD
git commit -m "$TAG"

info "Tagging $TAG"
git tag -a "$TAG" -m "$TAG"

info "Pushing main + tag to origin"
git push origin main
git push origin "$TAG"

ok "Released $TAG"
