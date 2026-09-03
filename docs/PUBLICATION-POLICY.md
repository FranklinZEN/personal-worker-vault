# Vault Next Publication Policy

## Purpose

The Git repository contains only publishable system source, synthetic fixtures, schemas, tests, and
reviewed technical documentation. It is never a backup, archive, or working location for the owner's
personal materials.

## Default-deny boundary

The repository's `.gitignore` excludes private working roots, the supplied handoff, local runtime
state, office documents, PDFs, spreadsheets, local configuration, and secret-bearing file formats.
Root-level Markdown is also excluded by default. Only `README.md` and reviewed Markdown beneath
`docs/` are intended to be publishable.

Personal Markdown must live under `private/`, `personal/`, `inbox/`, or `working/`; personal material
must never be placed in `docs/`. `docs/private/` and nested `private/` or `personal/` documentation
folders are likewise excluded.

## Required publication check

Before an initial commit or any push:

1. Run `git add --dry-run --all` and inspect every proposed path.
2. Confirm no personal facts, raw notes, credentials, local account names, absolute local paths, or
   proprietary source content are present in the proposed text.
3. Confirm that no ignored file was force-added.
4. Review the staged diff before committing.
5. Push only after the owner explicitly approves the exact staged set and repository visibility.

Git ignore rules prevent ordinary addition of matching untracked files; they cannot determine whether
the text inside an allowed source or documentation file is personal. The staged review is therefore a
required human gate, not an optional convenience.
