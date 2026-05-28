---
name: wp-playground
description: "Use as the WordPress Playground routing wrapper for ambiguous Playground work, local CLI runs with @wp-playground/cli, playground.wordpress.net share links, browser previews, snapshots, mounts, version switching, and Xdebug. For Blueprint JSON authoring or review, prefer the blueprint skill directly."
compatibility: "Targets WordPress 6.9+ (PHP 7.2.24+). Playground CLI requires Node.js 20.18+; runs WordPress in WebAssembly with SQLite."
---

# WordPress Playground

This is a thin routing wrapper. Use it to pick the right Playground workflow, then load only the focused reference or skill needed for the task.

## Route by intent

- **Blueprint JSON, schema, steps, resources, bundles, or Blueprint review**: use the `blueprint` skill directly. Do not duplicate Blueprint schema details here.
- **Local CLI execution**: read `references/cli.md` for `@wp-playground/cli` server, `run-blueprint`, `build-snapshot`, mounts, version switching, and local validation.
- **Xdebug or stuck CLI runs**: read `references/debugging.md` after `references/cli.md`.
- **Browser-only Playground website workflows**: read `references/website.md` for `playground.wordpress.net`, share URLs, Blueprint Editor, hosted bundles, and browser limitations.

## Inputs to collect

- The intended workflow: Blueprint authoring, local CLI run, website/share link, snapshot, or debugging.
- Project or bundle path if local code must be mounted or packaged.
- Desired WordPress/PHP versions if compatibility matters.
- Port preference if a local server is needed.
- Whether browser-only sharing or local filesystem access is required.

## Guardrails

- Playground instances are disposable, SQLite-backed environments; never point them at production data.
- Keep Blueprint JSON guidance in `blueprint` so the schema and examples have one source of truth.
- For local CLI work, verify Node.js 20.18+ and `npm`/`npx` before running commands.
- Browser-only Playground cannot read local filesystem paths; use public URLs, hosted ZIP bundles, or inline Blueprint JSON.

## Verification

- For Blueprint content, validate against the published schema and follow the `blueprint` skill verification.
- For local CLI runs, verify the mounted plugin/theme or Blueprint side effects in the Playground instance.
- For share links, open the generated URL and confirm the expected landing page and installed assets load.

## Escalation

- If the task needs PHP extensions, native database access, persistence, or production-like infrastructure that Playground cannot provide, use a full WordPress stack such as wp-env, Docker, or the project-provided environment.
