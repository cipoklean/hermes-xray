# Plugin X-Ray

**It doesn't watch plugins. It sets traps for them.**

977 plugins are in the Hermes catalog. The install scanner reads their code once, at admission.
Nobody checks what a plugin actually *does* on your machine — after a week, after an update, or
when it thinks nobody is looking.

Plugin X-Ray does three things a static scanner, a prompt, or a skill can't:

1. **Detonation Chamber** — `hermes xray detonate <plugin>` runs the plugin in a sealed, throwaway
   Hermes world *before* you trust it: a fake home full of **honeytokens**, every tool **fuzzed**
   from its own schema, every hook fired, real network egress **blocked**, and the same run replayed
   with the clock **warped +30 and +90 days** to trip time-bombs.
2. **Live bait** — `hermes xray bait plant` (opt-in) drops decoy credential files into *empty*
   well-known paths. Nothing you own uses them, so an honest plugin has no reason to open one. If an
   installed plugin reads one, or a honeytoken shows up in an outbound URL, X-Ray names the plugin,
   the file and the line, and (with `enforce` on) Hermes asks your approval before that plugin's
   next tool call. **Every alert comes with the line of code that did it, so you can check it.**
3. **Behaviour fingerprints** — every detonation is stored per plugin@sha. `hermes xray diff` shows
   what changed in *behaviour* between versions ("+ host x.ru"), and `hermes xray disclose` drafts
   the honest catalog disclosure line from what the plugin actually did.

Stdlib only. No LLM calls. No network of its own. Works on an 8 GB laptop.

```
$ hermes xray detonate demo/sunny-weather
⚗️  Detonating sunny-weather in a sealed chamber (bait planted, egress blocked, clock now, +30d, +90d)…
  VERDICT: ⛔ RED
  Why it's flagged:
    • read bait credential files: aws_credentials, hermes_env (at sunny-weather/__init__.py:11)
    • honeytoken values sent out toward: sunny-weather-cdn.ru (at sunny-weather/__init__.py:22)
    • new behaviour only after clock warp (possible time-bomb): +30d ['sunny-weather-cdn.ru']
  Honeytoken trips (proof, not guesswork):
    • read   aws_credentials                 sunny-weather/__init__.py:11  [+30d, tool:weather]
    • leak   honeytoken → sunny-weather-cdn.ru sunny-weather/__init__.py:22  [+30d, tool:weather]
  Disclosure — READS CREDENTIAL FILES (keys, tokens, wallet); contacts sunny-weather-cdn.ru; …
```

On day 0 that plugin is spotless. A one-shot scan, or a quick test after install, sees a cheerful
weather tool. Only the clock warp catches it.

## Against real catalog plugins

First pass, six catalog plugins detonated at their pinned SHAs (Nov 2026):

| Result | What X-Ray saw |
|---|---|
| 3 × GREEN | Two of them read their API key through `agent.secret_scope` — X-Ray recognises Hermes' own secret API and marks it as sanctioned use, not theft |
| 2 × AMBER | One contacts an LLM host its manifest never names; one writes into the Hermes home outside its data dir |
| 1 × RED | Parses `$HERMES_HOME/.env` itself instead of asking `agent.secret_scope` — exactly what catalog rule 11 forbids. Its GitHub token then went only to `api.github.com`, which X-Ray marks as the key's own provider (OK) |

Nothing malicious — but one rule break and two undisclosed behaviours that a static read had let
through, found in about a minute each with zero LLM calls.

## Install

```bash
hermes plugins install cipoklean/hermes-xray/xray   # once listed: hermes plugins install xray
hermes plugins enable xray --no-allow-tool-override  # X-Ray overrides no tools
```

The plugin lives in the `xray/` subdirectory. The repo root also holds `demo/`, deliberately
malicious specimens for trying X-Ray, so Hermes' install scanner rightly blocks installing the
repo root itself.

Plugins are kept in `$HERMES_HOME/plugins` (`~/.hermes` on macOS/Linux,
`%LOCALAPPDATA%\hermes` on Windows). Turn on enforcement with
`hermes config set plugins.entries.xray.settings.enforce true`.

## Commands

| Command | What it does |
|---|---|
| `hermes xray detonate <path \| installed-name \| owner/repo[@sha]>` | Sandbox run → RED / AMBER / GREEN report card. `--subdir`, `--warps 0,30,90`, `--entry catalog.yaml`, `--json`, `--ci` (exit 2 on RED, 1 on AMBER), `--allow-exec`, `--keep` |
| `hermes xray verdicts` | Latest verdict for every plugin you've detonated |
| `hermes xray show <plugin> [--sha]` | Stored report card |
| `hermes xray diff <plugin> [old_sha new_sha]` | Behaviour diff between two versions (`--ci` exits 1 on change) |
| `hermes xray disclose <plugin>` | Draft catalog disclosure line from observed behaviour |
| `hermes xray bait plant \| status \| remove` | Opt-in live decoys (never overwrites a real file; removes only what it wrote) |
| `hermes xray alerts` | Runtime bait alerts: plugin, file:line, time |
| `/xray` (in a session) | Verdicts and recent alerts |
| Desktop → **Plugin X-Ray** page | Verdict cards with proof, a Detonate box, live bait alerts |

## Verdicts

- **RED** — read bait, leaked a honeytoken (URL, DNS name, command line), or changed behaviour only
  after the clock warp.
- **AMBER** — undisclosed real-world reach: a host not named in its manifest/README/catalog entry,
  a subprocess, writes outside its data dir, or code built and `exec`'d at runtime.
- **GREEN** — none of the above, across every clock.

## How it works

```
 parent (your Hermes)                         sealed child (throwaway)
 ─────────────────────                         ───────────────────────────────────────
 build fake HOME + HERMES_HOME  ──────────▶   sitecustomize: sys.addaudithook
   with unique honeytokens                       • records open / connect / DNS / urllib /
 strip real env, pass bait env                     subprocess / exec / ctypes, attributed to the
 for warp in 0, +30d, +90d:                        plugin's own frames (file:line)
   spawn child  ───────────────────────────▶     • blocks non-loopback egress + process spawns
                                               harness: load plugin with a recording ctx
                                                 → register() at real time
                                                 → clock jumps +N days ("N days after install")
                                                 → fuzz every tool from its JSON schema
                                                 → fire every hook, invoke every slash command
 collect events ◀──────────────────────────    events.jsonl
 verdict + fingerprint + disclosure → plugin-data SQLite
```

The runtime side is a single observe-only audit hook in the Hermes process. It only wakes for file
opens whose name matches a planted decoy and for network events, attributes them to the installed
plugin on the stack, and never raises — it cannot break a session. With `enforce: true`, a RED
plugin's tools are routed to Hermes' **own** approval gate through the public `pre_tool_call`
directive; X-Ray never auto-approves or disables a guard.

## Settings

```yaml
plugins:
  entries:
    xray:
      settings:
        enforce: false        # escalate a RED plugin's tool calls to human approval
        bait_runtime: true    # watch planted decoys at runtime
```

## Disclosure (catalog rule 13)

- Spawns short-lived child Python processes to detonate the plugin under test; the child gets a fake
  `HOME`/`HERMES_HOME` and bait environment only — real keys and tokens are stripped from its env.
- Egress and process spawns from the child are recorded and blocked. Code in the plugin under test
  still runs (sandboxed by environment, not by a VM) — detonate unknown code on a box you don't mind.
- `bait plant` is opt-in and writes decoy files only into empty paths under your home
  (`~/.aws/credentials`, `~/.ssh/id_ed25519`, `~/.git-credentials`, `~/.config/solana/id.json`,
  `~/Documents/wallet-backup.txt`, `~/.env.backup`). It never writes into your Hermes home and never
  overwrites an existing file. `bait remove` deletes only unchanged files it created.
- Reads the source directories of other installed plugins to attribute events. Never reads real
  credential stores, never calls an LLM, never contacts the network itself (except `git clone` when
  you detonate a remote repo).
- Never patches Hermes core. The clock warp exists only inside the child process.

## Limits (honest)

- Python audit hooks see Python-level events. A plugin that ships native code can act below them;
  X-Ray reports any `ctypes` load, and the catalog already rejects unscannable binaries.
- Reading an environment variable is not an audit event, so env-only theft is caught when the
  value *leaves* (URL, DNS, command line, file path), not when it is read.
- Desktop `plugin.js` code is not detonated (Python side only).

## Tests

```bash
python -m unittest discover -s tests     # no Hermes needed
```

Demo specimens (a malicious time-bomb and a clean tool) are in [`demo/`](demo/) and are **not**
part of the installed plugin.

MIT © cipoklean
