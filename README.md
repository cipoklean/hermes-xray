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
   well-known paths. A legitimate plugin never touches them. If an installed plugin reads one, or a
   honeytoken shows up in an outbound URL, X-Ray names the plugin, the file and the line. **Proof,
   not guesswork: no false positives.**
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

## Install

```bash
hermes plugins install cipoklean/hermes-xray   # catalog name: xray
hermes plugins enable xray
```

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
