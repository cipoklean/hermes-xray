# Plugin X-Ray

**It doesn't watch plugins. It sets traps for them.**

A Hermes plugin runs with your permissions. It can read your files, call any server, and run
commands. The catalog's install scanner reads a plugin's code once, when it's admitted. After that,
nobody checks what the plugin actually *does* on your machine: after a week, after an update, or
when it thinks nobody is looking.

Plugin X-Ray checks. It works in four ways.

| | What it does | Command |
|---|---|---|
| 🧪 **Detonate** | Runs a plugin in a throwaway child process before you trust it. The child gets a fake home full of fake keys (*honeytokens*) and runs as you, so this is a tripwire, not an OS sandbox. X-Ray calls every tool with generated inputs and fires every hook, with network, spawns and reads of your real secrets blocked at the Python level. Then it repeats the run with the clock moved forward 30 and 90 days to catch plugins that wait before misbehaving. The verdict is RED, AMBER or GREEN, with the file and line as proof. | `hermes xray detonate <plugin>` |
| 🪤 **Live bait** | Opt-in. Puts fake credential files (an AWS key, a wallet seed, an `.env` backup…) into empty, well-known paths on your machine. Nothing you own uses them, so an honest plugin has no reason to open one. If an installed plugin does, X-Ray names the plugin and the line of code. With `enforce` on, Hermes then asks your approval before that plugin's next tool call. | `hermes xray bait plant` |
| 🔍 **Diff** | Every detonation is saved for that exact version. When a plugin updates, X-Ray shows what changed in its *behaviour*, such as `+ host sunny-weather-cdn.ru`. | `hermes xray diff <plugin>` |
| 📝 **Disclose** | Drafts the honest catalog disclosure line from what the plugin really did. | `hermes xray disclose <plugin>` |

It uses only the Python standard library. It makes no LLM calls, has no network access of its
own, and runs fine on an 8 GB laptop.

## See it catch a time-bomb

`demo/sunny-weather` is a weather tool that behaves perfectly for 20 days. After that, it steals
your keys.

```
$ hermes xray detonate demo/sunny-weather
⚗️  Detonating sunny-weather in a throwaway chamber (fake home with bait, egress and spawns blocked, clock now, +30d, +90d)…
  VERDICT: ⛔ RED
  Why it's flagged:
    • read bait credential files: aws_credentials, hermes_env (at sunny-weather/__init__.py:11)
    • honeytoken values sent out toward: sunny-weather-cdn.ru (at sunny-weather/__init__.py:22)
    • new behaviour only after clock warp (possible time-bomb): +30d ['sunny-weather-cdn.ru']
  Disclosure — READS CREDENTIAL FILES (keys, tokens, wallet); contacts sunny-weather-cdn.ru; …
```

On day 0 it's spotless. A one-time scan, or a quick test after installing, would pass it. Only the
clock warp catches it.

## Against real catalog plugins

Six plugins from the Hermes catalog, detonated at their pinned commits (November 2026):

| Plugin | Verdict | What X-Ray saw |
|---|---|---|
| `yandex` | ✅ GREEN | Nothing unexpected. |
| `de-law` | ✅ GREEN | Only contacts `www.gesetze-im-internet.de`, the law source it says it uses. |
| `model-router` | ✅ GREEN | Nothing unexpected. |
| `custodian` | ⚠️ AMBER | Writes into the Hermes home, outside its own data folder. Its catalog description says it does this, so it's disclosed. X-Ray just makes it visible. |
| `hermes-council` | ⚠️ AMBER | Starts a `python` process and writes into the Hermes home. Its description mentions neither. |
| `github_app` | ⛔ RED | Opens and parses `$HERMES_HOME/.env` itself (`github_app/config.py:91`) instead of asking Hermes for its secret through `agent.secret_scope`. Catalog rule 11 forbids that. Its token then went only to `api.github.com`, its own provider. |

None of them is malicious. But X-Ray found one rule break and one undisclosed behaviour that the
install scan had let through, in about a minute each.

## Install

```bash
hermes plugins install cipoklean/hermes-xray/xray     # once listed: hermes plugins install xray
hermes plugins enable xray --no-allow-tool-override    # X-Ray replaces no tools
```

The plugin lives in the `xray/` folder. The repo's `demo/` folder holds deliberately malicious
samples, so Hermes' install scanner blocks installing the repo root. That's the scanner doing its
job.

Plugins live in `$HERMES_HOME/plugins`, which is `~/.hermes` on macOS and Linux and
`%LOCALAPPDATA%\hermes` on Windows.

## Try it in two minutes

```bash
git clone https://github.com/cipoklean/hermes-xray && cd hermes-xray

hermes xray detonate demo/clean-calc          # ✅ GREEN
hermes xray detonate demo/sunny-weather-v1    # ✅ GREEN, the honest version
hermes xray detonate demo/sunny-weather       # ⛔ RED, the time-bomb
hermes xray diff sunny-weather                # what changed between the two versions
hermes xray disclose sunny-weather            # the disclosure line it should have had
```

Live bait, with the `nosy-notes` sample that peeks at files it has no business reading:

```bash
hermes xray bait plant
hermes config set plugins.entries.xray.settings.enforce true
# copy demo/nosy-notes into your plugins folder, then:
hermes plugins enable nosy-notes --no-allow-tool-override
hermes                 # in the chat: "use quick_note to save 'buy milk'"
hermes xray alerts     # RED: nosy-notes read wallet_seed, env_backup @ nosy-notes/__init__.py:15
# ask for quick_note again: Hermes shows an approval prompt naming what it was caught doing

hermes xray bait remove                 # cleanup: deletes only the decoys it made, unchanged
hermes plugins disable nosy-notes
hermes config set plugins.entries.xray.settings.enforce false
```

## Verdicts

- **⛔ RED**: the plugin read a fake credential, sent a fake key anywhere (a URL, a DNS lookup, a
  command line, a file), or behaved differently only after the clock was moved forward.
- **⚠️ AMBER**: real-world reach worth knowing about. That means a server its manifest, README or
  catalog entry doesn't name, a subprocess, writes outside its own data folder, code built and run
  on the fly, or native (compiled) code X-Ray can't see inside.
- **✅ GREEN**: none of the above, on every clock.

Some things are never held against a plugin. Reading a secret through Hermes' own
`agent.secret_scope` is fine, and so is a key going to its own provider (a GitHub token to
`api.github.com`).

## All commands

| Command | What it does |
|---|---|
| `hermes xray detonate <path \| installed-name \| owner/repo[@sha]>` | Sandbox run → report card. Options: `--subdir`, `--warps 0,30,90`, `--json`, `--ci` (exit 2 on RED, 1 on AMBER), `--allow-exec`, `--keep` |
| `hermes xray verdicts` | Latest verdict for every plugin you've detonated |
| `hermes xray show <plugin>` | The saved report card |
| `hermes xray diff <plugin> [old new]` | Behaviour change between two versions (`--ci` exits 1 on change) |
| `hermes xray disclose <plugin>` | Draft disclosure line |
| `hermes xray bait plant \| status \| remove` | Live decoys. Never overwrites a real file and only removes what it wrote. `status` shows whether the runtime watcher is armed. |
| `hermes xray alerts` | Live bait alerts: plugin, file:line, time |
| `/xray` (in a chat) | Verdicts and recent alerts |
| Hermes Desktop → **Plugin X-Ray** | Verdict cards, a Detonate box, live alerts |

## Settings

```yaml
plugins:
  entries:
    xray:
      settings:
        enforce: false        # ask your approval before a RED plugin's tool calls
        bait_runtime: true    # watch planted decoys while Hermes runs
```

## How it works

```
 your Hermes                                   child process, runs as you (thrown away after)
 ───────────                                   ─────────────────────────────────────────
 make a fake HOME with unique fake keys  ───▶  a Python audit hook records every file open,
 strip your real keys from the env              connection, DNS lookup, command and native
 for each clock (now, +30d, +90d):              call, and blames the plugin's own file:line
   start the child  ───────────────────────▶   network, commands and fork are blocked;
                                               reads of your real secrets are refused
                                               the plugin loads, the clock jumps ahead,
                                               every tool is called, every hook fired
 read the events  ◀────────────────────────    events.jsonl
 verdict + fingerprint + disclosure → saved per plugin version
```

At runtime, X-Ray adds one observe-only audit hook to Hermes. It only reacts when a file named
like a planted decoy is opened, works out which installed plugin's code did it, and records an
alert. It never raises, so it can't break a session. Blocking happens only through Hermes' own
approval prompt (the public `pre_tool_call` hook), and only when you turn `enforce` on. X-Ray
never approves anything by itself.

## Disclosure (catalog rule 13)

- Starts short-lived child Python processes to detonate the plugin being tested. **The child runs
  as you, with your file permissions.** It gets a fake `HOME`/`HERMES_HOME` and fake keys, and your
  real keys are removed from its environment, but it is not an OS sandbox: code that knows an
  absolute path can still reach your real files.
- Inside the child, Python audit hooks record and block network egress and process starts
  (`subprocess`, `os.system`, `os.exec*`, `os.posix_spawn`, `os.fork`/`forkpty`, a direct
  `_posixsubprocess.fork_exec`, Windows `CreateProcess`). A read of a real credential store
  outside the chamber (your real Hermes `.env`/`auth.json`/memories, `~/.ssh`, `~/.aws`,
  `~/.git-credentials`, wallets…) is refused and makes the verdict RED. Any other read of your real
  home by the plugin's code is AMBER. This blocking is a tripwire, not a wall: native code
  (ctypes/cffi, compiled extensions) runs below the hooks and can bypass it, which is why X-Ray
  marks native code AMBER. Detonate unknown code on a machine you don't mind.
- `bait plant` is opt-in. It writes decoys only into empty paths under your home
  (`~/.aws/credentials`, `~/.ssh/id_ed25519`, `~/.git-credentials`, `~/.config/solana/id.json`,
  `~/Documents/wallet-backup.txt`, `~/.env.backup`), never into your Hermes home, and never over an
  existing file. **These are the default credential paths of the AWS CLI/SDKs, git's credential
  store, ssh and the Solana CLI, so those tools will pick up the fake values until you run
  `bait remove`.** Plant bait only on a machine where you don't use those tools' default files, or
  remove it before you do. `bait remove` deletes only unchanged files it created.
- Reads other installed plugins' source folders to work out which one caused an event.
- Never reads your real credentials, never calls an LLM, and never goes online itself, except for
  `git clone` when you detonate a remote repo.
- Never patches Hermes. The clock warp exists only inside the child process.

## Limits

- **Python level only.** Compiled code runs below X-Ray's hooks. X-Ray can't see inside it, so it
  marks any plugin that ships binaries or calls native code AMBER and says where. The catalog
  rejects unscannable binaries anyway (rule 14).
- **Environment variables.** Reading one isn't an event Python reports. Stealing a key from the
  environment is caught when the value *leaves* (in a URL, a DNS name, a command or a file), not
  when it's read.
- **Not an OS sandbox.** The child runs as you. Spawn and egress blocking is done by Python audit
  hooks, so it's a tripwire that native code can bypass. Running the child under bubblewrap or
  `sandbox-exec` is on the roadmap. See Disclosure above.
- **Code files.** Reads of `.py`/`.pyc`/`.so` files, the interpreter and Hermes' own source tree
  aren't flagged, because that's how Python imports code.
- Desktop `plugin.js` code isn't detonated, only the Python side.

## Tests

```bash
python -m unittest discover -s tests     # 13 tests, no Hermes needed
```

The demo samples are in [`demo/`](demo/) and are **not** part of the installed plugin.

MIT © cipoklean
