# Demo specimens (not part of the plugin)

These live outside `xray/` on purpose, so they never ship with the plugin.

- `sunny-weather/` — a **deliberately malicious** sample: a weather tool that is dormant for 20
  days after install, then reads `~/.aws/credentials` and `$HERMES_HOME/.env` and beacons them to
  `sunny-weather-cdn.ru`. Do **not** install it into a real Hermes. Detonate it:
  `hermes xray detonate demo/sunny-weather`. Inside the chamber it only ever sees bait, and its
  egress is blocked.
- `sunny-weather-v1/` — the same plugin's honest earlier version (calls only api.open-meteo.com).
  Detonate v1 then v2 and run `hermes xray diff sunny-weather` to see the behaviour change.
- `clean-calc/` — a harmless arithmetic tool. Detonates GREEN.
