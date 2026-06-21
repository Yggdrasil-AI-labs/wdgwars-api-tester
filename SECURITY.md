# Security Notes

## What this tool does

`wdgwars-api-tester` is a read-only HTTP probe. Each invocation issues
a fixed catalog of requests against one or more configured hosts (by
default `https://wdgwars.pl`) and emits a verdict per route.

- Requests are GET / POST / OPTIONS with synthetic, idempotent payloads.
  Nothing the probe sends is intended to mutate server state. Endpoints
  that would mutate (uploads, captures-accept) are exercised with
  invalid bodies that the server rejects on schema, not on auth.
- With `--watch`, the probe loops indefinitely, repeating the same
  catalog every N seconds and printing compact deltas on verdict
  changes.
- With `--alert-telegram` / `--alert-webhook` / `--exec-on-change`, a
  verdict transition triggers an outbound notification or local
  command. All three are opt-in flags.

That's the entire outbound footprint.

## What this tool does not do

- No telemetry or analytics. The probe never phones home about its own
  use. There is no version-check probe (yet); when one is added, it
  will be gated by `--no-version-check` to match the rest of the
  WDGoWars feeder family.
- No `eval`, no `exec`, no `shell=True`. `--exec-on-change` invokes
  `subprocess.run(cmd, shell=True)` ONLY for the command the operator
  passed on the CLI — see "Exec-on-change" below for the threat model.
- No remote code execution at runtime. The probe is single-file
  stdlib-only Python; no PyPI install step, no runtime dependency
  fetch.
- No data sent anywhere except the hosts you pass to `--hosts`, plus
  the Telegram / webhook destinations you opt into via the alert
  flags.

## API key handling

- WDGoWars key resolution: `--key` flag, then `$WDGWARS_API_KEY`, then
  `~/.config/wigle-to-wdgwars/wdgwars.key` (the shared family config
  path; api-tester does not save its own).
- The key is sent over HTTPS only, in the `X-API-Key` request header
  on `--variants valid` probes. TLS context is Python's
  `ssl.create_default_context()` default — system trust store,
  hostname verification on, TLS 1.2+.
- The key is never logged. Verdict output includes only HTTP status,
  Content-Type, and a body excerpt that is scrubbed of any substring
  matching the key.
- The `--variants none,garbage,valid` flag controls which auth
  variants get exercised. `garbage` sends an obvious sentinel string,
  never the real key; `valid` sends the real key only when the user
  explicitly invokes the variant.

## What the API key can do

The WDGoWars API key authorises the holder to submit observations
under the account it belongs to. If it leaks, an attacker could:

- Submit fake Wi-Fi / BLE / mesh / aircraft captures under your name.
- Read your account stats via `GET /api/me`.

It cannot (as far as we know):

- Change your password.
- Withdraw money or make purchases.
- Affect other users' accounts.

If you suspect your key has leaked, rotate it on the WDGoWars site and
re-save it via `wigle-to-wdgwars --setup` (api-tester reads from the
shared config path).

## Exec-on-change

`--exec-on-change "<cmd>"` runs the literal command string the
operator supplies, with `shell=True`, on every verdict transition.
Env vars exported to the subprocess: `WDGWARS_OVERALL`,
`WDGWARS_PREV_OVERALL`, `WDGWARS_DELTAS`, `WDGWARS_VERDICTS`,
`WDGWARS_RECOVERY`, `WDGWARS_KIND`.

Threat model: the command is whatever the operator typed. The tool
does NOT interpolate untrusted data into the command string; the env
vars are exported to the subprocess environment, not substituted into
the shell line. As long as the operator does not embed
`$WDGWARS_DELTAS` (or similar) directly into a `--exec-on-change`
command without quoting, network data cannot influence the command
text. If you do need to consume the verdict payload in your hook,
read the env vars from inside your script rather than interpolating
them at the shell level.

## Alert payloads

- `--alert-telegram` POSTs JSON to
  `https://api.telegram.org/bot<TOKEN>/sendMessage`. The bot token is
  passed via `--telegram-bot-token` or `$TELEGRAM_BOT_TOKEN`. The chat
  ID is the destination DM / group / channel.
- `--alert-webhook URL` POSTs JSON to an arbitrary URL. The payload
  carries both Slack-shaped (`text`) and Discord-shaped (`content`)
  fields so the same flag works against either provider, plus
  structured fields (`overall`, `prev_overall`, `deltas`, `kind`).
  The probe trusts the URL the operator supplies; it does not validate
  the hostname or scheme beyond Python's `urllib`.

Both alert paths suppress the API key from the alert body. If you
need to disable alert dispatch in a hurry (suspected leak of webhook
URL or Telegram bot token), kill the `--watch` process; alerts only
fire while the probe is running.

## Static-analysis review

A review of this tool against the SonarCloud SAST finding classes (path
traversal, command/argument injection, insecure temp use, unsafe DB opens)
found nothing to remediate. The one security-sensitive construct — the
`shell=True` exec-on-change hook — is acceptable by design (operator-authored
command; network-influenced state passed via environment variables, never
interpolated into the command string), and that behavior is now pinned by
`test_security.py`. The full write-up is in
[SECURITY-FINDINGS.md](SECURITY-FINDINGS.md).

## Reporting issues

Open a GitHub issue, or DM the maintainer on the WDGoWars community
channels. For anything potentially exploitable upstream (in WDGoWars
itself), please disclose privately to LOCOSP first rather than filing
a public issue here.
