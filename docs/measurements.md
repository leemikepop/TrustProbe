# Measurements

Taken 2026-11-18 on the Android emulator `API37.0-GAPPS` (API 37, x86_64), booted with
`-dns-server 8.8.8.8 -no-snapshot-save`, host: Windows 11. Debug builds of TrustProbe and the testbed
unless stated. Every figure is an **emulator** figure; the Pixel 7 column in the README is pending.

Setup common to all runs: VPN consent and notification permission were pre-granted
(`appops set io.github.leemikepop.trustprobe ACTIVATE_VPN allow`, `pm grant ... POST_NOTIFICATIONS`), so no system
dialog appears. Sessions were started with the debug-only `DebugSessionActivity` (`--es package <testbed> --ei durationSec N`),
which logs every engine event with tag `TrustProbe`. The testbed was started with its `autorun` extra, which is the same code path as
the "Run all" button. Window animations were disabled.

## (a) Testbed correctness

4/4 verdicts correct (example.com PASS, example.net VULNERABLE / ACCEPTS_ANY_CERT, example.org PASS, www.example.com PASS).
Asserted automatically by `TestbedVerdictsTest`; the CI `e2e` job passes on a GitHub-hosted API 35 x86_64 emulator
(run 44278624065, 4 min 18 s). All three manual sessions below produced the same four verdicts.

## (b) "Run all" to all four hosts done

Time from issuing the `am start ... --ez autorun true` command (device clock, `date +%s%3N`) until the last of the four
hosts first shows a `Forwarded(HOST_DONE)` event (engine `atMillis`). 3 sessions:

| run | ms |
|---|---|
| 1 | 3771 |
| 2 | 3875 |
| 3 | 3774 |

Median **3774 ms** (about 3.8 s). Includes the testbed's cold start and its retries (up to 4 attempts per button, 200 ms apart).
Tapping the button by hand would add the person's reaction time.

## (c) `Probed.result.durationMs`

24 probe results (8 per session, 3 sessions), read from the engine event log (the same field the JSON export carries).
`durationMs` covers the server-side handshake; for an accepted case it also includes waiting for the app's first request.

- All 24: median **9 ms**
- 18 rejected cases: median 6 ms (range 4 to 61 ms)
- 6 accepted cases: median 219 ms (range 208 to 242 ms)

## (d) Forwarding overhead

CORRECT scenario (`https://example.com/`, fresh OkHttp client, fresh connection each time), `elapsedMs` as logged by the testbed
(`TrustProbeTestbed` tag). 20 runs each, app force-stopped between runs, medians:

| condition | median ms | min | max |
|---|---|---|---|
| no TrustProbe, block 1 (before the sessions) | 521 | 481 | 614 |
| no TrustProbe, block 2 (after the sessions) | 548 | 485 | 741 |
| TrustProbe session running, host already done (forward mode) | 441 | 288 | 667 |

Reading: no measurable forwarding overhead on the emulator. Forward mode was not slower; the 27 ms gap between the two
baseline blocks and the sign of the forward-vs-baseline difference show that the emulator's network noise is larger than any
effect of forwarding. I do not claim forwarding is faster. The forward-mode block was measured once, in one session
(run 1 of (b)). The Pixel 7 run is pending.

## (e) Release APK size

`./gradlew :app:assembleRelease` (unsigned): `app-release-unsigned.apk` = 31,926,880 bytes = **31.9 MB** (30.4 MiB).
R8/minification is off, so most of it is unshrunk dex (about 30 MB of `classes*.dex`: Compose, Room, Kotlin, Bouncy Castle);
the native part is two `libhev-socks5-tunnel.so` files of about 350 KB (arm64-v8a, x86_64). The APK contains both ABIs.

## Demo GIF

Recorded on the same emulator with `adb shell screenrecord --time-limit 60 --size 540x1200`, driven with `adb shell input`
(pick testbed, 2 min, Start, switch to testbed, Run all, back, Stop, report). Converted with ffmpeg
(trimmed to 36 s, 10 fps, 360 px wide, palettegen/paletteuse) to `docs/demo.gif` (about 0.4 MB). Consent dialogs were pre-granted as above.
