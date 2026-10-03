# Nord Optimizer for Android

An LSPosed module that makes the NordVPN Android app quieter and more private: it stops the app's own
telemetry, refuses tracker name lookups, removes upsell/survey nags, and adds optional WireGuard
handshake-covering noise (AmneziaWG-style "junk packets"). It runs inside `com.nordvpn.android` and every
switch is measured — the app shows what was actually blocked, not what was merely installed.

Tested against **NordVPN 9.13.2 (2102)** and **9.14.1 (2121)** on LineageOS 23.2 / Android 16 with
Magisk + Zygisk Next + LSPosed 2.2.0.

---

## What it does

| Feature | Default | What it does |
| :--- | :--- | :--- |
| **DNS sinkhole** | off | Refuses DNS resolution for tracker/analytics domains found in the APK (Braze, AppsFlyer, Google Analytics, DoubleClick, measurement endpoints). Nord's own API hosts are excluded and resolve through the app's internal resolver, so the VPN itself is never affected. |
| **Moose analytics** | off | Nord's in-house telemetry ("Moose", the `applytics.*` endpoints). Uploads are dropped at the HTTP callback so its queue drains instead of retrying, its send-flags are forced off, and initialisation is skipped. Connection-quality events stay read-only on purpose: the app consumes their return values, and blocking them breaks connecting. |
| **Firebase + Braze intake** | off | Suppresses `FirebaseAnalytics` event logging and Braze's JavaScript bridge inside Nord's process. GA4 uploads made by Google Play services are outside any module's reach and are not claimed. |
| **Moose UI events / debugger** | off | Blocks the "user tapped/viewed" behavioural stream and the debug/exception report channel. Both were substituted during successful tunnels, so they are measured-safe; they stay off by default because "the app accepted it" was never proven. |
| **Nag & survey suppression** | off | No-ops CSAT survey triggers, promo/market-message database inserts, the Threat-Protection keep-active sheet, promo API banners, rating-prompt counters, and promo reminder broadcasts — at the write path, so nothing is stored to delete later. |
| **NordLynx junk packets** | off | Sends `Jc` unparseable UDP datagrams of random size in `[Jmin, Jmax]` on the tunnel's own socket immediately before each WireGuard initiation, AmneziaWG-style, so deep packet inspection sees noise in front of the handshake. Client-side only: a stock Nord peer drops them and handles the real handshake normally. It does not hide the handshake itself (that needs Amnezia's `H1-H4`/`A1-A4`, which require server support). |
| **Correct poisoned Nord DNS** | on | On networks that censor VPNs by poisoning DNS (measured live: `api.nordvpn.com` answered with a private `10.10.34.36`), hands the app back the truthful address it already learned from its own DNS-over-HTTPS resolver. Nothing is invented; only public answers are ever used. |
| **Tunnel MTU clamp** | off | Lowers the MTU the app requests from Android when it is above the target. Only useful on broken links; off by default because it touches live connectivity. |
| **OpenVPN mssfix rewrite** | off | Would rewrite the OpenVPN config template's `mssfix`. Off because the argument's shape was never observed on a device — running a text regex over a file path would break OpenVPN. NordLynx (the default protocol) never triggers it. |
| **Verbose hook logging** | off | Logs every suppressed event by name to logcat. For debugging; chatty. |
| **Blocked hosts list** | 12 hosts | The sinkhole list as data: add your own domains, or re-enable any default you want un-blocked. The app warns if you type something functional. |

Every switch is read by the hooked app within seconds, survives force-stop and reboot, and the ACTIVITY
page shows what was actually blocked this session.

## Requirements

- Rooted device with **Magisk + Zygisk** and **LSPosed** (Zygisk flavour).
- NordVPN installed. Other NordVPN versions than the two listed above are untested — the module shows a
  warning banner and, if Nord renamed a hook target, the adb report says so explicitly (nothing fails
  silently).

## Install

1. `adb install -r NordOptimizer-v1.8.0-signed.apk` (or sideload).
2. Open **LSPosed → Modules → Nord Optimizer**, enable it, and set its scope to **NordVPN only**.
3. **LSPosed → Settings → Framework → Invalidate inline hooks → tick NordVPN.**
   This is required, and it is not the module's fault: NordVPN ships Google's PairIP anti-tamper, whose
   native code checks that `libart.so`'s memory matches the file on disk. LSPosed's hook engine patches
   libart in memory, so PairIP kills the app ~2 seconds after launch. That reproduces with *any* module in
   NordVPN's scope — even one that runs no code at all — so it cannot be fixed from inside the module. The
   invalidation restores the clean libart image for NordVPN only, and is the supported escape hatch.
4. **Reboot.** LSPosed reads scope and per-app tables at boot only. (After this one reboot, module updates
   apply with just a force-stop of NordVPN; reboot again only if the module ever goes silent.)
5. Open **Nord Optimizer from the LSPosed manager** (there is deliberately no app-drawer icon) and follow
   the ONE-TIME SETUP card, which walks through steps 2–4 again.
6. Open NordVPN. The manager's pill turns green (ATTACHED) and STATUS starts counting what gets blocked.

## The settings, one by one

Long-press any switch in the app for the same explanation in place.

- **DNS sinkhole — enable** unless you have a reason not to. It cannot break the VPN (Nord's own names are
  excluded and its API resolves internally). Cost: some SDKs will log harmless connection errors.
- **Moose analytics — enable** to stop Nord's first-party product telemetry entirely. Disabling changes
  nothing you would notice as a user; it only resumes Nord's analytics.
- **Firebase + Braze intake — enable** to stop third-party SDK event intake. No Nord feature depends on
  these. GA4 traffic from Google Play services is unaffected either way.
- **Moose UI events / debugger — your call.** Measured safe (tunnels came up while they were substituted),
  but their "accepted" contract is unproven, so they default off. Debugger off = Nord stops receiving
  exception reports from your device.
- **Nag & survey suppression — enable** if you never want to see upsell sheets, survey prompts, promo
  banners or reminder notifications. Disable if you *want* the deals.
- **NordLynx junk packets — enable** only if you specifically want handshake-covering noise (for example
  on a network that throttles or flags WireGuard). Costs: a few packets of extra traffic per handshake and
  up to ~20-100 ms added latency in front of each initiation. Honest limits: it cannot defeat inspection
  that matches WireGuard's packet signatures, and it does not fix DNS censorship (that is the next knob).
- **Correct poisoned Nord DNS — keep on.** On a clean network it never fires; on a censored one it can be
  the difference between connecting and "Connecting…".
- **Tunnel MTU clamp / MTU clamp target — leave off** unless you see "connected but data broken" on a
  specific network; then try targets below the default 1360.
- **OpenVPN mssfix rewrite — leave off.** Unverified target; NordLynx never triggers it.
- **Verbose hook logging — off** for daily use; on while debugging with `adb logcat`.
- **Blocked hosts** — add domains you personally want sinkholed; remove defaults you don't. It will warn
  before you block something that would break login, the server list, or push.

## Troubleshooting

- **NordVPN closes ~2 seconds after opening** → step 3 of Install was skipped: tick NordVPN under
  Invalidate inline hooks, then reboot.
- **Manager stuck on WAITING** → module not enabled/scoped in LSPosed, or LSPosed still holds the previous
  APK path after an update: force-stop NordVPN once; if still silent, reboot.
- **The pill is grey but the banner warns about the NordVPN version** → expected after a NordVPN update.
  The module keeps working for targets that still resolve; the adb report (below) lists what no longer
  matches.
- **Connecting fails on some networks** → check STATUS → LATEST EVENTS for "Censored DNS detected". That
  is the network poisoning DNS, which the module reports and, with "Correct poisoned Nord DNS", corrects
  when a truthful answer is available. Junk packets do not address this.
- **"Too many connections / device limit"** → that is NordVPN's account-side device cap, unrelated to the
  module. Remove a device in your Nord account dashboard.

## For developers

Diagnostics were removed from the UI on purpose; they remain over adb:

```bash
adb shell content query --uri content://com.nordoptimizer.lsposed.status/state   # full report: hooks, facts, counters, hosts
adb shell content call  --uri content://com.nordoptimizer.lsposed.status --method config
adb logcat -d | grep NOPT          # note: LSPosed re-logs under its own tag; grep the message, not the tag
adb logcat -b crash -d | grep nord # should be empty
```

- **Architecture**: `MainHook` (framework `Instrumentation` context acquisition — PairIP owns the
  `Application` class) → `hooks/*` per feature → `core/HookReport` (install/fire/substitute measurement) →
  `StatusProvider` (the only IPC channel; settings live in the module app's prefs because
  `XSharedPreferences` is dead under SELinux since API 24) → `ConfigClient` (target-side cache, 3 s
  generation poll). `Contract` is the single owner of keys, defaults, target class names, report fields and
  verdict strings.
- **Bisection**: build with `-PhookGroups=moose` (or any group) to install exactly that hook set plus the
  context infrastructure; `-PhookGroups=off` loads nothing (separates "PairIP hates LSPosed" from "PairIP
  hates a hook").
- **Self-test**: re-resolves all 61 hook targets without hooking; trigger by bumping the
  `selftest_nonce` config key. 61/61 PASS means a NordVPN update renamed nothing.
- **Junk native path**: `app/src/main/jni/nordjunk.c` patches the `sendto` PLT slot of the app's libraries
  and bursts into the handshake's own descriptor; the Java routes were measured dead (DatagramSocket.send
  never fires under the tunnel; `/proc/net/udp` and `/proc/self/fd` are unreadable from the app) and were
  removed in 1.6.0. The build mirrors jni sources and output to space-free paths
  (`-PjniMirrorDir` / `-PbuildMirrorDir`) because `ndk-build` mishandles the space in this project's path.

### Build

```powershell
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21.0.4.7-hotspot"
.\gradlew.bat clean assembleRelease checksums
```

Requires NDK 27.3 (pinned). The signed APK and its hashes land in `C:/Android/nordjunk-build/outputs/apk/release/`.

### Verification history

The long-form measurement logs (PairIP crash forensics, junk A/B captures, DNS poisoning measurements, the
1.6.0 line-by-line audit) lived in this README until it was restructured for release. They are preserved in
git history up to tag `1.7.0`-era commits; the short version is baked into the module itself: every hook is
shape-checked before install (an abstract facade cannot look "installed"), every claim is a counter
(installed ≠ fired ≠ changed anything), and "INSTALLED BUT NEVER FIRED" is reported as the failure it is.

## License

MIT.
