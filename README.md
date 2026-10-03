# NordOptimizer LSPosed

**NordOptimizer LSPosed** is a module for [LSPosed](https://github.com/LSPosed/LSPosed) that strips the
annoyances out of the NordVPN Android app: it stops the app's own telemetry, refuses tracker name lookups,
hides upsell and survey nags, and can optionally wrap every WireGuard handshake in cover noise the way
AmneziaWG does.

Everything it does is *measured*, not claimed — the module's ACTIVITY page shows exactly what was blocked
on your device, with counters.

![Release](https://img.shields.io/github/v/release/deathline94/nordoptimizer-lsposed?include_prereleases&label=release)
![License](https://img.shields.io/github/license/deathline94/nordoptimizer-lsposed)

---

## What it can block

| Feature | What it means for you | Default |
| :--- | :--- | :--- |
| **DNS sinkhole** | Stops the app from even reaching known tracker and analytics domains (Braze, AppsFlyer, Google Analytics, DoubleClick…). NordVPN's own servers are never touched, so connecting is unaffected. | off |
| **Moose analytics** | Nord's in-house telemetry pipeline (the `applytics.*` servers). Uploads are silently dropped so the app never retries them, and its "send telemetry" flags are forced off. | off |
| **Firebase + Braze intake** | Blocks third-party SDK event logging inside the app. (GA4 traffic sent by Google Play services is outside any module's reach — nothing can honestly claim to block that.) | off |
| **Moose UI events** | Stops the "user tapped / viewed" behavioural tracking stream. | off |
| **Moose debugger** | Stops the app shipping debug and exception reports to Nord. | off |
| **Nag & survey suppression** | No more upsell sheets, survey prompts, rating reminders or promo notifications — promo content is stopped before it is ever stored, so there is nothing to show you later. | off |
| **NordLynx junk packets** | Sends a burst of meaningless UDP packets right before every WireGuard handshake, AmneziaWG-style, so deep packet inspection sees noise instead of a clean VPN start. Client-side only — Nord's servers drop them and connect normally. | off |
| **Correct poisoned Nord DNS** | On censored networks that answer `api.nordvpn.com` with a fake private address, hands the app the real answer it already learned from its own secure resolver. Does nothing on a normal network. | on |
| **Tunnel MTU clamp** | Advanced: lowers the requested VPN MTU on broken networks where "connected but nothing loads". | off |
| **Verbose hook logging** | Debugging only — logs every suppressed event to logcat. | off |
| **Blocked hosts list** | Add your own domains to the sinkhole, or re-enable any default. The app warns you before blocking something that could break login or push. | 12 domains |

## Requirements

- A rooted Android device with **Magisk + Zygisk**
- **[LSPosed](https://github.com/LSPosed/LSPosed)** (Zygisk flavour)
- The **NordVPN** app — verified against **9.13.2** and **9.14.1**. Newer versions usually keep working,
  but are untested; the app shows a warning banner if it does not recognise your NordVPN version.

## Installation (one-time, about 5 minutes)

1. Grab the newest `NordOptimizer-v*.apk` from
   [Releases](https://github.com/deathline94/nordoptimizer-lsposed/releases) and install it
   (`adb install -r NordOptimizer-v*.apk`, or just sideload the file). Updating later is the same:
   install the new APK over the top and force-stop NordVPN once — no reboot needed.
2. Open **LSPosed → Modules → NordOptimizer LSPosed**, enable it, and set its scope to
   **NordVPN only**.
3. > ⚠️ **Required step:** LSPosed → Settings → Framework → **Invalidate inline hooks** → tick
   **NordVPN**.
   NordVPN ships an anti-tamper layer that closes the app a couple of seconds after launch whenever any
   module is hooked into it. This switch restores the unmodified system image for NordVPN only, and is the
   official fix. It is not something the module can do for you — every LSPosed module needs this for
   NordVPN.
4. **Reboot the phone.** LSPosed only reads these settings at boot. (Later module updates just need a
   force-stop of NordVPN — no more reboots.)
5. Open the manager from **LSPosed → NordOptimizer LSPosed → Launch**. There is no icon in your app
   drawer — that is by design.
6. Follow the **ONE-TIME SETUP** card inside, then open NordVPN. The manager's pill turns green and
   STATUS starts counting what gets blocked.

## Which switches should I enable?

Long-press any switch in the app for the same explanation in place.

| Switch | Recommendation | Why |
| :--- | :--- | :--- |
| DNS sinkhole | **On** | Pure win: trackers stop resolving; the VPN itself cannot be affected. |
| Moose analytics | **On** | Stops Nord's own product telemetry completely. No feature you use depends on it. |
| Firebase + Braze intake | **On** | Stops third-party SDK logging. No Nord feature depends on it. |
| Moose UI events | Optional | Usage tracking; safe in testing, but off by default until its behaviour is proven. |
| Moose debugger | Off | Leave on only if you want Nord support to receive exception reports from your device. |
| Nag & survey suppression | **On** | If you never want upsells, surveys or promo banners. Turn off only if you want the deals. |
| NordLynx junk packets | Your call | For networks that throttle or flag WireGuard. Costs a little extra traffic and a few dozen milliseconds per handshake; it does not fix DNS censorship (the next switch does). |
| Correct poisoned Nord DNS | **On** | Harmless on normal networks, and often the difference between connecting and endless "Connecting…" on censored ones. |
| Tunnel MTU clamp | **Off** | Only for broken networks where "connected but nothing loads" — try targets below 1360 there. |
| OpenVPN mssfix rewrite | **Off** | Experimental and unused with NordLynx (the default protocol). |
| Verbose hook logging | **Off** | Debugging only. |

## Troubleshooting

- **NordVPN closes a second or two after opening** → you skipped step 3. Tick NordVPN under
  *Invalidate inline hooks*, then reboot.
- **The manager is stuck on WAITING** → check the module is enabled with NordVPN in scope; force-stop
  NordVPN once. If it is still silent after a module update, reboot (LSPosed can hold the previous
  module path until boot).
- **A yellow banner says my NordVPN version is untested** → informational. The module keeps working for
  every hook target that still resolves after a NordVPN update.
- **Connecting fails on some networks** → open STATUS → LATEST EVENTS. If you see
  "Censored DNS detected", your network is poisoning DNS; keep *Correct poisoned Nord DNS* on.
  Junk packets do not address this problem.
- **"Too many connections / device limit reached"** → that is your Nord account's device cap, not the
  module. Remove an old device in your Nord account dashboard.

## Building from source

```bash
./gradlew clean assembleRelease checksums
```

Requires JDK 21 and Android's NDK 27.3 (downloaded automatically). On Windows, note that `ndk-build`
cannot handle spaces in paths: the build mirrors its working directories elsewhere
(`-PjniMirrorDir` / `-PbuildMirrorDir`, defaults under `C:/Android`), so the APK lands there rather than
in `app/build/outputs`.

## License

[MIT](LICENSE)
