# Mobile application security (iOS / Android)

Load when the repo contains a mobile project: IPA/APK/AAB, an Xcode project, an
Android project (`build.gradle` + `AndroidManifest.xml`), or a React Native /
Flutter / Expo / Capacitor root.

**ZAP / `validate_target` does NOT apply to the mobile binary** — the active-scan
tool targets an HTTP endpoint; a compiled app is not that. Mobile testing here is
static binary analysis plus on-device runtime/storage inspection. If the app
talks to a separate running backend API, that API is a normal web target — test
it through `get_methodology("runtime-zap")` as its own surface.

Tag every finding `[mobile-ios]` or `[mobile-android]`. Cite `file:field`, never
paste decompiled blocks. Test only on your own simulator/emulator; redact PII.

## Static analysis

Run MobSF for a broad first pass, then by hand:

**iOS** — `Info.plist` ATS exceptions (`NSAllowsArbitraryLoads`), custom URL
schemes (hijackable), `UIFileSharingEnabled`, background-snapshot exposure;
`strings` on the binary for secrets/keys/backend URLs; entitlements (over-broad
keychain access groups, associated domains).

**Android** — `AndroidManifest.xml`: `android:exported="true"` components,
`android:debuggable`, `allowBackup`, `usesCleartextTraffic`, every
`<intent-filter>` deep link; `jadx` to decompile the auth/crypto/networking
classes; `strings` on `classes.dex` and `lib/*/*.so`.

**Cross-platform** — React Native: grep `main.jsbundle` / `index.android.bundle`
for secrets/endpoints (JS ships in clear). Flutter: `reFlutter` on `libapp.so`.

## Insecure data storage (usually highest-yield)

- iOS: `Library/Preferences/*.plist`, unprotected files, Keychain items with weak
  accessibility (`kSecAttrAccessibleAlways`); inspect at runtime with `objection`.
- Android: `shared_prefs/*.xml`, `databases/*.db`, external storage, files
  world-readable via `allowBackup`.
- Any plaintext token / JWT / national-ID / PII / credential = HIGH. Secondary
  leaks: logs (`Log.*`/`NSLog`), clipboard, app-switcher snapshot.

## IPC & deep links

- Android: exported components callable by any app; intent redirection; content
  providers exposing data; broadcast injection; `PendingIntent` without
  `FLAG_IMMUTABLE`. A deep link reaching an auth/state-changing action without
  re-auth = HIGH.
- iOS: URL-scheme hijacking; universal-link validation; pasteboard leakage.

## WebView

A WebView loading a user-derived URL = open redirect / XSS surface.
`addJavascriptInterface` (Android) or an exposed JS bridge reachable from a
non-allowlisted origin = potential RCE.

## Network & device integrity

- Cleartext traffic (`usesCleartextTraffic`, ATS exceptions).
- Missing cert pinning, or a custom `TrustManager`/`NSURLSession` delegate that
  accepts all certs (MITM). On health/payment: missing pinning MEDIUM, trust-all HIGH.
- Biometric/local-auth as the ONLY gate with no server-side check → HIGH
  (patchable client). Missing root/jailbreak detection on health/payment = MEDIUM.
- Tokens issued to the app follow the same JWT/session rules as web —
  cross-reference `get_methodology("code-review")` §B.

## Confidence

Static-only (hardcoded secret, exported component, cleartext config) = "Confirmed
in code" — quote the manifest/plist line. Storage/bypass findings reproduced on an
emulator = "Confirmed exploitable" — note the device path, redact the value.
