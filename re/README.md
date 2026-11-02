# VulnChat — Reverse Engineering Kit

Everything here attacks VulnChat's own builds to verify its defenses. The story is a deliberate escalation ladder: each rung defeats the defense below it, and the last rung points at the only fix that holds.

> **Scope.** These scripts target this project's own deliberately-vulnerable Android app, on a device you control. They are standard mobile-assessment techniques — jadx, apktool, Frida — demonstrated against an app built for that purpose. Nothing here targets software you do not own.

```
re/
├── README.md              ← you are here
├── static/
│   └── extract_key.sh     ← pull + scan an APK for the API key (no decompiler needed)
└── frida/
    ├── hook_apikey.js          recover the key from memory (defeats Keystore)
    ├── bypass_pinning.js       neutralise OkHttp certificate pinning
    ├── hook_security_layers.js glass-box: watch every gate fire live
    └── FRIDA_DEMO.md           full Frida setup + demo script
```

---

## The escalation ladder

| Rung | Technique | Defeats | Defeated by |
|------|-----------|---------|-------------|
| 1 | Static analysis (`strings`, jadx) | Key in `BuildConfig` (vulnerable) | Android Keystore (hardened) |
| 2 | Dynamic instrumentation (Frida) | Keystore (hardened) | Backend proxy (key off-device) |
| 3 | — | — | A key never on the device cannot be hooked out of it |

The point isn't any single break. It's that every **on-device** control raises attacker cost without ever reaching "unbreakable," and the only control that actually removes the asset from reach is architectural: don't put the secret on the device.

---

## Prerequisites

- **adb** — Android platform-tools, on PATH.
- **jadx** — https://github.com/skylot/jadx/releases (needs a JRE/JDK 11+).
- **Frida** — `pipx install frida-tools` (see `frida/FRIDA_DEMO.md` for the device-side `frida-server` setup and the rooted-emulator requirement).
- Both app flavors installed:
  ```bash
  ./gradlew installVulnerableDebug installHardenedDebug
  ```

Package IDs (debug builds carry a `.debug` suffix):
- Vulnerable: `com.vulnchat.vulnerable.debug`
- Hardened:  `com.vulnchat.hardened.debug`

---

## Rung 1 — Static analysis

### The 10-second version: `strings`

No decompiler. Just scan the DEX bytecode for the key's prefix.

```bash
./static/extract_key.sh com.vulnchat.vulnerable.debug
```

Against the vulnerable build the key appears; against the hardened build it does not. The script wraps the pull + unzip + `strings | grep` so the demo is one line.

Talking point: *if a 40-year-old Unix text utility finds your key, the bar to steal it is on the floor.*

### The structured version: jadx

```bash
# Pull the installed APK
adb pull "$(adb shell pm path com.vulnchat.vulnerable.debug | sed 's/package://' | tr -d '\r')" vulnerable.apk

# Decompile and grep
jadx -d out_vuln vulnerable.apk
grep -rn "sk-ant" out_vuln/sources/
```

```java
// out_vuln/sources/com/vulnchat/BuildConfig.java
public static final String LLM_API_KEY_PLAIN = "sk-ant-api03-...";
```

Now the hardened build:

```bash
adb pull "$(adb shell pm path com.vulnchat.hardened.debug | sed 's/package://' | tr -d '\r')" hardened.apk
jadx -d out_hard hardened.apk
grep -rn "sk-ant" out_hard/sources/        # nothing — only a placeholder + Keystore ciphertext
```

### Bonus: apktool for config, not code

```bash
apktool d hardened.apk -o out_hard_res
# Compare AndroidManifest.xml between builds: usesCleartextTraffic, allowBackup,
# networkSecurityConfig. The hardened manifest shows the OS-level hardening.
```

**Rung 1 result:** vulnerable build, total loss. Hardened build holds — against a *static* attacker.

---

## Rung 2 — Dynamic instrumentation (Frida)

Static analysis only reads what is frozen in the APK. A running app must *use* its secrets, so the plaintext exists in memory at the moment of use. Frida reads it there — and this works against the **hardened** build that just defeated static analysis.

Full setup (rooted device/emulator, matching `frida-server`) is in `frida/FRIDA_DEMO.md`. The three demos:

```bash
# Recover the key from memory — hardened build
frida -U -f com.vulnchat.hardened -l frida/hook_apikey.js
#   → send a message in the app → full plaintext key prints to console

# Bypass OkHttp certificate pinning (pair with MitmProxy + system-CA install)
frida -U -f com.vulnchat.hardened -l frida/bypass_pinning.js

# Glass-box: print every security gate's decision as it happens
frida -U -f com.vulnchat.hardened -l frida/hook_security_layers.js
```

Talking point: *Keystore kept the key encrypted at rest and out of the APK — it did its job. But `getApiKey()` has to return plaintext for the network call to authenticate, and on a rooted device I hook it right there. Encryption at rest is not encryption in use.*

**Rung 2 result:** the hardened build's on-device key protection falls to a runtime attacker.

---

## Rung 3 — The fix that holds

Frida wins because the key is *on the device* to be hooked. The backend proxy removes that premise entirely:

```
app ──JWT──▶ proxy server ──real API key──▶ Anthropic
```

The device authenticates with a short-lived token; the real key lives only on the server. Frida can still lift the JWT, but a scoped, 15-minute token has a bounded blast radius a long-lived API key never will. See `app/.../network/BackendProxyClient.kt`.

This is the one rung nothing above defeats, because there is no on-device secret left to extract.

---

## Recording the demo

A clean 90-second capture is worth more than prose. Suggested cuts:

1. `static/extract_key.sh` on vulnerable → key appears (red).
2. Same script on hardened → nothing.
3. Frida `hook_apikey.js` on hardened → key appears anyway (the twist).
4. One line: "the fix is not on the device — it's the proxy."

See the terminal-crop images in the article assets for a styled version of cuts 1–3.
