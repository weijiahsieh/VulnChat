# I Built a Secure Android LLM Chat App. Then I Tried to Break It.

*What jadx, apktool, and Frida taught me about the limits of on-device security.*

---

When I set out to secure an Android chat app that talks to an LLM API, I did what most tutorials tell you to do. I moved the API key out of source control. I hardened the system prompt. I added certificate pinning. I encrypted secrets with the Android Keystore. The checklist looked complete.

Then I picked up the tools an attacker would use — jadx, apktool, and Frida — and pointed them at my own APK. Some of my defenses held exactly as designed. Others fell in a single command. The gap between "I followed the security checklist" and "my app is actually secure" turned out to be wide, and it lives almost entirely in one distinction: **the difference between an attacker who reads your app and an attacker who runs it.**

This is a writeup of what I learned wearing both hats. The app is called VulnChat — a deliberately dual-mode LLM chat client I built with a `SECURE_MODE` flag that flips the entire app between a vulnerable implementation and a hardened one. That flag let me attack the same feature in both states and watch precisely where each defense started and stopped mattering.

---

## The threat model I started with

An LLM chat app has a few assets worth stealing:

- **The API key.** It has real monetary value — anyone who extracts it bills their usage to your account.
- **The system prompt.** It encodes your app's behavior and guardrails. Leaking it hands an attacker the blueprint for bypassing them.
- **The traffic.** Prompts and responses may contain user data you don't want a network observer reading.

My hardened build addressed all three on paper. The question was whether "on paper" survived contact with tooling.

I sorted the tools into two camps, and that sorting turned out to be the whole story:

- **Static analysis** reads the app without running it: jadx, apktool, `strings`.
- **Dynamic analysis** runs the app and manipulates it live: Frida.

---

## Round 1: Static analysis, and the defense that worked

### The vulnerable build falls in one command

The vulnerable build stores the API key the way an alarming number of real apps do — as a compile-time constant that lands in `BuildConfig`. You don't even need a decompiler to find it. The humble `strings` command, scanning the raw DEX bytecode, is enough:

```bash
unzip -o app-vulnerable.apk classes.dex -d extracted
strings extracted/classes.dex | grep "sk-ant"
```

```
sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxx...
```

There it is. A 40-year-old Unix text utility, no reverse-engineering expertise required. This is the demonstration I find most persuasive, precisely because it's so unsophisticated. If `strings` can find your key, the bar to steal it is on the floor.

`jadx` tells the same story with more structure, reconstructing readable Java from the DEX:

```bash
jadx -d out app-vulnerable.apk
grep -r "sk-ant" out/sources/
```

```java
// out/sources/com/vulnchat/BuildConfig.java
public static final String LLM_API_KEY_PLAIN = "sk-ant-api03-...";
```

### The hardened build holds

Now the same commands against the hardened build. The key is no longer a constant — it's AES-256-GCM encrypted, the ciphertext lives in `SharedPreferences`, and the encryption key is generated inside the Android Keystore, backed by hardware where the device supports it.

```bash
strings extracted/classes.dex | grep "sk-ant"     # nothing
jadx -d out app-hardened.apk
grep -r "sk-ant" out/sources/                       # nothing
```

`BuildConfig` now yields only a placeholder. Static analysis has nothing to grab. **This is the defense working exactly as intended** — against a static attacker.

### apktool: reading the manifest, not the code

Where jadx reconstructs Java, apktool decodes resources and the manifest and stops at smali (Dalvik assembly). It sidesteps the decompilation edge cases that trip jadx on some builds, and it surfaces a different class of finding — configuration rather than logic:

```bash
apktool d app-hardened.apk -o out_hardened
```

Comparing the two builds' decoded `AndroidManifest.xml` makes the hardening legible at the config layer:

```xml
<!-- Hardened -->
android:usesCleartextTraffic="false"
android:allowBackup="false"
android:networkSecurityConfig="@xml/network_security_config"
```

The `network_security_config.xml` it extracts also reveals the certificate pins — which foreshadows the next round, because a pin an attacker can *read* is not the same as a pin an attacker can *defeat*.

**The static scorecard:** vulnerable build, total loss. Hardened build, holds the line. If this were the whole story, the Keystore checklist item would be vindicated and we'd stop here. Dynamic analysis is where that conclusion comes apart.

---

## Round 2: Dynamic analysis, and the defense that didn't hold

Static analysis only ever reads what's frozen in the APK. But a running app has to *use* its secrets — decrypt the key, present a certificate, evaluate a filter. Frida attaches to the live process and rewrites method behavior at runtime, which means it operates on those secrets at the exact moment they exist in the clear.

*(Frida needs a rooted device or emulator — it's the attacker's environment, not the average user's. That caveat matters for calibrating the real-world risk, and I'll come back to it.)*

### Hooking the key straight out of memory

Here's the uncomfortable truth about the Keystore defense: `getApiKey()` **has to** return the plaintext key, or the network layer can't authenticate. However well-encrypted the key is at rest, the moment it's used it's plaintext in memory. Frida intercepts it right there:

```javascript
Java.perform(function () {
    var Provider = Java.use('com.vulnchat.security.ApiKeyProvider');

    Provider.getApiKey.implementation = function () {
        var key = this.getApiKey();   // let real decryption happen
        console.log('[KEY RECOVERED] ' + key);
        return key;                    // app keeps working, none the wiser
    };
});
```

```bash
frida -U -f com.vulnchat.hardened -l hook_apikey.js
```

Send one message in the app, and the full plaintext key prints to the console — **from the hardened build that defeated every static tool minutes earlier.** The hook observes without altering behavior, so the app runs normally and the user sees nothing.

This isn't a flaw in the Keystore implementation. The Keystore did its job: it kept the key encrypted at rest and out of the APK. The point is subtler and more important — **encryption at rest doesn't protect a secret from an attacker who is present at the moment of use.**

### Bypassing certificate pinning

Certificate pinning was supposed to stop traffic interception. Against a network attacker, it does. Against an attacker inside the process, pinning is just client-side code — and client-side code on a rooted device isn't trustworthy. Neutralizing OkHttp's pinner takes a few lines:

```javascript
var CertificatePinner = Java.use('okhttp3.CertificatePinner');
CertificatePinner.check.overload('java.lang.String', 'java.util.List')
    .implementation = function (hostname, peerCertificates) {
        return;   // a pin check that never fails
    };
```

With the check defanged and an intercepting proxy in place, the request — API key header, full prompt, everything — is readable in cleartext against the pinned build.

Worth being precise here: my hardened build pins at *two* layers, OkHttp and the OS Network Security Config. Frida handles the OkHttp layer; the OS layer still requires installing the interception CA as a system certificate on the rooted device. Two layers meant the bypass wasn't a one-liner — which is the honest, if modest, dividend of defense in depth.

---

## What the escalation ladder actually teaches

Lining up the two rounds produces a ladder, and each rung motivates the next:

| Defense | Static analysis | Dynamic analysis (rooted) |
|---|---|---|
| Key in BuildConfig | **Broken** — `strings` finds it | Broken |
| Key in Keystore | Holds — only ciphertext | **Broken** — hooked from memory |
| Certificate pinning | Holds — it's runtime-enforced | **Broken** — pinner neutralized |

The pattern is what matters. Every on-device defense I added raised the bar for the *next* class of attacker without ever reaching "unbreakable." Keystore defeats static analysis and forces the attacker to escalate to a rooted device and runtime instrumentation. That escalation is not nothing — it's a real increase in attacker cost and a real narrowing of who can pull it off. But it is a speed bump, not a wall.

Which leads to the conclusion I didn't have when I started: **for a truly sensitive secret, the fix isn't better on-device protection. It's not putting the secret on the device at all.**

A backend proxy is the architectural answer. The app authenticates to a server you control; the server holds the real API key and talks to the LLM. The key is never in the APK, never in the device's memory, never hookable — because it was never there. Frida can still lift the session token, but a short-lived, narrowly-scoped token has a bounded blast radius that a long-lived API key never will. It's the one design on the ladder that doesn't eventually fall to the next rung, because it removes the asset from the attacker's reach entirely.

---

## The honest caveat, and why it doesn't rescue the checklist

Every dynamic attack here needs root. The overwhelming majority of your users aren't running a rooted device with a matching `frida-server`, so the practical risk to any single user's data is lower than a raw reading of the ladder suggests. Client-side hardening is genuinely worth doing — it defeats casual static analysis, raises attacker cost, and protects ordinary users.

But "the attacker needs root" is not a defense for the asset that *is* the target. An API key isn't tied to a victim's device — an attacker extracts it from *their own* rooted device and bills *your* account. For that asset, "most users aren't rooted" is irrelevant, because the attacker only needs to root the one device they own. This is exactly the class of secret that belongs behind a proxy, and exactly why the checklist — which quietly assumes a static or network attacker — gives false comfort.

---

## What I'd tell my past self

1. **Sort your defenses by which attacker they stop.** Static, network, and runtime attackers are different threats. A control that stops one may do nothing against another, and a checklist that doesn't name the attacker is hiding that gap.
2. **Encryption at rest is not encryption in use.** Keystore protects a key in storage. It does nothing at the moment of use, which is exactly when a runtime attacker is watching.
3. **Client-side controls delay a runtime attacker; they never defeat one.** Pinning, obfuscation, root detection — all speed bumps. Useful, finite, not solutions.
4. **The only way to protect a secret from the device is to keep it off the device.** For anything genuinely sensitive, that means a backend proxy and short-lived tokens.

Attacking my own app taught me more than building it did. Following the checklist produced an app that *looked* secure and stopped the attacker I had implicitly imagined — someone reading the APK. It was picking up Frida, and watching a "hardened" key print to my console, that showed me the attacker I hadn't imagined, and the one architectural decision that actually holds up.

If you build LLM apps on mobile: put the key behind a proxy. Everything else on the checklist is worth doing, but that's the line between raising the bar and actually protecting the asset.

---

*VulnChat is a personal project built to explore mobile and AI security. All reverse engineering described here was performed against my own application. The techniques are standard practice in mobile security assessments; the tools — jadx, apktool, and Frida — are staples of any Android security engagement.*
