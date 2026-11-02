# VulnChat

An Android AI chat app that demonstrates real LLM attack surfaces and their defenses — built as a security portfolio project bridging Android reverse engineering with AI/LLM security.

A single codebase ships in two flavors. The **vulnerable** flavor is naive on purpose; the **hardened** flavor implements layered defenses. A `SECURE_MODE` build flag flips the entire app between them, so every attack can be run against both states and the difference watched live.

---

## What it demonstrates

Risk categories reference the **OWASP GenAI Security Project — Top 10 for LLM Applications 2026**.

| Attack | Defense | OWASP 2026 |
|--------|---------|------------|
| Direct prompt injection | Dual-stage input filter (regex + LLM classifier) | LLM01 |
| Jailbreak attempts | System-prompt hardening + output moderation | LLM01 |
| System-prompt / hidden-context leakage | Hardened prompt, output scanner, context framing | LLM02, LLM08 |
| Indirect prompt injection (via documents) | Document sanitization + provenance + context framing | LLM01, LLM08 |
| API-key extraction (static) | Android Keystore AES-256-GCM; backend proxy | LLM02 |
| API-key extraction (runtime) | Honest limitation — proxy is the real fix | LLM02 |
| Traffic interception | TLS 1.3 + certificate pinning (OkHttp + NSC) | — |
| Document exfiltration via embeddings | On-device embedding (no third-party egress) | LLM09 |
| API quota abuse | Client-side rate limiting (token bucket) | LLM06 |
| Insecure output rendering | Output moderation before UI render | LLM10 |

---

## Status

Feature-complete for demo purposes. All core layers are implemented and wired end to end.

**Implemented**
- Chat pipeline (Jetpack Compose UI → MVVM ViewModel → streaming SSE API client)
- Four security gates: input filter, API-key protection, system-prompt hardening, output moderation
- Secure transport: TLS 1.3, certificate pinning (programmatic + Network Security Config)
- Client-side rate limiting and security headers
- Optional backend-proxy client (JWT exchange) — the architectural key-protection answer
- Full RAG pipeline: document ingestion, sanitization, on-device embedding, vector search, context building
- Document-management UI: paste text, pick a file (Storage Access Framework), load demo samples
- Reverse-engineering demo kit: Frida hook scripts + static-analysis walkthrough

**Known limitations (intentional / documented)**
- RAG embeddings are lexical (hashed n-gram), not semantic — swap in a TFLite sentence-transformer behind the same interface for production quality.
- File picker reads text formats only; PDF/Office extraction needs a parsing library.
- Conversation history and vector index are in-memory by design (no recoverable on-disk corpus).

---

## Architecture

```
Chat UI (Jetpack Compose)
    │
    ▼
InputFilter            Stage 1 regex  →  Stage 2 LLM classifier     [LLM01]
    │ clean
    ▼
RagRetriever           embed → vector search → build context         [LLM08/09]
    │   (only if documents are indexed)
    ▼
SystemPrompt           wrap the whole user turn in a boundary        [LLM02/08]
    │
    ▼
LlmApiClient           TLS 1.3 · cert pinning · rate limit · SSE
    │                  key via ApiKeyProvider (Keystore)             [LLM02]
    ▼
OutputModerator        scan each streamed chunk                      [LLM10]
    │ clean
    ▼
ConversationRepository → UI
```

Both InputFilter (gate 1) and OutputModerator (last gate) are independently sufficient to stop the demonstrated injection attacks — that redundancy is the point. No single layer is trusted.

---

## Two builds, one codebase

`BuildConfig.SECURE_MODE` switches the whole app. Two product flavors let both APKs install side by side on one demo device.

```bash
# Vulnerable build — raw attack surface
./gradlew installVulnerableDebug

# Hardened build — defenses active
./gradlew installHardenedDebug
```

A persistent banner in the UI shows which build is running (amber = vulnerable, teal = hardened), so a demo audience always knows the state.

---

## Setup

### 1. Add your API key

```bash
cp secrets.properties.template secrets.properties
# edit secrets.properties → LLM_API_KEY=sk-ant-...
```

`secrets.properties` is gitignored and never committed.

If your key is identity-linked (not scoped to a workspace), also set `LLM_WORKSPACE_ID` — see the template for how to find it. A workspace-scoped key needs no workspace ID.

### 2. Derive certificate pins (hardened build)

```bash
openssl s_client -connect api.anthropic.com:443 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary | base64
```

Put the leaf pin and one backup (intermediate CA) pin into:
- `app/src/main/java/com/vulnchat/network/LlmApiClient.kt`
- `app/src/main/res/xml/network_security_config.xml`

### 3. Build and install

```bash
./gradlew installVulnerableDebug
./gradlew installHardenedDebug
```

---

## Demo walkthroughs

### A. Static reverse engineering (3 min)

Shows the vulnerable key falling to trivial tooling, and the hardened key resisting it.

```bash
# Pull the installed APK
adb shell pm path com.vulnchat.vulnerable.debug
adb pull <path> vulnerable.apk

# Simplest possible extraction — no decompiler
unzip -o vulnerable.apk classes.dex -d extracted
strings extracted/classes.dex | grep "sk-ant"      # key appears

# Structured view
jadx -d out vulnerable.apk
grep -r "sk-ant" out/sources/                       # key in BuildConfig.java
```

Repeat against `com.vulnchat.hardened.debug` → the key is absent; only a placeholder and Keystore ciphertext remain.

### B. Dynamic reverse engineering — Frida (5 min)

Defeats the Keystore defense static analysis cannot touch. Requires a rooted device/emulator with a matching `frida-server`. See `frida/FRIDA_DEMO.md` for setup.

```bash
# Recover the key from memory — works on the HARDENED build
frida -U -f com.vulnchat.hardened -l frida/hook_apikey.js
# → send a message → full plaintext key prints

# Bypass certificate pinning
frida -U -f com.vulnchat.hardened -l frida/bypass_pinning.js

# Glass-box: watch every security gate fire live
frida -U -f com.vulnchat.hardened -l frida/hook_security_layers.js
```

The escalation ladder this proves: static analysis is defeated by the hardened build → the hardened build is defeated by Frida → Frida is defeated by the backend proxy (a key never on the device cannot be hooked out of it).

### C. Indirect prompt injection via RAG (5 min)

The RAG attack: a planted document, not the user's message, carries the payload.

1. Tap **+** in the chat screen → **Poisoned: marker injection (reliable)**.
2. **Vulnerable build** → ask any question (e.g. "what was endpoint coverage?"). The retrieved document's injected instruction fires: every reply ends with `[[INJECTED-7781]]`. A "Referenced: …" notice confirms the document was retrieved.
3. **Hardened build** → load the same sample. `DocumentSanitizer` rejects it at ingestion ("contains: instruction override"); the marker never appears.
4. For the dramatic variant, use **Poisoned: prompt disclosure** on the vulnerable build — the decoy "secret" planted in the vulnerable system prompt leaks into the chat.

Lead with the marker payload: its success is deterministic. The disclosure payload is more striking but less reliable, because a frontier model may refuse the leak on its own — which is itself the lesson: the model's own resistance is not a control you own.

---

## Project structure

```
vulnchat/
├── app/src/main/java/com/vulnchat/
│   ├── VulnChatApplication.kt
│   ├── security/
│   │   ├── InputFilter.kt          regex + LLM classifier         [LLM01]
│   │   ├── ApiKeyProvider.kt       Keystore AES-256-GCM           [LLM02]
│   │   ├── SystemPrompt.kt         hardened vs vulnerable prompt  [LLM02/08]
│   │   └── OutputModerator.kt      response scanner               [LLM10]
│   ├── network/
│   │   ├── LlmApiClient.kt         OkHttp · TLS · pinning · SSE
│   │   ├── NetworkInterceptors.kt  security headers · rate limit  [LLM06]
│   │   └── BackendProxyClient.kt   JWT proxy (key off-device)     [LLM02]
│   ├── rag/
│   │   ├── RagModels.kt            trust levels, chunks, reports
│   │   ├── DocumentSanitizer.kt    ingestion-time injection gate  [LLM01/08]
│   │   ├── ContextBuilder.kt       delimited, labelled context    [LLM08]
│   │   ├── EmbeddingProvider.kt    on-device vs remote            [LLM09]
│   │   ├── VectorIndex.kt          cosine search, trust-weighted
│   │   └── RagRetriever.kt         pipeline orchestration
│   ├── data/
│   │   └── ConversationRepository.kt   in-memory history
│   └── ui/
│       ├── MainActivity.kt
│       ├── ChatScreen.kt
│       ├── ChatViewModel.kt        wires all layers together
│       ├── DocumentSheet.kt        document management + file picker
│       └── theme/VulnChatTheme.kt
├── app/src/main/res/xml/
│   ├── network_security_config.xml  OS-level cert pinning
│   ├── data_extraction_rules.xml    backup exclusions
│   └── backup_rules.xml
├── frida/
│   ├── hook_apikey.js
│   ├── bypass_pinning.js
│   ├── hook_security_layers.js
│   └── FRIDA_DEMO.md
├── app/proguard-rules.pro
├── secrets.properties.template      ← commit this (not secrets.properties)
└── build files (Gradle, manifest, version catalog)
```

---

## Security notes

- `secrets.properties` is gitignored — never commit the real key.
- Certificate pins expire; update `network_security_config.xml` and `LlmApiClient.kt` before expiry.
- The vulnerable flavor is for demonstration only — never publish it.
- The Storage Access Framework file picker requests **no** storage permission: it reads only the single file the user selects. Least privilege by construction.
- Conversation history and the vector index live in memory, so no document corpus is recoverable via `adb backup` or root file access.

---

## Tech stack

Kotlin · Jetpack Compose · MVVM (ViewModel + StateFlow) · Coroutines · OkHttp/Retrofit · Android Keystore · Anthropic Messages API (streaming SSE).

## Related portfolio projects

- **VulnDroid** — deliberately vulnerable Android app covering the OWASP Mobile Top 10.
- **LLM Red Team Tool** — Python CLI targeting the OWASP LLM Top 10.

---

*VulnChat is a personal project for exploring mobile and AI security. All reverse engineering and attacks described here are performed against this application. The tools referenced — jadx, apktool, Frida — are standard in mobile security assessments.*
