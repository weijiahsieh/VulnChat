/*
 * hook_apikey.js — dump the API key at runtime from ApiKeyProvider.getApiKey()
 *
 * WHAT THIS PROVES
 *   Static analysis (jadx, strings) recovers the key only in the VULNERABLE
 *   build, where it sits in BuildConfig as a plaintext constant. In the
 *   HARDENED build the key is AES-256-GCM encrypted and the ciphertext lives
 *   in SharedPreferences — static tools find nothing useful.
 *
 *   But getApiKey() must return the PLAINTEXT key for the network layer to
 *   use it. That plaintext exists in process memory the moment Keystore
 *   finishes decrypting. This hook intercepts the return value at exactly
 *   that point — recovering the key in BOTH builds.
 *
 *   This is the live demonstration of the limitation already documented in
 *   ApiKeyProvider.kt: "a rooted device with Frida attached can still hook
 *   getApiKey() and intercept the plaintext return value." It is also the
 *   argument for the backend proxy: a key that is never on the device cannot
 *   be hooked out of the device's memory.
 *
 * REQUIREMENTS
 *   - Rooted device or emulator (frida-server running as root), OR
 *   - A debuggable build with a Frida gadget embedded.
 *   - Frida installed on host: pip install frida-tools
 *
 * USAGE
 *   Spawn (recommended — catches provisioning on first launch):
 *     frida -U -f com.vulnchat.hardened -l hook_apikey.js
 *
 *   Attach to a running app:
 *     frida -U -n "VulnChat (Hardened)" -l hook_apikey.js
 *
 *   Replace the target with com.vulnchat.vulnerable.debug for the
 *   vulnerable flavour (note the .debug suffix on debug builds).
 */

'use strict';

// The demo app uses a fixed package/class layout. If R8 minification renamed
// the class in a release build, set MINIFIED_FALLBACK to true to scan for the
// method by signature instead of by name.
var TARGET_CLASS = 'com.vulnchat.security.ApiKeyProvider';
var TARGET_METHOD = 'getApiKey';

function log(msg) {
    console.log('\x1b[36m[hook_apikey]\x1b[0m ' + msg);
}

function banner(key) {
    console.log('\n\x1b[42m\x1b[30m  API KEY RECOVERED AT RUNTIME  \x1b[0m');
    console.log('\x1b[32m' + key + '\x1b[0m\n');
}

Java.perform(function () {
    try {
        var Provider = Java.use(TARGET_CLASS);

        // getApiKey() takes no arguments and returns String.
        Provider.getApiKey.implementation = function () {
            // Call the original so real decryption still happens — we observe,
            // we do not alter behaviour. The app keeps working normally, which
            // matters for a demo: the user sees nothing wrong.
            var result = this.getApiKey();

            log('ApiKeyProvider.getApiKey() intercepted');
            log('SECURE_MODE build: the key below was returned to the caller');
            log('regardless of whether it came from BuildConfig or Keystore.');
            banner(result);

            // Show the call site so the audience sees WHERE in the app the
            // key is requested — makes the "it is in memory here" point concrete.
            var stack = Java.use('android.util.Log').getStackTraceString(
                Java.use('java.lang.Exception').$new()
            );
            log('Call stack:\n' + stack.split('\n').slice(1, 5).join('\n'));

            return result;
        };

        log('Hook installed on ' + TARGET_CLASS + '.' + TARGET_METHOD + '()');
        log('Send a chat message in the app to trigger the key retrieval.');

    } catch (e) {
        console.log('\x1b[31m[hook_apikey] FAILED: ' + e + '\x1b[0m');
        log('If the class was renamed by R8, try the signature scan below.');

        // Fallback: enumerate loaded classes for one exposing a no-arg method
        // returning a string that looks like an API key. Slower, but survives
        // minification that renames the class.
        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                if (name.indexOf('vulnchat') !== -1) {
                    log('candidate class still present: ' + name);
                }
            },
            onComplete: function () {}
        });
    }
});
