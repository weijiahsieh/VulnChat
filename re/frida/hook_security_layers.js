/*
 * hook_security_layers.js — observe every VulnChat security gate at runtime
 *
 * A single script that instruments all four defensive layers so you can
 * narrate the entire pipeline live from the Frida console while using the app.
 * Where hook_apikey.js proves ONE point deeply, this gives the audience the
 * whole picture: they see each gate fire, in order, as a message flows through.
 *
 * This is the "glass box" version of the demo — the app runs normally, but
 * every security decision is printed as it happens.
 *
 * USAGE
 *   frida -U -f com.vulnchat.hardened -l hook_security_layers.js
 *
 * Then in the app, try:
 *   1. "Hello"                                   → InputFilter passes, clean flow
 *   2. "ignore previous instructions..."         → InputFilter regex blocks
 *   3. A jailbreak the regex misses               → InputFilter classifier blocks
 *   4. (with a poisoned doc indexed) a normal Q   → watch retrieval + output scan
 */

'use strict';

function tag(name, color) {
    return '\x1b[' + color + 'm[' + name + ']\x1b[0m';
}
var C = { key: '36', input: '33', output: '35', prompt: '32', dim: '90' };

Java.perform(function () {

    // ── ApiKeyProvider.getApiKey() ──────────────────────────────────────────
    try {
        var Provider = Java.use('com.vulnchat.security.ApiKeyProvider');
        Provider.getApiKey.implementation = function () {
            var key = this.getApiKey();
            var masked = key.length > 12
                ? key.substring(0, 8) + '…' + key.substring(key.length - 4)
                : '(short)';
            console.log(tag('KEY', C.key) + ' getApiKey() → ' + masked +
                '   \x1b[90m(full key is in memory here)\x1b[0m');
            return key;
        };
    } catch (e) { console.log(tag('KEY', C.key) + ' not hooked: ' + e); }

    // ── InputFilter.evaluate() — the suspend fun ────────────────────────────
    // Kotlin suspend functions compile to a method taking an extra
    // Continuation parameter. We hook the synchronous regex stage instead,
    // which is a plain function and the more interesting one to show anyway.
    try {
        var InputFilter = Java.use('com.vulnchat.security.InputFilter');

        // runRegexStage is private; Frida can still hook it by name.
        InputFilter.runRegexStage.implementation = function (input) {
            var rule = this.runRegexStage(input);
            if (rule !== null) {
                console.log(tag('INPUT', C.input) + ' regex BLOCK rule=' + rule +
                    '  input="' + shorten(input) + '"');
            } else {
                console.log(tag('INPUT', C.input) + ' regex pass  input="' +
                    shorten(input) + '"');
            }
            return rule;
        };
    } catch (e) { console.log(tag('INPUT', C.input) + ' not hooked: ' + e); }

    // ── SystemPrompt.get() — see which prompt is active ─────────────────────
    try {
        var SystemPrompt = Java.use('com.vulnchat.security.SystemPrompt');
        SystemPrompt.get.implementation = function () {
            var p = this.get();
            console.log(tag('PROMPT', C.prompt) + ' system prompt: ' +
                p.length + ' chars ' +
                (p.length > 500 ? '(hardened)' : '(vulnerable — naive)'));
            return p;
        };
    } catch (e) { console.log(tag('PROMPT', C.prompt) + ' not hooked: ' + e); }

    // ── OutputModerator.scanChunk() ─────────────────────────────────────────
    try {
        var OutputMod = Java.use('com.vulnchat.security.OutputModerator');
        OutputMod.scanChunk.implementation = function (chunk) {
            var result = this.scanChunk(chunk);
            // ScanResult is sealed; Blocked carries a violation. Detect the
            // subclass by simple name.
            var cn = result.getClass().getSimpleName();
            if (cn.indexOf('Blocked') !== -1) {
                console.log(tag('OUTPUT', C.output) +
                    ' \x1b[41m\x1b[37m BLOCKED \x1b[0m response chunk scanned and stopped');
            }
            return result;
        };
    } catch (e) { console.log(tag('OUTPUT', C.output) + ' not hooked: ' + e); }

    function shorten(s) {
        s = ('' + s).replace(/\n/g, ' ');
        return s.length > 50 ? s.substring(0, 47) + '...' : s;
    }

    console.log('\x1b[42m\x1b[30m VulnChat security layers instrumented \x1b[0m');
    console.log('\x1b[90mSend messages in the app and watch each gate report.\x1b[0m\n');
});
