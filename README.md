<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authenticator v3</title>
<style>
  :root{--bg:#0f172a;--card:#1e293b;--fg:#e2e8f0;--muted:#94a3b8;--accent:#22d3ee}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,sans-serif}
  .card{background:var(--card);border-radius:16px;padding:32px 28px;width:min(92vw,420px);box-shadow:0 10px 40px rgba(0,0,0,.45)}
  h1{font-size:18px;margin:0 0 4px}
  .badge{display:inline-block;background:#065f46;color:#a7f3d0;font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;vertical-align:middle;margin-left:8px}
  p.sub{color:var(--muted);margin:0 0 22px;font-size:13px}
  label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px}
  input[type=text]{width:100%;padding:10px 12px;border:1px solid #334155;border-radius:8px;background:#0b1220;color:var(--fg);font-family:monospace;font-size:14px;letter-spacing:1px}
  input[type=text]:focus{outline:none;border-color:var(--accent)}
  .code{font-family:"Consolas","Menlo",monospace;font-size:56px;font-weight:700;letter-spacing:8px;text-align:center;margin:28px 0 6px;user-select:all}
  .hint{text-align:center;color:var(--muted);font-size:13px;min-height:18px}
  .bar{height:8px;background:#334155;border-radius:4px;margin-top:14px;overflow:hidden}
  .fill{height:100%;background:var(--accent);width:100%;border-radius:4px;transition:width .2s linear}
  .sec{text-align:center;font-size:12px;color:var(--muted);margin-top:8px}
  .note{margin-top:20px;font-size:11px;color:var(--muted);line-height:1.6}
  .debug{margin-top:12px;font-size:11px;color:#f59e0b;word-break:break-all}
</style>
</head>
<body>
<div class="card">
  <h1>Authenticator<span class="badge">v3</span></h1>
  <p class="sub">Single account code - updates like the phone</p>

  <label for="secret">Base32 secret</label>
  <input type="text" id="secret" spellcheck="false" autocomplete="off" value="i2zmsub33ldt4nuiqvsqnadf5reyo2mu">

  <div class="code" id="code">------</div>
  <div class="hint" id="hint">Computing…</div>
  <div class="bar"><div class="fill" id="fill" style="width:100%"></div></div>
  <div class="sec" id="sec">&nbsp;</div>
  <div class="debug" id="dbgclock" style="color:#64748b"></div>

  <div class="note">Codes refresh every 30 seconds and are generated entirely on this device. Anyone who can read this secret can log in as the account, so keep this file private.</div>
</div>

<script>
(function () {
  "use strict";

  /* ===== SHA-1 (plain arrays only — no TypedArray or DataView) ===== */
  function sha1(msg) {
    var len = msg.length;
    var bitLen = len * 8;
    msg = msg.concat([0x80]);
    while (msg.length % 64 !== 56) msg.push(0);
    msg.push(0); msg.push(0); msg.push(0);                    /* length bytes 7-5 (0) */
    msg.push((bitLen / 0x100000000) & 0xFF);                  /* byte 4 */
    msg.push((bitLen / 0x1000000) & 0xFF);                    /* byte 3 */
    msg.push((bitLen / 0x10000) & 0xFF);                      /* byte 2 */
    msg.push((bitLen / 0x100) & 0xFF);                        /* byte 1 */
    msg.push(bitLen & 0xFF);                                  /* byte 0 */

    var h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    var w = [], a, b, c, d, e, f, k, t, i;

    for (var blk = 0; blk < msg.length; blk += 64) {
      for (i = 0; i < 16; i++)
        w[i] = (msg[blk + i*4] << 24) | (msg[blk + i*4+1] << 16) | (msg[blk + i*4+2] << 8) | msg[blk + i*4+3];

      for (i = 16; i < 80; i++) {
        t = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = ((t << 1) | (t >>> 31)) & 0xFFFFFFFF;
      }

      a = h0; b = h1; c = h2; d = h3; e = h4;

      for (i = 0; i < 80; i++) {
        if      (i < 20) { f = (b & c) | ((~b) & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                     k = 0xCA62C1D6; }

        t = ((a << 5) | (a >>> 27)) + f + e + k + w[i];
        e = d; d = c; c = ((b << 30) | (b >>> 2)) & 0xFFFFFFFF; b = a; a = t & 0xFFFFFFFF;
      }

      h0 = (h0 + a) & 0xFFFFFFFF; h1 = (h1 + b) & 0xFFFFFFFF;
      h2 = (h2 + c) & 0xFFFFFFFF; h3 = (h3 + d) & 0xFFFFFFFF;
      h4 = (h4 + e) & 0xFFFFFFFF;
    }

    return [(h0>>>24)&0xFF,(h0>>>16)&0xFF,(h0>>>8)&0xFF,h0&0xFF,
            (h1>>>24)&0xFF,(h1>>>16)&0xFF,(h1>>>8)&0xFF,h1&0xFF,
            (h2>>>24)&0xFF,(h2>>>16)&0xFF,(h2>>>8)&0xFF,h2&0xFF,
            (h3>>>24)&0xFF,(h3>>>16)&0xFF,(h3>>>8)&0xFF,h3&0xFF,
            (h4>>>24)&0xFF,(h4>>>16)&0xFF,(h4>>>8)&0xFF,h4&0xFF];
  }

  /* ===== HMAC-SHA1 (plain arrays) ===== */
  function hmacSha1(key, msg) {
    if (key.length > 64) key = sha1(key);
    var k = key.slice();
    while (k.length < 64) k.push(0);
    var ipad = [], opad = [], i;
    for (i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5C; }
    return sha1(opad.concat(sha1(ipad.concat(msg))));
  }

  /* ===== Base32 decode (plain arrays) ===== */
  function base32Decode(s) {
    var upper = "", i, c, v;
    for (i = 0; i < s.length; i++) { c = s.charCodeAt(i); upper += String.fromCharCode(c >= 97 && c <= 122 ? c - 32 : c); }
    var out = [], bits = 0, val = 0;
    for (i = 0; i < upper.length; i++) {
      c = upper.charCodeAt(i);
      if (c >= 65 && c <= 90) v = c - 65;
      else if (c >= 50 && c <= 55) v = c - 24;
      else continue;
      val = val * 32 + v;
      bits += 5;
      while (bits >= 8) { bits -= 8; out.push((val / (1 << bits)) & 0xFF); val = val % (1 << bits); }
    }
    return out;
  }

  /* ===== TOTP ===== */
  function totp(secret, digits, step) {
    var key = base32Decode(secret);
    var counter = Math.floor(Date.now() / 1000 / step);
    var msg = [], i, ctr = counter;
    for (i = 0; i < 8; i++) { msg.unshift(ctr & 0xFF); ctr = Math.floor(ctr / 256); }
    var h = hmacSha1(key, msg);
    var o = h[19] & 0x0F;
    var code = (((h[o] & 0x7F) * 0x1000000) + (h[o+1] * 0x10000) + (h[o+2] * 0x100) + h[o+3]) >>> 0;
    var mod = 1;
    for (i = 0; i < digits; i++) mod = mod * 10;
    var s = String(code % mod);
    while (s.length < digits) s = "0" + s;
    return s;
  }

  /* ===== page logic ===== */
  var codeEl   = document.getElementById("code");
  var hintEl   = document.getElementById("hint");
  var fillEl   = document.getElementById("fill");
  var secEl    = document.getElementById("sec");
  var inputEl  = document.getElementById("secret");
  var clockEl  = document.getElementById("dbgclock");

  function tick() {
    var unix = Math.floor(Date.now() / 1000);
    var secsLeft = 29 - (unix % 30);
    clockEl.textContent = "browser clock (UTC unix): " + unix + "  |  counter: " + Math.floor(unix / 30);
    var secret = inputEl.value.trim();
    if (!secret) {
      codeEl.textContent = "------";
      hintEl.textContent = "Enter your secret above";
      fillEl.style.width = "100%";
      secEl.textContent = "\u00a0";
      return;
    }
    try {
      var code = totp(secret, 6, 30);
      codeEl.textContent = code;
      hintEl.textContent = "Valid for the next " + (secsLeft + 1) + " s";
    } catch (e) {
      codeEl.textContent = "------";
      hintEl.textContent = "Couldn't generate a code - paste the secret exactly as shown";
      clockEl.textContent += "  |  err=" + e.message;
      fillEl.style.width = "100%";
      secEl.textContent = "\u00a0";
      return;
    }
    fillEl.style.width = ((secsLeft + 1) / 30 * 100) + "%";
    secEl.textContent = "Refreshes in " + secsLeft + " s";
  }

  setInterval(tick, 200);
  tick();
})();
</script>
</body>
</html>
