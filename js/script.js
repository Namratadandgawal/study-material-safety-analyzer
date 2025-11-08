// Study Material Safety Analyzer - script.js
// Simple logic-based checks (no AI, no backend).
// Written with readability in mind for beginners.

(function () {
  // DOM elements
  const filenameInput = document.getElementById('filenameInput');
  const urlInput = document.getElementById('urlInput');
  const checkFilenameBtn = document.getElementById('checkFilenameBtn');
  const checkUrlBtn = document.getElementById('checkUrlBtn');
  const results = document.getElementById('results');

  // Suspicious patterns you can expand — these are intentionally simple
  const suspiciousNameKeywords = [
    '_final', '_finalversion', 'finalversion', '_compressed', 'compressed',
    'freebook', 'crack', 'unlock', 'serial', 'keygen', 'patch'
  ];
  const clickbaitKeywords = [
    '100% free', 'guaranteed', 'instant download', 'no ads', 'leaked', 'premium free'
  ];
  const unsafeExtensions = ['exe','bat','scr','msi','com','pif','cmd']; // don't run these on PC
  const riskyUrlKeywords = ['drive-download', 'fastload', 'file-share', 'secure-mirror', 'download-now'];

  // Helpers
  function addResult(title, level, text) {
    // level: 'safe' | 'warn' | 'danger'
    const el = document.createElement('div');
    el.className = 'result';
    el.innerHTML = `
      <h3>${title} <span class="badge ${level === 'safe' ? 'safe' : level === 'warn' ? 'warn' : 'danger'}">${level.toUpperCase()}</span></h3>
      <div class="small">${text}</div>
    `;
    results.prepend(el);
  }

  function lower(s){ return (s||'').toLowerCase(); }

  // 1. Filename analysis
  function analyzeFilename(raw) {
    if (!raw || raw.trim() === '') {
      addResult('Filename', 'warn', 'No filename provided.');
      return;
    }
    const name = raw.trim();
    const lowerName = name.toLowerCase();

    // multiple dots (e.g. ebook.pdf.exe) -> suspicious
    const dotCount = (name.match(/\./g) || []).length;
    if (dotCount > 1) {
      addResult('Filename: Multiple dots', 'danger', `File contains multiple dots (${dotCount}). This often hides executable extensions. Example: "ebook.pdf.exe".`);
    } else {
      addResult('Filename: Dot check', 'safe', `Single dot detected (${dotCount}).`);
    }

    // suspicious keywords in name
    const foundKeywords = suspiciousNameKeywords.filter(k => lowerName.includes(k));
    if (foundKeywords.length) {
      addResult('Filename: Suspicious words', 'danger', `Found suspicious words: ${foundKeywords.join(', ')} — these often appear in cracked/pirated or repacked files.`);
    } else {
      addResult('Filename: Name keywords', 'safe', 'No common suspicious keywords found in filename.');
    }

    // check extension
    const extMatch = name.match(/\.([0-9a-zA-Z]+)$/);
    if (extMatch) {
      const ext = extMatch[1].toLowerCase();
      if (unsafeExtensions.includes(ext)) {
        addResult('Filename: Unsafe extension', 'danger', `File extension ".${ext}" is an executable/installer. Do NOT run on your computer.`);
      } else {
        addResult('Filename: Extension check', 'safe', `Extension ".${ext}" looks normal for documents.`);
      }
    } else {
      addResult('Filename: No extension', 'warn', 'No file extension found — be careful and ask for clarification.');
    }

    // quick heuristic: long filenames with 'zip' but suspicious naming
    if (lowerName.includes('zip') && (lowerName.includes('exe') || lowerName.includes('bat'))) {
      addResult('Filename: Hidden executable in archive', 'danger', 'Archive name contains signs of hidden executable content.');
    }
  }

  // 2. URL analysis (local logic)
  function analyzeUrl(rawUrl) {
    if (!rawUrl || rawUrl.trim() === '') {
      addResult('URL', 'warn', 'No URL provided.');
      return;
    }
    const url = rawUrl.trim();

    // try to parse URL
    let parsed;
    try {
      parsed = new URL(url);
    } catch (e) {
      addResult('URL: Parse error', 'danger', 'Invalid URL format.');
      return;
    }

    // HTTPS check
    if (parsed.protocol !== 'https:') {
      addResult('URL: HTTPS check', 'warn', `Site does not use HTTPS (${parsed.protocol}). Data may be sent in plain text.`);
    } else {
      addResult('URL: HTTPS check', 'safe', 'HTTPS found.');
    }

    // domain heuristics
    const hostname = parsed.hostname;
    if (hostname.length > 30) {
      addResult('URL: Long domain', 'warn', `Domain is long (${hostname.length} chars). Long domains can hide malicious subdomains.`);
    } else {
      addResult('URL: Domain length', 'safe', `Domain length OK (${hostname.length} chars).`);
    }

    // many hyphens -> suspicious
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      addResult('URL: Hyphen check', 'warn', 'Domain has many hyphens — often used to mimic trusted sites.');
    }

    // suspicious keywords in domain or path
    const hostAndPath = (hostname + parsed.pathname + parsed.search).toLowerCase();
    const foundRisk = riskyUrlKeywords.filter(k => hostAndPath.includes(k));
    if (foundRisk.length) {
      addResult('URL: Risky keywords', 'danger', `Found risky URL keywords: ${foundRisk.join(', ')} — treat with caution.`);
    } else {
      addResult('URL: Risky keywords', 'safe', 'No common risky keywords found in URL.');
    }

    // redirect param / chain detection
    const suspiciousParams = ['redirect','redirect_uri','url','next','goto','jump','token','offer','ads'];
    const query = parsed.search.toLowerCase();
    const foundParams = suspiciousParams.filter(p => query.includes(p + '='));
    if (foundParams.length) {
      addResult('URL: Redirect / chain params', 'warn', `URL contains redirect-like parameters (${foundParams.join(', ')}). These can lead to external downloads.`);
    }

    // number of subdomains
    const subCount = hostname.split('.').length - 2; // rough heuristic
    if (subCount >= 2) {
      addResult('URL: Subdomain count', 'warn', `Multiple subdomains detected (${subCount}). Check that the root domain is trusted.`);
    }

    // final simple 'website safety score' computed from heuristics
    const score = computeSimpleSiteScore(parsed);
    const scoreText = `Simple site safety score: ${score}/100 (higher is safer).`;
    if (score >= 75) addResult('Website Safety Score', 'safe', scoreText);
    else if (score >= 45) addResult('Website Safety Score', 'warn', scoreText);
    else addResult('Website Safety Score', 'danger', scoreText + ' — avoid downloading here if possible.');
  }

  // compute a very simple score (local heuristics only)
  function computeSimpleSiteScore(parsedUrl) {
    let score = 80; // start neutral
    if (parsedUrl.protocol !== 'https:') score -= 20;
    const hostname = parsedUrl.hostname;
    if (hostname.length > 30) score -= 10;
    const hyphenCount = (hostname.match(/-/g) || []).length;
    score -= Math.min(hyphenCount * 5, 15);
    const riskyFound = riskyUrlKeywords.some(k => (hostname + parsedUrl.pathname).toLowerCase().includes(k));
    if (riskyFound) score -= 30;
    const query = parsedUrl.search.toLowerCase();
    if (query.includes('redirect=') || query.includes('url=')) score -= 15;
    // clamp
    if (score < 0) score = 0;
    if (score > 100) score = 100;
    return score;
  }

  // wire events
  checkFilenameBtn.addEventListener('click', function () {
    // clear any old results optionally (here we just keep history but you can clear)
    analyzeFilename(filenameInput.value);
  });

  checkUrlBtn.addEventListener('click', function () {
    analyzeUrl(urlInput.value);
  });

  // optional: allow Enter key
  filenameInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') checkFilenameBtn.click(); });
  urlInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') checkUrlBtn.click(); });

})();
