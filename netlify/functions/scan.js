// Netlify Function: URL phishing scanner
// Replicates the Python FastAPI backend logic

function extractFeatures(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    parsed = null;
  }

  const netloc = parsed ? parsed.hostname : "";

  return {
    length: url.length,
    has_at_symbol: url.includes("@"),
    has_hyphen_in_domain: netloc.includes("-"),
    is_ip_address: isIp(netloc),
    suspicious_keywords: countSuspiciousKeywords(url),
    subdomain_count: countSubdomains(netloc),
    protocol: parsed ? parsed.protocol.replace(":", "") : "unknown",
  };
}

function isIp(domain) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain);
}

function countSuspiciousKeywords(url) {
  const keywords = [
    "login",
    "bank",
    "secure",
    "verify",
    "update",
    "account",
    "paypal",
    "free",
    "admin",
  ];
  const lower = url.toLowerCase();
  return keywords.filter((kw) => lower.includes(kw)).length;
}

function countSubdomains(domain) {
  if (!domain) return 0;
  const parts = domain.split(".");
  return Math.max(0, parts.length - 2);
}

function calculateRiskScore(features) {
  let score = 0;
  const reasons = [];

  if (features.has_at_symbol) {
    score += 30;
    reasons.push(
      "URL contains '@' symbol, often used to obfuscate the real domain."
    );
  }

  if (features.has_hyphen_in_domain) {
    score += 10;
    reasons.push(
      "Domain contains a hyphen, which is common in phishing sites."
    );
  }

  if (features.is_ip_address) {
    score += 50;
    reasons.push("Domain is an IP address instead of a standard hostname.");
  }

  if (features.suspicious_keywords > 0) {
    score += 20 * features.suspicious_keywords;
    reasons.push(
      `URL contains ${features.suspicious_keywords} suspicious keywords (e.g., 'login', 'secure').`
    );
  }

  if (features.subdomain_count > 2) {
    score += 20;
    reasons.push("Unusually high number of subdomains detected.");
  }

  if (features.protocol !== "https") {
    score += 15;
    reasons.push("URL does not use secure HTTPS protocol.");
  }

  const finalScore = Math.min(100, score);

  let threatLevel = "Safe";
  if (finalScore > 60) {
    threatLevel = "Malicious";
  } else if (finalScore > 30) {
    threatLevel = "Suspicious";
  }

  return {
    risk_score: finalScore,
    threat_level: threatLevel,
    reasons: reasons,
  };
}

exports.handler = async (event) => {
  // Handle CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 200,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
      },
      body: "",
    };
  }

  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Method not allowed" }),
    };
  }

  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return {
      statusCode: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Invalid JSON body" }),
    };
  }

  const url = body.url;
  if (!url) {
    return {
      statusCode: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "URL is required" }),
    };
  }

  const features = extractFeatures(url);
  const assessment = calculateRiskScore(features);

  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
    body: JSON.stringify({
      url: url,
      features: features,
      assessment: assessment,
    }),
  };
};
