const shortenerHosts = new Set([
  "bit.ly",
  "buff.ly",
  "cutt.ly",
  "is.gd",
  "ow.ly",
  "t.co",
  "tinyurl.com",
]);

const suspiciousTerms = /\b(?:account|bank|billing|confirm|credential|login|password|payment|secure|signin|update|verify|wallet)\b/i;

function finding(key, label, detail, weight) {
  return { key, label, detail, weight };
}

function assess(findings, type, input) {
  const score = Math.min(100, findings.reduce((total, item) => total + item.weight, 0));
  const level = score >= 55 ? "high" : score >= 25 ? "medium" : "low";

  return {
    type,
    input,
    score,
    level,
    signals: findings,
  };
}

function analyzeUrl(value) {
  const input = String(value ?? "").trim();
  if (!input) throw new Error("Enter a URL to analyze.");

  const hasScheme = /^[a-z][a-z\d+.-]*:/i.test(input) && !/^[\w.-]+:\d+(?:\/|$)/.test(input);
  const candidate = hasScheme ? input : `https://${input}`;
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("That does not look like a valid URL.");
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Only HTTP and HTTPS links can be analyzed.");
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");
  const findings = [];
  const raw = input.toLowerCase();

  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.startsWith("[")) {
    findings.push(finding("ip-host", "IP address used as host", "The link points to a raw network address instead of a recognizable domain.", 28));
  }
  if (hostname.startsWith("xn--") || hostname.split(".").some((part) => part.startsWith("xn--"))) {
    findings.push(finding("punycode", "Encoded domain characters", "Internationalized characters can be used to make a domain resemble another brand.", 24));
  }
  if (parsed.username || parsed.password || raw.includes("@")) {
    findings.push(finding("at-sign", "User information or @ sign", "An @ sign in a link can obscure which host the browser will open.", 22));
  }
  if (parsed.protocol !== "https:") {
    findings.push(finding("no-https", "No HTTPS encryption", "The link does not use HTTPS. This alone does not prove it is malicious.", 12));
  }
  const domainParts = hostname.split(".").filter(Boolean);
  if (domainParts.length > 4) {
    findings.push(finding("many-subdomains", "Unusually deep subdomain", "Several subdomain levels can hide the registered domain in a long address.", 12));
  }
  if (shortenerHosts.has(hostname)) {
    findings.push(finding("short-link", "Link shortener", "The final destination is hidden until the shortened link is opened.", 18));
  }
  if (input.length > 120) {
    findings.push(finding("long-url", "Unusually long URL", "Long links can conceal the destination among extra path or query text.", 10));
  }
  if (suspiciousTerms.test(`${parsed.hostname}${parsed.pathname}${parsed.search}`)) {
    findings.push(finding("sensitive-terms", "Account or sign-in wording", "The address contains words often used in credential or payment lures.", 16));
  }
  if (/(?:%[0-9a-f]{2}){4,}/i.test(input)) {
    findings.push(finding("encoded-url", "Heavily encoded address", "Repeated encoded characters make the destination harder to inspect.", 10));
  }

  return assess(findings, "url", input);
}

function analyzeMessage(value) {
  const input = String(value ?? "").trim();
  if (!input) throw new Error("Paste a message to analyze.");

  const findings = [];
  const rules = [
    ["urgency", "Urgent or threatening language", /\b(?:urgent|immediately|act now|final notice|account.{0,18}suspend(?:ed)?|within \d+ hours|avoid.{0,16}(?:closure|suspension))\b/i, "The message pressures the reader to act quickly.", 18],
    ["credentials", "Request for credentials or codes", /\b(?:password|passcode|one[- ]time code|verification code|sign in|log ?in|confirm.{0,24}(?:identity|account)|verify.{0,24}(?:identity|account))\b/i, "It asks for sign-in details, a verification code, or account confirmation.", 22],
    ["reward", "Unexpected reward or money", /\b(?:you(?:'ve| have) won|winner|prize|claim your|gift card|refund|cash reward|guaranteed return|free crypto)\b/i, "Unexpected prizes or financial rewards are common lures.", 16],
    ["payment", "Payment or banking pressure", /\b(?:payment failed|unusual transaction|bank security|billing problem|card.{0,16}(?:blocked|declined)|wire transfer)\b/i, "It invokes a payment or banking problem that may prompt a rushed response.", 14],
    ["attachment", "Potentially unsafe attachment", /\b[^\s]+\.(?:exe|hta|iso|js|msi|scr|vbs|zip)\b/i, "The message mentions an executable or archive attachment.", 18],
  ];

  for (const [key, label, pattern, detail, weight] of rules) {
    if (pattern.test(input)) findings.push(finding(key, label, detail, weight));
  }

  const links = input.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) ?? [];
  for (const [index, link] of links.slice(0, 3).entries()) {
    const cleanedLink = link.replace(/[),.!?;:]+$/, "");
    try {
      const result = analyzeUrl(cleanedLink);
      if (result.score >= 18) {
        findings.push(finding(`message-link-${index}`, "Suspicious link in message", `An embedded link has ${result.signals.length} notable URL indicator(s).`, Math.min(28, result.score)));
      }
    } catch {
      findings.push(finding(`message-link-${index}`, "Unclear link in message", "An embedded address could not be parsed reliably.", 12));
    }
  }

  return assess(findings, "message", input);
}

function describeRisk(level) {
  if (level === "high") return "Several strong warning signs were found. Do not open links or share information.";
  if (level === "medium") return "Some warning signs were found. Verify the sender and destination independently.";
  return "No obvious warning signs were found. A low score does not guarantee that a message or link is safe.";
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { analyzeUrl, analyzeMessage, describeRisk };
}
if (typeof window !== "undefined") {
  window.PhishingDetector = { analyzeUrl, analyzeMessage, describeRisk };
}