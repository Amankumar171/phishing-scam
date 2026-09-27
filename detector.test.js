const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeUrl, analyzeMessage, describeRisk } = require("./detector.js");

test("ordinary HTTPS URL has no obvious warning signals", () => {
  const result = analyzeUrl("https://example.com/about");
  assert.equal(result.level, "low");
  assert.equal(result.score, 0);
  assert.equal(result.signals.length, 0);
});

test("IP-hosted sign-in URL receives a high-risk assessment", () => {
  const result = analyzeUrl("http://192.168.0.1/login?verify=1");
  assert.equal(result.level, "high");
  assert.ok(result.signals.some((item) => item.key === "ip-host"));
  assert.ok(result.signals.some((item) => item.key === "sensitive-terms"));
});

test("message analysis combines pressure, credential, and link indicators", () => {
  const result = analyzeMessage("URGENT: Your account is suspended. Verify your password now at http://bit.ly/a");
  assert.equal(result.level, "high");
  assert.ok(result.signals.some((item) => item.key === "urgency"));
  assert.ok(result.signals.some((item) => item.key === "credentials"));
  assert.ok(result.signals.some((item) => item.key.startsWith("message-link-")));
});

test("detector rejects non-web URL schemes", () => {
  assert.throws(() => analyzeUrl("javascript:alert(1)"), /Only HTTP and HTTPS/);
});

test("risk guidance avoids treating a low score as proof of safety", () => {
  assert.match(describeRisk("low"), /does not guarantee/);
});