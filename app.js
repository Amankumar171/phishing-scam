const form = document.querySelector("#analysis-form");
const input = document.querySelector("#content-input");
const inputLabel = document.querySelector("#input-label");
const inputGuidance = document.querySelector("#input-guidance");
const characterCount = document.querySelector("#character-count");
const resultOutput = document.querySelector("#result-output");
const resultState = document.querySelector("#result-state");
const modeButtons = [...document.querySelectorAll(".mode-button")];
const exampleButton = document.querySelector("#example-button");

let mode = "url";

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function updateInputMode(nextMode) {
  mode = nextMode;
  const isUrl = mode === "url";
  inputLabel.textContent = isUrl ? "Link to check" : "Message to check";
  input.placeholder = isUrl
    ? "Paste a link, e.g. https://example.com"
    : "Paste an email, text, or direct message...";
  input.maxLength = isUrl ? 2048 : 2000;
  inputGuidance.textContent = isUrl
    ? "Tip: you can paste a link without “https://”."
    : "Tip: include the sender’s message and any link text.";
  modeButtons.forEach((button) => {
    const selected = button.dataset.mode === mode;
    button.classList.toggle("is-active", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
  updateCharacterCount();
}

function updateCharacterCount() {
  const maximum = mode === "url" ? 2048 : 2000;
  characterCount.textContent = `${input.value.length.toLocaleString()} / ${maximum.toLocaleString()}`;
}

function renderResult(result) {
  const riskNames = { high: "HIGH RISK", medium: "CAUTION", low: "LOW SIGNAL" };
  const riskTitles = { high: "Do not interact", medium: "Pause and verify", low: "No obvious flags" };
  resultOutput.className = `result-output result-output--${result.level}`;
  resultOutput.replaceChildren();

  const assessment = makeElement("div", "assessment");
  const summary = makeElement("div", "score-summary");
  const dial = makeElement("div", "score-dial");
  dial.setAttribute("role", "progressbar");
  dial.setAttribute("aria-label", "Signal score, not a probability");
  dial.setAttribute("aria-valuemin", "0");
  dial.setAttribute("aria-valuemax", "100");
  dial.setAttribute("aria-valuenow", String(result.score));
  dial.style.setProperty("--score", String(result.score));
  const dialValue = makeElement("span");
  dialValue.append(makeElement("strong", "", String(result.score).padStart(2, "0")), makeElement("small", "", "/ 100"));
  dial.append(dialValue);

  const description = makeElement("div");
  description.append(
    makeElement("div", "risk-label", riskNames[result.level]),
    makeElement("h3", "risk-title", riskTitles[result.level]),
    makeElement("p", "risk-description", window.PhishingDetector.describeRisk(result.level)),
  );
  summary.append(dial, description);
  assessment.append(summary);

  const heading = makeElement("div", "signals-heading");
  heading.append(makeElement("strong", "", "What we noticed"), makeElement("span", "", `${result.signals.length} SIGNAL${result.signals.length === 1 ? "" : "S"}`));
  assessment.append(heading);

  if (result.signals.length) {
    const list = makeElement("ol", "signal-list");
    result.signals.forEach((signal, index) => {
      const item = makeElement("li", "signal-item");
      item.append(
        makeElement("span", "signal-index", String(index + 1).padStart(2, "0")),
        makeElement("div", "signal-copy"),
      );
      const copy = item.lastElementChild;
      copy.append(makeElement("p", "signal-name", signal.label), makeElement("p", "signal-detail", signal.detail));
      list.append(item);
    });
    assessment.append(list);
  } else {
    assessment.append(makeElement("p", "no-signals", "This baseline did not spot common warning patterns. That is not proof the content is safe."));
  }

  assessment.append(makeElement("p", "assessment-note", "Signal score is a hand-weighted screening aid, not a probability or a verified verdict."));
  resultOutput.append(assessment);
  resultState.textContent = riskNames[result.level];
}

modeButtons.forEach((button) => button.addEventListener("click", () => updateInputMode(button.dataset.mode)));
input.addEventListener("input", updateCharacterCount);

exampleButton.addEventListener("click", () => {
  input.value = mode === "url"
    ? "http://192.0.2.44/secure-account/verify"
    : "URGENT: Your account is suspended. Verify your password now at http://192.0.2.44/secure-account/verify";
  updateCharacterCount();
  input.focus();
});

form.addEventListener("submit", (event) => {
  event.preventDefault();
  try {
    const result = mode === "url"
      ? window.PhishingDetector.analyzeUrl(input.value)
      : window.PhishingDetector.analyzeMessage(input.value);
    renderResult(result);
  } catch (error) {
    input.setAttribute("aria-invalid", "true");
    input.focus();
    resultState.textContent = "CHECK INPUT";
    resultOutput.className = "result-output";
    resultOutput.replaceChildren(makeElement("p", "no-signals", error.message));
    return;
  }
  input.removeAttribute("aria-invalid");
});

input.addEventListener("input", () => input.removeAttribute("aria-invalid"));
document.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") form.requestSubmit();
});

updateInputMode("url");