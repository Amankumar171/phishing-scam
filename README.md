# Signal Check

A small, browser-based first-pass review tool for suspicious URLs and message text. The detector runs locally: submitted content is not sent to a server or stored by the app.

## Run

Open `index.html` in a current browser. No packages, API keys, or build step are required.

Run the detector tests from this folder with Node.js 18 or newer:

```sh
node --test
```

## What it checks

- URL structure, including raw IP hosts, encoded domain labels, link shorteners, unusually deep subdomains, and account-related wording.
- Message patterns such as urgency, credential requests, unexpected rewards, payment pressure, risky attachment names, and suspicious embedded links.
- A hand-weighted 0–100 signal score with the specific matching indicators shown alongside it.

## Limitations

This is an explainable heuristic baseline, not a trained machine-learning model. Its score is not a probability, and a low score does not mean content is safe. It has not been validated against a labeled phishing dataset and should not replace sender verification, security tooling, or human judgment. For a production AI detector, train and evaluate a model on representative, up-to-date labeled data and measure false positives and false negatives before deployment.