# Workspace guidance

- Keep analysis local to the browser; do not transmit or persist submitted message content.
- Treat the detector as a transparent heuristic baseline. Do not describe its score as a probability or claim trained-model accuracy.
- Use `node --test` to validate detector behavior after changes.
- Keep rendering of user-provided text on `textContent` paths to avoid HTML injection.