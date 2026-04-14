# Calculator Web App

A small calculator web app built for the Nucleus Security engineering intern take-home. The React frontend sends expressions to a Node/Express backend which evaluates them server-side using [`mathjs`](https://mathjs.org). The frontend never does the math itself.

## Requirements

- Node.js **20.x** (LTS). Should work on 18+ but 20 is tested.
- npm 10+.

## Running it

Two terminals.

**Terminal 1 — backend** (runs on `localhost:3001`):

```sh
cd backend
npm install
npm start
```

**Terminal 2 — frontend** (runs on `localhost:5173`):

```sh
cd frontend
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in a browser.

## API

`POST /api/calculate`

Request:
```json
{ "expression": "2+3*4" }
```

Success (200):
```json
{ "result": 14 }
```

Error (400):
```json
{ "error": "Expression is empty" }
```

## Design notes

- **Backend does the math.** The frontend is a thin UI; it posts the raw expression string and renders whatever the backend returns. This was an explicit requirement of the exercise.
- **`mathjs.evaluate`, not `eval`.** `mathjs` has a safe evaluator that doesn't execute arbitrary JavaScript — important because the input is user-controlled.
- **Input guards.** Expression must be a non-empty string, ≤ 256 chars. Request body capped at 4 KB via `express.json({ limit: "4kb" })`. Non-finite results (`1/0`, `NaN`, unit results, matrices) are rejected with a 400 so the UI can show `NaN` cleanly.
- **No proxy or env vars.** The frontend hits `http://localhost:3001` directly. Zero setup friction; would change for a real deployment.

## What I'd add with more time

- **Keyboard input** — currently buttons only.
- **History** — last N expressions and results, clickable to restore.
- **Rate limiting** on the backend (`express-rate-limit`) to prevent trivial DoS.
- **Stricter expression validation** — a character allow-list on the server before handing to `mathjs`, so truly malformed input is rejected fast.
- **Tests** — at minimum, a few backend integration tests for the validation paths and a component smoke test.
- **Deployment config** — Dockerfile, env-var-driven backend URL for the frontend, production build served by Express or a CDN.
- **Error differentiation in the UI** — show *why* evaluation failed (empty, too long, invalid syntax, non-finite) instead of a generic `NaN`.
- **Accessibility** — keyboard navigation across buttons, ARIA labels on the display.
