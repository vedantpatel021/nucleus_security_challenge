# Engineering Intern Interview Questions

## Introduction

Thank you for your interest in the Nucleus Security Engineering
internship program! This document contains 2 primary interview
challenges for you. The first is a code review question, and the second
is a coding challenge.

For both, we absolutely encourage the use of AI. If you do use AI, we
would like for you to share your prompts and then answer the follow-up
questions about how you thought through your prompts.

We know this time of the year is crazy for college students and that
your time is very valuable. Please try not to spend more than about 1
total hour collectively on this.

------------------------------------------------------------------------

## Contents

-   Introduction
-   Code Review (10 minutes)
    -   Task
    -   PHP
    -   Python
    -   Code comments
    -   Follow-up Questions
-   Coding Challenge (\~50 minutes)
    -   Exercise
    -   Follow-up questions
-   Delivery

------------------------------------------------------------------------

# Code Review (10 minutes)

You are welcome and encouraged to use AI for this section. If you do,
please provide your prompts and answer the questions in the follow-up
section.

## Task

Your colleague or team member was given the following task:

1.  Add a `/webhook` endpoint to receive vendor events about users who
    are vendors.

2.  Input data will look like:

    ``` json
    {"email":"a@b.com","role":"admin","metadata":{"source":"vendor"}}
    ```

3.  Verify signature header `X-Signature`.

4.  Parse JSON and upsert the user data.

5.  Store the raw payload for audit/debug.

They have opened a PR with the code below. Review the code and comment
on any issues you find.

**Note:** Both the PHP and Python do the same thing. You can choose to
review whichever one you want. It is not intended for you to review
both.

------------------------------------------------------------------------

## PHP

``` php
<?php
// webhook.php
require_once "db.php"; // provides $pdo (PDO instance)

// Config (dev defaults)
$WEBHOOK_SECRET = getenv("WEBHOOK_SECRET") ?: "dev-secret";
$DB_AUDIT_ENABLED = getenv("AUDIT_ENABLED") ?: "true";

function verify_signature($sig, $body, $secret) {
    // Vendor docs: SHA256(secret + body)
    $expected = hash("sha256", $secret . $body);
    return $expected == $sig; // simple compare
}

$method = $_SERVER["REQUEST_METHOD"] ?? "GET";
$path = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);

// Basic routing
if ($method !== "POST" || $path !== "/webhook") {
    http_response_code(404);
    echo "not found";
    exit;
}

$raw = file_get_contents("php://input"); // raw body string
$sig = $_SERVER["HTTP_X_SIGNATURE"] ?? "";

if (!verify_signature($sig, $raw, $WEBHOOK_SECRET)) {
    http_response_code(401);
    echo "bad sig";
    exit;
}

// Decode JSON
$payload = json_decode($raw, true);
$email = $payload["email"] ?? "";
$role = $payload["role"] ?? "user";

// Store raw payload for auditing / debugging
if ($DB_AUDIT_ENABLED) {
    $pdo->exec("INSERT INTO webhook_audit(email, raw_json) VALUES ('$email', '$raw')");
}

// Upsert user (simple)
$pdo->exec("INSERT INTO users(email, role) VALUES('$email', '$role')");

echo "ok";
```

------------------------------------------------------------------------

## Python

``` python
# app.py
import os
import json
import sqlite3
import hashlib
from flask import Flask, request

app = Flask(__name__)
DB_PATH = os.getenv("DB_PATH", "/tmp/app.db")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "dev-secret")  # default for dev

def get_db():
    return sqlite3.connect(DB_PATH)

def verify(sig, body: bytes) -> bool:
    # Vendor docs: SHA256(secret + body)
    expected = hashlib.sha256(
        (WEBHOOK_SECRET + body.decode("utf-8")).encode("utf-8")
    ).hexdigest()
    return expected == sig  # simple compare

@app.post("/webhook")
def webhook():
    raw = request.data  # bytes
    sig = request.headers.get("X-Signature", "")

    if not verify(sig, raw):
        return ("bad sig", 401)

    payload = json.loads(raw.decode("utf-8"))

    # Example payload:
    # {"email":"a@b.com","role":"admin","metadata":{"source":"vendor"}}
    email = payload.get("email", "")
    role = payload.get("role", "user")

    db = get_db()
    cur = db.cursor()

    # Store raw payload for auditing / debugging
    cur.execute(
        f"INSERT INTO webhook_audit(email, raw_json) VALUES ('{email}', '{raw.decode('utf-8')}')"
    )

    # Upsert user
    cur.execute(
        f"INSERT INTO users(email, role) VALUES('{email}', '{role}')"
    )

    db.commit()

    return ("ok", 200)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
```

------------------------------------------------------------------------

## Code comments

Put your code comments here. For comments on specific lines, please
include the line number. Feel free to comment on the general task as
well.

I reviewed the Python version. Comments are grouped by severity. Line numbers refer to the Python snippet above.

### Critical

**1. SQL injection in audit insert - lines 41-43**
`email` and the raw body are interpolated directly into the SQL string via an f-string. A malicious `email` value can break out of the quotes and execute arbitrary SQL. Fix: use a parameterized query `cur.execute("INSERT INTO webhook_audit(email, raw_json) VALUES (?, ?)", (email, raw))`.

**2. SQL injection in user insert - lines 46-48**
Same problem as #1. `email` and `role` are interpolated directly. Fix: `cur.execute("INSERT INTO users(email, role) VALUES(?, ?)", (email, role))`.

**3. Timing-attack-vulnerable signature comparison - line 20**
`expected == sig` is a non-constant-time comparison, which leaks information about the correct signature through response timing. Fix: `hmac.compare_digest(expected, sig)`.

**4. Signature scheme is not HMAC - lines 17–19**
`sha256(secret + body)` is a known-broken MAC construction (length-extension attacks). Even if the vendor docs specify this, it should be flagged and pushed back on. Fix: `hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()`.

**5. Insecure default secret - line 10**
`WEBHOOK_SECRET` silently falls back to `"dev-secret"` if the env var is unset, meaning a misconfigured production deployment accepts a guessable secret. Fix: fail fast at startup `WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"]`.

### Major

**6. Unvalidated `email` and `role`, and priv-esc via `role` - lines 34–35**
Neither field is validated. `email` is never checked for format, and `payload.get("email", "")` silently accepts a *missing* email and inserts an empty string as an identifier. More importantly, `role` is accepted verbatim from an external vendor webhook meaning anyone who can send a valid webhook can assign themselves `role: "admin"`. This is privilege escalation, not just bad hygiene. Fix: validate `email` format; either ignore `role` entirely from webhook input or map it through an explicit allow-list before storing.

**7. Unhandled JSON / decode errors - lines 18, 30**
`json.loads` on line 30 will raise `ValueError` on malformed JSON, and `raw.decode("utf-8")` on both lines 18 and 30 will raise `UnicodeDecodeError` on non-UTF-8 bytes. Both currently crash the handler with a 500. Fix: wrap in `try/except` and return 400 on parse failure.

**8. No replay protection - whole handler**
There's no timestamp check, nonce, or idempotency key. An attacker who captures one valid signed request can resend it indefinitely. Fix: require a signed timestamp header, reject requests older than ~5 minutes, and/or dedupe on an event ID.

**9. No payload size limit or `Content-Type` check - line 24**
`request.data` will read whatever the client sends into memory. Fix: `app.config["MAX_CONTENT_LENGTH"] = 65536` and verify `request.is_json`.

**10. "Upsert" is actually a plain INSERT - lines 46–48**
The task specifies upsert semantics, but this is a plain `INSERT`. The second event for the same email will either raise `IntegrityError` (if `email` is unique) or produce duplicate rows (if it isn't). Fix: `INSERT INTO users(email, role) VALUES(?, ?) ON CONFLICT(email) DO UPDATE SET role = excluded.role`.

**11. No transaction boundary / rollback on failure - lines 37–50**
If anything between `get_db()` and `db.commit()` raises, the connection leaks *and* no rollback is issued. Fix: use `with closing(get_db()) as db:` (context-managed close) combined with `try/except` and `db.rollback()` on error, or `with db:` for sqlite's automatic transaction handling.

**12. `metadata` field silently dropped - lines 34–35**
The spec payload includes a `metadata` object, but the handler extracts only `email` and `role`. Either persist it (e.g., a JSON column on `webhook_audit`) or document explicitly that it is intentionally ignored.

### Minor

**13. Missing `X-Signature` header is treated the same as a wrong signature - line 25**
`request.headers.get("X-Signature", "")` coerces an absent header into an empty string, which flows into `verify()` and returns 401. Functionally equivalent, but semantically a missing header is a malformed request (400) and should be logged distinctly to aid debugging.

**14. No logging on authentication failure - line 28**
`return ("bad sig", 401)` without a log line means there's no forensic trail when real attacks happen. Fix: `app.logger.warning("bad sig from %s", request.remote_addr)` on failure.

**15. Flask dev server bound to 0.0.0.0 - line 55**
Not a code bug per se, but `app.run(host="0.0.0.0")` should never face the internet. Production should use gunicorn/uwsgi behind a reverse proxy.

### Summary

The three authentication-layer bugs (#3 timing compare, #4 non-HMAC, #5 default secret) are the most dangerous because they mean the SQL injection and authorization bugs (#1, #2, #6) can be reached by any attacker not just someone who already holds the vendor's secret. I'd fix those three first.

------------------------------------------------------------------------

## Follow-up Questions

1.  Share your prompts and the AI outputs.
2.  For each prompt:
    -   Tell us what you were hoping for the AI to accomplish.
    -   Tell us what it actually did.
    -   Did you have to re-prompt it based on its output?
    -   If you had to change your approach, why?

### 1. Prompts and AI outputs

I used a single prompt for this section. The full prompt and full AI response are attached as **`Nucleus_Security.pdf`** in the submission. A brief summary:

- **Prompt:** I gave the AI the task description, the Python code, and my own list of five issues I had already identified with line numbers and reasoning. I explicitly asked the AI to (a) tell me which of my points were wrong or overstated, (b) identify anything significant I missed - especially around security, concurrency, error handling, and input validation - and (c) for each new issue, give a line number, severity, and minimal fix. I also told it not to repeat issues I had already listed unless my reasoning was wrong or incomplete.
- **AI output:** A structured review validating all five of my original points (with two small refinements to my reasoning), plus eleven additional issues I had missed, grouped into Critical / Major / Minor with line numbers, a one-line risk explanation, and a minimal fix for each, followed by a consolidated fix table and a short prioritization note.

### 2. Reflection on the prompt

- **What I was hoping the AI would accomplish.** I wanted the AI to act as a second reviewer that pressure tested my own analysis, not as a first-pass reviewer that did the work for me. Specifically: I wanted it to (1) confirm or push back on my five findings so I could catch my own mistakes. I was almost certain that my 5 issues I found were not going to be the only ones present, and that an LLM could help find the other issues present. (2) surface blind spots in categories I might be weaker on (cryptographic details, HTTP/transport layer concerns, transaction semantics). (3) force prioritization through severity labels so I could structure the final writeup.

- **What it actually did.** It did all three reasonably well. It confirmed all five of my findings and it added a sharper framing for point 3 (the missing-email case and the dropped `metadata` field) and for point 5 (that the real issue isn't a closed connection but the lack of a rollback path on exception). It surfaced the cryptographic issues I hadn't considered: the timing-unsafe `==` comparison and the fact that `sha256(secret + body)` is a length-extension-vulnerable construction rather than real HMAC. It also caught the "upsert is actually an INSERT" spec-compliance bug and the missing replay protection, which I would have missed. The severity table made it easy to sort the final writeup.

- **Did I have to re-prompt.** No. The first response covered everything I needed and the quality was high enough that a second prompt would have been redundant. I did, however, independently spot-check every line number the AI produced against the code file and found five that were off (either off by one, pointing at a comment line instead of the execute call, or pointing at the wrong line of a two-line statement). I corrected those in my final writeup. I think this is the most important takeaway: even a good AI review needs manual verification on anything factual like line numbers or proposed fixes.

- **Why I would not change my approach.** The decision I care about most is that I did my own review *first*, before touching AI. That choice is what made the AI output useful. I had a real baseline to compare against, which let me (a) evaluate the AI's suggestions critically instead of accepting them, (b) notice when the AI restated my own points back at me in different words, and (c) produce genuine follow-up reflections rather than hand-waving. If I had led with the AI, I would have ended up with a longer but shallower review and nothing meaningful to say here. The only thing I'd do differently is verify line numbers as I went, rather than at the end.

------------------------------------------------------------------------

# Coding Challenge (\~50 minutes)

For the below coding exercise, there is no expectation that you will
have a fully working solution. For anything you feel you didn't
accomplish, please let us know in the follow-up section after the
exercise.

## Exercise

Build a calculator web application. It should include a frontend piece
and any backend logic needed to perform the calculations.

You can use any language of your choosing for both the frontend and
backend code.

------------------------------------------------------------------------

## Follow-up questions

1.  How far were you able to get with the exercise?
2.  What challenges did you encounter in the process?
3.  If you were given unlimited time, what additional functionality
    would you include?
4.  If you used AI, please include all of your prompts and answer the
    following questions:
    -   What did the AI do well?
    -   What did the AI do poorly?
    -   For the places it did poorly, how did you change your approach
        to your prompts to improve its output?

### 1. How far were you able to get with the exercise?

I finished a working end-to-end calculator within the time budget. The submission includes:

- A React + Vite frontend with a full button grid (digits 0–9, `+ − * /`, parentheses, decimal point, clear, backspace, equals) and a two-line display showing the current expression and the last result.
- A Node/Express backend exposing `POST /api/calculate` that validates input (must be a non-empty string ≤ 256 chars), evaluates the expression server-side with `mathjs.evaluate`, and returns either `{ result }` (200) or `{ error }` (400). Non-finite results (`1/0`, etc.) are rejected so the UI can render `NaN` cleanly.
- A root `README.md` with Node version, run commands, API shape, design notes, and a "what I'd add with more time" list.
- A `.gitignore` that excludes `node_modules/`, `dist/`, and local artifacts.

I verified the backend end-to-end with `curl` (success cases, empty input, divide-by-zero) and manually exercised the UI in the browser.

### 2. What challenges did you encounter?

- **Scoping against the time budget.** The exercise is open-ended and it's easy to over-build. I had to actively decide *against* adding things I normally would (tests, richer error UI, keyboard input) to make sure I shipped something clean and complete rather than half-polished.
- **Edge cases in `mathjs` results.** `mathjs.evaluate` can return things that aren't finite numbers (e.g. `Infinity` for `1/0`), complex numbers, units, or matrices depending on the input. A naive implementation would happily serialize those back to the client and break the display. I added an explicit `Number.isFinite` check server-side so the frontend's contract stays simple: you either get a number or a 400.
- **Deciding what belongs on the server vs. the client.** The exercise specifically says the backend should do the calculation, so I kept the frontend deliberately dumb — it concatenates characters and POSTs the string. The server is the single source of truth for what's a valid expression.
- **CORS and local dev URLs.** Rather than configure a Vite proxy, I enabled default CORS on the backend and hardcoded `http://localhost:3001` in the frontend fetch. Faster to set up and easier for a reviewer to run, at the cost of not being deploy-ready (which this isn't meant to be).

### 3. If you had unlimited time, what would you add?

(Also listed in the README.)

- **Keyboard input** so you can type expressions directly instead of clicking.
- **History**: last N expressions + results, clickable to restore into the display.
- **Server-side rate limiting** (`express-rate-limit`) to guard against trivial DoS.
- **Stricter server-side validation** — a character allow-list before handing to `mathjs`, so malformed input is rejected faster and gives a clearer error.
- **Differentiated error UI** — show *why* evaluation failed (empty, too long, syntax error, non-finite) instead of a blanket `NaN`.
- **Tests** — at minimum, backend integration tests for each validation path and a React component smoke test.
- **Accessibility** — keyboard focus order across buttons and UI theme options.
- **Scientific functions** — `sqrt`, `^`, trig, constants. `mathjs` supports all of these natively, so it's mostly UI work.

### 4. AI usage

#### Prompt

I used a single AI prompt to scaffold the app. The full prompt:

I'm building a small calculator web app as an interview take-home. I have about 50 minutes and want a clean, working minimal version I can extend if time allows. Stack and constraints:

Frontend: React (Vite, JavaScript, no TypeScript to save setup time).
Backend: Node.js with Express. The backend must perform the actual calculation — the frontend sends an expression, the backend evaluates it and returns the result. Use mathjs for evaluation (its evaluate() is safe against eval-style injection).
API shape: POST /api/calculate with body { "expression": "2+3*4" } → responds { "result": 14 } on success or { "error": "..." } with a 400 on invalid input. Validate that the body contains a string expression; reject empty strings and overly long inputs (cap at ~256 chars).
Frontend UX: A simple calculator UI with digit buttons 0-9, operators (+, -, *, /), parentheses, decimal point, clear, backspace, and equals. Display the current expression as the user types. On equals, POST to the backend and render the result or error (NaN).
Project layout: Two top-level folders, frontend/ and backend/, each with its own package.json. Include a root README.md with exact commands to install and run both (cd backend && npm install && npm start in one terminal; cd frontend && npm install && npm run dev in another). Mention the Node version I should use.
CORS: Enable CORS on the backend so the Vite dev server can call it in development.
Do not add tests, Docker, auth, deployment config, TypeScript, or a state-management library. Keep the code small and easy to read. This is going to be a simple standalone calculator app.
Please produce the plan for this application for me to review and approve.

Do not use eval() anywhere. Use parameterized error handling. If mathjs.evaluate throws, return the error message to the client as a 400 and display NaN.

#### What the AI did well

- **Respected the explicit non-goals.** Because I named the things *not* to add (tests, TypeScript, Docker, state libraries), the output stayed tight.
- **Produced the plan first, then the code.** Asking for a plan before implementation let me catch and lock in decisions (port numbers, file layout, validation rules, result normalization for non-finite values) before any code was written. Cheaper to correct a plan than to refactor generated code (token wise and time wise).
- **Security-conscious defaults.** `mathjs.evaluate` instead of `eval`, `express.json({ limit: "4kb" })`, 256-char expression cap, rejection of non-finite `mathjs` results. All of these made it into the plan and implementation without me having to explicitly spell each one out.
- **Complete, runnable output.** Every file the app needed (`package.json`s, `vite.config.js`, `index.html`, entry point, component, API wrapper, CSS, README, `.gitignore`) was produced without me having to chase missing pieces. Build succeeded first try.

#### What the AI did poorly

- **Couldn't verify the UI visually.** The AI confirmed the backend with `curl` and confirmed the frontend built and served a 200, but it explicitly could not open a browser, click buttons, or confirm the calculator *looked* right. That's a category of verification it simply cannot do, and I had to do it manually. A submission that relied entirely on the AI's "everything works" would have been overconfident.
- **Default answers not always right for my environment.** The generated code hardcodes `localhost:3001` and `localhost:5173`, assumes port 3001 is free, and assumes a specific Node version. All defensible for a local dev demo, but the AI didn't proactively ask whether my dev box already had something on those ports while a developer pairing with me would have.
- **Minor tool/protocol mistakes.** When writing the `.gitignore`, the AI tried to create it before reading the existing file and got blocked. It recovered by reading first and then appending. Small thing, but a reminder that AI-generated workflows aren't infallible.

#### How I adjusted prompts where AI did poorly

- **Verification.** After the scaffold was built, rather than re-prompting the AI with "did you actually test it?", I just ran the app myself in the browser. The right fix for "AI can't test the UI" isn't a better prompt, it's recognizing that some checks must be done by a human and budgeting time for them.
- **Environment assumptions.** Next time I'd include specifics up front like "assume ports 3001 and 5173 are free, assume Node 20" to remove ambiguity and prevent the AI from either making silent assumptions or over-asking.
- **Writing vs. reading order.** For tool-using AI specifically, I'd add "read files before overwriting them" to the constraints. Small cost, avoids the protocol stumble.

Overall, the biggest prompting lesson from this exercise was that the *non-goals* section of the prompt was more valuable than any of the positive requirements. Telling the AI what **not** to build is what kept the output shippable in 50 minutes. It helps prevent it from going overboard and helps stick to the task at hand.

------------------------------------------------------------------------

# Delivery

Please reply to the email you received with:

1.  Answers to any follow-up above.
2.  Any questions or thoughts you had on the exercise.
3.  A link to a public GitHub repository including your answer to the
    coding challenge.
    -   If we can't get to the repository, we won't be able to consider
        your answer to the coding challenge.
