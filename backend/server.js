const express = require("express");
const cors = require("cors");
const { evaluate } = require("mathjs");

const app = express();
const PORT = 3001;
const MAX_EXPRESSION_LENGTH = 256;

app.use(cors());
app.use(express.json({ limit: "4kb" }));

app.post("/api/calculate", (req, res) => {
  const { expression } = req.body || {};

  if (typeof expression !== "string") {
    return res.status(400).json({ error: "Expression must be a string" });
  }

  const trimmed = expression.trim();
  if (trimmed.length === 0) {
    return res.status(400).json({ error: "Expression is empty" });
  }

  if (expression.length > MAX_EXPRESSION_LENGTH) {
    return res.status(400).json({ error: "Expression too long" });
  }

  let result;
  try {
    result = evaluate(trimmed);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  if (typeof result !== "number" || !Number.isFinite(result)) {
    return res.status(400).json({ error: "Invalid result" });
  }

  res.json({ result });
});

app.listen(PORT, () => {
  console.log(`listening on ${PORT}`);
});
