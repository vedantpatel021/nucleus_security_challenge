import { useState } from "react";
import { calculate } from "./api.js";

const BUTTONS = [
  "C", "⌫", "(", ")",
  "7", "8", "9", "/",
  "4", "5", "6", "*",
  "1", "2", "3", "-",
  "0", ".", "=", "+",
];

export default function App() {
  const [expression, setExpression] = useState("");
  const [result, setResult] = useState(null);

  const handleClick = async (label) => {
    if (label === "C") {
      setExpression("");
      setResult(null);
      return;
    }
    if (label === "⌫") {
      setExpression((e) => e.slice(0, -1));
      return;
    }
    if (label === "=") {
      if (!expression.trim()) return;
      try {
        const value = await calculate(expression);
        setResult(String(value));
      } catch {
        setResult("NaN");
      }
      return;
    }
    setExpression((e) => e + label);
  };

  return (
    <div className="app">
      <div className="calculator">
        <div className="display">
          <div className="expression">{expression || "\u00A0"}</div>
          <div className="result">{result ?? "\u00A0"}</div>
        </div>
        <div className="buttons">
          {BUTTONS.map((label) => (
            <button
              key={label}
              className={`btn btn-${buttonClass(label)}`}
              onClick={() => handleClick(label)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function buttonClass(label) {
  if (/\d/.test(label) || label === ".") return "digit";
  if (["+", "-", "*", "/", "(", ")"].includes(label)) return "op";
  if (label === "=") return "equals";
  return "action";
}
