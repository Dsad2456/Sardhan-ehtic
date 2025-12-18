import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.post("/scan", async (req, res) => {
  const { url } = req.body;

  if (!url || !url.startsWith("http")) {
    return res.json({ error: "Invalid URL. Use https://example.com" });
  }

  let score = 0;
  const results = [];

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 7000);

  try {
    const response = await fetch(url, {
      method: "HEAD",
      signal: controller.signal
    });

    clearTimeout(timeout);
    const headers = response.headers;

    // HTTPS
    if (url.startsWith("https://")) {
      score++;
      results.push(pass("HTTPS Enabled"));
    } else {
      results.push(fail("HTTPS Not Enabled", "Install SSL certificate"));
    }

    check(headers, "content-security-policy", "Add CSP header");
    check(headers, "x-frame-options", "Prevent clickjacking");
    check(headers, "x-content-type-options", "Prevent MIME sniffing");
    check(headers, "referrer-policy", "Limit referrer leakage");
    check(headers, "permissions-policy", "Restrict browser permissions");

    if (headers.get("server")) {
      results.push(fail("Server Header Exposed", "Hide server information"));
    } else {
      score++;
      results.push(pass("Server Header Hidden"));
    }

    const percentage = Math.round((score / 7) * 100);
    res.json({ score: percentage, results });

  } catch (err) {
    clearTimeout(timeout);
    res.json({
      error: "Scan failed (site blocked request or hosting restriction)"
    });
  }

  function check(headers, name, fix) {
    if (headers.get(name)) {
      score++;
      results.push(pass(name + " Present"));
    } else {
      results.push(fail(name + " Missing", fix));
    }
  }

  function pass(text) {
    return { status: "pass", text };
  }

  function fail(text, fix) {
    return { status: "fail", text, fix };
  }
});

app.listen(PORT, () => {
  console.log("Sardhan Security Scanner running on port", PORT);
});
