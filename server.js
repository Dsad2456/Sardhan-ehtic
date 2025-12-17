import express from "express";
import fetch from "node-fetch";
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
        return res.json({ error: "Invalid URL" });
    }

    let score = 0;
    let results = [];

    try {
        const response = await fetch(url, { method: "GET" });
        const headers = response.headers;

        // HTTPS
        if (url.startsWith("https://")) {
            score++;
            results.push(pass("HTTPS Enabled"));
        } else {
            results.push(fail("HTTPS Not Enabled", "Use SSL certificate"));
        }

        // Security Headers
        checkHeader(headers, "content-security-policy", "Add CSP header");
        checkHeader(headers, "x-frame-options", "Prevent clickjacking");
        checkHeader(headers, "x-content-type-options", "Prevent MIME sniffing");
        checkHeader(headers, "referrer-policy", "Limit referrer data");
        checkHeader(headers, "permissions-policy", "Restrict browser permissions");

        // Server exposure
        if (headers.get("server")) {
            results.push(fail("Server Header Exposed", "Hide server info"));
        } else {
            score++;
            results.push(pass("Server Header Hidden"));
        }

        // robots.txt
        try {
            await fetch(url + "/robots.txt");
            score++;
            results.push(pass("robots.txt Found"));
        } catch {
            results.push(warn("robots.txt Missing"));
        }

        const percentage = Math.round((score / 8) * 100);

        res.json({
            score: percentage,
            results
        });

    } catch (err) {
        res.json({ error: "Unable to scan website" });
    }

    function checkHeader(headers, name, fix) {
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
    function warn(text) {
        return { status: "warn", text };
    }
});

app.listen(PORT, () => {
    console.log("Sardhan Security Scanner running on port", PORT);
});
