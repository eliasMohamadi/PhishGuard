// Zero-dependency static server for previewing the site locally.
// Usage: node website/serve.js [port]   (defaults to 4173, listens on 127.0.0.1 only)
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const root = __dirname;
const port = Number(process.argv[2]) || 4173;
const types = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon"
};

http.createServer((req, res) => {
  const pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
  const file = path.normalize(path.join(root, pathname === "/" ? "index.html" : pathname));
  // Serve only files inside website/, and never this script.
  if (!file.startsWith(root + path.sep) || file === __filename) {
    res.writeHead(404).end("Not found");
    return;
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404).end("Not found");
      return;
    }
    res.writeHead(200, { "Content-Type": types[path.extname(file)] || "application/octet-stream" });
    res.end(data);
  });
}).listen(port, "127.0.0.1", () => {
  console.log(`PhishGuard site: http://127.0.0.1:${port}`);
});
