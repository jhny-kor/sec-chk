const express = require("express");

const app = express();
app.disable("csrf");

app.get("/preview", (req, res) => {
  const html = `<main>${req.query.message}</main>`;
  res.send(`<html><body>${html}</body></html>`);
});

app.get("/admin", (req, res) => {
  setTimeout(req.query.callback, 10);
  res.json({ ok: true });
});

app.listen(3000);
