import time
import queue
import threading
from pathlib import Path
from flask import Flask, Response, send_file, render_template_string
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# === config ===
PDF_PATH = Path("./main.pdf").resolve()  # change to your file
HOST = "127.0.0.1"
PORT = 5000

app = Flask(__name__)

# Subscribers for SSE
subscribers: list[queue.SimpleQueue] = []

HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Live PDF</title>
  <style>
    html, body { height: 100%; margin: 0; }
    #bar { padding: 8px; font-family: system-ui, sans-serif; border-bottom: 1px solid #eee; }
    iframe { width: 100%; height: calc(100% - 41px); border: 0; }
    button { padding: 6px 10px; }
  </style>
</head>
<body>
  <div id="bar">
    <button id="refreshBtn">Refresh</button>
    <span id="status">Connected…</span>
  </div>
  <iframe id="pdfFrame" src="/pdf"></iframe>

  <script>
    const frame = document.getElementById("pdfFrame");
    const statusEl = document.getElementById("status");
    const refreshBtn = document.getElementById("refreshBtn");

    function cacheBust(url) {
      const u = new URL(url, window.location.origin);
      u.searchParams.set("t", Date.now().toString());
      return u.toString();
    }

    function reloadPdf() {
      frame.src = cacheBust("/pdf");
    }

    refreshBtn.addEventListener("click", reloadPdf);

    const es = new EventSource("/events");
    es.addEventListener("open", () => statusEl.textContent = "Connected…");
    es.addEventListener("error", () => statusEl.textContent = "Reconnecting…");
    es.addEventListener("pdf-changed", () => reloadPdf());
  </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/pdf")
def pdf():
    # Serve the current PDF (browser cache is bypassed by cache-busting query)
    return send_file(PDF_PATH, mimetype="application/pdf", as_attachment=False)

@app.route("/events")
def events():
    q = queue.SimpleQueue()
    subscribers.append(q)

    def stream():
        try:
            # Tell client retry delay
            yield "retry: 2000\n\n"
            while True:
                data = q.get()  # blocks
                yield f"event: pdf-changed\ndata: {data}\n\n"
        finally:
            try:
                subscribers.remove(q)
            except ValueError:
                pass

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    }
    return Response(stream(), headers=headers)

# === Watch the file and notify clients ===
class PdfChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if Path(event.src_path).resolve() == PDF_PATH:
            ts = str(time.time())
            for q in list(subscribers):
                try:
                    q.put_nowait(ts)
                except Exception:
                    pass

def start_watcher():
    PDF_PATH.parent.mkdir(parents=True, exist_ok=True)
    observer = Observer()
    handler = PdfChangeHandler()
    observer.schedule(handler, str(PDF_PATH.parent), recursive=False)
    observer.start()

    # Keep thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    # Start watchdog in a background thread
    t = threading.Thread(target=start_watcher, daemon=True)
    t.start()

    print(f"Serving on http://{HOST}:{PORT} — watching {PDF_PATH}")
    app.run(host=HOST, port=PORT, threaded=True, debug=True)


