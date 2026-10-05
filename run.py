"""Start the KIVZO console:  python run.py   then open http://localhost:8000"""
import argparse
import os
import sys
import threading
import webbrowser

import uvicorn

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    url = f"http://localhost:{args.port}"
    print(f"KIVZO console -> {url}")
    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run("kivzo.server:app", host="0.0.0.0", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
