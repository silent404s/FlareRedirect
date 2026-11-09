"""Entry point for FlareRedirect Local Web Dashboard.
Starts the local HTTP server on http://localhost:5050 and launches
the web dashboard automatically in the user's default browser.
"""

import sys
import os

# Ensure current directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from web.server import run_server


def main():
    port = 5050
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run_server(port=port)


if __name__ == "__main__":
    main()
