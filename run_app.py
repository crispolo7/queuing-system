import threading
import webbrowser
import socket
import os

from waitress import serve
from app import app

def open_browser():
    server_host = os.getenv('SERVER_HOST', '127.0.0.1')
    server_port = int(os.getenv('SERVER_PORT', '5000'))
    browser_host = '127.0.0.1' if server_host == '0.0.0.0' else server_host

    webbrowser.open(
        f"http://{browser_host}:{server_port}"
    )

if __name__ == '__main__':

    server_host = os.getenv('SERVER_HOST', '127.0.0.1')
    server_port = int(os.getenv('SERVER_PORT', '5000'))

    print("\n")
    print("=" * 60)
    print("   COMELEC QUEUE MANAGEMENT SYSTEM")
    print("=" * 60)
    print("\n")

    print(" Server Status : RUNNING")
    print(" Browser will open automatically")
    print("\n")

    print(" IMPORTANT:")
    print(" Do NOT close this window.")
    print(" Closing this window will stop")
    print(" the Queue Management System.")
    print("\n")
    print(" Thanks to Engr. Crispolo L. Bernardino, Jr.")
    print(" for Developing this COMELEC Queuing System at no cost to the Commission.")
    print("\n")

    print("=" * 60)
    print("\n")

    threading.Timer(
        2,
        open_browser
    ).start()

    serve(
        app,
        host=server_host,
        port=server_port,
        threads=8
    )
