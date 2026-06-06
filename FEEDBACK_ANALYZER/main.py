import threading
import subprocess
import time
import os

from scapy.all import conf
from feedback_analyzer import FeedbackAnalyzer


TARGET = "192.168.20.10"


def run_test(port):

    iface = conf.iface  # FIX: evita "any" error

    analyzer = FeedbackAnalyzer(
        target_ip=TARGET,
        target_port=port,
        iface=iface,
        timeout=4
    )

    # 1. start sniffer
    t = threading.Thread(target=analyzer.run)
    t.start()

    # 2. give time to attach
    time.sleep(0.5)

    # 3. generate traffic
    try:

        """subprocess.run(
            ["curl", "-s", "-I", f"http://{TARGET}:{port}"],
            timeout=3
        )"""

        subprocess.run(
            [
                "curl",
                "-s",
                "-I",
                "-A", "Mozilla",
                f"http://{TARGET}:{port}/mfolder"
            ],
            timeout=3
        )

    except subprocess.TimeoutExpired:
        pass

    # 4. wait analyzer
    t.join()

    print(f"PORT={port} SCORE={analyzer.score} REASON={analyzer.reason}")


if __name__ == "__main__":
    run_test(80)
    run_test(9999)
    run_test(22)