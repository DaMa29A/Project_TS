import json
import threading
import subprocess
import time
import os
import signal

from netfilterqueue import NetfilterQueue
from evasion_proxy import EvasionProxy
from feedback_analyzer import FeedbackAnalyzer

from constants import TARGET_IP, BASELINE_JSON, CSV_MUTATIONS
from models import PacketState, NetworkFeedback
from utils import load_json, calculate_js_distance, get_mutation_from_csv


MAX_ATTEMPTS = 20


def orchestrator_loop(proxy):

    print("[Orchestratore] Avvio...")
    time.sleep(1.5)

    mutations = get_mutation_from_csv(CSV_MUTATIONS)
    baseline = load_json(BASELINE_JSON)

    success_count = 0
    latencies = []

    applied_mutations = {"ttl": [], "win_size": [], "seq_num": []}
    active_mutations = {}

    last_feedback = None

    for i, mutation in enumerate(mutations):

        print(f"\n--- TEST {i + 1} ---")

        start_time = time.time()

        strategy = mutation

        # Stato test
        test_state = active_mutations.copy()
        test_state[strategy.field_to_mutate] = strategy.new_value

        print(f"[Orchestratore] State: {test_state}")

        # L7 mutations (opzionale)
        l7_mutations = {}
        if "user_agent" in test_state:
            l7_mutations["user_agent"] = test_state["user_agent"]
        if "accept_language" in test_state:
            l7_mutations["accept_language"] = test_state["accept_language"]

        if l7_mutations:
            with open("current_l7_mutation.json", "w") as f:
                json.dump(l7_mutations, f)
        else:
            if os.path.exists("current_l7_mutation.json"):
                os.remove("current_l7_mutation.json")

        # L4/L3 state reset
        proxy.flow_state = {}
        proxy.p_state = PacketState()

        if "ttl" in test_state:
            proxy.p_state.ttl = test_state["ttl"]
        if "win_size" in test_state:
            proxy.p_state.win_size = test_state["win_size"]
        if "seq_num" in test_state:
            proxy.p_state.seq_num = test_state["seq_num"]

        proxy.mutation = strategy

        print(f"[Orchestratore] Mutation: {strategy.field_to_mutate} → {strategy.new_value}")

        # ---------------- SNIF + CURL ----------------

        analyzer = FeedbackAnalyzer(target_ip=TARGET_IP, interface="eth0", timeout=3.5)
        analyzer.start()

        time.sleep(0.1)  # bootstrap sniff

        print("[Orchestratore] Curl request...")

        result = subprocess.run(
            ["curl", "-x", "http://127.0.0.1:8080", "-s", "--max-time", "3", f"http://{TARGET_IP}"],
            capture_output=True,
            text=True
        )

        reward, reason = analyzer.wait()

        http_ok = (result.returncode == 0 and len(result.stdout) > 0)

        # ---------------- DECISION LOGIC ----------------

        if http_ok:
            reward = 1
            verdict = "PASS"
            success_count += 1
            active_mutations[strategy.field_to_mutate] = strategy.new_value
        else:
            reward = -1
            verdict = "BLOCK"

        end_time = time.time()
        latencies.append(end_time - start_time)

        print(f"Result: {verdict} | reward={reward} | sniff={reason}")

        proxy.classifier.add_experience(proxy.p_state, reward)

        last_feedback = NetworkFeedback(
            verdict=verdict,
            reward=reward,
            reason=reason,
            field_tested=strategy.field_to_mutate,
            value_tested=strategy.new_value
        )

    proxy.classifier.save_state()

    avg_latency = sum(latencies) / len(latencies)

    evasion_rate = (success_count / MAX_ATTEMPTS) * 100

    print("\n" + "=" * 50)
    print("FINAL REPORT")
    print("=" * 50)
    print(f"Evasion Rate: {evasion_rate:.2f}%")
    print(f"Avg Latency: {avg_latency:.2f}s")
    print("=" * 50)

    os.kill(os.getpid(), signal.SIGINT)


def main():
    proxy = EvasionProxy()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, proxy.manage_packet)

    t = threading.Thread(target=orchestrator_loop, args=(proxy,))
    t.start()

    try:
        print("[*] Engine running...")
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    finally:
        nfqueue.unbind()


if __name__ == "__main__":
    main()