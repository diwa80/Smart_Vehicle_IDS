from flask import Flask, jsonify, request
import random
import json
import os
from datetime import datetime
from collections import Counter

app = Flask(__name__, static_folder="static", static_url_path="")

# ---------- Global state ----------

ECU_NAMES = [
    "Engine ECU",
    "Brake ECU",
    "Steering ECU",
    "Infotainment",
    "Telematics",
    "ADAS ECU",
]

ATTACK_TYPES = [
    "Spoofing",
    "Replay",
    "DoS",
    "Fuzzing",
    "Sensor Tampering",
]

FORCE_ATTACK = False

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "telemetry.log")
os.makedirs(LOG_DIR, exist_ok=True)

ANALYTICS = {
    "attack_counts_by_ecu": Counter(),
    "attack_counts_by_type": Counter(),
    "attack_counts_by_attacker": Counter(),
    "events_timeline": [],
}

LAST_SNAPSHOT = None


# ---------- Helpers ----------

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def log_telemetry(data):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data) + "\n")
    except:
        pass


def generate_can_packets(attack_hint):
    packets = []
    for _ in range(15):
        ecu = random.choice(ECU_NAMES)
        can_id = hex(random.randint(0x100, 0x7FF))
        data_hex = " ".join(f"{random.randint(0,255):02X}" for _ in range(8))

        anomaly_prob = 0.03
        if attack_hint:
            anomaly_prob = 0.35

        packets.append({
            "timestamp": datetime.utcnow().strftime("%H:%M:%S"),
            "id": can_id,
            "ecu": ecu,
            "dlc": 8,
            "data": data_hex,
            "anomaly": random.random() < anomaly_prob,
        })
    return packets


def evaluate_rules(snapshot, prev_snapshot, can_packets):
    alerts = []
    rule_attack = False

    # ----- CAN Anomaly Rule -----
    anomaly_frames = [p for p in can_packets if p["anomaly"]]
    if len(anomaly_frames) >= 8:
        rule_attack = True
        alerts.append({
            "level": "HIGH",
            "source": "Telematics",
            "message": f"{len(anomaly_frames)} anomalous CAN frames detected",
            "attack_type": "DoS/Fuzzing",
            "attacker_ip": random_ip(),
        })

    # ----- Physics Rule -----
    speed = snapshot["speed"]
    if prev_snapshot is not None:
        delta = abs(speed - prev_snapshot["speed"])
        if delta > 60:
            rule_attack = True
            alerts.append({
                "level": "HIGH",
                "source": "Engine ECU",
                "message": f"Implausible speed jump Δv={delta} km/h",
                "attack_type": "Physical Implausibility",
                "attacker_ip": random_ip(),
            })

    # ----- Brake Rule -----
    if snapshot["brake_status"] == "ON" and speed > 120:
        rule_attack = True
        alerts.append({
            "level": "CRITICAL",
            "source": "Brake ECU",
            "message": f"Brake engaged at {speed} km/h",
            "attack_type": "Safety Violation",
            "attacker_ip": random_ip(),
        })

    return rule_attack, alerts


def update_analytics(alerts, attack_active):
    ANALYTICS["events_timeline"].append({
        "timestamp": datetime.utcnow().strftime("%H:%M:%S"),
        "total_alerts": len(alerts),
        "critical_alerts": sum(a["level"] in ("HIGH","CRITICAL") for a in alerts),
        "attack_active": attack_active,
    })

    if len(ANALYTICS["events_timeline"]) > 200:
        ANALYTICS["events_timeline"].pop(0)

    for a in alerts:
        if a["source"] in ECU_NAMES:
            ANALYTICS["attack_counts_by_ecu"][a["source"]] += 1
        ANALYTICS["attack_counts_by_type"][a["attack_type"]] += 1
        ANALYTICS["attack_counts_by_attacker"][a["attacker_ip"]] += 1


# ---------- Main Telemetry Generator ----------

def generate_telemetry():
    global LAST_SNAPSHOT, FORCE_ATTACK

    speed = random.randint(0, 140)
    brake_status = "ON" if random.random() < 0.25 else "OFF"
    ecu_health = {e: round(random.uniform(0.8, 1.0), 2) for e in ECU_NAMES}

    base_anomaly = random.random() * 0.2
    can_anomaly_score = base_anomaly

    attack_hint = FORCE_ATTACK or random.random() < 0.1

    can_packets = generate_can_packets(attack_hint)
    snapshot = {
        "speed": speed,
        "brake_status": brake_status,
        "ecu_health": ecu_health,
        "can_anomaly_score": round(can_anomaly_score, 2),
        "attack_active": False,
        "heatmap": [{"name": e, "status": "ok"} for e in ECU_NAMES],
        "security_alerts": [],
        "can_packets": can_packets,
        "forced_attack": FORCE_ATTACK,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Apply real IDS rules
    rule_attack, rule_alerts = evaluate_rules(snapshot, LAST_SNAPSHOT, can_packets)
    snapshot["security_alerts"].extend(rule_alerts)

    if rule_attack:
        snapshot["attack_active"] = True
        for c in snapshot["heatmap"]:
            if c["name"] in ["Engine ECU", "Brake ECU", "Telematics"]:
                c["status"] = "warning"
                snapshot["ecu_health"][c["name"]] = round(random.uniform(0.3, 0.7), 2)

    # Forced Attack mode
    if FORCE_ATTACK:
        snapshot["attack_active"] = True
        snapshot["can_anomaly_score"] = round(random.uniform(0.85, 1.0), 2)
        for c in snapshot["heatmap"]:
            c["status"] = "compromised"
            snapshot["ecu_health"][c["name"]] = round(random.uniform(0.2, 0.5), 2)

    update_analytics(snapshot["security_alerts"], snapshot["attack_active"])
    LAST_SNAPSHOT = snapshot
    log_telemetry(snapshot)
    return snapshot


# ---------- Routes ----------

@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/api/telemetry")
def api_tel():
    return jsonify(generate_telemetry())


@app.route("/api/force_attack", methods=["POST"])
def force_attack():
    global FORCE_ATTACK
    FORCE_ATTACK = request.json.get("mode") == "on"
    return jsonify({"forced_attack": FORCE_ATTACK})


@app.route("/api/analytics")
def get_analytics():
    return jsonify({
        "top_ecu_targets": [{"ecu": k, "count": v} for k, v in ANALYTICS["attack_counts_by_ecu"].most_common(5)],
        "top_attack_types": [{"type": k, "count": v} for k, v in ANALYTICS["attack_counts_by_type"].most_common(5)],
        "top_attackers": [{"attacker": k, "count": v} for k, v in ANALYTICS["attack_counts_by_attacker"].most_common(5)],
        "events_timeline": ANALYTICS["events_timeline"]
    })


if __name__ == "__main__":
    print("🚀 Smart Vehicle IDS running at http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
