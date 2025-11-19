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
    "flood",
    "gps_spoof",
    "lane_spoof",
    "brake_spoof",
    "ecu_replay",
    "sensor_manip",
]

ACTIVE_ATTACK = None  # one of ATTACK_TYPES or None

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "telemetry.log")
os.makedirs(LOG_DIR, exist_ok=True)

ANALYTICS = {
    "attack_counts_by_ecu": Counter(),
    "attack_counts_by_type": Counter(),
    "attack_counts_by_attacker": Counter(),
    "events_timeline": [],
}

LAST_SNAPSHOT = None  # for replay / physics rules


# ---------- Signal definitions (decoded CAN-like signals) ----------

SIGNAL_DEFS = [
    # Engine
    {"ecu": "Engine ECU", "signal": "Vehicle Speed", "unit": "km/h",
     "min": 0, "max": 220, "normal_min": 0, "normal_max": 140},
    {"ecu": "Engine ECU", "signal": "Engine RPM", "unit": "rpm",
     "min": 600, "max": 6500, "normal_min": 700, "normal_max": 4000},
    {"ecu": "Engine ECU", "signal": "Engine Torque", "unit": "Nm",
     "min": 0, "max": 500, "normal_min": 20, "normal_max": 400},
    {"ecu": "Engine ECU", "signal": "Fuel Level", "unit": "%",
     "min": 0, "max": 100, "normal_min": 10, "normal_max": 100},
    {"ecu": "Engine ECU", "signal": "Coolant Temperature", "unit": "°C",
     "min": -20, "max": 130, "normal_min": 70, "normal_max": 105},
    {"ecu": "Engine ECU", "signal": "Oil Temperature", "unit": "°C",
     "min": -20, "max": 150, "normal_min": 70, "normal_max": 120},

    # Steering / chassis
    {"ecu": "Steering ECU", "signal": "Steering Angle", "unit": "°",
     "min": -540, "max": 540, "normal_min": -180, "normal_max": 180},
    {"ecu": "ADAS ECU", "signal": "Yaw Rate", "unit": "°/s",
     "min": -90, "max": 90, "normal_min": -45, "normal_max": 45},
    {"ecu": "ADAS ECU", "signal": "Longitudinal Accel", "unit": "m/s²",
     "min": -10, "max": 10, "normal_min": -5, "normal_max": 5},
    {"ecu": "ADAS ECU", "signal": "Lateral Accel", "unit": "m/s²",
     "min": -10, "max": 10, "normal_min": -5, "normal_max": 5},

    # Braking
    {"ecu": "Brake ECU", "signal": "Brake Pressure", "unit": "%",
     "min": 0, "max": 100, "normal_min": 0, "normal_max": 80},
    {"ecu": "Brake ECU", "signal": "ABS Slip Ratio", "unit": "%",
     "min": 0, "max": 100, "normal_min": 0, "normal_max": 30},

    # Power / electrical
    {"ecu": "Telematics", "signal": "Battery Voltage", "unit": "V",
     "min": 10, "max": 15, "normal_min": 11.5, "normal_max": 14.5},

    # Throttle / driver input
    {"ecu": "Engine ECU", "signal": "Throttle Position", "unit": "%",
     "min": 0, "max": 100, "normal_min": 0, "normal_max": 80},

    # Infotainment / GPS
    {"ecu": "Infotainment", "signal": "GPS Latitude", "unit": "°",
     "min": -90, "max": 90, "normal_min": -90, "normal_max": 90},
    {"ecu": "Infotainment", "signal": "GPS Longitude", "unit": "°",
     "min": -180, "max": 180, "normal_min": -180, "normal_max": 180},

    # ADAS / perception
    {"ecu": "ADAS ECU", "signal": "Front Object Distance", "unit": "m",
     "min": 0, "max": 200, "normal_min": 10, "normal_max": 200},
    {"ecu": "ADAS ECU", "signal": "Lane Offset", "unit": "m",
     "min": -3, "max": 3, "normal_min": -1.5, "normal_max": 1.5},

    # Connectivity / telematics
    {"ecu": "Telematics", "signal": "Upload Data Rate", "unit": "kbps",
     "min": 0, "max": 5000, "normal_min": 0, "normal_max": 2000},
    {"ecu": "Telematics", "signal": "Download Data Rate", "unit": "kbps",
     "min": 0, "max": 5000, "normal_min": 0, "normal_max": 2000},
]


# ---------- Helper functions ----------

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def log_telemetry(data):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(data) + "\n")
    except Exception:
        pass


def generate_can_signals(attack_hint: bool, speed_value: int, attack_mode: str | None, prev_snapshot):
    """
    Generate decoded CAN-like "signals" instead of raw hex frames.
    Each item:
    {
      "timestamp": "HH:MM:SS",
      "ecu": "Engine ECU",
      "signal": "Vehicle Speed",
      "value": "65.0 km/h",
      "numeric": 65.0,
      "unit": "km/h",
      "anomaly": bool
    }
    """
    signals = []
    now = datetime.utcnow().strftime("%H:%M:%S")

    # For ECU replay attack, use previous snapshot's numeric values if available
    prev_signals_map = {}
    if prev_snapshot and "can_packets" in prev_snapshot:
        for s in prev_snapshot["can_packets"]:
            key = (s["ecu"], s["signal"])
            prev_signals_map[key] = s

    for definition in SIGNAL_DEFS:
        ecu = definition["ecu"]
        sig_name = definition["signal"]
        unit = definition["unit"]

        # base numeric
        if sig_name == "Vehicle Speed":
            numeric = float(speed_value)
        else:
            numeric = random.uniform(definition["min"], definition["max"])

        # ATTACK MODE EFFECTS
        # --------------------

        # CAN Bus Flooding: many signals go out of normal range
        if attack_mode == "flood":
            if random.random() < 0.6:
                # push outside normal range
                if random.random() < 0.5:
                    numeric = definition["normal_max"] + (
                        definition["max"] - definition["normal_max"]
                    ) * random.random()
                else:
                    numeric = definition["normal_min"] - (
                        definition["normal_min"] - definition["min"]
                    ) * random.random()

        # GPS Spoofing: crazy GPS jumps
        if attack_mode == "gps_spoof" and sig_name in ["GPS Latitude", "GPS Longitude"]:
            numeric = random.uniform(definition["min"], definition["max"])  # teleport
            # stronger anomaly
            definition_normal_min = definition["normal_min"]
            definition_normal_max = definition["normal_max"]
            # we keep numeric as random; anomaly will pick it up

        # Lane Camera Spoof: insane lane offset/yaw
        if attack_mode == "lane_spoof" and sig_name in ["Lane Offset", "Yaw Rate"]:
            if sig_name == "Lane Offset":
                numeric = random.choice([-3, -2.5, 2.5, 3])  # far out of lane
            if sig_name == "Yaw Rate":
                numeric = random.choice([-90, 90])

        # Brake Spoofing: brake pressure high even if driver not braking
        if attack_mode == "brake_spoof" and sig_name in ["Brake Pressure", "ABS Slip Ratio"]:
            numeric = random.uniform(60, 100)

        # ECU Replay Attack: reuse previous values, but mark as anomaly
        if attack_mode == "ecu_replay":
            key = (ecu, sig_name)
            if key in prev_signals_map and random.random() < 0.7:
                numeric = prev_signals_map[key]["numeric"]

        # Sensor Manipulation: ADAS-related sensors go wrong
        if attack_mode == "sensor_manip" and sig_name in [
            "Front Object Distance", "Longitudinal Accel", "Lateral Accel"
        ]:
            if sig_name == "Front Object Distance":
                numeric = random.choice([0.1, 0.2, 250, 300])  # impossible distances
            else:
                numeric = random.uniform(-15, 15)

        # Mark anomaly if outside "normal" range
        anomaly = not (definition["normal_min"] <= numeric <= definition["normal_max"])

        # Format display value
        if unit in ["km/h", "Nm", "%", "°C", "°", "m", "kbps", "V"]:
            display = f"{numeric:.1f} {unit}"
        elif unit in ["rpm"]:
            display = f"{numeric:.0f} {unit}"
        else:
            display = f"{numeric:.3f} {unit}"

        signals.append({
            "timestamp": now,
            "ecu": ecu,
            "signal": sig_name,
            "value": display,
            "numeric": numeric,
            "unit": unit,
            "anomaly": anomaly,
        })

    return signals


def evaluate_rules(snapshot, prev_snapshot, signal_frames):
    """Rule-based IDS logic using signals + vehicle state."""
    alerts = []
    rule_attack = False

    speed = snapshot["speed"]
    brake_status = snapshot["brake_status"]

    # Physics: speed jump
    if prev_snapshot is not None:
        prev_speed = prev_snapshot.get("speed", 0)
        delta_v = abs(speed - prev_speed)
        if delta_v > 60:
            rule_attack = True
            alerts.append({
                "level": "HIGH",
                "source": "Engine ECU",
                "message": f"Implausible speed jump Δv={delta_v} km/h",
                "attack_type": "Physical Implausibility",
                "attacker_ip": random_ip(),
            })

    # Brake at high speed
    if brake_status == "ON" and speed > 120:
        rule_attack = True
        alerts.append({
            "level": "CRITICAL",
            "source": "Brake ECU",
            "message": f"Brake engaged at unsafe speed ({speed} km/h)",
            "attack_type": "Safety Violation",
            "attacker_ip": random_ip(),
        })

    # CAN anomaly density rule
    anomaly_count = sum(1 for s in signal_frames if s["anomaly"])
    if anomaly_count >= 10:
        rule_attack = True
        alerts.append({
            "level": "HIGH",
            "source": "Telematics",
            "message": f"{anomaly_count} anomalous CAN signals detected",
            "attack_type": "DoS/Fuzzing",
            "attacker_ip": random_ip(),
        })

    # Adjust anomaly score using anomaly_count
    score_from_can = min(1.0, 0.2 + 0.03 * anomaly_count)
    snapshot["can_anomaly_score"] = round(
        max(snapshot["can_anomaly_score"], score_from_can), 2
    )

    return rule_attack, alerts


def update_analytics(alerts, attack_active, attack_mode):
    ANALYTICS["events_timeline"].append({
        "timestamp": datetime.utcnow().strftime("%H:%M:%S"),
        "total_alerts": len(alerts),
        "critical_alerts": sum(a["level"] in ("HIGH", "CRITICAL") for a in alerts),
        "attack_active": attack_active,
    })

    if len(ANALYTICS["events_timeline"]) > 200:
        ANALYTICS["events_timeline"].pop(0)

    for a in alerts:
        src = a["source"]
        if src in ECU_NAMES:
            ANALYTICS["attack_counts_by_ecu"][src] += 1
        ANALYTICS["attack_counts_by_type"][a["attack_type"]] += 1
        ANALYTICS["attack_counts_by_attacker"][a["attacker_ip"]] += 1

    # also track selected attack mode as type in analytics
    if attack_mode:
        ANALYTICS["attack_counts_by_type"][f"MODE: {attack_mode}"] += 1


# ---------- Telemetry generator ----------

def generate_telemetry():
    global LAST_SNAPSHOT, ACTIVE_ATTACK

    # base vehicle state
    speed = random.randint(0, 140)
    brake_status = "ON" if random.random() < 0.25 else "OFF"
    ecu_health = {e: round(random.uniform(0.8, 1.0), 2) for e in ECU_NAMES}
    base_anomaly = random.random() * 0.2
    can_anomaly_score = base_anomaly

    # random background hint
    random_attack_hint = random.random() < 0.08
    attack_hint = random_attack_hint or (ACTIVE_ATTACK is not None)

    # generate decoded signals
    can_signals = generate_can_signals(
        attack_hint=attack_hint,
        speed_value=speed,
        attack_mode=ACTIVE_ATTACK,
        prev_snapshot=LAST_SNAPSHOT
    )

    snapshot = {
        "speed": speed,
        "brake_status": brake_status,
        "ecu_health": ecu_health,
        "can_anomaly_score": round(can_anomaly_score, 2),
        "attack_active": False,
        "heatmap": [{"name": e, "status": "ok"} for e in ECU_NAMES],
        "security_alerts": [],
        "can_packets": can_signals,
        "attack_mode": ACTIVE_ATTACK,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # rule-based IDS
    rule_attack, rule_alerts = evaluate_rules(snapshot, LAST_SNAPSHOT, can_signals)
    snapshot["security_alerts"].extend(rule_alerts)

    # if any rule triggered, mark active
    if rule_attack:
        snapshot["attack_active"] = True
        for cell in snapshot["heatmap"]:
            if cell["name"] in ["Engine ECU", "Brake ECU", "Telematics"]:
                cell["status"] = "warning"
                snapshot["ecu_health"][cell["name"]] = round(
                    random.uniform(0.3, 0.7), 2
                )

    # explicit active attack mode
    if ACTIVE_ATTACK is not None:
        snapshot["attack_active"] = True
        # degrade ECUs depending on attack mode
        if ACTIVE_ATTACK == "flood":
            # many ECUs stressed
            for cell in snapshot["heatmap"]:
                if random.random() < 0.6:
                    cell["status"] = "compromised"
                    snapshot["ecu_health"][cell["name"]] = round(
                        random.uniform(0.2, 0.5), 2
                    )
            snapshot["security_alerts"].insert(0, {
                "level": "CRITICAL",
                "source": "Telematics",
                "message": "CAN bus flooding simulation active.",
                "attack_type": "CAN Flooding",
                "attacker_ip": random_ip(),
            })
        elif ACTIVE_ATTACK == "gps_spoof":
            snapshot["security_alerts"].insert(0, {
                "level": "HIGH",
                "source": "Infotainment",
                "message": "GPS coordinates spoofed (position jump).",
                "attack_type": "GPS Spoofing",
                "attacker_ip": random_ip(),
            })
        elif ACTIVE_ATTACK == "lane_spoof":
            snapshot["security_alerts"].insert(0, {
                "level": "HIGH",
                "source": "ADAS ECU",
                "message": "Lane camera spoofing – unrealistic lane offset.",
                "attack_type": "Lane Camera Spoof",
                "attacker_ip": random_ip(),
            })
        elif ACTIVE_ATTACK == "brake_spoof":
            snapshot["security_alerts"].insert(0, {
                "level": "CRITICAL",
                "source": "Brake ECU",
                "message": "Brake spoofing – braking command inconsistent.",
                "attack_type": "Brake Spoofing",
                "attacker_ip": random_ip(),
            })
        elif ACTIVE_ATTACK == "ecu_replay":
            snapshot["security_alerts"].insert(0, {
                "level": "HIGH",
                "source": "Engine ECU",
                "message": "ECU replay attack – stale signal frames detected.",
                "attack_type": "ECU Replay",
                "attacker_ip": random_ip(),
            })
        elif ACTIVE_ATTACK == "sensor_manip":
            snapshot["security_alerts"].insert(0, {
                "level": "HIGH",
                "source": "ADAS ECU",
                "message": "Sensor manipulation – inconsistent ADAS sensor readings.",
                "attack_type": "Sensor Manipulation",
                "attacker_ip": random_ip(),
            })

    # analytics + logging
    update_analytics(snapshot["security_alerts"], snapshot["attack_active"], ACTIVE_ATTACK)
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


@app.route("/api/attack_mode", methods=["POST"])
def api_attack_mode():
    """
    Set or clear active attack type.

    body: { "mode": "gps_spoof" } or { "mode": "off" }
    """
    global ACTIVE_ATTACK
    payload = request.get_json(silent=True) or {}
    mode = payload.get("mode")

    if mode == "off" or mode is None:
        ACTIVE_ATTACK = None
    elif mode in ATTACK_TYPES:
        ACTIVE_ATTACK = mode
    else:
        return jsonify({"error": "invalid attack type"}), 400

    return jsonify({"attack_mode": ACTIVE_ATTACK})


@app.route("/api/analytics")
def get_analytics():
    return jsonify({
        "top_ecu_targets": [{"ecu": k, "count": v}
                            for k, v in ANALYTICS["attack_counts_by_ecu"].most_common(5)],
        "top_attack_types": [{"type": k, "count": v}
                             for k, v in ANALYTICS["attack_counts_by_type"].most_common(5)],
        "top_attackers": [{"attacker": k, "count": v}
                          for k, v in ANALYTICS["attack_counts_by_attacker"].most_common(5)],
        "events_timeline": ANALYTICS["events_timeline"],
    })


if __name__ == "__main__":
    print("🚀 Smart Vehicle IDS running at http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
