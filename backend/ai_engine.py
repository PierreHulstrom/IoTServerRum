import json
import numpy as np
from sklearn.ensemble import IsolationForest
from db import get_conn

# ASHRAE TC 9.9 anbefalede grænser for serverrum
TEMP_MIN, TEMP_MAX = 18.0, 27.0
HUM_MIN, HUM_MAX = 20.0, 80.0
NOISE_MAX = 75.0


def analyze_reading(device_id: str, temp, hum, noise):
    reasons = []
    is_anomaly = False
    anomaly_score = 0.0
    predicted_critical_min = None
    critical_action_needed = False
    threshold_breached = False

    # 1. Hårde serverrums-grænser (ASHRAE)
    if temp is not None and (temp > TEMP_MAX or temp < TEMP_MIN):
        is_anomaly = True
        threshold_breached = True
        reasons.append(f"Temperatur uden for ASHRAE-grænse ({temp:.1f} °C)")
        if temp > TEMP_MAX:
            critical_action_needed = True
    if hum is not None and (hum > HUM_MAX or hum < HUM_MIN):
        is_anomaly = True
        threshold_breached = True
        reasons.append(f"Luftfugtighed uden for grænse ({hum:.1f} %)")
    if noise is not None and noise > NOISE_MAX:
        is_anomaly = True
        threshold_breached = True
        reasons.append(f"Højt støjniveau ({noise:.1f} dB)")

    # 2. Hent historik til flatline-tjek, AI-model & trendforudsigelse
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT UNIX_TIMESTAMP(time) AS ts, temperature, humidity, noise_db
                FROM sensor_readings
                WHERE device_id = %s
                  AND temperature IS NOT NULL
                  AND humidity IS NOT NULL
                  AND noise_db IS NOT NULL
                ORDER BY time DESC
                LIMIT 150
                """,
                (device_id,),
            )
            rows = cur.fetchall()

    # 2B. Sensordefekt / Flatline-detektion (20 helt identiske temp+fugt målinger i træk)
    if len(rows) >= 20:
        last20 = rows[:20]
        t_vals = {round(float(r["temperature"]), 2) for r in last20}
        h_vals = {round(float(r["humidity"]), 2) for r in last20}
        if len(t_vals) == 1 and len(h_vals) == 1:
            is_anomaly = True
            reasons.append("Mulig sensordefekt: DHT22 flatline (20 identiske målinger i træk)")

    # 3. Hybrid ML (Robust multivariat Z-score + Unsupervised Isolation Forest)
    if len(rows) >= 20 and None not in (temp, hum, noise):
        hist = rows[1:] if len(rows) > 20 else rows
        X = np.array([[r["temperature"], r["humidity"], r["noise_db"]] for r in hist], dtype=float)
        current = np.array([[temp, hum, noise]], dtype=float)

        means = np.mean(X, axis=0)
        stds = np.maximum(np.std(X, axis=0), np.array([0.5, 1.5, 2.0]))
        max_z = float(np.max(np.abs((current[0] - means) / stds)))
        if max_z >= 4.0:
            is_anomaly = True
            anomaly_score = round(max_z, 2)
            reasons.append(f"AI Z-score afvigelse (z={max_z:.1f})")

        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(X)
        pred = int(model.predict(current)[0])
        iso_score = float(-model.decision_function(current)[0])
        if pred == -1:
            is_anomaly = True
            anomaly_score = max(anomaly_score, round(iso_score, 4))
            reasons.append(f"AI Isolation Forest afvigelse (score={iso_score:.3f})")

    # 4. Trend-forudsigelse (støjfilter + hele minutter uden decimaler)
    recent = list(reversed(rows[:15]))
    if len(recent) >= 10 and temp is not None and temp < TEMP_MAX:
        times_min = np.array([(r["ts"] - recent[0]["ts"]) / 60.0 for r in recent])
        temps = np.array([r["temperature"] for r in recent])
        temp_rise = float(temps[-1] - temps[0])
        if times_min[-1] >= 0.75 and temp_rise >= 0.8:
            slope_per_min = float(np.polyfit(times_min, temps, 1)[0])
            if slope_per_min >= 0.25:
                mins_left = max(1, int(round((TEMP_MAX - temp) / slope_per_min)))
                if mins_left <= 120:
                    predicted_critical_min = mins_left
                    reasons.append(
                        f"Forudsigelse: kritisk temp ({int(TEMP_MAX)} °C) om ca. {mins_left} min"
                    )
                    if mins_left <= 5:
                        critical_action_needed = True

    # 5. Gem i ai_anomalies og system_logs
    if is_anomaly or predicted_critical_min is not None:
        msg = "; ".join(reasons)
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO ai_anomalies
                        (device_id, anomaly_score, is_anomaly, predicted_critical_min, message)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (device_id, anomaly_score, is_anomaly, predicted_critical_min, msg),
                )
                cur.execute(
                    """
                    INSERT INTO system_logs (source, level, message, details)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        "ai_engine",
                        "WARNING" if is_anomaly else "INFO",
                        msg,
                        json.dumps({"device_id": device_id, "score": anomaly_score}),
                    ),
                )

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": anomaly_score,
        "predicted_critical_min": predicted_critical_min,
        "critical_action_needed": critical_action_needed,
        "threshold_breached": threshold_breached,
        "reasons": reasons,
    }
