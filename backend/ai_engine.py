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

    # 1. Hårde serverrums-grænser (ASHRAE)
    if temp is not None and (temp > TEMP_MAX or temp < TEMP_MIN):
        is_anomaly = True
        reasons.append(f"Temperatur uden for ASHRAE-grænse ({temp:.1f} C)")
    if hum is not None and (hum > HUM_MAX or hum < HUM_MIN):
        is_anomaly = True
        reasons.append(f"Luftfugtighed uden for grænse ({hum:.1f} %)")
    if noise is not None and noise > NOISE_MAX:
        is_anomaly = True
        reasons.append(f"Højt støjniveau ({noise:.1f} dB)")

    # 2. Hent historik til AI-model & trendforudsigelse
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

    # 3. Isolation Forest anomaly detection (kræver min. 20 målinger)
    if len(rows) >= 20 and None not in (temp, hum, noise):
        X = np.array([[r["temperature"], r["humidity"], r["noise_db"]] for r in rows])
        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(X)
        current = np.array([[temp, hum, noise]])
        pred = int(model.predict(current)[0])       # -1 = anomaly, 1 = normal
        score = float(-model.decision_function(current)[0])
        anomaly_score = round(score, 4)
        if pred == -1:
            is_anomaly = True
            reasons.append(f"AI Isolation Forest afvigelse (score={anomaly_score:.3f})")

    # 4. Trend-forudsigelse: hvornår rammer temperaturen kritisk 27 C?
    recent = list(reversed(rows[:15]))
    if len(recent) >= 5 and temp is not None and temp < TEMP_MAX:
        times_min = np.array([(r["ts"] - recent[0]["ts"]) / 60.0 for r in recent])
        temps = np.array([r["temperature"] for r in recent])
        if times_min[-1] > 0.2:
            slope_per_min = float(np.polyfit(times_min, temps, 1)[0])
            if slope_per_min > 0.05:  # stiger mere end 0.05 C/min
                mins_left = (TEMP_MAX - temp) / slope_per_min
                if 0 < mins_left <= 120:
                    predicted_critical_min = round(mins_left, 1)
                    reasons.append(
                        f"Forudsigelse: kritisk temp ({TEMP_MAX} C) om ca. {predicted_critical_min} min"
                    )

    # 5. Gem i ai_anomalies og system_logs hvis der er afvigelse eller forudsigelse
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
        "reasons": reasons,
    }
