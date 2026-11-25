import os
import shutil
import subprocess
import sys
import tempfile

SRC = "/app"
MUTANTS = [
    ("M1: Slå ASHRAE temp-grænse fra",     "ai_engine.py",   "if temp is not None and (temp > TEMP_MAX or temp < TEMP_MIN):", "if temp is not None and (temp > 999.0 or temp < -999.0):"),
    ("M2: Slå DHT22 flatline-tjek fra",    "ai_engine.py",   "if len(t_vals) == 1 and len(h_vals) == 1:",                     "if False:"),
    ("M3: Slå robust Z-score fra",         "ai_engine.py",   "if max_z >= 4.0:",                                                "if max_z >= 9999.0:"),
    ("M4: Slå HMAC signatur-tjek fra",     "main.py",        "if not hmac.compare_digest(sig, expected):",                      "if False:"),
    ("M5: Slå RBAC 403-rolleblokering fra","main.py",        'if session["role"] not in allowed_roles:',                        "if False:"),
    ("M6: Lad spærrede adgangskort ind",   "mqtt_worker.py", 'if card and card["is_active"]:',                                  "if card:"),
    ("M7: Slå PBKDF2 password-tjek fra",   "auth_utils.py",  "return hmac.compare_digest(dk, expected_hex)",                    "return True"),
]

killed = 0
print(f"{'MUTANT':<40} | {'RESULTAT':<10} | {'FANGET AF'}")
print("-" * 92)

for label, filename, orig, mutated in MUTANTS:
    tmp = tempfile.mkdtemp(prefix="mut_")
    try:
        work = os.path.join(tmp, "app")
        shutil.copytree(SRC, work)
        target = os.path.join(work, filename)
        txt = open(target, encoding="utf-8").read()
        assert orig in txt, f"Kunne ikke finde streng i {filename}"
        open(target, "w", encoding="utf-8").write(txt.replace(orig, mutated, 1))

        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "tests/test_unit.py"],
            cwd=work,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            killed += 1
            fails = [ln.strip() for ln in proc.stderr.splitlines() if ln.startswith("FAIL:") or ln.startswith("ERROR:")]
            catcher = fails[0].split(" ", 1)[1].split(" ")[0] if fails else "unittest fail"
            print(f"{label:<40} | KILLED ✅  | {catcher}")
        else:
            print(f"{label:<40} | SURVIVED ❌| INGEN TEST FANGEDE FEJLEN!")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

score = (killed / len(MUTANTS)) * 100.0
print("-" * 92)
print(f"MUTATION SCORE: {killed}/{len(MUTANTS)} ({score:.1f}%)")
