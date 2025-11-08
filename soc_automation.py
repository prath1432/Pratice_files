#!/usr/bin/env python3
# soc_automation.py
import json, os, time, subprocess, csv
from datetime import datetime
from dateutil import parser as dparser

EVE_PATH = "/var/log/suricata/eve.json"
OUT_CSV  = "/var/log/suricata/automated_alerts.csv"
LOW_SCORE_THRESHOLD = 0.3
HIGH_SCORE_THRESHOLD = 0.7

# === helper: append to csv ===
def append_csv(row):
    header = ["time","src_ip","dest_ip","proto","signature","severity","score","action"]
    newfile = not os.path.exists(OUT_CSV)
    with open(OUT_CSV,"a",newline="") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        if newfile: writer.writeheader()
        writer.writerow(row)

# === basic enrichment: reverse DNS & whois (slow) ===
def enrich_ip(ip):
    info = {"rdns":None,"whois":None}
    try:
        rd = subprocess.check_output(["dig","+short","-x",ip], stderr=subprocess.DEVNULL).decode().strip()
        info["rdns"] = rd if rd else None
    except Exception:
        info["rdns"] = None
    try:
        w = subprocess.check_output(["whois", ip], stderr=subprocess.DEVNULL, timeout=10).decode()
        info["whois"] = w.splitlines()[0:5]
    except Exception:
        info["whois"] = None
    return info

# === placeholder AI scoring function (replace with real LLM call) ===
def ai_score_alert(alert):
    # Small heuristic: higher score if signature contains critical terms
    sig = (alert.get("alert",{}) .get("signature","") or "").lower()
    score = 0.0
    if "sql" in sig or "shellcode" in sig or "ransom" in sig: score += 0.6
    if "dos" in sig or "ddos" in sig: score += 0.4
    if alert.get("src_port") in (22,23,3389): score += 0.1
    score = min(1.0, score)
    return score

# === optional action: block IP via iptables ===
def block_ip(ip):
    try:
        subprocess.check_call(["sudo","iptables","-I","INPUT","-s",ip,"-j","DROP"])
        return True
    except Exception as e:
        print("block error:",e)
        return False

# === main tailing loop ===
def tail_eve():
    # start tail -F for robust rotation handling
    p = subprocess.Popen(["tail","-F",EVE_PATH], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    while True:
        line = p.stdout.readline()
        if not line:
            time.sleep(0.1)
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        # interested in alerts
        if obj.get("event_type") != "alert": continue
        alert = obj.get("alert",{})
        src_ip = obj.get("src_ip")
        dest_ip = obj.get("dest_ip")
        proto = obj.get("proto")
        signature = alert.get("signature")
        ts = obj.get("timestamp")
        # enrichment
        enrich = enrich_ip(src_ip)
        score = ai_score_alert(obj)
        action = "none"
        if score >= HIGH_SCORE_THRESHOLD:
            # block and notify
            blocked = block_ip(src_ip)
            action = "blocked" if blocked else "block_failed"
            # --- optionally send to Slack / Email / SIEM call here ---
        elif score >= LOW_SCORE_THRESHOLD:
            action = "investigate"
        else:
            action = "low"
        # write to CSV
        append_csv({
            "time": ts,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "proto": proto,
            "signature": signature,
            "severity": obj.get("alert",{}).get("severity",""),
            "score": score,
            "action": action
        })
        print(f"[{ts}] {src_ip} -> {dest_ip} sig:{signature} score:{score:.2f} action:{action}")

if __name__=="__main__":
    print("Starting SOC automation tailer...")
    tail_eve()
