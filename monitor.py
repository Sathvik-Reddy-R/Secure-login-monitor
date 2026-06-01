import sqlite3
import time
import os
import re

from collections import defaultdict
from flask_mail import Mail, Message

# ==================================================
# CONFIG
# ==================================================

LOG_FILE = "/var/log/apache2/access.log"
DB = "security.db"

CHECK_INTERVAL = 5

# ==================================================
# SUSPICIOUS PATHS
# ==================================================

SUSPICIOUS_PATHS = [

    "/wp-admin",
    "/phpmyadmin",
    "/.env",
    "/config",
    "/backup",
    "/server-status",
    "/cgi-bin",
    "/shell",
    "/mysql",
    "/db",
    "/admin"

]

# ==================================================
# BAD USER AGENTS
# ==================================================

BAD_USER_AGENTS = [

    "sqlmap",
    "nikto",
    "curl",
    "python",
    "wget",
    "scanner",
    "bot"

]

# ==================================================
# DATABASE
# ==================================================

def get_connection():

    return sqlite3.connect(DB)

# ==================================================
# BLOCK IP
# ==================================================

def block_ip(ip, reason):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT OR IGNORE INTO blocked_ips
        (
            ip,
            reason
        )
        VALUES (?,?)
        """,
        (
            ip,
            reason
        )
    )

    conn.commit()
    conn.close()

# ==================================================
# SAVE DETECTION
# ==================================================

def save_detection(
    ip,
    threat_level,
    reason
):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO detections
        (
            ip,
            country,
            region,
            city,
            organization,
            provider_type,
            risk_score,
            threat_level
        )
        VALUES (?,?,?,?,?,?,?,?)
        """,
        (
            ip,
            "Unknown",
            "Unknown",
            "Unknown",
            reason,
            "LOG_MONITOR",
            10,
            threat_level
        )
    )

    conn.commit()
    conn.close()

# ==================================================
# PARSE APACHE LOG
# ==================================================

def parse_line(line):

    try:

        parts = line.split()

        ip = parts[0]

        method = parts[5].replace('"', '')

        path = parts[6]

        return ip, method, path

    except:

        return None, None, None

# ==================================================
# MONITOR LOOP
# ==================================================

def monitor():

    print("Apache Monitor Started")

    if not os.path.exists(LOG_FILE):

        print(
            f"Log file not found: {LOG_FILE}"
        )

        return

    with open(LOG_FILE, "r") as file:

        file.seek(0, os.SEEK_END)

        request_counter = defaultdict(int)

        while True:

            line = file.readline()

            if not line:

                time.sleep(1)
                continue

            ip, method, path = parse_line(line)

            if not ip:
                continue

            request_counter[ip] += 1

            # ==========================================
            # RATE LIMIT
            # ==========================================

            if request_counter[ip] >= 100:

                print(
                    f"[BLOCKED] Flood detected {ip}"
                )

                block_ip(
                    ip,
                    "Request Flood"
                )

                save_detection(
                    ip,
                    "HIGH",
                    "Request Flood"
                )

            # ==========================================
            # SUSPICIOUS PATH
            # ==========================================

            for suspicious in SUSPICIOUS_PATHS:

                if suspicious in path:

                    print(
                        f"[WARNING] {ip} -> {path}"
                    )

                    save_detection(
                        ip,
                        "MEDIUM",
                        f"Path Scan: {path}"
                    )

                    if request_counter[ip] >= 10:

                        block_ip(
                            ip,
                            f"Repeated Scan: {path}"
                        )

                    break

            # ==========================================
            # USER AGENT CHECK
            # ==========================================

            lower_line = line.lower()

            for agent in BAD_USER_AGENTS:

                if agent in lower_line:

                    print(
                        f"[BLOCKED] Bad Agent {ip}"
                    )

                    block_ip(
                        ip,
                        f"Bad User Agent: {agent}"
                    )

                    save_detection(
                        ip,
                        "HIGH",
                        f"Bad Agent: {agent}"
                    )

                    break

# ==================================================
# MAIN
# ==================================================

if __name__ == "__main__":

    monitor()
