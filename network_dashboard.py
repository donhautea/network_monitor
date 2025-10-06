
import os
import io
import time
import sqlite3
import socket
import subprocess
import shutil as _shutil
import json
from datetime import datetime, timedelta, timezone, date, time as dtime
from typing import Optional, Tuple, List

import pandas as pd
import streamlit as st

import hashlib
from contextlib import closing

def _sqlite_safe_copy(src_path: str, dst_path: str):
    """Create a consistent snapshot using the sqlite3 backup API."""
    with closing(sqlite3.connect(src_path, check_same_thread=False)) as src, \
         closing(sqlite3.connect(dst_path)) as dst:
        src.backup(dst)  # atomic, consistent

def _md5sum(path: str, chunk=1024*1024) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()

try:
    import altair as alt
except Exception:
    alt = None

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
except Exception:
    plt = None
    mdates = None

try:
    import requests
except Exception:
    requests = None

try:
    import speedtest
except Exception:
    speedtest = None

APP_DB_PATH = os.environ.get("NETDASH_DB", "network_metrics.db")

st.set_page_config(page_title="Network Speed & Uptime Dashboard", page_icon="📶", layout="wide")

if speedtest is None:
    st.warning("python speedtest-cli is not installed. Install with: `pip install speedtest-cli` or install the Ookla CLI (`speedtest`) and ensure it is on PATH.")

# ---------------- DB ----------------
def _conn():
    conn = sqlite3.connect(APP_DB_PATH, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            ping_ms REAL,
            download_mbps REAL,
            upload_mbps REAL,
            public_ip TEXT,
            local_ip TEXT,
            ssid TEXT,
            server_name TEXT,
            is_online INTEGER NOT NULL DEFAULT 1,
            notes TEXT
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS outages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_ts TEXT NOT NULL,
            end_ts TEXT,
            duration_seconds INTEGER,
            last_online_before TEXT,
            first_online_after TEXT,
            start_sample_id INTEGER,
            end_sample_id INTEGER,
            UNIQUE(start_ts)
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS kv (
            k TEXT PRIMARY KEY,
            v TEXT
        );
    """)
    return conn

def insert_metric(row: dict):
    conn = _conn()
    cols = ",".join(row.keys())
    qmarks = ",".join(["?"] * len(row))
    conn.execute(f"INSERT INTO metrics ({cols}) VALUES ({qmarks})", tuple(row.values()))
    conn.commit()

def fetch_metrics(start: Optional[datetime] = None, end: Optional[datetime] = None) -> pd.DataFrame:
    conn = _conn()
    if start and end:
        df = pd.read_sql_query(
            "SELECT * FROM metrics WHERE ts >= ? AND ts < ? ORDER BY ts ASC",
            conn, params=(start.isoformat(), end.isoformat())
        )
    else:
        df = pd.read_sql_query("SELECT * FROM metrics ORDER BY ts ASC", conn)
    if not df.empty:
        df["ts"] = pd.to_datetime(df["ts"])
    return df

def kv_get(key: str, default=None):
    conn = _conn()
    row = conn.execute("SELECT v FROM kv WHERE k = ?", (key,)).fetchone()
    if not row:
        return default
    try:
        return json.loads(row[0])
    except Exception:
        return row[0]

def kv_set(key: str, value):
    conn = _conn()
    conn.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", (key, json.dumps(value)))
    conn.commit()

# ------------- Drive & Email -------------
def _gdrive_service():
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        sa_info = dict(st.secrets["gdrive_service_account"])
        creds = service_account.Credentials.from_service_account_info(
            sa_info, scopes=["https://www.googleapis.com/auth/drive"]
        )
        return build("drive", "v3", credentials=creds, cache_discovery=False)
    except Exception:
        return None

def gdrive_sync_db():
    """
    Uploads a safe snapshot of APP_DB_PATH to the configured Drive folder.

    - Uses sqlite backup API to avoid locked/partial copies.
    - Skips upload if MD5 matches what’s already on Drive.
    - Returns (ok: bool, message: str)
    """
    folder_id = None
    try:
        folder_id = st.secrets.get("gdrive_folder_id", None)
    except Exception:
        folder_id = None
    svc = _gdrive_service()
    if not svc or not folder_id:
        return False, "Drive not configured"

    # 1) Make a consistent snapshot to a temp file
    name = os.path.basename(APP_DB_PATH)
    snapshot_path = os.path.join(os.path.dirname(APP_DB_PATH), f".__tmp_{name}")
    try:
        _sqlite_safe_copy(APP_DB_PATH, snapshot_path)
    except Exception as e:
        return False, f"Snapshot failed: {e}"

    local_md5 = _md5sum(snapshot_path)

    try:
        # 2) Look for existing file in folder
        q = f"'{folder_id}' in parents and name = '{name}' and trashed = false"
        resp = svc.files().list(
            q=q,
            fields="files(id, name, md5Checksum, modifiedTime)",
            pageSize=1
        ).execute()
        files = resp.get("files", [])
        file_id = files[0]["id"] if files else None
        remote_md5 = files[0].get("md5Checksum") if files else None

        # 3) Skip if content identical
        if remote_md5 and remote_md5 == local_md5:
            kv_set("last_drive_sync", {"ts": time.time(), "status": "skipped (no changes)", "md5": local_md5})
            try:
                os.remove(snapshot_path)
            except Exception:
                pass
            return True, f"Synced (no changes) — md5 {local_md5}"

        # 4) Upload/update with resumable upload
        from googleapiclient.http import MediaFileUpload
        media = MediaFileUpload(snapshot_path, mimetype="application/x-sqlite3", resumable=True)

        if file_id:
            updated = svc.files().update(
                fileId=file_id,
                media_body=media,
                fields="id, md5Checksum, modifiedTime"
            ).execute()
            new_md5 = updated.get("md5Checksum")
            kv_set("last_drive_sync", {"ts": time.time(), "status": "updated", "md5": new_md5, "file_id": updated.get("id")})
            msg = f"Updated on Drive — md5 {new_md5}, modified {updated.get('modifiedTime')}"
        else:
            created = svc.files().create(
                body={"name": name, "parents": [folder_id]},
                media_body=media,
                fields="id, md5Checksum, modifiedTime"
            ).execute()
            new_md5 = created.get("md5Checksum")
            kv_set("last_drive_sync", {"ts": time.time(), "status": "created", "md5": new_md5, "file_id": created.get("id")})
            msg = f"Created on Drive — md5 {new_md5}, modified {created.get('modifiedTime')}"

        # 5) Clean up temp
        try:
            os.remove(snapshot_path)
        except Exception:
            pass

        # 6) Integrity check
        if new_md5 != local_md5 and new_md5 is not None:
            return False, f"Warning: MD5 mismatch (local {local_md5} vs drive {new_md5})"
        return True, "Synced to Drive"

    except Exception as e:
        try:
            os.remove(snapshot_path)
        except Exception:
            pass
        return False, f"Drive sync failed: {e}"

def _smtp_cfg():
    try:
        smtp_cfg = dict(st.secrets.get("smtp", {}))
    except Exception:
        smtp_cfg = None
    if not smtp_cfg:
        smtp_cfg = {
            "host": "smtp.gmail.com",
            "port": 587,
            "username": os.environ.get("NETDASH_SMTP_USER", ""),
            "password": os.environ.get("NETDASH_SMTP_PASS", ""),
            "use_tls": True,
        }
    return smtp_cfg

def _send_email_with_attachments(subject: str, to_email: str, html_body: str, attachments: List[Tuple[str, bytes, str]]):
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime_text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders

    cfg = _smtp_cfg()
    host = cfg.get("host", "smtp.gmail.com")
    port = int(cfg.get("port", 587))
    user = cfg.get("username", "")
    pwd  = cfg.get("password", "")
    use_tls = bool(cfg.get("use_tls", True))
    if not (host and port and user and pwd):
        return False, "SMTP not configured"

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

    for fname, data, mime in attachments or []:
        maintype, subtype = mime.split("/", 1)
        part = MIMEBase(maintype, subtype)
        part.set_payload(data)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{fname}"')
        msg.attach(part)

    try:
        server = smtplib.SMTP(host, port, timeout=30)
        if use_tls:
            server.starttls()
        server.login(user, pwd)
        server.sendmail(user, [to_email], msg.as_string())
        server.quit()
        return True, "Email sent"
    except Exception as e:
        return False, f"Email send failed: {e}"

# ------------- Network & Speed -------------
def get_local_ip() -> str:
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except Exception:
        return ""

def get_public_ip(timeout=5) -> str:
    if not requests:
        return ""
    for url in ["https://api.ipify.org","https://ifconfig.me/ip","https://ipinfo.io/ip"]:
        try:
            r = requests.get(url, timeout=timeout)
            if r.ok:
                return r.text.strip()
        except Exception:
            continue
    return ""

def get_wifi_ssid() -> str:
    try:
        out = subprocess.check_output(["netsh","wlan","show","interfaces"], stderr=subprocess.DEVNULL, text=True, timeout=3)
        for line in out.splitlines():
            if "SSID" in line and "BSSID" not in line:
                return line.split(":",1)[1].strip()
    except Exception:
        pass
    try:
        out = subprocess.check_output(["nmcli","-t","-f","active,ssid","dev","wifi"], stderr=subprocess.DEVNULL, text=True, timeout=3)
        for row in out.splitlines():
            parts = row.split(":")
            if parts and parts[0]=="yes":
                return parts[1] if len(parts)>1 else ""
    except Exception:
        pass
    try:
        out = subprocess.check_output(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport","-I"], stderr=subprocess.DEVNULL, text=True, timeout=3)
        for line in out.splitlines():
            if " SSID:" in line:
                return line.split("SSID:",1)[1].strip()
    except Exception:
        pass
    return ""

def run_speed_test():
    # 1) Try python speedtest-cli
    if speedtest:
        try:
            stest = speedtest.Speedtest()
            stest.get_servers([])
            best = stest.get_best_server()
            ping_ms = float(stest.results.ping)
            download_mbps = round(stest.download() / 1_000_000, 3)
            upload_mbps = round(stest.upload() / 1_000_000, 3)
            server_name = f"{best.get('sponsor','')} - {best.get('name','')} ({best.get('country','')})"
            return ping_ms, download_mbps, upload_mbps, server_name
        except Exception as e:
            py_err = f"python speedtest-cli failed: {e}"
    else:
        py_err = "python speedtest-cli not installed"

    # 2) Try Ookla CLI (speedtest)
    cli = _shutil.which("speedtest")
    if not cli:
        return None, None, None, py_err + " | Ookla CLI not found on PATH"

    def _try_ookla(args):
        # Run CLI, capture both stdout/stderr
        p = subprocess.run(
            [cli] + args,
            text=True,
            capture_output=True,
            timeout=180
        )
        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        return p.returncode, out, err

    # Common flag sets across versions
    attempts = [
        ["--format=json", "--accept-license", "--accept-gdpr"],
        ["-f", "json", "--accept-license", "--accept-gdpr"],
        ["--format=json", "--progress=no", "--accept-license", "--accept-gdpr"],
    ]

    last_err = py_err
    for args in attempts:
        try:
            rc, out, err = _try_ookla(args)
            if rc != 0:
                last_err = f"Ookla CLI exit {rc}: {err or 'no stderr'}"
                continue
            if not out:
                last_err = f"Ookla CLI produced no output. stderr: {err or 'empty'}"
                continue

            # Some proxies inject HTML. Guard that.
            if out.lstrip().startswith("<") or out.lstrip().startswith("<?xml"):
                last_err = "Ookla CLI returned non-JSON (HTML/XML). Possible captive portal/proxy."
                continue

            # Parse JSON (strip BOM if any)
            out_clean = out.lstrip("\ufeff").strip()
            data = json.loads(out_clean)

            # Validate expected fields (schema differs by versions)
            ping_ms = float(data.get("ping", {}).get("latency", data.get("ping", 0.0)))

            def _extract_bps(section):
                sec = data.get(section, {})
                bw = sec.get("bandwidth")
                if bw is not None:
                    return float(bw) * 8.0
                bps = sec.get("bps")
                if bps is not None:
                    return float(bps)
                return None

            dl_bps = _extract_bps("download")
            ul_bps = _extract_bps("upload")

            if dl_bps is None or ul_bps is None:
                last_err = "Ookla JSON missing bandwidth fields."
                continue

            download_mbps = round(dl_bps / 1_000_000, 3)
            upload_mbps = round(ul_bps / 1_000_000, 3)

            srv = data.get("server", {})
            server_name = f"{srv.get('name','')} - {srv.get('location','')} ({srv.get('country','')})".strip()

            return ping_ms, download_mbps, upload_mbps, server_name or "Ookla server"
        except json.JSONDecodeError as je:
            last_err = f"JSON parse error: {je}"
        except Exception as e:
            last_err = f"Ookla CLI error: {e}"

    return None, None, None, last_err

def classify_online(download_mbps: Optional[float], ping_ms: Optional[float], dl_threshold: float = 0.1) -> int:
    try:
        return 1 if (download_mbps is not None and download_mbps >= dl_threshold and ping_ms is not None) else 0
    except Exception:
        return 0

def compute_uptime(df: pd.DataFrame) -> Tuple[float, float]:
    if df.empty:
        return 0.0, 0.0
    online = int(df["is_online"].sum())
    total = int(len(df))
    uptime = 100.0 * online / max(total, 1)
    return uptime, 100.0 - uptime

# -------- Outage bookkeeping --------
def _insert_outage_start(conn, start_ts: str, last_online_before: Optional[str], start_sample_id: int):
    try:
        conn.execute(
            "INSERT OR IGNORE INTO outages (start_ts,last_online_before,start_sample_id) VALUES (?,?,?)",
            (start_ts, last_online_before, start_sample_id)
        )
        conn.commit()
    except Exception:
        pass

def _close_latest_outage(conn, end_ts: str, first_online_after: str, end_sample_id: int):
    cur = conn.cursor()
    cur.execute("SELECT id, start_ts FROM outages WHERE end_ts IS NULL ORDER BY start_ts DESC LIMIT 1")
    row = cur.fetchone()
    if not row:
        return
    outage_id, start_ts = row
    try:
        start_dt = datetime.fromisoformat(start_ts.replace("Z", ""))
        end_dt = datetime.fromisoformat(end_ts.replace("Z", ""))
        duration = int((end_dt - start_dt).total_seconds())
    except Exception:
        duration = None
    cur.execute(
        "UPDATE outages SET end_ts=?, duration_seconds=?, first_online_after=?, end_sample_id=? WHERE id=?",
        (end_ts, duration, first_online_after, end_sample_id, outage_id)
    )
    conn.commit()

def analyze_outage_transition(latest_sample_id: int):
    conn = _conn()
    df = pd.read_sql_query("SELECT id, ts, is_online FROM metrics ORDER BY ts DESC LIMIT 2", conn)
    if df.empty:
        return None
    if len(df) == 1:
        try:
            cur_online = int(df.loc[0, "is_online"]) if pd.notna(df.loc[0, "is_online"]) else 0
        except Exception:
            cur_online = 0
        if cur_online == 0:
            _insert_outage_start(conn, str(df.loc[0, "ts"]), None, int(df.loc[0, "id"]))
            return "start"
        return None
    cur, prev = df.iloc[0], df.iloc[1]
    cur_online = int(cur["is_online"]) if pd.notna(cur["is_online"]) else 0
    prev_online = int(prev["is_online"]) if pd.notna(prev["is_online"]) else 0
    if prev_online == 1 and cur_online == 0:
        _insert_outage_start(conn, str(cur["ts"]), str(prev["ts"]), int(cur["id"]))
        return "start"
    elif prev_online == 0 and cur_online == 1:
        _close_latest_outage(conn, str(cur["ts"]), str(cur["ts"]), int(cur["id"]))
        return "end"
    return None

# ---------------- Time helpers ----------------
def _to_naive_datetime_series(s: pd.Series) -> pd.Series:
    s = pd.to_datetime(s, errors="coerce")
    try:
        if s.dt.tz is not None:
            try:
                s = s.dt.tz_convert(None)
            except Exception:
                s = s.dt.tz_localize(None)
    except Exception:
        try:
            s = s.dt.tz_localize(None)
        except Exception:
            pass
    return s

# ------------- Bands & chart -------------
def compute_bands_and_restores(df: pd.DataFrame, df_out: pd.DataFrame):
    if df.empty:
        return [], pd.DataFrame()
    df2 = df.copy()
    df2["ts"] = _to_naive_datetime_series(df2["ts"])
    t_start = df2["ts"].min(); t_end = df2["ts"].max()

    events = []
    if df_out is not None and not df_out.empty:
        df_out2 = df_out.copy()
        for col in ["start_ts","end_ts"]:
            if col in df_out2.columns:
                df_out2[col] = _to_naive_datetime_series(df_out2[col])
        for _, r in df_out2.sort_values("start_ts").iterrows():
            if pd.notna(r.get("start_ts")): events.append((r["start_ts"], 'down_start'))
            if pd.notna(r.get("end_ts")): events.append((r["end_ts"], 'up_start'))
    events = sorted(events, key=lambda x: x[0])

    try:
        first_state = int(df2.sort_values("ts").iloc[0]["is_online"]) if "is_online" in df2.columns else 1
    except Exception:
        first_state = 1
    cur_state = 'up' if first_state==1 else 'down'
    cur_time = t_start

    bands = []
    for ev_time, ev_type in events:
        if ev_time < t_start: continue
        if ev_time > t_end: break
        if ev_time <= cur_time:
            if ev_type == 'down_start': cur_state = 'down'
            elif ev_type == 'up_start': cur_state = 'up'
            continue
        bands.append({"start": cur_time, "end": ev_time, "state": cur_state})
        if ev_type == 'down_start': cur_state = 'down'
        elif ev_type == 'up_start': cur_state = 'up'
        cur_time = ev_time
    if cur_time < t_end: bands.append({"start": cur_time, "end": t_end, "state": cur_state})

    restores_df = pd.DataFrame(columns=["ts","duration_seconds"])
    if df_out is not None and not df_out.empty:
        df_out2 = df_out.copy()
        if "end_ts" in df_out2.columns:
            df_out2["end_ts"] = _to_naive_datetime_series(df_out2["end_ts"])
            restores_df = df_out2[df_out2["end_ts"].notna()][["end_ts","duration_seconds"]].copy()
            if not restores_df.empty:
                restores_df["ts"] = restores_df["end_ts"]
                restores_df["duration_hr"] = restores_df["duration_seconds"].astype(float)/3600.0
                restores_df = restores_df.sort_values("ts")
                restores_df["avg_duration_hr"] = restores_df["duration_hr"].expanding().mean()

    return bands, restores_df

def make_combined_chart_image(df: pd.DataFrame, df_out: pd.DataFrame) -> bytes:
    if plt is None or mdates is None or df.empty:
        return b""
    bands, restores_df = compute_bands_and_restores(df, df_out)

    ts = pd.to_datetime(df["ts"])
    try:
        if ts.dt.tz is not None:
            ts = ts.dt.tz_convert(None)
    except Exception:
        try:
            ts = ts.dt.tz_localize(None)
        except Exception:
            pass

    dl = df["download_mbps"]; ul = df["upload_mbps"]

    fig, ax1 = plt.subplots(figsize=(12, 4.5))
    ax1.plot(ts, dl, label="Download (Mbps)")
    ax1.plot(ts, ul, label="Upload (Mbps)")
    ax1.set_ylabel("Speed (Mbps)")
    ax1.set_xlabel("Time")

    for b in bands:
        color = "red" if b["state"]=="down" else "green"
        ax1.axvspan(pd.to_datetime(b["start"]), pd.to_datetime(b["end"]), color=color, alpha=0.12)

    df_out2 = df_out.copy()
    if not df_out2.empty:
        for col in ["start_ts","end_ts"]:
            if col in df_out2.columns:
                df_out2[col] = _to_naive_datetime_series(df_out2[col])
        for t in pd.to_datetime(df_out2["start_ts"].dropna()):
            ax1.axvline(t, color="red", linestyle="--", alpha=0.6, linewidth=1)
        for t in pd.to_datetime(df_out2["end_ts"].dropna()):
            ax1.axvline(t, color="green", linestyle="--", alpha=0.6, linewidth=1)

    ax2 = ax1.twinx()
    if restores_df is not None and not restores_df.empty:
        ax2.scatter(pd.to_datetime(restores_df["ts"]), restores_df["duration_hr"], marker="^", label="Outage duration (hr)")
        ax2.plot(pd.to_datetime(restores_df["ts"]), restores_df["avg_duration_hr"], linewidth=1, label="Avg outage (hr)")
        ax2.set_ylabel("Outage (hours)")

    ax1.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d\n%H:%M"))
    fig.autofmt_xdate()

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1+lines2, labels1+labels2, loc="upper left")

    buf = io.BytesIO()
    fig.tight_layout()
    fig.savefig(buf, format="png", dpi=150)
    plt.close(fig)
    return buf.getvalue()

# ---------- Bucket logic (table only) with optional anchor ----------
def _tz_naive_series(s: pd.Series) -> pd.Series:
    s = pd.to_datetime(s, errors="coerce")
    try:
        if hasattr(s.dt, "tz_localize") and s.dt.tz is not None:
            s = s.dt.tz_localize(None)
    except Exception:
        try:
            s = s.dt.tz_convert(None)
        except Exception:
            pass
    return s

def overlap_seconds(a_start, a_end, b_start, b_end) -> int:
    start = max(a_start, b_start)
    end = min(a_end, b_end)
    if end <= start:
        return 0
    return int((end - start).total_seconds())

def _align_start_to_anchor(window_start: datetime, step: timedelta, anchor: Optional[datetime]) -> datetime:
    if not anchor:
        return window_start
    anchor = anchor.replace(minute=0, second=0, microsecond=0)
    delta = window_start - anchor
    k = int(delta.total_seconds() // step.total_seconds())
    aligned = anchor + k * step
    while aligned + step <= window_start:
        aligned += step
    return aligned

def build_buckets(start: datetime, end: datetime, mode: str, n_hours: int = 6, anchor: Optional[datetime] = None) -> List[tuple]:
    buckets = []
    if start >= end:
        return buckets
    start = start.replace(minute=0, second=0, microsecond=0)
    if mode == "Hourly":
        step = timedelta(hours=1)
        cur = _align_start_to_anchor(start, step, anchor)
        while cur < end:
            buckets.append((cur, min(cur + step, end)))
            cur += step
    elif mode == "Every N hours":
        step = timedelta(hours=max(1, int(n_hours)))
        cur = _align_start_to_anchor(start, step, anchor)
        while cur < end:
            buckets.append((cur, min(cur + step, end)))
            cur += step
    elif mode == "Daily":
        cur = datetime(start.year, start.month, start.day)
        while cur < end:
            nxt = cur + timedelta(days=1)
            buckets.append((cur, min(nxt, end)))
            cur = nxt
    elif mode == "Weekly":
        cur = start - timedelta(days=start.weekday())
        cur = datetime(cur.year, cur.month, cur.day)
        while cur < end:
            nxt = cur + timedelta(days=7)
            buckets.append((cur, min(nxt, end)))
            cur = nxt
    elif mode == "Monthly":
        cur = datetime(start.year, start.month, 1)
        while cur < end:
            if cur.month == 12:
                nxt = datetime(cur.year+1, 1, 1)
            else:
                nxt = datetime(cur.year, cur.month+1, 1)
            buckets.append((cur, min(nxt, end)))
            cur = nxt
    return buckets

def compute_bucket_table(df_out_all: pd.DataFrame, date_range, mode: str, n_hours: int, anchor: Optional[datetime]):
    if df_out_all.empty:
        return pd.DataFrame(columns=["bucket_start","bucket_end","outage_count","downtime_hours"])

    for col in ["start_ts","end_ts"]:
        df_out_all[col] = _tz_naive_series(df_out_all[col])

    if isinstance(date_range, tuple) and len(date_range)==2 and all(date_range):
        window_start = datetime.combine(date_range[0], datetime.min.time())
        window_end = datetime.combine(date_range[1], datetime.min.time()) + timedelta(days=1)
    else:
        window_start = df_out_all["start_ts"].min().to_pydatetime()
        last_end = df_out_all["end_ts"].dropna().max()
        window_end = (last_end.to_pydatetime() if pd.notna(last_end) else datetime.now())

    buckets = build_buckets(window_start, window_end, mode, n_hours, anchor)

    outages = []
    now_naive = datetime.now()
    for _, r in df_out_all.iterrows():
        s = r["start_ts"]
        e = r["end_ts"] if pd.notna(r["end_ts"]) else now_naive
        if e <= window_start or s >= window_end:
            continue
        s_clip = max(s, window_start)
        e_clip = min(e, window_end)
        outages.append((s_clip, e_clip))

    rows = []
    for b_start, b_end in buckets:
        total_sec = 0
        for s,e in outages:
            total_sec += overlap_seconds(s, e, b_start, b_end)
        count_start = sum(1 for s,e in outages if (s >= b_start and s < b_end))
        rows.append({
            "bucket_start": b_start, "bucket_end": b_end,
            "outage_count": count_start,
            "downtime_hours": round(total_sec/3600.0, 3)
        })

    return pd.DataFrame(rows)

# --------- Email helpers ---------
def _format_dhms(seconds: int) -> str:
    if seconds is None:
        return "—"
    try:
        s = int(seconds)
    except Exception:
        return "—"
    m, s = divmod(s, 60); h, m = divmod(m, 60); d, h = divmod(h, 24)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)

def build_summary_html(df_metrics_window: pd.DataFrame, df_out_window: pd.DataFrame) -> str:
    if df_metrics_window.empty:
        avg_dl = avg_ul = uptime = 0.0
    else:
        avg_dl = round(df_metrics_window["download_mbps"].dropna().mean() or 0.0, 3)
        avg_ul = round(df_metrics_window["upload_mbps"].dropna().mean() or 0.0, 3)
        up, _ = compute_uptime(df_metrics_window)
        uptime = round(up, 2)

    if df_out_window.empty:
        outage_count = 0
        total_down_s = 0
        longest_s = 0
        last_restore = "—"
    else:
        outage_count = int(len(df_out_window))
        total_down_s = int(df_out_window["duration_seconds"].fillna(0).sum())
        longest_s = int(df_out_window["duration_seconds"].fillna(0).max())
        last_restore_dt = pd.to_datetime(df_out_window["end_ts"]).dropna().max()
        last_restore = str(last_restore_dt) if pd.notna(last_restore_dt) else "—"

    html = f"""
    <h3>Downtime Summary</h3>
    <ul>
      <li><b>Outage count:</b> {outage_count}</li>
      <li><b>Total downtime:</b> {_format_dhms(total_down_s)}</li>
      <li><b>Longest outage:</b> {_format_dhms(longest_s)}</li>
      <li><b>Last back online:</b> {last_restore}</li>
    </ul>
    <h3>Performance (last 24 hours)</h3>
    <ul>
      <li><b>Average Download:</b> {avg_dl} Mbps</li>
      <li><b>Average Upload:</b> {avg_ul} Mbps</li>
      <li><b>Uptime:</b> {uptime}%</li>
    </ul>
    <h3>Definitions</h3>
    <ul>
      <li><b>Outage:</b> A period where samples are classified as offline (download speed below threshold or ping missing) from the first offline sample until the next online sample.</li>
      <li><b>Restore time:</b> The timestamp of the first online sample after an outage; outage duration is measured from outage start to restore.</li>
      <li><b>Shading:</b> <span style="background-color:#ffcccc;">red</span> = downtime (outage start→restore), <span style="background-color:#ccffcc;">green</span> = uptime (restore→next outage).</li>
      <li><b>Duration markers:</b> Triangles on the chart show each outage’s duration in <b>hours</b>; the faint line is the running average duration.</li>
      <li><b>Bucket table:</b> Rows reflect outage counts and total downtime hours within each aligned time bucket.</li>
    </ul>
    """
    return html

def _smtp_cfg():
    try:
        smtp_cfg = dict(st.secrets.get("smtp", {}))
    except Exception:
        smtp_cfg = None
    if not smtp_cfg:
        smtp_cfg = {
            "host": "smtp.gmail.com",
            "port": 587,
            "username": os.environ.get("NETDASH_SMTP_USER", ""),
            "password": os.environ.get("NETDASH_SMTP_PASS", ""),
            "use_tls": True,
        }
    return smtp_cfg

def _send_email_with_attachments(subject: str, to_email: str, html_body: str, attachments: List[Tuple[str, bytes, str]]):
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders

    cfg = _smtp_cfg()
    host = cfg.get("host", "smtp.gmail.com")
    port = int(cfg.get("port", 587))
    user = cfg.get("username", "")
    pwd  = cfg.get("password", "")
    use_tls = bool(cfg.get("use_tls", True))
    if not (host and port and user and pwd):
        return False, "SMTP not configured"

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

    for fname, data, mime in attachments or []:
        maintype, subtype = mime.split("/", 1)
        part = MIMEBase(maintype, subtype)
        part.set_payload(data)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{fname}"')
        msg.attach(part)

    try:
        server = smtplib.SMTP(host, port, timeout=30)
        if use_tls:
            server.starttls()
        server.login(user, pwd)
        server.sendmail(user, [to_email], msg.as_string())
        server.quit()
        return True, "Email sent"
    except Exception as e:
        return False, f"Email send failed: {e}"

def email_bucket_chart_and_summary(to_email: str, bucket_df: pd.DataFrame, chart_png: bytes, title_suffix: str, df_metrics_24h: pd.DataFrame, df_out_window: pd.DataFrame):
    rows = ["<tr><th>Bucket start</th><th>Bucket end</th><th>Outages</th><th>Downtime (hours)</th></tr>"]
    if not bucket_df.empty:
        for _, r in bucket_df.iterrows():
            rows.append(f"<tr><td>{r['bucket_start']}</td><td>{r['bucket_end']}</td><td>{int(r['outage_count'])}</td><td>{r['downtime_hours']}</td></tr>")
    html_table = "<table border='1' cellspacing='0' cellpadding='4'>" + "".join(rows) + "</table>"
    summary_html = build_summary_html(df_metrics_24h, df_out_window)
    body = f"<p>The Following are the Internet Connection Management System</p>{summary_html}<h3>Bucket Table</h3>{html_table}"
    atts = []
    if chart_png:
        atts.append(("combined_chart.png", chart_png, "image/png"))
    return _send_email_with_attachments(f"Network Report {title_suffix}", to_email, body, atts)

# ---------------- UI ----------------
st.title("📶 Network Speed & Uptime Dashboard")

with st.sidebar:
    st.header("Controls")
    dl_threshold = st.number_input("Online threshold (Mbps)", min_value=0.0, value=0.10, step=0.05, help="Below this download speed, a sample is considered 'down'.")
    auto_every_min = st.number_input("Auto test every (minutes)", min_value=0, value=0, step=1, help="Set > 0 to auto-run speed tests.")
    date_range = st.date_input("Filter date range", value=(), help="Optional filter for charts and KPIs.")
    show_raw = st.checkbox("Show raw dataset (metrics)", value=False)

    # (Removed stray buggy line here)

    st.subheader("Bucket options")
    group_mode = st.selectbox("Group by (bucket table)", ["Hourly", "Every N hours", "Daily", "Weekly", "Monthly"], index=2)
    n_hours = st.number_input("N hours (if applicable)", min_value=1, max_value=168, value=6, step=1)
    use_anchor = st.checkbox("Use bucket anchor", value=False, help="Align time buckets to a specific start (e.g., 2025-09-19 20:00).")
    anchor_dt = None
    if use_anchor:
        a_date = st.date_input("Anchor date", value=date(2025, 9, 19))
        a_time = st.time_input("Anchor time", value=dtime(20,0))
        anchor_dt = datetime.combine(a_date, a_time)

    if st.button("Run test now", use_container_width=True):
        st.session_state["_run_now"] = True
    else:
        st.session_state.setdefault("_run_now", False)

    st.divider()
    st.subheader("📧 Email report")
    default_to = "donhautea@gmail.com"
    try:
        default_to = st.secrets.get("report_to", default_to)
    except Exception:
        pass
    report_to = st.text_input("Recipient email", value=str(default_to))
    if st.button("Send report now", use_container_width=True):
        # Use the SAME "current window" that powers the on-screen chart
        if isinstance(date_range, tuple) and len(date_range)==2 and all(date_range):
            sdt = datetime.combine(date_range[0], datetime.min.time())
            edt = datetime.combine(date_range[1], datetime.min.time()) + timedelta(days=1)
        else:
            sdt = None; edt = None
        df_metrics_window = fetch_metrics(sdt, edt)
        conn_tmp = _conn()
        if sdt and edt:
            df_out_window = pd.read_sql_query(
                "SELECT * FROM outages WHERE (start_ts < ?) AND (COALESCE(end_ts, ?) > ?) ORDER BY start_ts ASC",
                conn_tmp, params=(edt.isoformat(), edt.isoformat(), sdt.isoformat())
            )
        else:
            df_out_window = pd.read_sql_query("SELECT * FROM outages ORDER BY start_ts ASC", conn_tmp)
        # Chart PNG for this exact window
        chart_png = make_combined_chart_image(df_metrics_window if not df_metrics_window.empty else fetch_metrics(), df_out_window)
        # Bucket table for the same window
        dr = (sdt.date(), (edt - timedelta(days=1)).date()) if (sdt and edt) else ()
        bucket_df = compute_bucket_table(df_out_window, dr, group_mode, int(n_hours), anchor_dt)
        # 24h rolling KPIs
        end_auto = datetime.now()
        start_auto = end_auto - timedelta(days=1)
        df_24h = fetch_metrics(start_auto, end_auto)
        ok,msg = email_bucket_chart_and_summary(
            str(report_to), bucket_df, chart_png, title_suffix=f"(on-demand)",
            df_metrics_24h=df_24h, df_out_window=df_out_window
        )
        st.info(f"Email report: {msg}")

    st.caption("Auto-email every 3 hours: uses last 24h window with 3-hour buckets.")

    st.divider()
    st.caption("Database: {}".format(os.path.abspath(APP_DB_PATH)))
    if st.button("Export CSV", use_container_width=True):
        df_all = fetch_metrics()
        if df_all.empty:
            st.warning("No data to export yet.")
        else:
            csv = df_all.to_csv(index=False).encode("utf-8")
            st.download_button("Download metrics.csv", data=csv, file_name="network_metrics.csv", mime="text/csv", use_container_width=True)

    # -------- Manual Google Drive sync UI --------
    st.divider()
    st.subheader("Google Drive")
    if st.button("Sync DB to Drive", use_container_width=True):
        ok, msg = gdrive_sync_db()
        (st.success if ok else st.error)(f"Drive sync: {msg}")

    last_sync = kv_get("last_drive_sync", None)
    if last_sync:
        ts_sync = datetime.fromtimestamp(float(last_sync.get("ts", 0))).strftime("%Y-%m-%d %H:%M:%S")
        st.caption(f"Last Drive sync: {last_sync.get('status')} at {ts_sync} (md5 {last_sync.get('md5', '—')})")
    else:
        st.caption("No Drive sync recorded yet.")

# Auto refresh/run
if auto_every_min and auto_every_min > 0:
    interval_ms = int(auto_every_min * 60 * 1000); interval_s = int(auto_every_min * 60)
    try:
        from streamlit_autorefresh import st_autorefresh
        st_autorefresh(interval=interval_ms, key=f"auto_tick_{interval_ms}")
    except Exception:
        import streamlit.components.v1 as components
        components.html(
            f"""
            <script>
                setTimeout(function() {{ window.parent.location.reload(); }}, {interval_ms});
            </script>
            """,
            height=0
        )
    now = time.time(); last = st.session_state.get("_last_auto", 0)
    if (last == 0) or (now - last >= interval_s):
        st.session_state["_run_now"] = True; st.session_state["_last_auto"] = now
    nxt = datetime.now() + timedelta(seconds=max(0, interval_s - (now - last if last else 0)))
    st.caption(f"Auto mode on: every {auto_every_min} min. Next run around {nxt:%Y-%m-%d %H:%M:%S}.")
else:
    st.caption("Auto mode off.")

# Run test
if st.session_state.get("_run_now"):
    with st.spinner("Running speed test..."):
        ping_ms, dl, ul, server_name = run_speed_test()
        public_ip = get_public_ip(); local_ip = get_local_ip(); ssid = get_wifi_ssid()
        ts = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        is_online = classify_online(dl, ping_ms, dl_threshold)
        insert_metric({
            "ts": ts,
            "ping_ms": ping_ms if ping_ms is not None else None,
            "download_mbps": dl if dl is not None else None,
            "upload_mbps": ul if ul is not None else None,
            "public_ip": public_ip,
            "local_ip": local_ip,
            "ssid": ssid,
            "server_name": server_name,
            "is_online": is_online,
            "notes": None
        })
        conn=_conn(); row=conn.execute("SELECT id FROM metrics ORDER BY ts DESC LIMIT 1").fetchone(); trans=None
        if row: trans = analyze_outage_transition(int(row[0]))
        if trans=='end':
            conn2=_conn()
            row_latest_closed = conn2.execute("SELECT id, end_ts FROM outages WHERE end_ts IS NOT NULL ORDER BY end_ts DESC LIMIT 1").fetchone()
            latest_id = int(row_latest_closed[0]) if row_latest_closed else None; last_emailed_id = kv_get("last_emailed_restore_id", None)
            should_email = True
            if latest_id is not None and last_emailed_id is not None:
                try: should_email = int(latest_id)!=int(last_emailed_id)
                except Exception: should_email = True
            ok,msg=gdrive_sync_db(); st.info(f"Drive sync: {msg}")
            if should_email:
                df_last10 = pd.read_sql_query("""
                    SELECT o.start_ts AS ts, 'Offline' AS status,
                           m.download_mbps, m.upload_mbps, m.ping_ms, m.public_ip, m.local_ip,
                           NULL AS duration_seconds
                    FROM outages o
                    LEFT JOIN metrics m ON m.id = o.start_sample_id
                    WHERE o.start_ts IS NOT NULL

                    UNION ALL

                    SELECT o.end_ts AS ts, 'Online' AS status,
                           m2.download_mbps, m2.upload_mbps, m2.ping_ms, m2.public_ip, m2.local_ip,
                           o.duration_seconds AS duration_seconds
                    FROM outages o
                    LEFT JOIN metrics m2 ON m2.id = o.end_sample_id
                    WHERE o.end_ts IS NOT NULL

                    ORDER BY ts DESC
                    LIMIT 10
                """, conn2)
                # transitions email (unchanged)
                def _send_transitions_email():
                    import smtplib
                    from email.mime.multipart import MIMEMultipart
                    from email.mime.text import MIMEText
                    rows = ["<tr><th>Time</th><th>Status</th><th>Downtime</th><th>DL (Mbps)</th><th>UL (Mbps)</th><th>Ping (ms)</th><th>Public IP</th><th>Local IP</th></tr>"]
                    def _fmt_dur(s):
                        try: s=int(float(s))
                        except Exception: return ""
                        if s<=0: return ""
                        mins, sec = divmod(s,60); hrs, mins = divmod(mins,60); days, hrs = divmod(hrs,24)
                        parts=[]; 
                        if days: parts.append(f"{days}d")
                        if hrs: parts.append(f"{hrs}h")
                        if mins: parts.append(f"{mins}m")
                        parts.append(f"{sec}s")
                        return " ".join(parts)
                    dfT = df_last10.copy()
                    for c in ["ts","download_mbps","upload_mbps","ping_ms","public_ip","local_ip","duration_seconds"]:
                        if c not in dfT.columns: dfT[c]=""
                    if "status" not in dfT.columns:
                        if "is_online" in dfT.columns: dfT["status"]=dfT["is_online"].map({1:"Online",0:"Offline"})
                        else: dfT["status"]=""
                    try: dfT["ts"]=pd.to_datetime(dfT["ts"]).dt.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception: dfT["ts"]=dfT["ts"].astype(str)
                    dfT["downtime"]=dfT.apply(lambda r: _fmt_dur(r["duration_seconds"]) if str(r.get("status",""))=="Online" else "", axis=1)
                    for _, r in dfT.sort_values("ts", ascending=False).head(10).iterrows():
                        rows.append(f"<tr><td>{r['ts']}</td><td>{r['status']}</td><td>{r['downtime']}</td><td>{r['download_mbps'] or ''}</td><td>{r['upload_mbps'] or ''}</td><td>{r['ping_ms'] or ''}</td><td>{r['public_ip'] or ''}</td><td>{r['local_ip'] or ''}</td></tr>")
                    html_table = "<table border='1' cellspacing='0' cellpadding='4'>" + "".join(rows) + "</table>"
                    subject = "Network Online/Offline Transitions (last 10)"
                    cfg = _smtp_cfg()
                    if not(cfg.get("username") and cfg.get("password")):
                        return False, "SMTP not configured"
                    msg = MIMEMultipart(); msg["Subject"]=subject; msg["From"]=cfg["username"]; 
                    try:
                        to_addr = st.secrets.get("report_to","donhautea@gmail.com")
                    except Exception:
                        to_addr = "donhautea@gmail.com"
                    msg["To"]=to_addr; msg.attach(MIMEText(f"<p>Recent transitions:</p>{html_table}", "html"))
                    try:
                        server = smtplib.SMTP(cfg["host"], int(cfg["port"]), timeout=30)
                        if cfg.get("use_tls", True): server.starttls()
                        server.login(cfg["username"], cfg["password"]); server.sendmail(cfg["username"], [to_addr], msg.as_string()); server.quit()
                        return True, "Transitions email sent"
                    except Exception as e:
                        return False, f"Email failed: {e}"
                okT,msgT = _send_transitions_email()
                st.info(msgT)
                if latest_id is not None and okT: kv_set("last_emailed_restore_id", int(latest_id))
            import streamlit.components.v1 as components
            components.html(
                """
                <script>
                  try {
                    const ctx = new (window.AudioContext || window.webkitAudioContext)();
                    function beep(f, d){const o=ctx.createOscillator();const g=ctx.createGain();o.connect(g);g.connect(ctx.destination);o.type='sine';o.frequency.value=f;g.gain.value=0.12;o.start();o.stop(ctx.currentTime + d/1000);}
                    beep(880,160); setTimeout(()=>beep(1046,160),200);
                  } catch(e) {}
                </script>
                """,
                height=0
            )
        if trans=='start':
            import streamlit.components.v1 as components
            components.html(
                """
                <script>
                  try {
                    const ctx = new (window.AudioContext || window.webkitAudioContext)();
                    function beep(f, d){const o=ctx.createOscillator();const g=ctx.createGain();o.connect(g);g.connect(ctx.destination);o.type='sine';o.frequency.value=f;g.gain.value=0.12;o.start();o.stop(ctx.currentTime + d/1000);}
                    beep(523,500); setTimeout(()=>beep(392,500),520); setTimeout(()=>beep(330,700),1040);
                  } catch(e) {}
                </script>
                """,
                height=0
            )
    if dl is None or ul is None:
        st.error(f"Speed test failed: {server_name}")
    else:
        st.success(f"Speed test OK via {server_name} — DL {dl} Mbps / UL {ul} Mbps, ping {ping_ms} ms")
    st.session_state["_run_now"] = False

# Data
start_dt = None; end_dt = None
if isinstance(date_range, tuple) and len(date_range)==2 and all(date_range):
    start_dt = datetime.combine(date_range[0], datetime.min.time()).astimezone()
    end_dt = (datetime.combine(date_range[1], datetime.min.time()) + timedelta(days=1)).astimezone()

df = fetch_metrics(start_dt, end_dt)

# Prepare current outages window matching the chart window
conn_win = _conn()
if start_dt and end_dt:
    df_out_current = pd.read_sql_query(
        "SELECT * FROM outages WHERE (start_ts < ?) AND (COALESCE(end_ts, ?) > ?) ORDER BY start_ts ASC",
        conn_win, params=(end_dt.isoformat(), end_dt.isoformat(), start_dt.isoformat())
    )
else:
    df_out_current = pd.read_sql_query("SELECT * FROM outages ORDER BY start_ts ASC", conn_win)

# KPIs
c1,c2,c3,c4 = st.columns(4)
if df.empty:
    c1.metric("Samples",0); c2.metric("Avg Download (Mbps)",0.0); c3.metric("Avg Upload (Mbps)",0.0); c4.metric("Uptime (%)",0.0)
else:
    avg_dl = df["download_mbps"].dropna().mean() if "download_mbps" in df else 0.0
    avg_ul = df["upload_mbps"].dropna().mean() if "upload_mbps" in df else 0.0
    uptime, downtime = compute_uptime(df)
    c1.metric("Samples",len(df)); c2.metric("Avg Download (Mbps)",round(avg_dl,3)); c3.metric("Avg Upload (Mbps)",round(avg_ul,3)); c4.metric("Uptime (%)",round(uptime,2))

st.divider()

# Downtime summary
st.subheader("Downtime summary")
if isinstance(date_range, tuple) and len(date_range)==2 and all(date_range):
    q="SELECT * FROM outages WHERE start_ts >= ? AND start_ts < ? ORDER BY start_ts DESC"
    df_out = pd.read_sql_query(q, conn_win, params=(start_dt.isoformat() if start_dt else "", end_dt.isoformat() if end_dt else ""))
else:
    df_out = pd.read_sql_query("SELECT * FROM outages ORDER BY start_ts DESC", conn_win)

if df_out.empty:
    st.info("No downtime events recorded yet.")
else:
    for col in ["start_ts","end_ts","last_online_before","first_online_after"]:
        if col in df_out.columns: df_out[col] = pd.to_datetime(df_out[col], errors="coerce")
    def _fmt_dur(s):
        if pd.isna(s) or s is None: return ""
        try: s=int(s)
        except Exception: return ""
        m,s=divmod(s,60); h,m=divmod(m,60); d,h=divmod(h,24)
        parts=[]
        if d: parts.append(f"{d}d")
        if h: parts.append(f"{h}h")
        if m: parts.append(f"{m}m")
        parts.append(f"{s}s")
        return " ".join(parts)
    df_out["duration"] = df_out["duration_seconds"].apply(_fmt_dur)
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Outage count", len(df_out))
    total_down = int(df_out["duration_seconds"].fillna(0).sum()); c2.metric("Total downtime", _fmt_dur(total_down))
    max_down = int(df_out["duration_seconds"].fillna(0).max()) if (df_out["duration_seconds"].notna().any()) else 0; c3.metric("Longest outage", _fmt_dur(max_down))
    recent_restore = df_out[df_out["end_ts"].notna()]["end_ts"].max(); c4.metric("Last back online", str(recent_restore) if pd.notna(recent_restore) else "—")
    st.dataframe(df_out[
        ["start_ts","end_ts","duration","last_online_before","first_online_after","start_sample_id","end_sample_id"]
    ].rename(columns={
        "start_ts":"Down since","end_ts":"Restored at","duration":"Downtime","last_online_before":"Last Online Before","first_online_after":"First Online After"
    }), use_container_width=True)
    csv_out = df_out.to_csv(index=False).encode("utf-8"); st.download_button("Download outages.csv", data=csv_out, file_name="outages.csv", mime="text/csv")

st.divider()

# Combined visualization (Altair) + EXACT PNG preview (same inputs)
if df.empty:
    st.info("No data yet. Click **Run test now** to record the first sample.")
else:
    st.subheader("Speed + Shaded uptime/downtime + Restore durations")
    if alt is not None:
        bands, restores_df = compute_bands_and_restores(df, df_out_current)
        bands_df = pd.DataFrame(bands)
        if not bands_df.empty:
            bands_df["y"] = 0; bands_df["y2"] = 1
            bands_df["color"] = bands_df["state"].map({"down":"red","up":"green"})
        sp = df[["ts","download_mbps","upload_mbps"]].copy(); sp_long = sp.melt("ts", var_name="metric", value_name="mbps")
        speed_lines = alt.Chart(sp_long).mark_line().encode(
            x=alt.X("ts:T", title="Time"),
            y=alt.Y("mbps:Q", title="Speed (Mbps)"),
            color=alt.Color("metric:N", title="Metric"),
            tooltip=[
                alt.Tooltip("ts:T", title="Time"),
                alt.Tooltip("metric:N", title="Metric"),
                alt.Tooltip("mbps:Q", title="Mbps", format=".2f")
            ]
        )
        layers = []
        if not bands_df.empty:
            layers.append(alt.Chart(bands_df).mark_rect(opacity=0.12).encode(
                x="start:T", x2="end:T",
                y=alt.Y("y:Q", scale=alt.Scale(domain=[0,1]), axis=None),
                y2="y2:Q",
                color=alt.Color("color:N", scale=None, legend=None)
            ))
        if not df_out_current.empty:
            starts_df = pd.DataFrame({"ts": pd.to_datetime(df_out_current["start_ts"].dropna())})
            layers.append(alt.Chart(starts_df).mark_rule(strokeDash=[6,3], opacity=0.6, color="red").encode(
                x="ts:T", tooltip=[alt.Tooltip("ts:T", title="Outage start")]
            ))
            rdf = df_out_current[["end_ts","duration_seconds"]].copy()
            rdf = rdf[rdf["end_ts"].notna()]
            if not rdf.empty:
                rdf["ts"] = pd.to_datetime(rdf["end_ts"])
                rdf["duration_hr"] = rdf["duration_seconds"].astype(float)/3600.0
                rdf = rdf.sort_values("ts")
                rdf["avg_duration_hr"] = rdf["duration_hr"].expanding().mean()
                layers.append(alt.Chart(rdf).mark_rule(strokeDash=[4,4], opacity=0.6, color="green").encode(
                    x="ts:T", tooltip=[
                        alt.Tooltip("ts:T", title="Restore time"),
                        alt.Tooltip("duration_hr:Q", title="Outage (hr)", format=".2f")
                    ]
                ))
                layers.append(alt.Chart(rdf).mark_point(shape="triangle-up", size=70, filled=True, color="green").encode(
                    x="ts:T", y=alt.Y("duration_hr:Q", title="Outage duration (hr)"),
                    tooltip=[
                        alt.Tooltip("ts:T", title="Restore time"),
                        alt.Tooltip("duration_hr:Q", title="Outage (hr)", format=".2f")
                    ]
                ))
                layers.append(alt.Chart(rdf).mark_line(opacity=0.6).encode(
                    x="ts:T", y=alt.Y("avg_duration_hr:Q", title="Avg outage (hr)"),
                    tooltip=[
                        alt.Tooltip("ts:T", title="Restore time"),
                        alt.Tooltip("avg_duration_hr:Q", title="Avg outage (hr)", format=".2f")
                    ]
                ))
        layers.append(speed_lines)
        combined = alt.layer(*layers).resolve_scale(y='independent').properties(height=360)
        st.altair_chart(combined, use_container_width=True)

    chart_png_current = make_combined_chart_image(df, df_out_current)
    if chart_png_current:
        st.image(chart_png_current, caption="Email/Export image (exact attachment for this window)", use_column_width=True)
        st.session_state["chart_png_current"] = chart_png_current

st.divider()

# -------- Analytics & Statistics — Bucket table
st.subheader("Analytics & Statistics — Bucket table")
connA = _conn()
bucket_df_cur = compute_bucket_table(
    df_out_current,
    (start_dt.date(), (end_dt - timedelta(days=1)).date()) if (start_dt and end_dt) else (),
    group_mode, int(n_hours),
    anchor_dt if 'anchor_dt' in locals() else None
)
if bucket_df_cur.empty:
    st.info("No outage analytics yet (no outages recorded).")
else:
    st.dataframe(bucket_df_cur[["bucket_start","bucket_end","outage_count","downtime_hours"]], use_container_width=True)
    csvb = bucket_df_cur.to_csv(index=False).encode("utf-8")
    st.download_button("Download analytics.csv", data=csvb, file_name="analytics_bucketed.csv", mime="text/csv")

# Optionally show raw dataset
if show_raw:
    st.subheader("Raw metrics dataset")
    df_all = fetch_metrics()
    st.dataframe(df_all, use_container_width=True)

# -------- Auto-email every 3 hours (last 24h window, buckets=3h) --------
try:
    last_auto = kv_get("last_auto_report_email_ts", None)
    now_ts = time.time()
    should_auto = (last_auto is None) or (float(now_ts) - float(last_auto) >= 3*3600)
    if should_auto:
        end_auto = datetime.now()
        start_auto = end_auto - timedelta(days=1)
        df_out_auto = pd.read_sql_query(
            "SELECT * FROM outages WHERE (start_ts < ?) AND (COALESCE(end_ts, ?) > ?) ORDER BY start_ts ASC",
            _conn(), params=(end_auto.isoformat(), end_auto.isoformat(), start_auto.isoformat())
        )
        bucket_df_auto = compute_bucket_table(df_out_auto, (start_auto.date(), end_auto.date()), "Every N hours", 3, anchor=None)
        df_metrics_auto = fetch_metrics(start_auto, end_auto)
        img = make_combined_chart_image(df_metrics_auto, df_out_auto)
        try:
            to_auto = st.secrets.get("report_to", "donhautea@gmail.com")
        except Exception:
            to_auto = "donhautea@gmail.com"
        okA, msgA = email_bucket_chart_and_summary(
            to_auto, bucket_df_auto, img, title_suffix="(auto 3h)",
            df_metrics_24h=df_metrics_auto, df_out_window=df_out_auto
        )
        if okA:
            kv_set("last_auto_report_email_ts", float(now_ts))
        st.caption(f"Auto email status: {msgA}")
except Exception as e:
    st.caption(f"Auto email skipped: {e}")

# -------- Auto Drive sync every 30 minutes --------
try:
    last_drive = kv_get("last_drive_sync_ts", 0.0) or 0.0
    now_s = time.time()
    if (now_s - float(last_drive)) >= 30*60:  # 30 minutes
        ok, msg = gdrive_sync_db()
        if ok:
            kv_set("last_drive_sync_ts", now_s)
        st.caption(f"Auto Drive sync: {msg}")
except Exception as e:
    st.caption(f"Auto Drive sync skipped: {e}")

st.caption("Shading: **red** = downtime (outage start→restore), **green** = uptime (restore→next outage). Triangles show outage duration at each restore in hours; faint line = running average (hours).")
