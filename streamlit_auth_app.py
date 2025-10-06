# streamlit_auth_app.py
# A compact Streamlit auth system mirroring the user's framework:
# - Separate users.db storing users, units, and reset tokens
# - Login, Register, Reset Password (email token)
# - Roles: admin, super, user, viewer
# - Admin Panel: activate users, change roles, manage units, and EDIT USER EMAIL
# - PBKDF2 password hashing; audit logging
#
# Secrets required (Streamlit Cloud -> Secrets):
# [smtp]
# host = "smtp.gmail.com"
# port = 587
# username = "you@example.com"
# password = "app-password"
# use_tls = true
# sender = "you@example.com"

import os
import io
import sqlite3
import hashlib
import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime, date, timedelta
from typing import Optional, List, Tuple

import pandas as pd
import streamlit as st

# ----------------------------- App Config -----------------------------
st.set_page_config(page_title="Auth System (FMG Framework)", layout="wide")

USERS_DB_PATH = os.environ.get("USERS_DB_PATH", "users.db")

# ----------------------------- DB Helpers -----------------------------
def get_user_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(USERS_DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def today_ts() -> str:
    return datetime.now().isoformat()

def hash_password(password: str, salt_hex: Optional[str]=None) -> Tuple[str,str]:
    if not salt_hex:
        salt = os.urandom(16); salt_hex = salt.hex()
    else:
        salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt_hex, dk.hex()

def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    _, calc = hash_password(password, salt_hex)
    return calc == hash_hex

def init_user_db():
    conn = get_user_conn(); c = conn.cursor()
    # Users
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password_hash TEXT,
            password_salt TEXT,
            role TEXT DEFAULT 'viewer',
            is_active INTEGER DEFAULT 0,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    # Units
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS units (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            is_active INTEGER DEFAULT 1
        )
        """
    )
    # User-Units
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS user_units (
            user_id INTEGER,
            unit_id INTEGER,
            PRIMARY KEY (user_id, unit_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (unit_id) REFERENCES units(id) ON DELETE CASCADE
        )
        """
    )
    # Password reset tokens
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    # Audit
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT
        )
        """
    )
    conn.commit()
    # Seed default admin if missing
    c.execute("SELECT id FROM users WHERE username='admin' OR email='admin@example.com'")
    row = c.fetchone()
    if not row:
        salt, pw = hash_password("admin")
        now = today_ts()
        c.execute(
            "INSERT INTO users (username,email,password_hash,password_salt,role,is_active,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
            ("admin","admin@example.com",pw,salt,"admin",1,now,now)
        )
        conn.commit()
    conn.close()

def log_action(action: str, user_id: Optional[int]=None, details: str=""):
    try:
        conn = get_user_conn(); c = conn.cursor()
        c.execute(
            "INSERT INTO audit_log (ts,user_id,action,details) VALUES (?,?,?,?)",
            (today_ts(), user_id, action, details)
        )
        conn.commit(); conn.close()
    except Exception:
        pass

# ----------------------------- Units Helpers -----------------------------
def ensure_units_exist(units: List[str], conn: Optional[sqlite3.Connection] = None) -> List[int]:
    ids: List[int] = []
    if not units:
        return ids
    close_conn = False
    if conn is None:
        conn = get_user_conn(); close_conn = True
    c = conn.cursor()
    for unit in units:
        name = unit.strip()
        if not name:
            continue
        c.execute("SELECT id FROM units WHERE LOWER(name)=LOWER(?)", (name,))
        row = c.fetchone()
        if row:
            unit_id = row[0]
        else:
            c.execute("INSERT INTO units (name,is_active) VALUES (?,1)", (name,))
            unit_id = c.lastrowid
        ids.append(unit_id)
    conn.commit()
    if close_conn: conn.close()
    return ids

def get_active_unit_names() -> List[str]:
    conn = get_user_conn(); c = conn.cursor()
    c.execute("SELECT name FROM units WHERE is_active=1 ORDER BY name ASC")
    rows = c.fetchall(); conn.close()
    return [r[0] for r in rows]

# ----------------------------- User CRUD -----------------------------
def get_user_by_key(user_key: str):
    conn = get_user_conn(); c = conn.cursor()
    c.execute(
        "SELECT id, username, email, password_hash, password_salt, role, is_active FROM users WHERE username=? OR email=?",
        (user_key, user_key)
    )
    row = c.fetchone()
    if not row:
        conn.close(); return None
    keys = ["id","username","email","password_hash","password_salt","role","is_active"]
    user = dict(zip(keys, row))
    # Units
    c.execute(
        """
        SELECT u.name
        FROM units AS u
        INNER JOIN user_units AS uu ON u.id = uu.user_id
        WHERE uu.user_id=? AND u.is_active=1
        """,
        (user["id"],)
    )
    unit_rows = c.fetchall()
    conn.close()
    user["units"] = [u[0] for u in unit_rows]
    return user

def create_user(username: str, email: str, password: str, units: Optional[List[str]]=None, role: str="user", is_active: int=0) -> Tuple[bool,str]:
    if not username or not email or not password:
        return False, "Missing fields"
    conn = get_user_conn(); c = conn.cursor()
    try:
        salt, pw = hash_password(password)
        now = today_ts()
        c.execute(
            "INSERT INTO users (username,email,password_hash,password_salt,role,is_active,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (username.strip(), email.strip(), pw, salt, role, is_active, now, now)
        )
        user_id = c.lastrowid
        unit_ids = ensure_units_exist(units or [], conn)
        for uid in unit_ids:
            c.execute("INSERT OR IGNORE INTO user_units (user_id, unit_id) VALUES (?,?)", (user_id, uid))
        conn.commit()
        log_action("register", user_id, f"username={username.strip()}")
        ok, msg = True, "Registered"
    except sqlite3.IntegrityError as e:
        ok, msg = False, "Username or email already exists"
    finally:
        conn.close()
    return ok, msg

# ----------------------------- Reset Password -----------------------------
def purge_expired_reset_tokens(conn: Optional[sqlite3.Connection]=None) -> None:
    close_conn = False
    if conn is None:
        conn = get_user_conn(); close_conn = True
    c = conn.cursor()
    c.execute("DELETE FROM password_reset_tokens WHERE expires_at < ?", (datetime.utcnow().isoformat(),))
    conn.commit()
    if close_conn: conn.close()

def generate_reset_token(length: int = 6) -> str:
    return ''.join(secrets.choice('0123456789') for _ in range(length))

def send_reset_email(to_email: str, token: str) -> Tuple[bool,str]:
    try:
        smtp_conf = st.secrets.get("smtp")
    except Exception:
        return False, "SMTP configuration missing in secrets."
    if not smtp_conf:
        return False, "SMTP configuration missing in secrets."
    try:
        host = smtp_conf.get("host")
        port = smtp_conf.get("port")
        username = smtp_conf.get("username")
        password = smtp_conf.get("password")
        use_tls = smtp_conf.get("use_tls", True)
        sender = smtp_conf.get("sender", username)
        if not (host and port and username and password):
            return False, "Incomplete SMTP configuration."
        msg = EmailMessage()
        msg["Subject"] = "Password Reset Token"
        msg["From"] = sender
        msg["To"] = to_email
        msg.set_content(f"Your password reset token is: {token}\n\nIf you did not request this, you may ignore this email.")
        with smtplib.SMTP(host, port) as server:
            if use_tls: server.starttls()
            server.login(username, password)
            server.send_message(msg)
        return True, "Reset token sent to your email."
    except Exception as e:
        return False, f"Failed to send email: {e}"

def create_password_reset_token(email: str) -> Tuple[bool,str]:
    if not email: return False, "Email is required."
    conn = get_user_conn(); c = conn.cursor()
    c.execute("SELECT id FROM users WHERE LOWER(email)=LOWER(?)", (email.strip(),))
    row = c.fetchone()
    if not row:
        conn.close(); return False, "No account with that email."
    user_id = row[0]
    purge_expired_reset_tokens(conn)
    token = generate_reset_token()
    expires_at = (datetime.utcnow() + timedelta(minutes=30)).isoformat()
    created_at = datetime.utcnow().isoformat()
    c.execute(
        "INSERT INTO password_reset_tokens (user_id, token, expires_at, created_at) VALUES (?,?,?,?)",
        (user_id, token, expires_at, created_at)
    )
    conn.commit(); conn.close()
    sent, msg = send_reset_email(email.strip(), token)
    return (True, msg) if sent else (False, msg)

def validate_password_reset_token(email: str, token: str) -> Optional[int]:
    if not (email and token): return None
    conn = get_user_conn(); c = conn.cursor()
    purge_expired_reset_tokens(conn)
    c.execute(
        """
        SELECT pr.user_id
        FROM password_reset_tokens pr
        JOIN users u ON pr.user_id = u.id
        WHERE LOWER(u.email)=LOWER(?) AND pr.token = ? AND pr.expires_at > ?
        ORDER BY pr.created_at DESC
        LIMIT 1
        """,
        (email.strip(), token.strip(), datetime.utcnow().isoformat())
    )
    row = c.fetchone(); conn.close()
    return row[0] if row else None

def update_user_password(user_id: int, new_password: str) -> Tuple[bool,str]:
    if not new_password: return False, "Password must not be empty."
    try:
        salt, pw_hash = hash_password(new_password)
        now = today_ts()
        conn = get_user_conn(); c = conn.cursor()
        c.execute("UPDATE users SET password_hash=?, password_salt=?, updated_at=? WHERE id=?", (pw_hash, salt, now, user_id))
        c.execute("DELETE FROM password_reset_tokens WHERE user_id=?", (user_id,))
        conn.commit(); conn.close()
        log_action("password_update", user_id, "password changed")
        return True, "Password updated successfully."
    except Exception as e:
        return False, f"Failed to update password: {e}"

# ----------------------------- INIT & Session -----------------------------
init_user_db()
if "user" not in st.session_state: st.session_state["user"] = None
if "reset_stage" not in st.session_state:
    st.session_state["reset_stage"] = "email"
    st.session_state["reset_email"] = ""
    st.session_state["reset_user_id"] = None

# ----------------------------- Sidebar / Navigation -----------------------------
st.sidebar.title("Auth System")
if st.session_state["user"]:
    u = st.session_state["user"]
    st.sidebar.success(f"Signed in as {u['username']} ({u['role']})")
    if st.sidebar.button("Logout"):
        log_action("logout", u.get("id"))
        st.session_state["user"] = None
        st.rerun()
else:
    st.sidebar.info("Please sign in.")

if st.session_state["user"] is None:
    page = st.sidebar.radio("Navigate", ["Auth"], index=0)
else:
    role = st.session_state["user"].get("role", "viewer")
    pages: List[str] = ["Dashboard"]
    if role in ("user","super","admin"):
        pages.append("My Profile")
    if role in ("super","admin"):
        pages.append("Admin")
    page = st.sidebar.radio("Navigate", pages, index=0)

# ----------------------------- Page: Auth -----------------------------
if page == "Auth":
    st.title("Sign in")
    tab_login, tab_register, tab_reset = st.tabs(["Login","Register","Reset Password"])
    with tab_login:
        with st.form("login_form"):
            user_key = st.text_input("Email or Username")
            pw = st.text_input("Password", type="password")
            ok = st.form_submit_button("Login", type="primary")
        if ok:
            conn = get_user_conn(); c = conn.cursor()
            c.execute(
                "SELECT id, username, email, password_hash, password_salt, role, is_active FROM users WHERE username=? OR email=?",
                (user_key, user_key)
            )
            row = c.fetchone(); conn.close()
            if not row:
                st.error("Invalid credentials.")
            else:
                uid, uname, email, pwh, pws, role, is_active = row
                if not is_active:
                    st.error("Your account is pending admin approval.")
                elif verify_password(pw, pws, pwh):
                    st.session_state["user"] = {"id": uid, "username": uname, "email": email, "role": role}
                    log_action("login", uid)
                    st.success("Logged in.")
                    st.rerun()
                else:
                    st.error("Invalid credentials.")
    with tab_register:
        with st.form("register_form"):
            r_user = st.text_input("Username")
            r_email = st.text_input("Email")
            r_pw1 = st.text_input("Password", type="password")
            r_pw2 = st.text_input("Confirm Password", type="password")
            r_units_raw = st.text_input("Division(s)/Unit(s) (comma-separated)")
            r_ok = st.form_submit_button("Create Account")
        if r_ok:
            if not r_user or not r_email or not r_pw1:
                st.error("All fields are required.")
            elif r_pw1 != r_pw2:
                st.error("Passwords do not match.")
            else:
                units_list = [u.strip() for u in r_units_raw.split(",") if u.strip()] if r_units_raw else []
                ok, msg = create_user(r_user.strip(), r_email.strip(), r_pw1, units=units_list, role="user", is_active=0)
                if ok:
                    st.success("Registration submitted. An admin must approve your account.")
                else:
                    st.error(msg)
    with tab_reset:
        stage = st.session_state["reset_stage"]
        if stage == "email":
            st.subheader("Request Password Reset")
            with st.form("reset_email_form"):
                email_input = st.text_input("Enter your registered email")
                send_tok = st.form_submit_button("Send Reset Token", type="primary")
            if send_tok:
                if not email_input:
                    st.error("Please enter your email.")
                else:
                    ok, msg = create_password_reset_token(email_input.strip())
                    if ok:
                        st.session_state["reset_email"] = email_input.strip()
                        st.session_state["reset_stage"] = "token"
                        st.success(msg); st.rerun()
                    else:
                        st.error(msg)
        elif stage == "token":
            st.subheader("Verify Reset Token")
            with st.form("reset_token_form"):
                token_input = st.text_input("Enter the reset token sent to your email")
                verify_tok = st.form_submit_button("Verify Token", type="primary")
            if verify_tok:
                if not token_input:
                    st.error("Please enter the token.")
                else:
                    user_id = validate_password_reset_token(st.session_state.get("reset_email",""), token_input.strip())
                    if user_id:
                        st.session_state["reset_user_id"] = user_id
                        st.session_state["reset_stage"] = "password"
                        st.success("Token verified. Please enter a new password.")
                        st.rerun()
                    else:
                        st.error("Invalid or expired token.")
        elif stage == "password":
            st.subheader("Set New Password")
            with st.form("reset_password_form"):
                new_pw = st.text_input("New Password", type="password")
                new_pw2 = st.text_input("Confirm New Password", type="password")
                change_pw = st.form_submit_button("Change Password", type="primary")
            if change_pw:
                if not new_pw:
                    st.error("Password is required.")
                elif new_pw != new_pw2:
                    st.error("Passwords do not match.")
                else:
                    user_id = st.session_state.get("reset_user_id")
                    if not user_id:
                        st.error("Unexpected error: user not found. Please restart the reset process.")
                    else:
                        ok, msg = update_user_password(user_id, new_pw)
                        if ok:
                            st.success(msg + " You can now log in with your new password.")
                            st.session_state["reset_stage"] = "email"
                            st.session_state["reset_email"] = ""
                            st.session_state["reset_user_id"] = None
                            st.rerun()
                        else:
                            st.error(msg)

# ----------------------------- Page: Dashboard -----------------------------
elif page == "Dashboard":
    st.title("Welcome")
    u = st.session_state.get("user")
    if u:
        st.write(f"You are signed in as **{u['username']}** (`{u['role']}`), email **{u['email']}**.")
    else:
        st.info("Please sign in.")

# ----------------------------- Page: My Profile -----------------------------
elif page == "My Profile":
    st.title("My Profile")
    u = st.session_state.get("user") or {}
    st.write(f"**Username:** {u.get('username','')}")
    st.write(f"**Email:** {u.get('email','')}")
    st.write(f"**Role:** {u.get('role','viewer')}")
    st.divider()
    st.subheader("Change Password")
    with st.form("self_pw_change"):
        pw1 = st.text_input("New Password", type="password")
        pw2 = st.text_input("Confirm New Password", type="password")
        sub = st.form_submit_button("Update Password", type="primary")
    if sub:
        if not pw1 or pw1 != pw2:
            st.error("Passwords must match and not be empty.")
        else:
            ok, msg = update_user_password(u.get("id"), pw1)
            st.success(msg) if ok else st.error(msg)

# ----------------------------- Page: Admin -----------------------------
elif page == "Admin":
    st.title("Admin Panel")
    u = st.session_state.get("user") or {}
    if u.get("role") not in ("admin","super"):
        st.warning("Only Admin and Super users can access Admin.")
    else:
        tab_users, tab_units, tab_audit = st.tabs(["Users","Units","Audit"])

        # ---- Users tab (with EMAIL EDIT) ----
        with tab_users:
            st.subheader("Manage Users")
            conn = get_user_conn()
            dfu = pd.read_sql(
                """
                SELECT u.id, u.username, u.email, u.role, u.is_active, u.created_at,
                       GROUP_CONCAT(units.name, ', ') AS units
                FROM users AS u
                LEFT JOIN user_units AS uu ON u.id = uu.user_id
                LEFT JOIN units ON units.id = uu.unit_id AND units.is_active=1
                GROUP BY u.id
                ORDER BY u.created_at DESC
                """,
                conn
            )
            conn.close()
            st.dataframe(dfu, use_container_width=True, height=320)
            if not dfu.empty:
                sel_map = {f"{r.username} ({r.email})": int(r.id) for r in dfu.itertuples(index=False)}
                sel_label = st.selectbox("Select user", options=list(sel_map.keys()))
                sel_id = sel_map[sel_label]
                row = dfu[dfu.id == sel_id].iloc[0]

                col1, col2, col3 = st.columns([1,1,2])
                with col1:
                    role_options = ["admin","super","user","viewer"]
                    try:
                        role_index = role_options.index(row["role"])
                    except ValueError:
                        role_index = role_options.index("viewer")
                    role_new = st.selectbox("Role", role_options, index=role_index)
                with col2:
                    active_new = st.checkbox("Active", value=bool(row["is_active"]))
                with col3:
                    # --- EMAIL EDIT FIELD (admin can edit) ---
                    email_new = st.text_input("Email (editable)", value=row["email"])

                # Units management
                conn = get_user_conn(); c = conn.cursor()
                c.execute("SELECT name FROM units WHERE is_active=1 ORDER BY name ASC")
                all_units = [r[0] for r in c.fetchall()]
                conn.close()
                current_units = [u.strip() for u in (row["units"] or "").split(",") if u.strip()]
                units_selected = st.multiselect("Divisions/Units", options=all_units, default=current_units, help="Select unit memberships")
                new_units_raw = st.text_input("Add new divisions/units (comma-separated)")

                if st.button("Apply Changes", type="primary"):
                    conn = get_user_conn(); c = conn.cursor()
                    # 1) EMAIL UPDATE w/ uniqueness handling
                    # Ensure the new email isn't used by another account
                    c.execute("SELECT id FROM users WHERE LOWER(email)=LOWER(?) AND id<>?", (email_new.strip(), sel_id))
                    dup = c.fetchone()
                    if dup:
                        st.error("Email already in use by another account.")
                        conn.close()
                    else:
                        c.execute("UPDATE users SET role=?, is_active=?, email=?, updated_at=? WHERE id=?",
                                  (role_new, 1 if active_new else 0, email_new.strip(), today_ts(), sel_id))
                        # 2) Units
                        new_units_list = [u.strip() for u in new_units_raw.split(",") if u.strip()]
                        unit_ids = ensure_units_exist(units_selected + new_units_list, conn)
                        c.execute("DELETE FROM user_units WHERE user_id=?", (sel_id,))
                        for uid_val in unit_ids:
                            c.execute("INSERT OR IGNORE INTO user_units (user_id, unit_id) VALUES (?,?)", (sel_id, uid_val))
                        conn.commit(); conn.close()
                        log_action("user_update", sel_id, f"role={role_new}, active={active_new}, email={email_new.strip()}")
                        st.success("User updated."); st.rerun()

        # ---- Units tab ----
        with tab_units:
            st.subheader("Manage Units")
            c1, c2 = st.columns([2,1])
            with c1:
                # Add unit
                with st.form("add_unit_form"):
                    nm = st.text_input("New Unit Name")
                    ok = st.form_submit_button("Add Unit")
                if ok and nm and nm.strip():
                    conn = get_user_conn(); c = conn.cursor()
                    try:
                        c.execute("INSERT INTO units (name,is_active) VALUES (?,1)", (nm.strip(),))
                        conn.commit(); st.success("Unit added.")
                    except sqlite3.IntegrityError:
                        st.warning("Unit already exists.")
                    finally:
                        conn.close()
            with c2:
                st.info("Units are used to tag access / visibility in broader apps.")
            # List units
            conn = get_user_conn()
            dfl = pd.read_sql("SELECT id, name, is_active FROM units ORDER BY name ASC", conn)
            conn.close()
            if dfl.empty:
                st.info("No units.")
            else:
                for r in dfl.itertuples(index=False):
                    u1, u2, u3 = st.columns([6,2,2])
                    with u1:
                        st.write(r.name)
                    with u2:
                        toggled = st.toggle("Active", value=bool(r.is_active), key=f"uact_{r.id}")
                        if toggled != bool(r.is_active):
                            conn = get_user_conn(); c = conn.cursor()
                            c.execute("UPDATE units SET is_active=? WHERE id=?", (1 if toggled else 0, r.id))
                            conn.commit(); conn.close()
                            st.experimental_rerun()
                    with u3:
                        if st.button("Delete", key=f"udel_{r.id}"):
                            conn = get_user_conn(); c = conn.cursor()
                            c.execute("DELETE FROM units WHERE id=?", (r.id,))
                            conn.commit(); conn.close()
                            st.experimental_rerun()

        # ---- Audit tab ----
        with tab_audit:
            st.subheader("Audit Log (latest 500)")
            conn = get_user_conn()
            dfa = pd.read_sql("SELECT ts, user_id, action, details FROM audit_log ORDER BY id DESC LIMIT 500", conn)
            conn.close()
            st.dataframe(dfa, use_container_width=True, height=360)
