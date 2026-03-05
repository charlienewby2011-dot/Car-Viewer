import streamlit as st
import psycopg2
import json
import hashlib
import os

# -----------------------------
# USER HELPERS (Postgres)
# -----------------------------
def user_exists(username: str) -> bool:
    return execute(
        "SELECT 1 FROM users WHERE username = %s",
        (username,),
        fetchone=True
    ) is not None

def try_login(username: str, password: str) -> bool:
    row = execute(
        "SELECT password FROM users WHERE username = %s",
        (username,),
        fetchone=True
    )
    if not row:
        return False

    stored_value = row[0]
    ok = verify_password(stored_value, password)
    if ok:
        upgrade_password_if_plaintext(username, stored_value, password)
    return ok

def create_user(username: str, password: str) -> str:
    if user_exists(username):
        return f"User '{username}' already exists. Choose a different username."

    execute(
        "INSERT INTO users (username, password) VALUES (%s, %s)",
        (username, hash_password(password))
    )
    return f"User '{username}' created successfully."

def delete_user(username_to_delete: str) -> str:
    if username_to_delete.lower() == "admin":
        return "You cannot delete the admin account."

    if not user_exists(username_to_delete):
        return f"User '{username_to_delete}' does not exist."

    # Delete cars first (also covered by ON DELETE CASCADE, but explicit is fine)
    execute("DELETE FROM cars WHERE username = %s", (username_to_delete,))
    execute("DELETE FROM users WHERE username = %s", (username_to_delete,))
    return f"User '{username_to_delete}' deleted successfully."

def list_users():
    rows = execute(
        "SELECT username FROM users ORDER BY username",
        fetchall=True
    ) or []
    return [u for (u,) in rows]

def change_password(username: str, current_pw: str, new_pw: str) -> str:
    row = execute(
        "SELECT password FROM users WHERE username = %s",
        (username,),
        fetchone=True
    )
    if not row:
        return "User not found."

    stored_value = row[0]
    if not verify_password(stored_value, current_pw):
        return "Incorrect current password."

    if new_pw == "":
        return "Password cannot be blank."

    execute(
        "UPDATE users SET password = %s WHERE username = %s",
        (hash_password(new_pw), username)
    )
    return "Password changed successfully."


# -----------------------------
# ADMIN CAR KEY HELPERS
# -----------------------------
def parse_car_key(key: str):
    # format is "username :: label"
    u, l = key.split(" :: ", 1)
    return u, l

# -----------------------------
# DATABASE (Postgres via Neon)
# -----------------------------
@st.cache_resource
def get_conn():
    db_url = st.secrets["DATABASE_URL"]
    return psycopg2.connect(db_url)

def execute(query, params=(), fetchone=False, fetchall=False):
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(query, params)
        # committing on every query is OK for simplicity
        conn.commit()
        if fetchone:
            return cur.fetchone()
        if fetchall:
            return cur.fetchall()
    return None

def init_db():
    execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL
    )
    """)

    execute("""
    CREATE TABLE IF NOT EXISTS cars (
        label TEXT NOT NULL,
        username TEXT NOT NULL,
        make TEXT,
        model TEXT,
        registration TEXT,
        year TEXT,
        PRIMARY KEY (label, username),
        FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
    )
    """)

# -----------------------------
# PASSWORD HASHING
# -----------------------------
def hash_password(plain_password: str) -> str:
    salt = os.urandom(16).hex()
    digest = hashlib.sha256((salt + plain_password).encode("utf-8")).hexdigest()
    return f"{salt}${digest}"

def verify_password(stored_value: str, entered_password: str) -> bool:
    if "$" in stored_value:
        salt, digest = stored_value.split("$", 1)
        check = hashlib.sha256((salt + entered_password).encode("utf-8")).hexdigest()
        return check == digest
    return stored_value == entered_password

def upgrade_password_if_plaintext(username: str, stored_value: str, entered_password: str):
    if "$" not in stored_value and stored_value == entered_password:
        execute(
            "UPDATE users SET password = %s WHERE username = %s",
            (hash_password(entered_password), username)
        )

def create_default_admin():
    row = execute("SELECT password FROM users WHERE username = 'admin'", fetchone=True)
    if row is None:
        execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            ("admin", hash_password("admin123"))
        )
    else:
        stored = row[0]
        upgrade_password_if_plaintext("admin", stored, "admin123")

# Initialize DB + ensure admin exists
init_db()
create_default_admin()
# -----------------------------
# CAR HELPERS
# -----------------------------
def add_or_replace_car(username, label, make, model, registration, year):
    execute("""
        INSERT INTO cars (label, username, make, model, registration, year)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (label, username)
        DO UPDATE SET
            make = EXCLUDED.make,
            model = EXCLUDED.model,
            registration = EXCLUDED.registration,
            year = EXCLUDED.year
    """, (label, username, make, model, registration, year))
def get_car(username, label):
    return execute("""
        SELECT make, model, registration, year
        FROM cars
        WHERE label = %s AND username = %s
    """, (label, username), fetchone=True)

def update_car(username, label, make, model, registration, year):
    execute("""
        UPDATE cars
        SET make = %s, model = %s, registration = %s, year = %s
        WHERE label = %s AND username = %s
    """, (make, model, registration, year, label, username))

def delete_car(username, label):
    execute("""
        DELETE FROM cars
        WHERE label = %s AND username = %s
    """, (label, username))

def list_car_labels(username):
    rows = execute("""
        SELECT label FROM cars
        WHERE username = %s
        ORDER BY label
    """, (username,), fetchall=True) or []
    return [l for (l,) in rows]

def export_cars_json(username):
    rows = execute("""
        SELECT label, make, model, registration, year
        FROM cars
        WHERE username = %s
        ORDER BY label
    """, (username,), fetchall=True) or []

    data = []
    for label, make, model, registration, year in rows:
        data.append({
            "label": label,
            "make": make,
            "model": model,
            "registration": registration,
            "year": year
        })
    return json.dumps(data, indent=4)
def list_all_car_keys(owner=None):
    if owner:
        rows = execute("""
            SELECT username, label
            FROM cars
            WHERE username = %s
            ORDER BY username, label
        """, (owner,), fetchall=True) or []
    else:
        rows = execute("""
            SELECT username, label
            FROM cars
            ORDER BY username, label
        """, fetchall=True) or []
    return [f"{u} :: {l}" for u, l in rows]

def get_car_any(user, label):
    return execute("""
        SELECT make, model, registration, year
        FROM cars
        WHERE username = %s AND label = %s
    """, (user, label), fetchone=True)

def list_all_cars_rows(owner=None):
    if owner:
        return execute("""
            SELECT username, label, make, model, registration, year
            FROM cars
            WHERE username = %s
            ORDER BY username, label
        """, (owner,), fetchall=True) or []
    return execute("""
        SELECT username, label, make, model, registration, year
        FROM cars
        ORDER BY username, label
    """, fetchall=True) or []

def export_all_cars_json(owner=None):
    rows = list_all_cars_rows(owner)
    data = []
    for user, label, make, model, registration, year in rows:
        data.append({
            "username": user,
            "label": label,
            "make": make,
            "model": model,
            "registration": registration,
            "year": year
        })
    return json.dumps(data, indent=4)

# -----------------------------
# SESSION STATE
# -----------------------------
st.set_page_config(page_title="Car Viewer", page_icon="🚗", layout="centered")

if "user" not in st.session_state:
    st.session_state.user = None
if "attempts" not in st.session_state:
    st.session_state.attempts = 3

def do_logout():
    st.session_state.user = None
    st.session_state.attempts = 3
    st.rerun()

# -----------------------------
# LOGIN SCREEN
# -----------------------------
st.title("🚗 Car Viewer")

if st.session_state.user is None:
    st.subheader("Welcome")

    login_tab, create_tab = st.tabs(["Login", "Create account"])

    # ---------- LOGIN ----------
    with login_tab:
        st.subheader("=== Login Required ===")

        if st.session_state.attempts <= 0:
            st.error("Too many failed attempts. Refresh the page to try again.")
            st.stop()

        with st.form("login_form"):
            username = st.text_input("Username", key="login_user")
            password = st.text_input("Password", type="password", key="login_pass")
            submitted = st.form_submit_button("Login")

        if submitted:
            if try_login(username.strip(), password):
                st.session_state.user = username.strip()
                st.session_state.attempts = 3
                st.success(f"Welcome, {st.session_state.user}!")
                st.rerun()
            else:
                st.session_state.attempts -= 1
                st.error(f"Incorrect login. Attempts remaining: {st.session_state.attempts}")

    # ---------- CREATE ACCOUNT ----------
    with create_tab:
        st.subheader("=== Create a New Account ===")
        st.caption("Choose a unique username and password.")

        with st.form("create_account_form"):
            new_user = st.text_input("New username", key="signup_user")
            new_pw = st.text_input("New password", type="password", key="signup_pass")
            confirm_pw = st.text_input("Confirm password", type="password", key="signup_confirm")
            create_submitted = st.form_submit_button("Create account")

        if create_submitted:
            new_user = new_user.strip()

            if new_user == "":
                st.error("Username cannot be blank.")
            elif new_user.lower() == "admin":
                st.error("You cannot create an account called 'admin'.")
            elif new_pw == "":
                st.error("Password cannot be blank.")
            elif new_pw != confirm_pw:
                st.error("Passwords do not match.")
            else:
                msg = create_user(new_user, new_pw)
                if msg.endswith("successfully."):
                    st.success(msg)

                    # OPTIONAL: auto-log in immediately after sign-up
                    st.session_state.user = new_user
                    st.session_state.attempts = 3
                    st.rerun()
                else:
                    st.error(msg)

    st.stop()
# -----------------------------
# APP (LOGGED IN) - TOP TABS
# -----------------------------
username = st.session_state.user
is_admin = (username == "admin")

st.success(f"Logged in as: **{username}**")

# small top "account actions" row (optional but handy)
colA, colB, colC = st.columns([3, 1, 1])
with colB:
    if st.button("Logout", key="top_logout"):
        do_logout()
with colC:
    st.caption("")

st.divider()

# Build tab list (top headings)
car_tabs = ["Add", "View", "Edit", "Delete", "List", "Export"]
account_tabs = ["Change Password"]
admin_tabs = ["Create User", "Delete User", "List Users"] if is_admin else []

tab_names = car_tabs + account_tabs + (["Admin"] if is_admin else []) + ["Quit"]
tabs = st.tabs(tab_names)

# -----------------------------
# CARS: ADD
# -----------------------------
with tabs[0]:
    st.header("Add Car")
    with st.form("add_car_form"):
        label = st.text_input("Enter a label for this car:")
        make = st.text_input("Enter make:")
        model = st.text_input("Enter model:")
        registration = st.text_input("Enter registration:")
        year = st.text_input("Enter year:")
        submitted = st.form_submit_button("Save")

    if submitted:
        add_or_replace_car(username, label.strip(), make, model, registration, year)
        st.success(f"Saved car under label '{label.strip()}'.")

# -----------------------------
# CARS: VIEW
# -----------------------------
with tabs[1]:
    st.header("View Car")

    if is_admin:
        owner_choice = st.session_state.get("admin_owner_filter", "All users")
        owner_filter = None if owner_choice == "All users" else owner_choice

        keys = list_all_car_keys(owner_filter)
        if not keys:
            st.info("No cars found for that selection.")
        else:
            key = st.selectbox("Choose a car (user :: label):", keys, key="view_key")
            car_user, car_label = parse_car_key(key)
            result = get_car_any(car_user, car_label)

            if result:
                make, model, registration, year = result
                st.text(
                    "Car Information\n"
                    "----------------\n"
                    f"Owner:        {car_user}\n"
                    f"Label:        {car_label}\n"
                    f"Make:         {make}\n"
                    f"Model:        {model}\n"
                    f"Registration: {registration}\n"
                    f"Year:         {year}"
                )
            else:
                st.error("Car not found.")
    else:
        labels = list_car_labels(username)
        if not labels:
            st.info("You have no cars saved.")
        else:
            label = st.selectbox("Choose a car label:", labels, key="view_label")
            result = get_car(username, label)
            if result:
                make, model, registration, year = result
                st.text(
                    "Car Information\n"
                    "----------------\n"
                    f"Make:         {make}\n"
                    f"Model:        {model}\n"
                    f"Registration: {registration}\n"
                    f"Year:         {year}"
                )
            else:
                st.error(f"No car found with label '{label}'.")
# -----------------------------
# CARS: EDIT
# -----------------------------
with tabs[2]:
    st.header("Edit Car")

    if is_admin:
        owner_choice = st.session_state.get("admin_owner_filter", "All users")
        owner_filter = None if owner_choice == "All users" else owner_choice

        keys = list_all_car_keys(owner_filter)
        if not keys:
            st.info("No cars found for that selection.")
        else:
            key = st.selectbox("Choose a car (user :: label) to edit:", keys, key="edit_key")
            car_user, car_label = parse_car_key(key)
            existing = get_car_any(car_user, car_label)

            if not existing:
                st.error("Car not found.")
            else:
                current_make, current_model, current_reg, current_year = existing
                st.caption("Leave a field blank to keep the current value.")

                with st.form("edit_car_form_admin"):
                    make = st.text_input(f"Enter new make ({current_make}):")
                    model = st.text_input(f"Enter new model ({current_model}):")
                    registration = st.text_input(f"Enter new registration ({current_reg}):")
                    year = st.text_input(f"Enter new year ({current_year}):")
                    submitted = st.form_submit_button("Update")

                if submitted:
                    make = make if make != "" else current_make
                    model = model if model != "" else current_model
                    registration = registration if registration != "" else current_reg
                    year = year if year != "" else current_year

                    update_car(car_user, car_label, make, model, registration, year)
                    st.success(f"Updated car '{car_label}' for user '{car_user}'.")
    else:
        labels = list_car_labels(username)
        if not labels:
            st.info("You have no cars saved.")
        else:
            label = st.selectbox("Choose a car label to edit:", labels, key="edit_label")
            existing = get_car(username, label)

            if not existing:
                st.error(f"No car found with label '{label}'.")
            else:
                current_make, current_model, current_reg, current_year = existing
                st.caption("Leave a field blank to keep the current value.")

                with st.form("edit_car_form"):
                    make = st.text_input(f"Enter new make ({current_make}):")
                    model = st.text_input(f"Enter new model ({current_model}):")
                    registration = st.text_input(f"Enter new registration ({current_reg}):")
                    year = st.text_input(f"Enter new year ({current_year}):")
                    submitted = st.form_submit_button("Update")

                if submitted:
                    make = make if make != "" else current_make
                    model = model if model != "" else current_model
                    registration = registration if registration != "" else current_reg
                    year = year if year != "" else current_year

                    update_car(username, label, make, model, registration, year)
                    st.success(f"Updated car '{label}'.")

# -----------------------------
# CARS: DELETE
# -----------------------------
with tabs[3]:
    st.header("Delete Car")

    if is_admin:
        owner_choice = st.session_state.get("admin_owner_filter", "All users")
        owner_filter = None if owner_choice == "All users" else owner_choice

        keys = list_all_car_keys(owner_filter)
        if not keys:
            st.info("No cars found for that selection.")
        else:
            key = st.selectbox("Choose a car (user :: label) to delete:", keys, key="delete_key")
            car_user, car_label = parse_car_key(key)

            confirm = st.checkbox(
                f"I want to delete '{car_label}' owned by '{car_user}'",
                key="delete_car_confirm_admin"
            )
            if st.button("Delete car", key="delete_car_btn_admin"):
                if not confirm:
                    st.error("Please tick the confirmation checkbox first.")
                else:
                    delete_car(car_user, car_label)
                    st.success(f"Deleted car '{car_label}' for user '{car_user}' (if it existed).")
                    st.rerun()
    else:
        labels = list_car_labels(username)
        if not labels:
            st.info("You have no cars saved.")
        else:
            label = st.selectbox("Choose a car label to delete:", labels, key="delete_label")
            confirm = st.checkbox(f"I want to delete '{label}'", key="delete_car_confirm")
            if st.button("Delete car", key="delete_car_btn"):
                if not confirm:
                    st.error("Please tick the confirmation checkbox first.")
                else:
                    delete_car(username, label)
                    st.success(f"Deleted car '{label}' (if it existed).")
                    st.rerun()

# -----------------------------
# CARS: LIST
# -----------------------------
with tabs[4]:
    st.header("Cars")

    if is_admin:
        # Admin filter dropdown (stored in session_state automatically by Streamlit)
        owners = ["All users"] + list_users()
        owner_choice = st.selectbox("Show cars for:", owners, key="admin_owner_filter")

        owner_filter = None if owner_choice == "All users" else owner_choice
        rows = list_all_cars_rows(owner_filter)

        if not rows:
            st.info("No cars found for that selection.")
        else:
            st.dataframe(
                [{"username": u, "label": l, "make": m, "model": mo, "registration": r, "year": y}
                 for u, l, m, mo, r, y in rows],
                use_container_width=True
            )
    else:
        labels = list_car_labels(username)
        if not labels:
            st.info("You have no cars saved.")
        else:
            for l in labels:
                st.write(f"- {l}")


# -----------------------------
# CARS: EXPORT JSON
# -----------------------------
with tabs[5]:
    st.header("Export JSON")

    if is_admin:
        owner_choice = st.session_state.get("admin_owner_filter", "All users")
        owner_filter = None if owner_choice == "All users" else owner_choice

        json_text = export_all_cars_json(owner_filter)
        filename = "all_cars.json" if owner_filter is None else f"{owner_filter}_cars.json"
    else:
        json_text = export_cars_json(username)
        filename = f"{username}_cars.json"

    # Ensure json_text is a supported type for download_button: str/bytes/file-like [1](https://docs.streamlit.io/develop/api-reference/widgets/st.download_button)
    if not isinstance(json_text, str):
        json_text = json.dumps(json_text, indent=4)

    st.download_button(
        label=f"Download {filename}",
        data=json_text.encode("utf-8"),
        file_name=filename,
        mime="application/json",
        key="download_json_btn"
    )
    st.text_area("Preview:", json_text, height=250, key="export_preview")

# -----------------------------
# ACCOUNT: CHANGE PASSWORD
# -----------------------------
with tabs[6]:
    st.header("Change Password")
    with st.form("change_pw_form"):
        current_pw = st.text_input("Current password", type="password")
        new_pw = st.text_input("New password", type="password")
        confirm_pw = st.text_input("Confirm new password", type="password")
        submitted = st.form_submit_button("Change password")

    if submitted:
        if new_pw != confirm_pw:
            st.error("New passwords do not match.")
        else:
            msg = change_password(username, current_pw, new_pw)
            if msg.endswith("successfully."):
                st.success(msg)
            else:
                st.error(msg)

# -----------------------------
# ADMIN TAB (contains sub-sections)
# -----------------------------
base_count = len(car_tabs) + len(account_tabs)  # Add..Export + Change Password
admin_tab_index = base_count                    # position where Admin tab would be
quit_tab_index = base_count + (1 if is_admin else 0)  # Quit comes after Admin (if admin exists)

if is_admin:
    with tabs[admin_tab_index]:
        st.header("Admin")

        sub = st.tabs(admin_tabs)

        # Create User
        with sub[0]:
            st.subheader("Create New User")
            with st.form("create_user_form"):
                new_user = st.text_input("New username")
                new_pw = st.text_input("New password", type="password")
                submitted = st.form_submit_button("Create user")

            if submitted:
                msg = create_user(new_user.strip(), new_pw)
                if msg.endswith("successfully."):
                    st.success(msg)
                else:
                    st.error(msg)

        # Delete User
        with sub[1]:
            st.subheader("Delete User")
            users = list_users()
            users_no_admin = [u for u in users if u.lower() != "admin"]

            if not users_no_admin:
                st.info("No deletable users found.")
            else:
                target = st.selectbox("Username to delete:", users_no_admin, key="admin_delete_user")
                st.warning("This will also delete all cars saved by that user.")
                confirm = st.checkbox(f"I understand and want to delete '{target}'", key="admin_delete_confirm")

                if st.button("Delete user", key="admin_delete_btn"):
                    if not confirm:
                        st.error("Please tick the confirmation checkbox first.")
                    else:
                        msg = delete_user(target)
                        if msg.endswith("successfully."):
                            st.success(msg)
                        else:
                            st.error(msg)

        # List Users
        with sub[2]:
            st.subheader("Registered Users")
            for u in list_users():
                st.write(u)

# -----------------------------
# QUIT TAB
# -----------------------------
with tabs[quit_tab_index]:
    st.header("Quit")
    st.info("In a web app, “Quit” can’t close the browser. It logs you out instead.")

    if st.button("Quit and log out", key="quit_btn"):
        st.success("Goodbye!")
        do_logout()
