# All the necessary imports for the application
import re
import math
import random
import string
import hashlib
import tkinter as tk
from tkinter import messagebox, ttk, filedialog, simpledialog, scrolledtext # Use themed widgets, add scrolledtext
import json
import os
import bcrypt
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import matplotlib.pyplot as plt
from collections import Counter
import pyperclip # For clipboard paste
import logging # For logging
import requests # For HIBP check
import hashlib # For HIBP check (SHA1)
from datetime import datetime # For history formatting and audit

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO, # Set default level (e.g., INFO or DEBUG)
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler("password_utility.log", encoding='utf-8'), # Log to a file
        logging.StreamHandler() # Also log to console
    ]
)
logging.info("Application started")

# --- Constants ---
AMBIGUOUS_CHARS = "Il1O0"
DEFAULT_SPECIAL_CHARS = "!@#$%^&*(),.?\":{}|<>~`_+-=;"
SETTINGS_FILE = "settings.json"
USERS_FILE = "users.json" # Consider encrypting this file at rest
DB_FILE = "passwords.db" # Centralized DB file name
CLIPBOARD_TIMEOUT_MS = 20000 # 20 seconds for auto-clear

# Global variable to track the last sensitive item copied
COPIED_PASSWORD_MARKER = None

# --- Helper Functions ---

# Secure Key Management Placeholder
def get_secure_key(user_password):
    """
    Placeholder function for secure key retrieval/derivation.
    NEVER hardcode keys. Use PBKDF2 or system keychain.
    This function is crucial if implementing DB/file encryption.
    """
    # TODO: Implement secure key management.
    # Example using PBKDF2 (requires salt storage):
    # salt = os.urandom(16) # Store salt securely per user
    # kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000) # Use high iterations
    # key = base64.urlsafe_b64encode(kdf.derive(user_password.encode()))
    # return key
    logging.warning("Using insecure placeholder key generation. Implement secure key handling!")
    # This insecure key is NOT used for encryption in this version.
    return b"insecure-demo-key-replace-me"

# --- Load and Save Settings ---
def load_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding='utf-8') as file:
                return json.load(file)
        else:
            logging.info("Settings file not found, creating default settings.")
            # Create default settings if file doesn't exist
            default_settings = {"theme": "light", "language": "en", "smtp_server": "", "smtp_port": 587, "smtp_user": ""}
            save_settings(default_settings)
            return default_settings
    except (IOError, json.JSONDecodeError) as e:
        logging.error(f"Error loading settings: {e}", exc_info=True)
    # Fallback defaults
    return {"theme": "light", "language": "en", "smtp_server": "", "smtp_port": 587, "smtp_user": ""}

def save_settings(settings):
    try:
        with open(SETTINGS_FILE, "w", encoding='utf-8') as file:
            json.dump(settings, file, indent=4)
        logging.info("Settings saved successfully.")
    except IOError as e:
        logging.error(f"Error saving settings: {e}", exc_info=True)

# --- User Authentication Functions ---
def load_users():
    # TODO: Decrypt USERS_FILE here using a secure key if implementing encryption at rest
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r", encoding='utf-8') as file:
                return json.load(file)
    except (IOError, json.JSONDecodeError) as e:
        logging.error(f"Error loading users file: {e}", exc_info=True)
    return {}

def save_users(users):
    # TODO: Encrypt USERS_FILE here using a secure key if implementing encryption at rest
    try:
        with open(USERS_FILE, "w", encoding='utf-8') as file:
            json.dump(users, file, indent=4)
        logging.info("Users file saved.")
    except IOError as e:
        logging.error(f"Error saving users file: {e}", exc_info=True)

def hash_password(password):
    """Hashes password using bcrypt."""
    logging.debug("Hashing new password.")
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    """Verifies a password against a bcrypt hash."""
    try:
        logging.debug(f"Verifying password attempt.")
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except ValueError as e: # Handle potential issues with invalid hash format
        logging.error(f"Error verifying password - likely invalid hash format: {e}")
        return False

def login_screen():
    login_root = tk.Tk()
    login_root.title("Login / Register")
    login_root.geometry("400x300")
    style = ttk.Style(login_root)
    try:
        style.theme_use('clam') # Use a consistent theme
    except tk.TclError:
        logging.warning("Clam theme not found, using default.")

    def authenticate():
        username = username_entry.get()
        password = password_entry.get()
        if not username or not password:
             messagebox.showwarning("Login Failed", "Username and password cannot be empty.")
             return

        users = load_users()

        if username in users:
            hashed_password = users[username]
            if verify_password(password, hashed_password):
                logging.info(f"User '{username}' logged in successfully.")
                login_root.destroy()
                # TODO: Pass the user's password or derived key if needed for DB encryption
                password_tester_with_analytics(username)
            else:
                logging.warning(f"Failed login attempt for user '{username}': Invalid password.")
                messagebox.showerror("Login Failed", "Invalid username or password.")
        else:
            logging.warning(f"Failed login attempt: Username '{username}' not found.")
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def register():
        username = username_entry.get()
        password = password_entry.get()

        if not username or not password:
             messagebox.showerror("Registration Failed", "Username and password cannot be empty.")
             return
        # Basic username validation (e.g., no spaces)
        if ' ' in username:
             messagebox.showerror("Registration Failed", "Username cannot contain spaces.")
             return

        users = load_users()

        if username in users:
            logging.warning(f"Registration failed: Username '{username}' already exists.")
            messagebox.showerror("Registration Failed", "Username already exists.")
        else:
            hashed = hash_password(password)
            users[username] = hashed
            save_users(users)
            logging.info(f"User '{username}' registered successfully.")
            messagebox.showinfo("Registration Successful", "User registered successfully. Please log in.")

    # Login UI using ttk for consistency
    ttk.Label(login_root, text="Username:").pack(pady=5)
    username_entry = ttk.Entry(login_root, width=30)
    username_entry.pack(pady=5)
    username_entry.focus_set() # Set focus

    ttk.Label(login_root, text="Password:").pack(pady=5)
    password_entry = ttk.Entry(login_root, show="*", width=30)
    password_entry.pack(pady=5)
    # Bind Enter key for convenience
    password_entry.bind("<Return>", lambda event=None: authenticate())
    username_entry.bind("<Return>", lambda event=None: password_entry.focus_set())

    button_frame = ttk.Frame(login_root)
    button_frame.pack(pady=10)

    login_button = ttk.Button(button_frame, text="Login", command=authenticate)
    login_button.pack(side=tk.LEFT, padx=10)

    register_button = ttk.Button(button_frame, text="Register", command=register)
    register_button.pack(side=tk.LEFT, padx=10)

    login_root.mainloop()

# --- Database Functions ---
def initialize_db():
    """Creates the database and table if they don't exist."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # Use TEXT affinity for username, description, password value for flexibility
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_description TEXT,
                password_value TEXT NOT NULL, -- TODO: Encrypt this column!
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Add index for faster lookups by username
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_username ON passwords (username)")
        conn.commit()
        conn.close()
        logging.info(f"Database '{DB_FILE}' initialized successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error during initialization: {e}", exc_info=True)
        messagebox.showerror("Database Error", f"Could not initialize database: {e}")


def save_password_to_db(username, password, description=""):
    """Saves a password to the database for the given user."""
    # TODO: Implement encryption for 'password_value' before saving.
    # Use a key derived from the user's login password or a dedicated secure key.
    # encrypted_password = encrypt_data(password, get_secure_key(user_password_from_login)) # Conceptual
    encrypted_password = password # Placeholder - Storing plain text (INSECURE)
    logging.warning("Saving password to DB without encryption!")

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO passwords (username, password_description, password_value)
            VALUES (?, ?, ?)
        """, (username, description, encrypted_password))
        conn.commit()
        conn.close()
        logging.info(f"Password saved to DB for user '{username}'. Description: '{description}'.")
        return True
    except sqlite3.Error as e:
        logging.error(f"Database error saving password for user '{username}': {e}", exc_info=True)
        messagebox.showerror("Database Error", f"Could not save password: {e}")
        return False

def get_passwords_from_db(username):
    """Fetches passwords for the given username from the database."""
    passwords = []
    try:
        conn = sqlite3.connect(DB_FILE)
        # Use a row factory for easier access by column name if needed later
        # conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, password_description, password_value, created_at
            FROM passwords WHERE username = ? ORDER BY created_at DESC
        """, (username,))
        rows = cursor.fetchall()
        conn.close()

        for row_id, desc, encrypted_pwd, created_at in rows:
            # TODO: Decrypt 'encrypted_pwd' here using the appropriate key derived during login.
            # decrypted_pwd = decrypt_data(encrypted_pwd, get_secure_key(user_password_from_login)) # Conceptual
            decrypted_pwd = encrypted_pwd # Placeholder - Assuming plain text (INSECURE)
            logging.warning(f"Fetching password ID {row_id} from DB without decryption!")
            passwords.append({
                "id": row_id,
                "description": desc if desc else "", # Ensure description is not None
                "password": decrypted_pwd,
                "created_at": created_at
            })

        logging.info(f"Fetched {len(passwords)} passwords from DB for user '{username}'.")
        return passwords
    except sqlite3.Error as e:
        logging.error(f"Database error fetching passwords for user '{username}': {e}", exc_info=True)
        messagebox.showerror("Database Error", f"Could not fetch password history: {e}")
        return [] # Return empty list on error

# --- Core Logic Functions ---

def check_strength(password):
    """Checks password strength based on length and character types."""
    if not password: # Handle empty password case
        return 0, 0.0, False, False, False, False, False

    min_length = 12 # Minimum recommended length
    length_ok = len(password) >= min_length
    upper_ok = bool(re.search(r'[A-Z]', password))
    lower_ok = bool(re.search(r'[a-z]', password))
    digit_ok = bool(re.search(r'\d', password))
    # Use re.escape on the default special chars constant for safety in regex
    special_ok = bool(re.search(r'[' + re.escape(DEFAULT_SPECIAL_CHARS) + r']', password))
    score = sum([length_ok, upper_ok, lower_ok, digit_ok, special_ok])

    # Calculate entropy
    char_set_size = 0
    if lower_ok: char_set_size += 26
    if upper_ok: char_set_size += 26
    if digit_ok: char_set_size += 10
    if special_ok: char_set_size += len(DEFAULT_SPECIAL_CHARS)

    entropy = 0
    # Avoid log2(0) or log2(1) issues
    if char_set_size > 1 and len(password) > 0:
        entropy = len(password) * math.log2(char_set_size)

    logging.debug(f"Strength check for password (len={len(password)}): Score={score}, Entropy={entropy:.1f}")
    return score, entropy, length_ok, upper_ok, lower_ok, digit_ok, special_ok

def suggest_improvements(password):
    """Suggests improvements for a weak password."""
    min_length = 12
    suggestions = []
    if not password: return ["• Enter a password."] # Handle empty case

    if len(password) < min_length:
        suggestions.append(f"• Increase length to at least {min_length} characters.")
    if not re.search(r'[A-Z]', password):
        suggestions.append("• Add at least one uppercase letter (A-Z).")
    if not re.search(r'[a-z]', password):
        suggestions.append("• Include at least one lowercase letter (a-z).")
    if not re.search(r'\d', password):
        suggestions.append("• Add at least one digit (0-9).")
    if not re.search(r'[' + re.escape(DEFAULT_SPECIAL_CHARS) + r']', password):
        suggestions.append(f"• Use a special character (e.g., {random.choice(DEFAULT_SPECIAL_CHARS)}).")

    logging.debug(f"Suggestions generated: {suggestions if suggestions else 'None'}")
    return suggestions

def generate_password(length=16, include_lower=True, include_upper=True, include_digits=True, include_special=True, exclude_ambiguous=False, custom_special_chars=None):
    """Generates a random password based on criteria, optionally using custom special chars."""
    char_pool = ""
    required_chars = []
    char_sets = []

    # Determine which special characters to use
    active_special_chars = custom_special_chars if custom_special_chars else DEFAULT_SPECIAL_CHARS

    if include_lower: char_sets.append((string.ascii_lowercase, 'lower'))
    if include_upper: char_sets.append((string.ascii_uppercase, 'upper'))
    if include_digits: char_sets.append((string.digits, 'digit'))
    if include_special: char_sets.append((active_special_chars, 'special'))

    if not char_sets:
        logging.warning("Password generation attempted with no character types selected.")
        return "" # No character types selected

    # Build the character pool and select one required character from each set
    for current_set, _type in char_sets:
        if exclude_ambiguous:
            # Filter based on ambiguous chars
            pool = ''.join(c for c in current_set if c not in AMBIGUOUS_CHARS)
        else:
            pool = current_set

        if pool: # Ensure the filtered pool is not empty
            char_pool += pool
            try:
                required_chars.append(random.choice(pool))
            except IndexError:
                logging.warning(f"Character pool for type '{_type}' became empty after filtering ambiguous chars.")
                # Optionally, could return error or try generation without this type
        else:
             logging.warning(f"Character pool for type '{_type}' is empty (possibly due to ambiguous filter).")


    if not char_pool: # Handle case where ambiguous filter removes all chars from all selected types
        logging.error("Password generation failed: Character pool empty after filtering.")
        return ""

    # Ensure length is sufficient for required characters
    if length < len(required_chars):
        logging.warning(f"Requested password length ({length}) is less than required characters ({len(required_chars)}). Adjusting length.")
        length = len(required_chars)

    # Fill remaining length using the combined pool
    try:
        remaining_length = length - len(required_chars)
        # Use secrets module for cryptographically secure random choices if available (Python 3.6+)
        try:
            import secrets
            password_list = required_chars + [secrets.choice(char_pool) for _ in range(remaining_length)]
        except ImportError:
            logging.warning("secrets module not available, falling back to random.choice")
            password_list = required_chars + [random.choice(char_pool) for _ in range(remaining_length)]

        # Shuffle thoroughly
        random.shuffle(password_list)
        generated_pwd = ''.join(password_list)
        logging.info(f"Generated password with length {length}.")
        return generated_pwd

    except Exception as e:
         logging.error(f"Error during password generation fill/shuffle: {e}", exc_info=True)
         return "" # Return empty string on error


def generate_hashes(password):
    """Generates various cryptographic hashes for the password."""
    if not password:
        return { "MD5": "", "SHA1": "", "SHA256": "", "SHA512": "" }

    # Use UTF-8 encoding consistently
    pwd_bytes = password.encode('utf-8')
    hashes = {
        # Insecure - for demonstration/comparison only
        "MD5": hashlib.md5(pwd_bytes).hexdigest(),
        "SHA1": hashlib.sha1(pwd_bytes).hexdigest(),
        # Secure alternatives
        "SHA256": hashlib.sha256(pwd_bytes).hexdigest(),
        "SHA512": hashlib.sha512(pwd_bytes).hexdigest(),
    }
    logging.debug("Generated hashes for input text.")
    return hashes

# --- Have I Been Pwned (HIBP) Check ---
def check_hibp(password):
    """Checks password against HIBP Pwned Passwords API using k-Anonymity.
    Returns breach count (int >= 0) or -1 on error."""
    if not password:
        return 0 # Empty password isn't pwned

    try:
        # 1. Hash the password with SHA-1 (required by HIBP API)
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        api_url = f"https://api.pwnedpasswords.com/range/{prefix}"
        logging.debug(f"Checking HIBP for hash prefix: {prefix}")

        # 2. Send the prefix to the API
        headers = {'User-Agent': 'PasswordUtilityTool-Python'} # Good practice to identify your client
        response = requests.get(api_url, headers=headers, timeout=10) # Add timeout
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        # 3. Check if our suffix is in the response
        # Response format: HASH_SUFFIX:COUNT\nHASH_SUFFIX:COUNT...
        hashes = (line.split(':') for line in response.text.splitlines())
        for h_suffix, count_str in hashes:
            if h_suffix == suffix:
                count = int(count_str)
                logging.warning(f"Password found in HIBP database! Breach count: {count}")
                return count # Return breach count if found

        logging.info("Password not found in HIBP database.")
        return 0 # Not found in breaches

    except requests.exceptions.Timeout:
        logging.error("HIBP API request timed out.")
        messagebox.showerror("API Error", "Connection timed out while checking Have I Been Pwned.")
        return -1
    except requests.exceptions.RequestException as e:
        logging.error(f"Error contacting HIBP API: {e}", exc_info=True)
        messagebox.showerror("API Error", f"Could not check Have I Been Pwned: {e}")
        return -1 # Indicate an error occurred
    except ValueError as e:
         logging.error(f"Error parsing HIBP API response or count: {e}", exc_info=True)
         messagebox.showerror("API Error", "Error processing response from Have I Been Pwned.")
         return -1
    except Exception as e:
        logging.error(f"An unexpected error occurred during HIBP check: {e}", exc_info=True)
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")
        return -1


# --- Email Sending Function ---
def send_email(recipient_email, subject, body, settings):
    """Sends an email (use with caution for passwords). Reads config from settings."""
    # Read SMTP config from settings
    sender_email = settings.get("smtp_user", "")
    sender_password = settings.get("smtp_password", "") # Need to store/retrieve password securely!
    smtp_server = settings.get("smtp_server", "")
    smtp_port = settings.get("smtp_port", 587) # Default to 587

    # Basic validation of settings
    if not all([sender_email, sender_password, smtp_server]):
         messagebox.showerror("Email Error", "SMTP settings (server, user, password) not configured in settings.json.")
         logging.error("Email sending failed: SMTP settings missing.")
         return

    # Validate recipient email format (basic check)
    if not re.match(r"[^@]+@[^@]+\.[^@]+", recipient_email):
        messagebox.showerror("Email Error", "Invalid recipient email address format.")
        logging.warning(f"Invalid recipient email format: {recipient_email}")
        return

    # Add a strong warning about emailing passwords
    confirm = messagebox.askyesno(
        "Security Warning",
        "Emailing passwords is INSECURE and not recommended.\n"
        "The password will be sent in plain text.\n\n"
        "Are you sure you want to proceed?",
        icon='warning'
    )
    if not confirm:
        logging.info("User cancelled sending email due to security warning.")
        return

    try:
        logging.info(f"Attempting to send email to {recipient_email} via {smtp_server}:{smtp_port}")
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain', 'utf-8')) # Specify encoding

        server = smtplib.SMTP(smtp_server, smtp_port, timeout=15) # Add timeout
        server.ehlo() # Identify client
        server.starttls() # Upgrade to secure connection
        server.ehlo() # Re-identify after TLS
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, recipient_email, text)
        server.quit()
        logging.info(f"Email successfully sent to {recipient_email}.")
        messagebox.showinfo("Email Sent", f"Email sent to {recipient_email}.")
    except smtplib.SMTPAuthenticationError:
         logging.error("SMTP Authentication failed. Check email/password or app-specific password settings.", exc_info=True)
         messagebox.showerror("Email Error", "Authentication failed. Check email/password or app-specific password settings.")
    except smtplib.SMTPConnectError:
         logging.error(f"Could not connect to SMTP server {smtp_server}:{smtp_port}.", exc_info=True)
         messagebox.showerror("Email Error", f"Could not connect to SMTP server {smtp_server}:{smtp_port}.")
    except smtplib.SMTPServerDisconnected:
         logging.error("SMTP server disconnected unexpectedly.", exc_info=True)
         messagebox.showerror("Email Error", "Server disconnected unexpectedly. Please try again.")
    except smtplib.SMTPException as e:
         logging.error(f"General SMTP error: {e}", exc_info=True)
         messagebox.showerror("Email Error", f"Failed to send email (SMTP Error): {e}")
    except TimeoutError: # Catch socket timeout
         logging.error(f"SMTP connection timed out ({smtp_server}:{smtp_port}).", exc_info=True)
         messagebox.showerror("Email Error", f"Connection to email server timed out.")
    except Exception as e:
        logging.error(f"Unexpected error sending email: {e}", exc_info=True)
        messagebox.showerror("Email Error", f"Failed to send email: {e}")

# --- Analytics Functions ---
def calculate_password_statistics(username):
    """Calculates statistics based on the user's password history."""
    passwords_data = get_passwords_from_db(username) # List of dicts
    if not passwords_data:
        logging.info(f"No password history found for user '{username}' for analytics.")
        return None # No data for analytics

    strengths = []
    lengths = []
    special_counts = []
    active_special_chars = DEFAULT_SPECIAL_CHARS # Assume default for stats calculation

    for entry in passwords_data:
        pwd = entry["password"]
        score, _, _, _, _, _, special_ok = check_strength(pwd)
        strengths.append(score)
        lengths.append(len(pwd))
        # Count special chars based on the default set for consistency in stats
        special_counts.append(sum(1 for c in pwd if c in active_special_chars))

    count = len(passwords_data)
    avg_strength = sum(strengths) / count if count else 0
    avg_length = sum(lengths) / count if count else 0
    avg_special = sum(special_counts) / count if count else 0

    stats_result = {
        "count": count,
        "average_strength": avg_strength,
        "average_length": avg_length,
        "average_special": avg_special,
        "strength_distribution": Counter(strengths),
        "length_distribution": Counter(lengths),
    }
    logging.info(f"Calculated password statistics for user '{username}': {stats_result}")
    return stats_result


# --- Display Analytics ---
def show_analytics(username):
    """Displays password analytics using matplotlib."""
    stats = calculate_password_statistics(username)

    if not stats or stats['count'] == 0:
        messagebox.showinfo("Password Analytics", "No password history found to generate analytics.")
        return

    # Display summary statistics
    summary_text = (
        f"Analytics based on {stats['count']} saved passwords:\n"
        f"Average Strength Score: {stats['average_strength']:.2f} / 5\n"
        f"Average Length: {stats['average_length']:.2f}\n"
        f"Average Special Chars: {stats['average_special']:.2f}"
    )
    messagebox.showinfo("Password Analytics Summary", summary_text)

    # Plot distributions
    try:
        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        fig.suptitle(f'Password Analytics for {username}') # Add main title

        # Strength Distribution
        strength_items = sorted(stats['strength_distribution'].items())
        if strength_items:
            s_keys = [str(k) for k, v in strength_items]
            s_values = [v for k, v in strength_items]
            axes[0].bar(s_keys, s_values, color='skyblue')
        axes[0].set_title("Strength Score Distribution")
        axes[0].set_xlabel("Strength Score (0-5)")
        axes[0].set_ylabel("Count")
        axes[0].grid(axis='y', linestyle='--')

        # Length Distribution
        length_items = sorted(stats['length_distribution'].items())
        if length_items:
            l_keys = [k for k, v in length_items]
            l_values = [v for k, v in length_items]
            axes[1].bar(l_keys, l_values, color='lightgreen')
            # Set x-axis ticks to ensure all lengths are shown if possible
            if len(l_keys) < 20: # Avoid clutter for many lengths
                 axes[1].set_xticks(l_keys)
            else:
                 # Use default ticker for many lengths
                 pass
        axes[1].set_title("Password Length Distribution")
        axes[1].set_xlabel("Length")
        axes[1].set_ylabel("Count")
        axes[1].grid(axis='y', linestyle='--')


        plt.tight_layout(rect=[0, 0.03, 1, 0.95]) # Adjust layout
        logging.info("Displaying analytics graphs.")
        plt.show()
    except Exception as e:
        logging.error(f"Could not display analytics graphs: {e}", exc_info=True)
        messagebox.showerror("Plotting Error", f"Could not display analytics graphs: {e}")


# --- Tooltip Class ---
class ToolTip:
    """Create a tooltip for a given widget."""
    def __init__(self, widget, text='widget info'):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.widget.bind("<ButtonPress>", self.leave) # Hide on click too
        self.id = None
        self.delay_ms = 500 # ms delay before showing

    def enter(self, event=None):
        self.schedule()

    def leave(self, event=None):
        self.unschedule()
        self.hidetip()

    def schedule(self):
        self.unschedule()
        self.id = self.widget.after(self.delay_ms, self.showtip)

    def unschedule(self):
        id = self.id
        self.id = None
        if id:
            self.widget.after_cancel(id)

    def showtip(self, event=None):
        if self.tooltip_window: # Avoid multiple tooltips
            return
        # Get widget position relative to screen
        x = y = 0
        x, y, cx, cy = self.widget.bbox("insert") # Get coords relative to widget
        x += self.widget.winfo_rootx() + 25 # Offset from mouse pointer
        y += self.widget.winfo_rooty() + 20

        # Creates a toplevel window
        self.tooltip_window = tk.Toplevel(self.widget)
        # Leaves only the label and removes the app window decorations
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")

        label = ttk.Label(self.tooltip_window, text=self.text, justify='left',
                          background="#FFFFE0", relief='solid', borderwidth=1,
                          font=("tahoma", "8", "normal"), padding=3)
        label.pack(ipadx=1)
        # Ensure tooltip window is raised above others
        self.tooltip_window.attributes('-topmost', True)


    def hidetip(self):
        tw = self.tooltip_window
        self.tooltip_window = None
        if tw:
            tw.destroy()

# --- Password Audit ---
def display_audit_results(results, parent):
    """Displays audit results in a new Toplevel window."""
    audit_win = tk.Toplevel(parent)
    audit_win.title("Password Audit Results")
    audit_win.geometry("600x400")

    txt_area = scrolledtext.ScrolledText(audit_win, wrap=tk.WORD, width=70, height=20)
    txt_area.pack(padx=10, pady=10, fill="both", expand=True)
    txt_area.configure(state='normal') # Make writable to insert text

    summary = f"Audit Complete.\nFound {results['weak']} weak, {results['reused']} reused, and {results['pwned']} pwned passwords.\n\nDetails:\n"
    txt_area.insert(tk.INSERT, summary + "="*20 + "\n")

    if results['details']:
        for item in results['details']:
            txt_area.insert(tk.INSERT, f"ID: {item['id']}, Desc: '{item['description']}'\n")
            for issue in item['issues']:
                 txt_area.insert(tk.INSERT, f"  - {issue}\n")
            txt_area.insert(tk.INSERT, "\n")
    else:
         txt_area.insert(tk.INSERT, "No issues found in password history.")

    txt_area.configure(state='disabled') # Make read-only
    logging.info("Displayed password audit results window.")

    close_button = ttk.Button(audit_win, text="Close", command=audit_win.destroy)
    close_button.pack(pady=10)
    audit_win.transient(parent) # Keep window on top of parent
    audit_win.grab_set() # Make modal
    parent.wait_window(audit_win) # Wait until closed


def audit_passwords(username, check_pwned=False):
    """Performs an audit on saved passwords for weaknesses, reuse, and optionally HIBP."""
    logging.info(f"Starting password audit for user '{username}'. Check Pwned: {check_pwned}")
    passwords_data = get_passwords_from_db(username) # List of dicts
    if not passwords_data:
        logging.info("No passwords found for audit.")
        messagebox.showinfo("Audit Results", "No password history found to audit.")
        return

    results = {'weak': 0, 'reused': 0, 'pwned': 0, 'details': []}
    password_counts = Counter(entry['password'] for entry in passwords_data if entry['password']) # Count occurrences of each password
    checked_pwned_passwords = {} # Cache HIBP results for reused passwords

    for entry in passwords_data:
        pwd_id = entry['id']
        pwd = entry['password']
        desc = entry['description']
        issues = []

        if not pwd: # Skip empty passwords in history if any
            continue

        # 1. Check Strength (Score < 3 considered weak for audit)
        score, _, _, _, _, _, _ = check_strength(pwd)
        if score < 3:
            issues.append(f"Weak (Score: {score}/5)")

        # 2. Check Reuse
        if password_counts[pwd] > 1:
            issues.append(f"Reused ({password_counts[pwd]} times)")

        # 3. Check Pwned (if requested)
        pwned_count = 0
        if check_pwned:
            if pwd in checked_pwned_passwords:
                pwned_count = checked_pwned_passwords[pwd]
                logging.debug(f"Using cached HIBP result for password ID {pwd_id}: {pwned_count}")
            else:
                logging.debug(f"Checking HIBP for password ID {pwd_id}...")
                pwned_count = check_hibp(pwd)
                checked_pwned_passwords[pwd] = pwned_count # Cache result (-1, 0, or >0)

            if pwned_count > 0:
                issues.append(f"Pwned ({pwned_count} breaches)")
            elif pwned_count == -1:
                 issues.append("Pwned check failed (API error)")


        if issues:
             results['details'].append({'id': pwd_id, 'description': desc, 'issues': issues})
             if any("Weak" in s for s in issues): results['weak'] += 1
             if any("Reused" in s for s in issues): results['reused'] += (1 if password_counts[pwd] == 2 else 0) # Count reuse pairs once
             if any("Pwned (" in s for s in issues): results['pwned'] += 1

    # Adjust reuse count to reflect number of *passwords* that are reused, not total instances
    reused_password_values = {p for p, count in password_counts.items() if count > 1}
    results['reused'] = len(reused_password_values)

    logging.info(f"Audit complete for user '{username}'. Results: {results}")
    return results


# --- Enhanced Application ---
def password_tester_with_analytics(username):
    root = tk.Tk()
    root.title(f"Password Utility Tool - Logged in as: {username}")
    root.geometry("750x750") # Increased size

    # Ensure DB is ready
    initialize_db()

    # Load settings
    settings = load_settings()
    # Ensure essential settings have defaults if missing from file
    current_theme = settings.setdefault("theme", "light")
    current_language = settings.setdefault("language", "en")
    dark_mode = tk.BooleanVar(value=(current_theme == "dark"))

    # --- Status Bar ---
    status_var = tk.StringVar(value="Status: Ready") # Initial status
    status_bar = ttk.Label(root, textvariable=status_var, relief=tk.SUNKEN, anchor="w", font=("Arial", 10))
    status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def update_status(message):
        status_var.set(f"Status: {message}")
        logging.info(f"Status Updated: {message}") # Log status updates

    # --- Export Password ---
    def export_password_action(password_to_export):
        if not password_to_export:
            messagebox.showwarning("No Password", "There is no password to export.")
            update_status("Export failed: No password available.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save Password As..."
        )
        if file_path:
            try:
                with open(file_path, "w", encoding='utf-8') as file:
                    file.write(password_to_export)
                update_status(f"Password exported successfully to {os.path.basename(file_path)}.")
                logging.info(f"Password exported to {file_path}")
                messagebox.showinfo("Export Successful", "Password exported.")
            except IOError as e:
                logging.error(f"Failed to export password to {file_path}: {e}", exc_info=True)
                messagebox.showerror("Export Error", f"Failed to export password: {e}")
                update_status(f"Export failed: {e}")

    # --- Clipboard Auto-Clear ---
    def clear_clipboard_if_matches(original_password):
        global COPIED_PASSWORD_MARKER
        if original_password is None: return # Safety check

        try:
            current_clipboard = root.clipboard_get()
            if current_clipboard == original_password:
                root.clipboard_clear()
                root.clipboard_append(" ") # Append space to truly clear in some systems
                root.clipboard_clear()
                update_status("Clipboard cleared automatically.")
                logging.info("Clipboard auto-cleared.")
            else:
                 logging.debug("Clipboard content changed, not auto-clearing.")
        except tk.TclError:
            logging.debug("Clipboard inaccessible or empty, skipping auto-clear check.")
            pass # Clipboard might be empty or inaccessible
        except Exception as e:
             logging.error(f"Unexpected error during clipboard clear check: {e}", exc_info=True)
        finally:
             # Clear marker regardless of whether clear happened, to prevent accidental future clears
             COPIED_PASSWORD_MARKER = None


    # --- Helper Function: Copy to Clipboard (with timeout option) ---
    def copy_to_clipboard(text_to_copy, message="Copied to clipboard!", is_sensitive=False):
        """Copies text, optionally scheduling auto-clear for sensitive data."""
        global COPIED_PASSWORD_MARKER
        # Cancel any pending clear operations first
        if COPIED_PASSWORD_MARKER is not None:
             # There might be a pending clear, try to cancel it
             # We need the after_id, which we don't store globally.
             # Simpler: just clear the marker, the old timer will fail the check.
             COPIED_PASSWORD_MARKER = None
             logging.debug("Cancelled previous clipboard clear timer (potentially).")


        if text_to_copy:
            try:
                root.clipboard_clear()
                root.clipboard_append(text_to_copy)
                update_status(message)
                logging.info(f"Copied to clipboard. Sensitive: {is_sensitive}. Text length: {len(text_to_copy)}")
                if is_sensitive:
                    COPIED_PASSWORD_MARKER = text_to_copy # Store the sensitive text
                    # Schedule clear
                    root.after(CLIPBOARD_TIMEOUT_MS, lambda: clear_clipboard_if_matches(text_to_copy))
                    logging.debug(f"Scheduled clipboard auto-clear in {CLIPBOARD_TIMEOUT_MS}ms.")

            except tk.TclError:
                logging.error("Failed to access clipboard for copying.", exc_info=True)
                messagebox.showwarning("Copy Failed", "Could not access clipboard.")
                COPIED_PASSWORD_MARKER = None # Ensure marker is cleared on error
            except Exception as e:
                 logging.error(f"Unexpected error copying to clipboard: {e}", exc_info=True)
                 messagebox.showerror("Error", f"An unexpected error occurred during copy: {e}")
                 COPIED_PASSWORD_MARKER = None
        else:
             update_status("Nothing to copy.")
             logging.debug("Copy attempted with empty text.")


    # --- Helper Function: Paste from Clipboard ---
    def paste_from_clipboard(entry_widget):
        try:
            clipboard_content = pyperclip.paste()
            if clipboard_content:
                logging.info(f"Pasting content of length {len(clipboard_content)} from clipboard.")
                entry_widget.delete(0, tk.END)
                entry_widget.insert(0, clipboard_content)
                # Trigger updates manually if needed for specific tabs
                if entry_widget == ch_entry:
                    checker_live_feedback() # Pass None or create dummy event
                elif entry_widget == hash_entry:
                    update_hashes()
                update_status("Pasted from clipboard.")
            else:
                update_status("Clipboard is empty.")
                logging.debug("Paste attempted with empty clipboard.")
        except pyperclip.PyperclipException as e:
            logging.error(f"Pyperclip error pasting from clipboard: {e}", exc_info=True)
            messagebox.showwarning("Paste Failed", f"Could not paste from clipboard.\nEnsure you have xclip (Linux) or other required backend installed.\nError: {e}")
            update_status("Paste failed.")
        except Exception as e:
             logging.error(f"Unexpected error pasting from clipboard: {e}", exc_info=True)
             messagebox.showwarning("Paste Failed", f"Could not paste from clipboard: {e}")
             update_status("Paste failed.")


    # --- Localization (Basic Example) ---
    # TODO: Expand translations significantly & load from external files (e.g., .po/.mo)
    LANGUAGES = {
        "en": {"welcome": f"Welcome {username}!", "export_success": "Password exported.", },
        "es": {"welcome": f"¡Bienvenido {username}!", "export_success": "Contraseña exportada.", },
    }

    def translate(key):
        return LANGUAGES.get(current_language, LANGUAGES["en"]).get(key, f"<{key}>") # Fallback

    update_status(translate("welcome")) # Set initial translated status

    # --- Save Settings on Exit ---
    def on_exit():
        settings["theme"] = 'dark' if dark_mode.get() else 'light'
        settings["language"] = current_language
        save_settings(settings)
        logging.info("Application exiting.")
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_exit)

    # --- Style Configuration ---
    style = ttk.Style(root)
    try:
        style.theme_use('clam')
    except tk.TclError:
        logging.warning("Clam theme not available, using default.")

    # Color definitions
    colors = {
        'light': {
            'bg': '#f0f0f0', 'fg': 'black', 'entry_bg': 'white', 'entry_fg': 'black',
            'btn_bg': '#e0e0e0', 'btn_fg': 'black', 'accent_btn_bg': '#007BFF', 'accent_btn_fg': 'white',
            'copy_btn_bg': '#28a745', 'clear_btn_bg': '#ffc107', 'warn_btn_bg': '#dc3545', 'btn_fg_light': 'black',
            'progress_trough': '#e9ecef', 'progress_colors': ["#dc3545", "#ffc107", "#ffc107", "#17a2b8", "#28a745"],
            'notebook_bg': '#f0f0f0', 'tab_bg': '#d0d0d0', 'tab_fg': 'black', 'tab_active_bg': '#f0f0f0', 'tab_active_fg': 'black',
            'warn_fg': '#dc3545', 'good_fg': '#28a745', 'insecure_hash_fg': '#6c757d', 'pwned_fg': '#dc3545',
            'check_good': '✓', 'check_bad': '✗', 'readonly_bg': '#e9ecef',
            'audit_issue_fg': '#dc3545', 'audit_ok_fg': '#28a745',
        },
        'dark': {
            'bg': '#2e2e2e', 'fg': 'white', 'entry_bg': '#3e3e3e', 'entry_fg': 'white',
            'btn_bg': '#555555', 'btn_fg': 'white', 'accent_btn_bg': '#0056b3', 'accent_btn_fg': 'white',
            'copy_btn_bg': '#218838', 'clear_btn_bg': '#e0a800', 'warn_btn_bg': '#c82333', 'btn_fg_light': 'white',
            'progress_trough': '#444444', 'progress_colors': ["#FF6347", "#FF8C00", "#FFD700", "#9ACD32", "#32CD32"],
            'notebook_bg': '#2e2e2e', 'tab_bg': '#444444', 'tab_fg': 'white', 'tab_active_bg': '#2e2e2e', 'tab_active_fg': 'white',
            'warn_fg': '#FF6347', 'good_fg': '#32CD32', 'insecure_hash_fg': '#adb5bd', 'pwned_fg': '#FF6347',
            'check_good': '✔', 'check_bad': '✘', 'readonly_bg': '#343a40',
            'audit_issue_fg': '#FF6347', 'audit_ok_fg': '#32CD32',
        }
    }

    def apply_theme():
        """Applies the current theme to all widgets."""
        theme_colors = colors[current_theme]
        root.configure(bg=theme_colors['bg'])
        logging.debug(f"Applying theme: {current_theme}")

        # General Styles
        style.configure('.', background=theme_colors['bg'], foreground=theme_colors['fg'], font=("Arial", 10))
        style.configure('TFrame', background=theme_colors['bg'])
        style.configure('TLabel', background=theme_colors['bg'], foreground=theme_colors['fg'])
        style.configure('TCheckbutton', background=theme_colors['bg'], foreground=theme_colors['fg'])
        style.map('TCheckbutton',
                  indicatorcolor=[('selected', theme_colors['accent_btn_bg']), ('!selected', theme_colors['entry_bg'])],
                  foreground=[('active', theme_colors['accent_btn_bg'])])
        style.configure('TEntry', fieldbackground=theme_colors['entry_bg'], foreground=theme_colors['entry_fg'], insertcolor=theme_colors['fg'])
        style.map('TEntry', fieldbackground=[('readonly', theme_colors['readonly_bg'])])  # Readonly style

        # Button Styles
        style.configure('TButton', background=theme_colors['btn_bg'], foreground=theme_colors['btn_fg'], padding=5)
        style.map('TButton', background=[('active', theme_colors['accent_btn_bg']), ('!disabled', theme_colors['btn_bg'])])
        style.configure('Accent.TButton', background=theme_colors['accent_btn_bg'], foreground=theme_colors['accent_btn_fg'])
        style.map('Accent.TButton', background=[('active', theme_colors['btn_bg'])])
        style.configure('Copy.TButton', background=theme_colors['copy_btn_bg'], foreground=theme_colors['accent_btn_fg'])
        style.map('Copy.TButton', background=[('active', theme_colors['btn_bg'])])
        style.configure('Clear.TButton', background=theme_colors['clear_btn_bg'], foreground=theme_colors['btn_fg_light'])
        style.map('Clear.TButton', background=[('active', theme_colors['btn_bg'])])
        style.configure('Warn.TButton', background=theme_colors['warn_btn_bg'], foreground=theme_colors['accent_btn_fg'])
        style.map('Warn.TButton', background=[('active', theme_colors['btn_bg'])])

        # Notebook
        style.configure('TNotebook', background=theme_colors['notebook_bg'])
        style.map('TNotebook.Tab',
                  background=[('selected', theme_colors['tab_active_bg']), ('!selected', theme_colors['tab_bg'])],
                  foreground=[('selected', theme_colors['tab_active_fg']), ('!selected', theme_colors['tab_fg'])])
        style.configure('TNotebook.Tab', padding=[10, 5], font=('Arial', 11))

        # Progress Bar
        style.configure("Horizontal.TProgressbar", troughcolor=theme_colors['progress_trough'], background=theme_colors['progress_colors'][0])

        # Scale
        style.configure('TScale', background=theme_colors['bg'], troughcolor=theme_colors['entry_bg'])

        # Treeview specific styling
        style.configure("Treeview",
                        background=theme_colors['entry_bg'],
                        foreground=theme_colors['fg'],
                        fieldbackground=theme_colors['entry_bg'],
                        rowheight=25)  # Adjust row height if needed
        style.map('Treeview', background=[('selected', theme_colors['accent_btn_bg'])], foreground=[('selected', theme_colors['accent_btn_fg'])])
        style.configure("Treeview.Heading",
                        background=theme_colors['btn_bg'],
                        foreground=theme_colors['btn_fg'],
                        font=('Arial', 10, 'bold'))
        style.map("Treeview.Heading", background=[('active', theme_colors['accent_btn_bg'])])

        # --- Re-apply styles/colors to specific elements ---
        # Status bar background/foreground
        status_bar.configure(background=theme_colors['bg'], foreground=theme_colors['fg'])

        # Update labels/buttons that need explicit color changes not covered by general styles
        hash_warn_lbl.configure(foreground=theme_colors['warn_fg'])  # Hasher warning label
        # Ensure feedback labels in checker get updated correctly by checker_live_feedback
        # Ensure hash value labels get updated by update_hashes

        # Call update functions to reflect theme changes immediately
        checker_live_feedback()  # Pass None or create dummy event
        update_hashes()
        update_status(translate("welcome"))  # Update status bar text color

    def toggle_dark_mode():
        """Toggles between light and dark themes."""
        global current_theme
        current_theme = 'dark' if dark_mode.get() else 'light'
        apply_theme()
        logging.info(f"Theme changed to {current_theme}.")

    # --- GUI Structure ---
    notebook = ttk.Notebook(root, style='TNotebook')
    notebook.pack(expand=True, fill="both", padx=10, pady=10)

    # Create frames using ttk
    checker_frame = ttk.Frame(notebook, padding=15)
    generator_frame = ttk.Frame(notebook, padding=15)
    hasher_frame = ttk.Frame(notebook, padding=15)
    history_frame = ttk.Frame(notebook, padding=15) # History Tab

    notebook.add(checker_frame, text=" Checker ") # Add spaces for better tab look
    notebook.add(generator_frame, text=" Generator ")
    notebook.add(hasher_frame, text=" Hasher ")
    notebook.add(history_frame, text=" History ")

    # ############################
    # # Password Checker Tab
    # ############################
    ch_lbl = ttk.Label(checker_frame, text="Enter password to check:", font=("Arial", 12))
    ch_lbl.pack(pady=(0, 5), anchor='w')

    ch_entry_frame = ttk.Frame(checker_frame)
    ch_entry_frame.pack(pady=5, fill='x')
    ch_entry = ttk.Entry(ch_entry_frame, show="*", width=50, font=("Arial", 12))
    ch_entry.pack(side=tk.LEFT, fill='x', expand=True, padx=(0, 5))
    ch_paste_btn = ttk.Button(ch_entry_frame, text="Paste", command=lambda: paste_from_clipboard(ch_entry), style='Accent.TButton')
    ch_paste_btn.pack(side=tk.LEFT)
    ToolTip(ch_paste_btn, "Paste text from clipboard")

    show_pwd_var_ch = tk.BooleanVar()
    def update_checker_visibility():
        ch_entry.config(show="" if show_pwd_var_ch.get() else "*")
    ch_show_pwd_btn = ttk.Checkbutton(checker_frame, text="Show Password", variable=show_pwd_var_ch, command=update_checker_visibility)
    ch_show_pwd_btn.pack(pady=(0,10), anchor='w')

    feedback_label_ch = ttk.Label(checker_frame, text="Start typing or paste for feedback...", font=("Arial", 11, "italic"))
    feedback_label_ch.pack(pady=5, anchor='w')

    strength_meter_ch = ttk.Progressbar(checker_frame, length=300, maximum=100, mode='determinate')
    strength_meter_ch.pack(pady=5, fill='x')
    ToolTip(strength_meter_ch, "Password strength score (0-100 based on criteria)")

    pwned_label_ch = ttk.Label(checker_frame, text="", font=("Arial", 10, "bold")) # Label for HIBP result
    pwned_label_ch.pack(pady=5, anchor='w')

    details_frame = ttk.Frame(checker_frame)
    details_frame.pack(pady=10, fill='x', expand=True)

    composition_label = ttk.Label(details_frame, text="Composition:", font=("Arial", 10, "bold"))
    composition_label.pack(anchor='w')
    composition_details_label = ttk.Label(details_frame, text="", font=("Arial", 10), justify="left")
    composition_details_label.pack(anchor='w', pady=(0,10))

    suggestion_label_ch = ttk.Label(details_frame, text="", font=("Arial", 10), wraplength=650, justify="left") # Increased wraplength
    suggestion_label_ch.pack(anchor='w')

    def checker_live_feedback(event=None): # Added event=None default
        pwd = ch_entry.get()
        theme_colors = colors[current_theme]

        # Reset pwned label on each update
        pwned_label_ch.config(text="", foreground=theme_colors['fg'])

        if pwd:
            score, entropy, length_ok, upper_ok, lower_ok, digit_ok, special_ok = check_strength(pwd)
            suggestions = suggest_improvements(pwd)
            progress_colors = theme_colors['progress_colors']

            # Clamp index safely
            color_index = max(0, min(score, len(progress_colors)) - 1) if score > 0 else 0
            bar_color = progress_colors[color_index]
            strength_meter_ch["value"] = score * 20 # Max score 5 -> 100
            style.configure("Horizontal.TProgressbar", background=bar_color) # Update color

            strength_text = "Very Weak"
            if score >= 5: strength_text = "Very Strong"
            elif score == 4: strength_text = "Strong"
            elif score == 3: strength_text = "Moderate"
            elif score >= 1: strength_text = "Weak"

            feedback_label_ch.config(
                text=f"Strength: {strength_text} | Est. Entropy: {entropy:.1f} bits",
                foreground=bar_color
            )

            suggestion_label_ch.config(
                text="Suggestions:\n" + ("\n".join(suggestions) if suggestions else f"{theme_colors['check_good']} Meets all criteria!"),
                foreground=(theme_colors['warn_fg'] if suggestions else theme_colors['good_fg'])
            )

            check = theme_colors['check_good']
            cross = theme_colors['check_bad']
            comp_text = (
                f" {check if length_ok else cross} Length (>=12) \t"
                f" {check if upper_ok else cross} Uppercase (A-Z)\n"
                f" {check if lower_ok else cross} Lowercase (a-z) \t"
                f" {check if digit_ok else cross} Digits (0-9)\n"
                f" {check if special_ok else cross} Special ({DEFAULT_SPECIAL_CHARS[:5]}...)"
            )
            composition_details_label.config(text=comp_text)
            composition_label.config(text="Composition Details:")

        else: # Reset when empty
            feedback_label_ch.config(text="Start typing or paste for feedback...", foreground=theme_colors['fg'], font=("Arial", 11, "italic"))
            suggestion_label_ch.config(text="", foreground=theme_colors['fg'])
            composition_label.config(text="Composition:")
            composition_details_label.config(text="")
            strength_meter_ch["value"] = 0
            style.configure("Horizontal.TProgressbar", background=theme_colors['progress_colors'][0])

    ch_entry.bind("<KeyRelease>", checker_live_feedback)

    ch_button_frame = ttk.Frame(checker_frame)
    ch_button_frame.pack(pady=10)

    def clear_checker():
        ch_entry.delete(0, tk.END)
        checker_live_feedback()
        pwned_label_ch.config(text="") # Clear pwned label too
        update_status("Checker input cleared.")

    ch_clear_btn = ttk.Button(ch_button_frame, text="Clear", command=clear_checker, style='Clear.TButton')
    ch_clear_btn.pack(side=tk.LEFT, padx=5)
    ToolTip(ch_clear_btn, "Clear the password input field.")

    def save_checked_password():
        pwd = ch_entry.get()
        if not pwd:
            messagebox.showwarning("No Password", "Enter a password before saving.")
            return

        desc = simpledialog.askstring("Password Description", "Enter a brief description (optional):", parent=root)
        if desc is None: # User cancelled
             logging.debug("Password save cancelled by user.")
             return

        if save_password_to_db(username, pwd, desc if desc else "Checked Password"):
            messagebox.showinfo("Saved", "Password saved to history.")
            update_status("Password saved to history.")
            refresh_history_tab() # Update history tab view
        # Error messages handled within save_password_to_db

    ch_save_btn = ttk.Button(ch_button_frame, text="Save to History", command=save_checked_password, style='Accent.TButton')
    ch_save_btn.pack(side=tk.LEFT, padx=5)
    ToolTip(ch_save_btn, "Save the currently checked password to your history (encryption recommended).")

    # --- HIBP Check Button ---
    def check_pwned_action():
        pwd = ch_entry.get()
        theme_colors = colors[current_theme]
        if not pwd:
            messagebox.showwarning("No Password", "Enter a password to check.")
            return

        update_status("Checking Have I Been Pwned...")
        pwned_label_ch.config(text="Checking...", foreground=theme_colors['fg'])
        root.update_idletasks() # Force UI update

        count = check_hibp(pwd)

        if count > 0:
            pwned_label_ch.config(text=f"PWNED! Found in {count:,} breaches.", foreground=theme_colors['pwned_fg'])
            update_status(f"Password found in {count:,} breaches.")
        elif count == 0:
            pwned_label_ch.config(text="Not found in known breaches.", foreground=theme_colors['good_fg'])
            update_status("Password not found in known breaches.")
        else: # count == -1 (error)
            pwned_label_ch.config(text="Pwned check failed (API error).", foreground=theme_colors['warn_fg'])
            update_status("Pwned check failed (API error).")

    ch_pwned_btn = ttk.Button(ch_button_frame, text="Check if Pwned", command=check_pwned_action, style='Warn.TButton')
    ch_pwned_btn.pack(side=tk.LEFT, padx=5)
    ToolTip(ch_pwned_btn, "Check if this password has appeared in known data breaches (via HIBP API).")


    # ############################
    # # Password Generator Tab
    # ############################
    gen_options_frame = ttk.Frame(generator_frame)
    gen_options_frame.pack(pady=10, fill='x')

    # Length Scale
    gen_len_frame = ttk.Frame(gen_options_frame)
    gen_len_frame.pack(fill='x')
    gen_len_lbl = ttk.Label(gen_len_frame, text="Password Length:")
    gen_len_lbl.pack(side=tk.LEFT, padx=(0,5))
    length_var = tk.IntVar(value=16) # Default length 16
    length_scale = ttk.Scale(
        gen_len_frame, from_=8, to=64, orient=tk.HORIZONTAL,
        variable=length_var, command=lambda v: length_val_lbl.config(text=f"{int(float(v))}")
    )
    length_scale.pack(side=tk.LEFT, fill='x', expand=True, padx=5)
    length_val_lbl = ttk.Label(gen_len_frame, text=f"{length_var.get()}", width=3)
    length_val_lbl.pack(side=tk.LEFT, padx=(5,0))

    # Checkboxes
    gen_checkbox_frame = ttk.Frame(generator_frame)
    gen_checkbox_frame.pack(pady=5, fill='x')
    # (Checkboxes remain similar, using grid for layout)
    include_lower_var = tk.BooleanVar(value=True)
    gen_lower_cb = ttk.Checkbutton(gen_checkbox_frame, text="Lowercase (a-z)", variable=include_lower_var)
    gen_lower_cb.grid(row=0, column=0, padx=10, pady=2, sticky='w')
    include_upper_var = tk.BooleanVar(value=True)
    gen_upper_cb = ttk.Checkbutton(gen_checkbox_frame, text="Uppercase (A-Z)", variable=include_upper_var)
    gen_upper_cb.grid(row=0, column=1, padx=10, pady=2, sticky='w')
    include_digits_var = tk.BooleanVar(value=True)
    gen_digits_cb = ttk.Checkbutton(gen_checkbox_frame, text="Digits (0-9)", variable=include_digits_var)
    gen_digits_cb.grid(row=1, column=0, padx=10, pady=2, sticky='w')
    include_special_var = tk.BooleanVar(value=True)
    gen_special_cb = ttk.Checkbutton(gen_checkbox_frame, text="Special Chars", variable=include_special_var) # Text changed
    gen_special_cb.grid(row=1, column=1, padx=10, pady=2, sticky='w')
    exclude_ambiguous_var = tk.BooleanVar(value=False)
    gen_ambiguous_cb = ttk.Checkbutton(gen_checkbox_frame, text=f"Exclude Ambiguous ({AMBIGUOUS_CHARS})", variable=exclude_ambiguous_var)
    gen_ambiguous_cb.grid(row=2, column=0, columnspan=2, padx=10, pady=2, sticky='w')
    ToolTip(gen_ambiguous_cb, "Excludes characters like I, l, 1, O, 0")

    # Custom Special Characters Entry
    gen_custom_special_frame = ttk.Frame(generator_frame)
    gen_custom_special_frame.pack(pady=5, fill='x')
    gen_custom_lbl = ttk.Label(gen_custom_special_frame, text="Custom Special:")
    gen_custom_lbl.pack(side=tk.LEFT, padx=(10, 5))
    custom_special_var = tk.StringVar(value=DEFAULT_SPECIAL_CHARS) # Initialize with default
    gen_custom_entry = ttk.Entry(gen_custom_special_frame, textvariable=custom_special_var, width=40)
    gen_custom_entry.pack(side=tk.LEFT, fill='x', expand=True, padx=5)
    ToolTip(gen_custom_entry, "Enter your own set of special characters to use if 'Special Chars' is checked.")
    # Update tooltip for the checkbox
    ToolTip(gen_special_cb, f"Include special characters (uses default or custom set below)")


    gen_result_frame = ttk.Frame(generator_frame)
    gen_result_frame.pack(pady=10, fill='x')
    gen_entry = ttk.Entry(gen_result_frame, width=50, font=("Courier", 12), state="readonly")
    gen_entry.pack(side=tk.LEFT, fill='x', expand=True, padx=(0, 5))
    # Use is_sensitive=True for password copy
    gen_copy_btn = ttk.Button(gen_result_frame, text="Copy", style='Copy.TButton',
                                command=lambda: copy_to_clipboard(gen_entry.get(), "Generated password copied!", is_sensitive=True))
    gen_copy_btn.pack(side=tk.LEFT)
    ToolTip(gen_copy_btn, "Copy generated password to clipboard (will auto-clear after 20s).")

    gen_button_frame = ttk.Frame(generator_frame)
    gen_button_frame.pack(pady=10)

    def generate_button_action():
        if not (include_lower_var.get() or include_upper_var.get() or include_digits_var.get() or include_special_var.get()):
            messagebox.showwarning("No Character Types", "Please select at least one character type.")
            return

        custom_specials = custom_special_var.get() if include_special_var.get() else None
        # Basic validation for custom specials if provided
        if include_special_var.get() and not custom_specials:
             messagebox.showwarning("Custom Specials Empty", "Custom special characters field is empty. Using default specials.")
             custom_specials = DEFAULT_SPECIAL_CHARS # Fallback to default

        new_password = generate_password(
            length_var.get(), include_lower_var.get(), include_upper_var.get(),
            include_digits_var.get(), include_special_var.get(), exclude_ambiguous_var.get(),
            custom_special_chars=custom_specials
        )
        gen_entry.config(state="normal")
        gen_entry.delete(0, tk.END)
        gen_entry.insert(0, new_password)
        gen_entry.config(state="readonly")
        update_status("New password generated.")

    gen_btn = ttk.Button(gen_button_frame, text="Generate Password", command=generate_button_action, style='Accent.TButton')
    gen_btn.pack(side=tk.LEFT, padx=5)
    ToolTip(gen_btn, "Generate a new random password based on selected criteria.")

    def clear_generator():
        gen_entry.config(state="normal")
        gen_entry.delete(0, tk.END)
        gen_entry.config(state="readonly")
        update_status("Generator field cleared.")

    gen_clear_btn = ttk.Button(gen_button_frame, text="Clear", command=clear_generator, style='Clear.TButton')
    gen_clear_btn.pack(side=tk.LEFT, padx=5)
    ToolTip(gen_clear_btn, "Clear the generated password field.")

    gen_export_btn = ttk.Button(gen_button_frame, text="Export", command=lambda: export_password_action(gen_entry.get()), style='Accent.TButton')
    gen_export_btn.pack(side=tk.LEFT, padx=5)
    ToolTip(gen_export_btn, "Export the generated password to a text file.")

    def save_generated_password():
        pwd = gen_entry.get()
        if not pwd:
            messagebox.showwarning("No Password", "Generate a password before saving.")
            return

        desc = simpledialog.askstring("Password Description", "Enter a brief description (optional):", parent=root)
        if desc is None: return

        if save_password_to_db(username, pwd, desc if desc else "Generated Password"):
             messagebox.showinfo("Saved", "Password saved to history.")
             update_status("Generated password saved to history.")
             refresh_history_tab() # Update history tab view

    gen_save_btn = ttk.Button(gen_button_frame, text="Save to History", command=save_generated_password, style='Accent.TButton')
    gen_save_btn.pack(side=tk.LEFT, padx=10)
    ToolTip(gen_save_btn, "Save the generated password to your history (encryption recommended).")


    # ############################
    # # Hash Generator Tab
    # ############################
    hash_lbl = ttk.Label(hasher_frame, text="Enter text to hash:", font=("Arial", 12))
    hash_lbl.pack(pady=(0, 5), anchor='w')

    hash_entry_frame = ttk.Frame(hasher_frame)
    hash_entry_frame.pack(pady=5, fill='x')
    hash_entry = ttk.Entry(hash_entry_frame, show="*", width=50, font=("Arial", 12))
    hash_entry.pack(side=tk.LEFT, fill='x', expand=True, padx=(0, 5))
    hash_paste_btn = ttk.Button(hash_entry_frame, text="Paste", command=lambda: paste_from_clipboard(hash_entry), style='Accent.TButton')
    hash_paste_btn.pack(side=tk.LEFT)
    ToolTip(hash_paste_btn, "Paste text from clipboard")

    show_hash_pwd_var = tk.BooleanVar()
    def update_hash_visibility():
         hash_entry.config(show="" if show_hash_pwd_var.get() else "*")
    hash_show_pwd_btn = ttk.Checkbutton(hasher_frame, text="Show Input Text", variable=show_hash_pwd_var, command=update_hash_visibility)
    hash_show_pwd_btn.pack(pady=(0,10), anchor='w')

    hash_warn_lbl = ttk.Label(
        hasher_frame,
        text="Note: MD5 and SHA1 are cryptographically broken and unsuitable for password storage.",
        font=("Arial", 9, "italic"), wraplength=650, justify='left'
        # Color set by apply_theme
    )
    hash_warn_lbl.pack(pady=5, anchor='w')

    hash_results_frame = ttk.Frame(hasher_frame)
    hash_results_frame.pack(pady=10, fill='x')

    # --- Function to create hash row (modified slightly) ---
    def create_hash_row(parent, label_text, is_insecure=False):
        row_frame = ttk.Frame(parent)
        row_frame.pack(fill='x', pady=2)
        lbl = ttk.Label(row_frame, text=f"{label_text}: ", font=("Courier", 10), width=8, anchor='e')
        lbl.pack(side=tk.LEFT, padx=(0,5))
        val_lbl = ttk.Label(row_frame, text="", font=("Courier", 10), anchor='w', wraplength=500) # Allow wrapping
        val_lbl.pack(side=tk.LEFT, fill='x', expand=True, padx=(0, 5))
        # Use is_sensitive=False for hashes (no auto-clear)
        copy_btn = ttk.Button(row_frame, text="Copy", width=6, style='Copy.TButton',
                                command=lambda v=val_lbl, lt=label_text: copy_to_clipboard(v.cget("text"), f"{lt} hash copied!", is_sensitive=False))
        copy_btn.pack(side=tk.RIGHT)
        ToolTip(copy_btn, f"Copy the {label_text} hash to clipboard.")
        return lbl, val_lbl, is_insecure # Return insecurity flag

    # Create rows, storing widgets and insecurity flag
    md5_lbl, md5_val_lbl, md5_insecure = create_hash_row(hash_results_frame, "MD5", True)
    sha1_lbl, sha1_val_lbl, sha1_insecure = create_hash_row(hash_results_frame, "SHA1", True)
    sha256_lbl, sha256_val_lbl, sha256_insecure = create_hash_row(hash_results_frame, "SHA256")
    sha512_lbl, sha512_val_lbl, sha512_insecure = create_hash_row(hash_results_frame, "SHA512")

    hash_widgets = [
        (md5_lbl, md5_val_lbl, md5_insecure),
        (sha1_lbl, sha1_val_lbl, sha1_insecure),
        (sha256_lbl, sha256_val_lbl, sha256_insecure),
        (sha512_lbl, sha512_val_lbl, sha512_insecure),
    ]

    def update_hashes(event=None):
        pwd = hash_entry.get()
        theme_colors = colors[current_theme]
        hashes = generate_hashes(pwd) # Handles empty pwd case

        for (label_widget, value_widget, is_insecure), hash_key in zip(hash_widgets, hashes.keys()):
            value_widget.config(text=hashes[hash_key])
            if pwd: # Only apply color if there is input
                fg_color = theme_colors['insecure_hash_fg'] if is_insecure else theme_colors['fg']
            else: # Reset color if input is empty
                fg_color = theme_colors['fg']
            value_widget.config(foreground=fg_color)
            label_widget.config(foreground=fg_color)

    hash_entry.bind("<KeyRelease>", update_hashes)

    hash_button_frame = ttk.Frame(hasher_frame)
    hash_button_frame.pack(pady=10)

    def clear_hasher():
        hash_entry.delete(0, tk.END)
        update_hashes()
        update_status("Hasher input cleared.")

    hash_clear_btn = ttk.Button(hash_button_frame, text="Clear Input", command=clear_hasher, style='Clear.TButton')
    hash_clear_btn.pack(side=tk.LEFT, padx=10)
    ToolTip(hash_clear_btn, "Clear the text input field for hashing.")

    # ############################
    # # Password History Tab
    # ############################
    history_lbl = ttk.Label(history_frame, text="Saved Passwords", font=("Arial", 12))
    history_lbl.pack(pady=(0, 5), anchor='w')
    # Add warning about plaintext storage if encryption not implemented
    # TODO: Remove this label once DB encryption is properly implemented
    history_warn_lbl = ttk.Label(history_frame, text="Warning: Passwords currently stored unencrypted in DB.", font=("Arial", 9, "italic"), foreground=colors[current_theme]['warn_fg'])
    history_warn_lbl.pack(pady=(0, 10), anchor='w')

    # Frame to hold Treeview and Scrollbar together
    tree_frame = ttk.Frame(history_frame)
    tree_frame.pack(fill="both", expand=True)

    history_tree = ttk.Treeview(
        tree_frame,
        columns=("ID", "Description", "Password", "Created"),
        show="headings", # Hide the default first empty column
        style="Treeview" # Apply Treeview style
    )
    history_tree.heading("ID", text="ID", command=lambda: sort_history_column('ID', False))
    history_tree.heading("Description", text="Description", command=lambda: sort_history_column('Description', False))
    history_tree.heading("Password", text="Password") # No sorting on password column
    history_tree.heading("Created", text="Date Saved", command=lambda: sort_history_column('Created', True)) # Sort descending initially

    history_tree.column("ID", width=50, anchor='center', stretch=tk.NO)
    history_tree.column("Description", width=250)
    history_tree.column("Password", width=200)
    history_tree.column("Created", width=150, anchor='center')

    # Add Scrollbar
    history_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=history_tree.yview)
    history_tree.configure(yscrollcommand=history_scrollbar.set)

    history_tree.pack(side=tk.LEFT, fill="both", expand=True)
    history_scrollbar.pack(side=tk.RIGHT, fill="y")

    # Variable to track sort column and direction
    history_sort_column = 'Created'
    history_sort_reversed = True

    def sort_history_column(col_name, default_reverse=False):
        """Sorts the history treeview by the clicked column."""
        nonlocal history_sort_column, history_sort_reversed

        # Toggle direction if sorting the same column again
        if col_name == history_sort_column:
             history_sort_reversed = not history_sort_reversed
        else:
             history_sort_column = col_name
             history_sort_reversed = default_reverse

        # Get data from treeview rows: list of (values_tuple, item_id)
        l = [(history_tree.set(k, col_name), k) for k in history_tree.get_children('')]

        # Sort based on data type
        try:
            if col_name == 'ID':
                l.sort(key=lambda t: int(t[0]), reverse=history_sort_reversed)
            elif col_name == 'Created':
                 # Basic ISO format sort should work for timestamps like 'YYYY-MM-DD HH:MM:SS'
                 l.sort(key=lambda t: t[0], reverse=history_sort_reversed)
            else: # Sort Description as case-insensitive string
                l.sort(key=lambda t: t[0].lower(), reverse=history_sort_reversed)
        except ValueError as e:
            logging.error(f"Error sorting history column '{col_name}': {e}", exc_info=True)
            # Fallback to simple string sort if conversion fails
            l.sort(key=lambda t: str(t[0]), reverse=history_sort_reversed)

        # Rearrange items in treeview
        for index, (val, k) in enumerate(l):
            history_tree.move(k, '', index)

        # Update heading indicator (optional visual feedback)
        for col in ("ID", "Description", "Created"):
             history_tree.heading(col, text=col) # Reset text
        arrow = ' ↓' if history_sort_reversed else ' ↑'
        history_tree.heading(col_name, text=col_name + arrow)
        logging.debug(f"Sorted history by {col_name}, Reversed: {history_sort_reversed}")


    def refresh_history_tab():
        """Clears and reloads the password history treeview."""
        logging.debug("Refreshing history tab.")
        # Clear existing items
        for item in history_tree.get_children():
            history_tree.delete(item)

        # Fetch and insert new data
        passwords_data = get_passwords_from_db(username) # List of dicts
        for entry in passwords_data:
            # Format timestamp nicely
            created_at_formatted = entry['created_at'] # Default
            try:
                # Attempt to parse common formats, adjust as needed for your DB
                # Example: '2024-03-15 10:30:00.123456' -> '2024-03-15 10:30:00'
                dt_obj = datetime.fromisoformat(entry['created_at'].split('.')[0])
                created_at_formatted = dt_obj.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                 logging.warning(f"Could not parse timestamp format: {entry['created_at']}")
                 pass # Keep original string if parsing fails

            # TODO: Replace entry['password'] with '********' if visibility toggle is off
            history_tree.insert("", tk.END, values=(
                entry['id'],
                entry['description'],
                entry['password'], # Displaying plain text (INSECURE)
                created_at_formatted
                ))
        update_status(f"Password history refreshed ({len(passwords_data)} items).")
        # Optionally re-sort after refresh based on current sort settings
        if history_sort_column:
             sort_history_column(history_sort_column, history_sort_reversed) # Re-apply sort


    # History Tab Buttons
    history_button_frame = ttk.Frame(history_frame)
    history_button_frame.pack(pady=10, fill='x')

    refresh_hist_btn = ttk.Button(history_button_frame, text="Refresh", command=refresh_history_tab, style='Accent.TButton')
    refresh_hist_btn.pack(side=tk.LEFT, padx=5)
    ToolTip(refresh_hist_btn, "Reload the password list from the database.")

    def delete_selected_password():
        selected_items = history_tree.selection() # Can select multiple
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select one or more password entries to delete.")
            return

        confirm_msg = f"Are you sure you want to delete {len(selected_items)} selected password entr{'y' if len(selected_items)==1 else 'ies'}?"
        confirm = messagebox.askyesno("Confirm Delete", confirm_msg, icon='warning')

        if confirm:
            deleted_count = 0
            errors = 0
            try:
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                for item_id_in_tree in selected_items:
                    item_values = history_tree.item(item_id_in_tree)['values']
                    password_db_id = item_values[0] # Assuming ID is the first column
                    logging.info(f"Attempting to delete password entry ID {password_db_id} for user '{username}'.")
                    cursor.execute("DELETE FROM passwords WHERE id = ? AND username = ?", (password_db_id, username))
                    if cursor.rowcount > 0:
                        deleted_count += 1
                    else:
                         errors += 1
                         logging.warning(f"Could not delete password ID {password_db_id} (not found or wrong user?).")
                conn.commit()
                conn.close()

                if deleted_count > 0:
                    messagebox.showinfo("Deleted", f"{deleted_count} password entr{'y' if deleted_count==1 else 'ies'} deleted.")
                    update_status(f"{deleted_count} password entr{'y' if deleted_count==1 else 'ies'} deleted.")
                    refresh_history_tab() # Refresh list
                if errors > 0:
                     messagebox.showerror("Error", f"Could not delete {errors} selected entr{'y' if errors==1 else 'ies'} (not found or permission issue).")

            except sqlite3.Error as e:
                logging.error(f"Database error deleting passwords: {e}", exc_info=True)
                messagebox.showerror("Database Error", f"Could not delete password(s): {e}")

    delete_hist_btn = ttk.Button(history_button_frame, text="Delete Selected", command=delete_selected_password, style='Warn.TButton')
    delete_hist_btn.pack(side=tk.LEFT, padx=5)
    ToolTip(delete_hist_btn, "Permanently delete the selected password entry/entries from the history.")

    # --- Audit Button ---
    def run_audit_action():
        check_pwned_audit = messagebox.askyesno(
            "Audit Option",
            "Do you want to check passwords against Have I Been Pwned during the audit?\n"
            "(This will make multiple API calls and may take time).",
            parent=root
        )
        update_status("Running password audit...")
        root.update_idletasks()
        audit_results = audit_passwords(username, check_pwned=check_pwned_audit)
        update_status("Audit complete. Displaying results...")
        if audit_results:
             display_audit_results(audit_results, root)
        update_status("Ready.")


    audit_hist_btn = ttk.Button(history_button_frame, text="Audit History", command=run_audit_action, style='Accent.TButton')
    audit_hist_btn.pack(side=tk.LEFT, padx=5)
    ToolTip(audit_hist_btn, "Scan saved passwords for weaknesses, reuse, and optional breach checks.")

    # Copy Password from History
    def copy_selected_password():
         selected_item = history_tree.focus()
         if not selected_item:
              messagebox.showwarning("No Selection", "Please select a password entry to copy.")
              return
         item_values = history_tree.item(selected_item)['values']
         password_to_copy = item_values[2] # Assuming Password is the third column
         copy_to_clipboard(password_to_copy, "Password copied from history!", is_sensitive=True)

    copy_hist_btn = ttk.Button(history_button_frame, text="Copy Password", command=copy_selected_password, style='Copy.TButton')
    copy_hist_btn.pack(side=tk.LEFT, padx=5)
    ToolTip(copy_hist_btn, "Copy the selected password to clipboard (will auto-clear after 20s).")


    # Initial population of history tab
    refresh_history_tab()

    # ############################
    # # Menu Bar
    # ############################
    menu_bar = tk.Menu(root)

    # File Menu
    file_menu = tk.Menu(menu_bar, tearoff=0)
    file_menu.add_command(label="Show Analytics", command=lambda: show_analytics(username))
    # Add option to export *all* history (needs secure implementation)
    # file_menu.add_command(label="Export History...", command=export_all_history) # Placeholder
    file_menu.add_separator()
    file_menu.add_command(label="Logout", command=lambda: [root.destroy(), login_screen()]) # Simple logout
    file_menu.add_command(label="Exit", command=on_exit)
    menu_bar.add_cascade(label="File", menu=file_menu)

    # Settings Menu
    settings_menu = tk.Menu(menu_bar, tearoff=0)
    # Add a function to toggle between dark and light mode
    def toggle_theme():
        nonlocal current_theme
        current_theme = 'dark' if current_theme == 'light' else 'light'
        dark_mode.set(current_theme == 'dark')
        apply_theme()

    # Update the dark mode checkbutton to use the toggle_theme function
    settings_menu.add_checkbutton(label="Dark Mode", variable=dark_mode, command=toggle_theme)
    # Add command to open settings configuration window (Placeholder)
    # settings_menu.add_command(label="Configure Settings...", command=open_settings_window)
    menu_bar.add_cascade(label="Settings", menu=settings_menu)

    # Help Menu
    help_menu = tk.Menu(menu_bar, tearoff=0)
    help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "Password Utility Tool v3.0\nEnhanced Version"))
    menu_bar.add_cascade(label="Help", menu=help_menu)

    root.config(menu=menu_bar)

    # Apply the initial theme
    current_theme = 'dark' if dark_mode.get() else 'light'
    apply_theme()
    # Update checker and hasher displays initially
    checker_live_feedback()
    update_hashes()

    logging.info(f"Main application window created for user '{username}'.")
    root.mainloop()


# --- Main Execution ---
if __name__ == "__main__":
    # Ensures the script block runs only when executed directly
    login_screen() # Start with the login screen