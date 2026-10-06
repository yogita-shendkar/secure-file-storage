from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
import os
from dotenv import load_dotenv

load_dotenv()

import uuid
import secrets
import time
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
import mysql.connector

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get('FLASK_COOKIE_SECURE', '0') == '1',
    SESSION_COOKIE_SAMESITE='Lax',
)

base_dir = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(base_dir, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'png', 'jpg','docx','txt','xlsx'}
app.config['SEND_FILE_MAX_AGE_DEFAULT']=0

#  DATABASE CONFIGURATION
db_config = {

    'host': os.environ.get('DB_HOST', 'localhost'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD'),
    'database': os.environ.get('DB_NAME', 'secure_file_system')
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

def log_action(user_id, action, details, actor_type=None, file_id=None, success=True):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        actor_type = actor_type or ('admin' if session.get('role') == 'admin' else 'user' if session.get('role') == 'user' else 'system')
        cursor.execute(
            """INSERT INTO audit_log
               (actor_id, actor_type, action_type, detail, file_id, ip_address, success)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (user_id, actor_type, action, details, file_id, request.remote_addr, success),
        )
        conn.commit()
    except mysql.connector.Error as error:
        print(f"Audit log error: {error}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def password_matches(stored_password, submitted_password):
    if stored_password.startswith(('scrypt:', 'pbkdf2:')):
        return check_password_hash(stored_password, submitted_password)
    return stored_password == submitted_password


def is_admin():
    return session.get('loggedin') and session.get('role') == 'admin'


def csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']


@app.context_processor
def inject_security_helpers():
    return {'csrf_token': csrf_token}


@app.before_request
def validate_csrf_token():
    if request.method == 'POST':
        submitted_token = request.form.get('_csrf_token')
        if not submitted_token or not secrets.compare_digest(submitted_token, session.get('csrf_token', '')):
            abort(400, description='Invalid or missing CSRF token.')


login_attempts = {}


def login_is_rate_limited(identifier):
    now = time.time()
    attempts = [attempt for attempt in login_attempts.get(identifier, []) if now - attempt < 900]
    login_attempts[identifier] = attempts
    return len(attempts) >= 5


def record_failed_login(identifier):
    login_attempts.setdefault(identifier, []).append(time.time())


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def storage_path(file_path):
    normalized_path = str(file_path).replace('\\', '/')
    path_parts = normalized_path.split('/')
    if normalized_path.startswith('/') or '..' in path_parts:
        abort(404)

    filename = secure_filename(path_parts[-1])
    if not filename:
        abort(404)
    directory = os.path.abspath(app.config['UPLOAD_FOLDER'])
    candidate = os.path.abspath(os.path.join(directory, filename))
    if os.path.commonpath((directory, candidate)) != directory:
        abort(404)
    return candidate


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    message = 'That file is too large. Please choose a file smaller than 10 MB.'
    if session.get('role') == 'admin':
        flash(message, 'error')
        return redirect(url_for('admin_dashboard'))
    if session.get('role') == 'user':
        flash(message, 'error')
        return redirect(url_for('user_dashboard'))
    return message, 413

# ROUTES 

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password')

        if login_is_rate_limited(email):
            log_action(None, 'login_rate_limited', f'Login temporarily blocked for {email or "unknown email"}.', actor_type='system', success=False)
            return "<h1>Login Failed</h1><p>Too many attempts. Please try again later.</p><a href='/login'>Try Again</a>", 429

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM admin WHERE email = %s", (email,))
            admin = cursor.fetchone()
            if admin and password_matches(admin['password_hash'], password):
                session.clear()
                log_action(admin['a_id'], 'login_success', 'Administrator logged in.', actor_type='admin')
                session['loggedin'] = True
                session['id'] = admin['a_id']
                session['role'] = 'admin'
                if admin['password_hash'] == password:
                    cursor.execute("UPDATE admin SET password_hash = %s WHERE a_id = %s", (generate_password_hash(password), admin['a_id']))
                    conn.commit()
                return redirect(url_for('admin_dashboard'))

            cursor.execute("SELECT u_id, email, password_hash, status, role FROM user WHERE email = %s", (email,))
            user = cursor.fetchone()
            if user and password_matches(user['password_hash'], password):
                if user['status'] == 'pending':
                    log_action(user['u_id'], 'login_blocked', 'Login blocked because the account is pending approval.')
                    flash('Your account is pending Admin approval.', 'error')
                    return redirect(url_for('login'))

                session.clear()
                log_action(user['u_id'], 'login_success', 'User logged in.', actor_type='user')
                session['loggedin'] = True
                session['id'] = user['u_id']
                session['role'] = user['role']
                session['email'] = user['email']

                if user['password_hash'] == password:
                    cursor.execute("UPDATE user SET password_hash = %s WHERE u_id = %s", (generate_password_hash(password), user['u_id']))
                    conn.commit()

                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('user_dashboard'))

            record_failed_login(email)
            log_action(None, 'login_failed', f'Failed login attempt for {email or "unknown email"}.', actor_type='system', success=False)
            if not admin and not user:
                flash('No account found for this email. Please register first.', 'error')
            else:
                flash('Invalid credentials.', 'error')
            return redirect(url_for('login'))
        finally:
            cursor.close()
            conn.close()
    

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT u_id FROM user WHERE email = %s", (email,))
            if cursor.fetchone():
                return "Email already exists! <a href='/register'>Try again</a>"

            cursor.execute("INSERT INTO user (email, password_hash, status) VALUES (%s, %s, 'pending')", (email, generate_password_hash(password)))
            conn.commit()
        finally:
            cursor.close()
            conn.close()
        return "Registration successful! Wait for Admin approval. <a href='/login'>Go to Login</a>"

    return render_template('registration.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/admin_dashboard')
def admin_dashboard():
    
    if not is_admin():
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT u_id, email, status FROM user")
    pending_users = cursor.fetchall()

    cursor.execute("""SELECT DISTINCT f.f_id, f.f_name, f.f_path, u.email AS owner_email FROM file f JOIN user u ON f.owner_id= u.u_id""") 
    all_files = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin_dashboard.html', users=pending_users, files=all_files)

@app.route('/approve_user/<int:user_id>', methods=['POST'])
def approve_user(user_id):
    if not is_admin():
        return "Unauthorized", 403

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE user SET status = 'active', approved_at = CURRENT_TIMESTAMP, approved_by = %s WHERE u_id = %s",
        (session.get('id'), user_id),
    )
    conn.commit()
    log_action(session.get('id'), 'user_approved', f'Approved user account {user_id}.')
    
    cursor.close()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/upload', methods=['POST']) # admin upload route
def upload_file():
    if not is_admin():
        return "Unauthorized", 403

    if 'file' not in request.files:
        return redirect(url_for('admin_dashboard'))
    
    file = request.files['file']
    assigned_to = request.form.get('target_user_id') # From your dropdown

    if file.filename == '':
        return redirect(url_for('admin_dashboard'))

    filename = secure_filename(file.filename)
    if not allowed_file(filename):
        flash('Unsupported file type. Please upload a PDF, PNG , JPG , DOCX , TXT or XLSX file.', 'error')
        return redirect(url_for('admin_dashboard'))

    if file and assigned_to:
        stored_filename = f'{uuid.uuid4().hex}_{filename}'
        file_save_path = storage_path(stored_filename)
        db_relative_path = os.path.join('uploads', stored_filename)

        file.save(file_save_path)

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        check_sql = "SELECT f_id FROM file WHERE f_name = %s AND owner_id = %s"
        cursor.execute(check_sql, (filename, assigned_to))
        
        if cursor.fetchone() is None:
            try:
                insert_sql = "INSERT INTO file (f_name, f_path, owner_id) VALUES (%s, %s, %s)"
                cursor.execute(insert_sql, (filename, db_relative_path, assigned_to))
                file_id = cursor.lastrowid
                conn.commit()
                log_action(session.get('id'), 'file_uploaded', f'Uploaded and assigned {filename} to user {assigned_to}.', file_id=file_id)
                print(f"SUCCESS: {filename} assigned to user {assigned_to}")
            except Exception as error:
                conn.rollback()
                if os.path.exists(file_save_path):
                    os.remove(file_save_path)
                log_action(session.get('id'), 'file_upload_failed', f'Failed to upload {filename} for user {assigned_to}: {error}', success=False)
                flash('The file could not be uploaded. Please try again.', 'error')
                cursor.close()
                conn.close()
                return redirect(url_for('admin_dashboard'))
        else:
            if os.path.exists(file_save_path):
                os.remove(file_save_path)
            log_action(session.get('id'), 'file_upload_skipped', f'Skipped duplicate file {filename} for user {assigned_to}.', success=False)
            print(f"SKIP: {filename} already exists for this user in database.")

        log_action(session.get('id'), 'file_upload_attempt', f'Attempted to upload {filename} for user {assigned_to}.')
        cursor.close()
        conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/user_upload', methods=['POST'])
def user_upload_file():
    if not session.get('loggedin') or session.get('role') != 'user':
        flash('Please log in as a user to upload files.', 'error')
        return redirect(url_for('login'))

    file = request.files.get('file')
    if file is None or not file.filename:
        flash('Choose a file before uploading.', 'error')
        return redirect(url_for('user_dashboard'))

    original_filename = secure_filename(file.filename)
    if not original_filename:
        flash('That filename is not valid.', 'error')
        return redirect(url_for('user_dashboard'))

    if not allowed_file(original_filename):
        flash('Unsupported file type. Please upload a PDF, PNG, JPG or DOCX file.', 'error')
        return redirect(url_for('user_dashboard'))

    stored_filename = f'{uuid.uuid4().hex}_{original_filename}'
    file_save_path = storage_path(stored_filename)
    db_relative_path = os.path.join('uploads', stored_filename)

    try:
        file.save(file_save_path)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO file (f_name, f_path, owner_id) VALUES (%s, %s, %s)",
            (original_filename, db_relative_path, session['id'])
        )
        file_id = cursor.lastrowid
        conn.commit()
        log_action(session.get('id'), 'file_uploaded', f'Uploaded {original_filename}.', file_id=file_id)
        flash(f'{original_filename} uploaded successfully.', 'success')
    except Exception as error:
        if 'conn' in locals():
            conn.rollback()
        if os.path.exists(file_save_path):
            os.remove(file_save_path)
        log_action(session.get('id'), 'file_upload_failed', f'Failed to upload {original_filename}: {error}', success=False)
        flash('The file could not be uploaded. Please try again.', 'error')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

    return redirect(url_for('user_dashboard'))

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if not session.get('loggedin'):
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT f_name, f_path, owner_id FROM file WHERE f_id = %s", (file_id,))
    file_data = cursor.fetchone()
    permitted = False
    if file_data and session.get('role') != 'admin':
        cursor.execute(
            "SELECT 1 FROM file_shares WHERE file_id = %s AND shared_with = %s AND revoked_at IS NULL LIMIT 1",
            (file_id, session.get('id')),
        )
        permitted = cursor.fetchone() is not None
    cursor.close()
    conn.close()

    if not file_data:
        return "File not found.", 404

    if session.get('role') != 'admin' and file_data['owner_id'] != session.get('id') and not permitted:
        return "Unauthorized", 403

    directory = os.path.abspath(app.config['UPLOAD_FOLDER'])
    filename = os.path.basename(file_data['f_path'])
    file_path = os.path.join(directory, filename)
    if os.path.exists(file_path):
        log_action(session.get('id'), 'file_downloaded', f'Downloaded {file_data["f_name"]}.', file_id=file_id)
        return send_from_directory(directory, filename, as_attachment=True, download_name=file_data['f_name'])
    else:
        return f"Error : File {filename} not found in uploads folder.", 404

@app.route('/user_dashboard')
def user_dashboard():
    if not session.get('loggedin'):
        return redirect(url_for('login'))
    
    user_id = session.get('id')
    print(f"Debug : current user ID in session is{user_id}")
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute(
        """SELECT f_id, f_name, f_path ,owner_id, upload_date
           FROM file
           WHERE owner_id = %s
           
              OR EXISTS (
                  SELECT 1 FROM file_shares fs
                  WHERE fs.file_id = file.f_id AND fs.shared_with = %s AND fs.revoked_at IS NULL
              )
           ORDER BY upload_date DESC""",
        (user_id, user_id),
    )
    user_files = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('user_dashboard.html', files=user_files)


@app.route('/share_file/<int:file_id>', methods=['POST'])
def share_file(file_id):
    if not session.get('loggedin') or session.get('role') != 'user':
        return "Unauthorized", 403

    recipient_email = (request.form.get('recipient_email') or '').strip().lower()
    if not recipient_email:
        flash('Enter the email address of the user you want to share with.', 'error')
        return redirect(url_for('user_dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT f_id FROM file WHERE f_id = %s AND owner_id = %s",
            (file_id, session.get('id')),
        )
        if cursor.fetchone() is None:
            return "Unauthorized", 403

        cursor.execute(
            "SELECT u_id, status FROM User WHERE email = %s AND role = 'user'",
            (recipient_email,),
        )
        recipient = cursor.fetchone()
        if not recipient or recipient['status'] != 'active':
            flash('That user does not have an active account.', 'error')
            return redirect(url_for('user_dashboard'))
        if recipient['u_id'] == session.get('id'):
            flash('You already own this file.', 'error')
            return redirect(url_for('user_dashboard'))

        cursor.execute(
            """INSERT INTO file_shares (file_id, shared_by, shared_with, access_level)
               VALUES (%s, %s, %s, 'download')
               ON DUPLICATE KEY UPDATE access_level = 'download', revoked_at = NULL""",
            (file_id, session.get('id'), recipient['u_id']),
        )
        conn.commit()
        log_action(session.get('id'), 'file_shared', f'Shared file {file_id} with {recipient_email}.', file_id=file_id)
        flash('File shared successfully.', 'success')
    except mysql.connector.Error:
        conn.rollback()
        flash('The file could not be shared. Please try again.', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('user_dashboard'))

@app.route('/delete_file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    # 1. Security check
    if not is_admin():
        flash("Unauthorized access!", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT f_name, f_path FROM file WHERE f_id = %s", (file_id,))
        file_record = cursor.fetchone()

        if file_record:
            filename = file_record['f_name']
            directory = os.path.abspath(app.config['UPLOAD_FOLDER'])
            filename = os.path.basename(file_record['f_path'])
            file_path = os.path.join(directory, filename)

            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Physical file {filename} removed.")

            cursor.execute("DELETE FROM file WHERE f_id = %s", (file_id,))
            conn.commit()
            log_action(session.get('id'), 'file_deleted', f'Deleted file {filename} (ID {file_id}).')
            
            flash(f"File '{filename}' deleted successfully.", "success")

        else:
            flash("File not found in database.", "warning")

    except Exception as e:
        print(f"Error during deletion: {e}")
        conn.rollback()
        flash("An error occurred during deletion.", "danger")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/audit_logs')
def audit_logs():
    if not is_admin():
        return redirect(url_for('login'))

    logs = []
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT log_id, actor_id, actor_type, action_type, action_timestamp,
                   detail, file_id, ip_address, success
            FROM audit_log
            ORDER BY action_timestamp DESC, log_id DESC
            LIMIT 50
        """)
        logs = cursor.fetchall()
        print("DEBUG LOGS FETCHED:", logs)  # Terminal check
        
    except Exception as e:
        print(f"Error fetching audit logs: {e}")
        logs = []
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return render_template('audit_logs.html', logs=logs)
if __name__ == '__main__':
    # app.run(debug=True)
    from waitress import serve
    print("serving production app on http://0.0.0.0:8080")
    serve(app, host='0.0.0.0', port=8080)