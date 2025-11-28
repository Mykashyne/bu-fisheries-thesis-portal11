"""
E-Thesis Portal: Bicol University Tabaco - Fisheries Department
A Flask web application for managing and accessing thesis abstracts (2015-2025)

Installation Requirements:
pip install flask flask-login werkzeug

To run:
python app.py

Default Admin Login:
Username: admin
Password: admin123
(Change this in production!)
"""

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize Flask-Login
login_manager = LoginManager()
@login_manager.user_loader
def load_user(user_id):
    """Load user from database for Flask-Login"""
    conn = sqlite3.connect('thesis_portal.db')
    c = conn.cursor()
    c.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()

    if user_data:
        return User(user_data[0], user_data[1])
    return None


login_manager.init_app(app)
login_manager.login_view = 'login'


# Database setup
def init_db():
    """Initialize the SQLite database with required tables"""
    conn = sqlite3.connect('thesis_portal.db')
    c = conn.cursor()

    # Create users table (for admin)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 1
    )''')

    # Create theses table
    c.execute('''CREATE TABLE IF NOT EXISTS theses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        authors TEXT NOT NULL,
        year INTEGER NOT NULL,
        adviser TEXT NOT NULL,
        abstract TEXT NOT NULL,
        keywords TEXT NOT NULL,
        pdf_filename TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Create default admin if not exists
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        admin_password = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                  ('admin', admin_password))

    conn.commit()
    conn.close()


# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username


def allowed_file(filename):
    """Check if uploaded file is a PDF"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# ------------------------------------------------------------
# STATIC FILE ROUTE (✔ MUST be above the main block)
# ------------------------------------------------------------
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)


# Routes
@app.route('/')
def home():
    """Home page with search functionality"""
    search_query = request.args.get('search', '')
    year_filter = request.args.get('year', '')

    conn = sqlite3.connect('thesis_portal.db')
    c = conn.cursor()

    # Build SQL query based on search parameters
    if search_query or year_filter:
        query = """SELECT * FROM theses WHERE 
                   (title LIKE ? OR authors LIKE ? OR keywords LIKE ? OR abstract LIKE ?)"""
        params = [f'%{search_query}%'] * 4

        if year_filter:
            query += " AND year = ?"
            params.append(year_filter)

        query += " ORDER BY year DESC, title ASC"
        c.execute(query, params)
    else:
        c.execute("SELECT * FROM theses ORDER BY year DESC, title ASC")

    theses = c.fetchall()

    # Get available years for filter dropdown
    c.execute("SELECT DISTINCT year FROM theses ORDER BY year DESC")
    available_years = [row[0] for row in c.fetchall()]

    conn.close()

    return render_template('home.html', theses=theses, search_query=search_query,
                           year_filter=year_filter, available_years=available_years)


@app.route('/thesis/<int:thesis_id>')
def view_thesis(thesis_id):
    """View detailed thesis information"""
    conn = sqlite3.connect('thesis_portal.db')
    c = conn.cursor()
    c.execute("SELECT * FROM theses WHERE id = ?", (thesis_id,))
    thesis = c.fetchone()
    conn.close()

    if not thesis:
        flash('Thesis not found.', 'error')
        return redirect(url_for('home'))

    return render_template('view_thesis.html', thesis=thesis)


@app.route('/download/<filename>')
def download_file(filename):
    """Download PDF file"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = sqlite3.connect('thesis_portal.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_data = c.fetchone()
        conn.close()

        if user_data and check_password_hash(user_data[2], password):
            user = User(user_data[0], user_data[1])
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Logout admin"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Admin dashboard showing all theses"""
    conn = sqlite3.connect('thesis_portal.db')
    c = conn.cursor()
    c.execute("SELECT * FROM theses ORDER BY year DESC, title ASC")
    theses = c.fetchall()
    conn.close()

    return render_template('dashboard.html', theses=theses)


@app.route('/add_thesis', methods=['GET', 'POST'])
@login_required
def add_thesis():
    """Add new thesis (admin only)"""
    if request.method == 'POST':
        title = request.form.get('title')
        authors = request.form.get('authors')
        year = request.form.get('year')
        adviser = request.form.get('adviser')
        abstract = request.form.get('abstract')
        keywords = request.form.get('keywords')

        # Validate year
        try:
            year = int(year)
            if year < 2015 or year > 2025:
                flash('Year must be between 2015 and 2025.', 'error')
                return redirect(url_for('add_thesis'))
        except ValueError:
            flash('Invalid year format.', 'error')
            return redirect(url_for('add_thesis'))

        # Handle PDF upload
        pdf_filename = None
        if 'pdf_file' in request.files:
            file = request.files['pdf_file']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Add timestamp to filename to avoid conflicts
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                pdf_filename = f"{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename))

        # Insert into database
        conn = sqlite3.connect('thesis_portal.db')
        c = conn.cursor()
        c.execute("""INSERT INTO theses (title, authors, year, adviser, abstract, keywords, pdf_filename)
                     VALUES (?, ?, ?, ?, ?, ?, ?)""",
                  (title, authors, year, adviser, abstract, keywords, pdf_filename))
        conn.commit()
        conn.close()

        flash('Thesis added successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_thesis.html')


@app.route('/edit_thesis/<int:thesis_id>', methods=['GET', 'POST'])
@login_required
def edit_thesis(thesis_id):
    """Edit existing thesis (admin only)"""
    conn = sqlite3.connect('thesis_portal.db')
    c = conn.cursor()

    if request.method == 'POST':
        title = request.form.get('title')
        authors = request.form.get('authors')
        year = request.form.get('year')
        adviser = request.form.get('adviser')
        abstract = request.form.get('abstract')
        keywords = request.form.get('keywords')

        # Validate year
        try:
            year = int(year)
            if year < 2015 or year > 2025:
                flash('Year must be between 2015 and 2025.', 'error')
                return redirect(url_for('edit_thesis', thesis_id=thesis_id))
        except ValueError:
            flash('Invalid year format.', 'error')
            return redirect(url_for('edit_thesis', thesis_id=thesis_id))

        # Get current thesis data
        c.execute("SELECT pdf_filename FROM theses WHERE id = ?", (thesis_id,))
        current_pdf = c.fetchone()[0]
        pdf_filename = current_pdf

        # Handle new PDF upload
        if 'pdf_file' in request.files:
            file = request.files['pdf_file']
            if file and file.filename and allowed_file(file.filename):
                # Delete old PDF if exists
                if current_pdf:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], current_pdf)
                    if os.path.exists(old_path):
                        os.remove(old_path)

                # Save new PDF
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                pdf_filename = f"{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename))

        # Update database
        c.execute("""UPDATE theses SET title=?, authors=?, year=?, adviser=?, 
                     abstract=?, keywords=?, pdf_filename=? WHERE id=?""",
                  (title, authors, year, adviser, abstract, keywords, pdf_filename, thesis_id))
        conn.commit()
        conn.close()

        flash('Thesis updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    # GET request - show edit form
    c.execute("SELECT * FROM theses WHERE id = ?", (thesis_id,))
    thesis = c.fetchone()
    conn.close()

    if not thesis:
        flash('Thesis not found.', 'error')
        return redirect(url_for('dashboard'))

    return render_template('edit_thesis.html', thesis=thesis)


@app.route('/delete_thesis/<int:thesis_id>', methods=['POST'])
@login_required
def delete_thesis(thesis_id):
    """Delete thesis (admin only)"""
    conn = sqlite3.connect('thesis_portal.db')
    c = conn.cursor()

    # Get PDF filename before deleting
    c.execute("SELECT pdf_filename FROM theses WHERE id = ?", (thesis_id,))
    result = c.fetchone()

    if result and result[0]:
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], result[0])
        if os.path.exists(pdf_path):
            os.remove(pdf_path)

    # Delete from database
    c.execute("DELETE FROM theses WHERE id = ?", (thesis_id,))
    conn.commit()
    conn.close()

    flash('Thesis deleted successfully!', 'success')
    return redirect(url_for('dashboard'))


# ------------------------------------------------------------
# MAIN APP RUNNER (✔ Always the last part)
# ------------------------------------------------------------
if __name__ == '__main__':
    # Initialize database on first run
    init_db()

    # For local development
    app.run(debug=True, host='0.0.0.0', port=5000)
else:
    # For production (Railway will use this)
    init_db()

