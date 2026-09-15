import os
import sqlite3
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import get_connection, initialize_database
from crypto_utils import (generate_rsa_keypair, encrypt_file, decrypt_file,
                          encrypt_aes_key, decrypt_aes_key)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-only-change-this-secret-key')
initialize_database()


def logged_in_user_id():
    return session.get('user_id')


def login_required():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return None


@app.route('/')
def index():
    return redirect(url_for('dashboard')) if logged_in_user_id() else redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Username and password are required.')
            return render_template('signup.html')
        public_key, private_key = generate_rsa_keypair()
        connection = get_connection()
        try:
            connection.execute('''INSERT INTO users
                (username, password_hash, public_key, private_key)
                VALUES (?, ?, ?, ?)''',
                (username, generate_password_hash(password), public_key, private_key))
            connection.commit()
        except sqlite3.IntegrityError:
            flash('That username already exists.')
            connection.close()
            return render_template('signup.html')
        connection.close()
        flash('Account created. Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        connection = get_connection()
        user = connection.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        connection.close()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    required = login_required()
    if required: return required
    return render_template('dashboard.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    required = login_required()
    if required: return required
    connection = get_connection()
    users = connection.execute('SELECT id, username FROM users WHERE id != ?', (session['user_id'],)).fetchall()
    if request.method == 'POST':
        receiver_id = request.form.get('receiver_id')
        uploaded = request.files.get('file')
        if not receiver_id or not uploaded or not uploaded.filename:
            flash('Choose a receiver and a file.')
            connection.close()
            return render_template('upload.html', users=users)
        receiver = connection.execute('SELECT public_key FROM users WHERE id = ?', (receiver_id,)).fetchone()
        if not receiver:
            flash('Receiver not found.')
            connection.close()
            return render_template('upload.html', users=users)
        original_filename = secure_filename(uploaded.filename) or 'downloaded_file'
        file_bytes = uploaded.read()
        aes_key, encrypted_bytes, nonce, tag = encrypt_file(file_bytes)
        encrypted_key = encrypt_aes_key(aes_key, receiver['public_key'])
        # Store tag after nonce so authentication data is preserved.
        stored_nonce = nonce + tag
        connection.execute('''INSERT INTO shared_files
            (sender_id, receiver_id, filename, encrypted_file, encrypted_key, nonce)
            VALUES (?, ?, ?, ?, ?, ?)''',
            (session['user_id'], receiver_id, original_filename,
             encrypted_bytes, encrypted_key, stored_nonce))
        connection.commit()
        connection.close()
        flash('File encrypted and shared successfully.')
        return redirect(url_for('upload'))
    connection.close()
    return render_template('upload.html', users=users)


@app.route('/inbox')
def inbox():
    required = login_required()
    if required: return required
    connection = get_connection()
    files = connection.execute('''SELECT shared_files.*, users.username AS sender_name
        FROM shared_files JOIN users ON users.id = shared_files.sender_id
        WHERE receiver_id = ? ORDER BY uploaded_at DESC''', (session['user_id'],)).fetchall()
    connection.close()
    return render_template('inbox.html', files=files)


@app.route('/sent')
def sent():
    required = login_required()
    if required: return required
    connection = get_connection()
    files = connection.execute('''SELECT shared_files.*, users.username AS receiver_name
        FROM shared_files JOIN users ON users.id = shared_files.receiver_id
        WHERE sender_id = ? ORDER BY uploaded_at DESC''', (session['user_id'],)).fetchall()
    connection.close()
    return render_template('sent.html', files=files)


@app.route('/download/<int:file_id>')
def download(file_id):
    required = login_required()
    if required: return required
    connection = get_connection()
    row = connection.execute('SELECT * FROM shared_files WHERE id = ?', (file_id,)).fetchone()
    if not row or row['receiver_id'] != session['user_id']:
        connection.close()
        flash('Unauthorized file access.')
        return redirect(url_for('inbox'))
    user = connection.execute('SELECT private_key FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    try:
        aes_key = decrypt_aes_key(row['encrypted_key'], user['private_key'])
        nonce, tag = row['nonce'][:16], row['nonce'][16:]
        plain_bytes = decrypt_file(aes_key, row['encrypted_file'], nonce, tag)
        connection.execute('UPDATE shared_files SET is_read = 1 WHERE id = ?', (file_id,))
        connection.commit()
    except (ValueError, TypeError, IndexError):
        connection.close()
        flash('The file could not be decrypted or may have been altered.')
        return redirect(url_for('inbox'))
    filename = row['filename']
    connection.close()
    return send_file(BytesIO(plain_bytes), as_attachment=True, download_name=filename)


if __name__ == '__main__':
    app.run(debug=False)
