from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, current_user, logout_user, login_required
from .models import User, File, FileShare, DownloadToken
from . import db
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import secrets

main = Blueprint('main', __name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_strong_password(password):
    import re
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        return False
    return True


@main.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    # Query files uploaded by the current user
    user_files = File.query.filter_by(user_id=current_user.id).all()

    # Query files shared with the current user
    shared_files = File.query.join(FileShare, File.id == FileShare.file_id)\
                             .filter(FileShare.shared_with_user_id == current_user.id).all()

    return render_template('index.html', files=user_files, shared_files=shared_files)


auth = Blueprint('auth', __name__)


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        user_by_username = User.query.filter_by(username=username).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('auth.register'))
        if user_by_username:
            flash('Username already exists')
            return redirect(url_for('auth.register'))
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.')
            return redirect(url_for('auth.register'))

        new_user = User(email=email, username=username, password=generate_password_hash(
            password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('auth.login'))

    return render_template('register.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login'))
        if user.account_locked:
            if user.lockout_time and user.lockout_time > datetime.utcnow():
                flash('Your account is locked due to too many failed login attempts. Please try again later or contact support at support@example.com.')
                return redirect(url_for('auth.login'))
            else:
                user.account_locked = False
                user.failed_login_attempts = 0
                user.lockout_time = None
                db.session.commit()
        if not check_password_hash(user.password, password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.account_locked = True
                user.lockout_time = datetime.utcnow() + timedelta(minutes=15)
                db.session.commit()
                flash('Your account has been locked due to too many failed login attempts. Please try again in 15 minutes or contact support at support@example.com.')
                return redirect(url_for('auth.login'))
            db.session.commit()
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login'))
        user.failed_login_attempts = 0
        user.account_locked = False
        user.lockout_time = None
        db.session.commit()
        login_user(user)
        return redirect(url_for('main.index'))

    return render_template('login.html')


@auth.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('auth.login'))


@main.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(
                current_app.config['UPLOAD_FOLDER'], filename))

            # Save file metadata to the database
            new_file = File(filename=filename, user_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()

            flash('File successfully uploaded')
            return redirect(url_for('main.index'))
    return render_template('upload.html')


@main.route('/download/<filename>')
@login_required
def download_file(filename):
    file = File.query.filter_by(filename=filename).first_or_404()
    # Check if the current user is the owner or has been shared the file
    if file.user_id != current_user.id and not FileShare.query.filter_by(file_id=file.id, shared_with_user_id=current_user.id).first():
        flash('You do not have permission to access this file')
        return redirect(url_for('main.index'))
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)


@main.route('/generate-download-link/<int:file_id>')
@login_required
def generate_download_link(file_id):
    file = File.query.get_or_404(file_id)
    # Check if the current user is the owner or has access
    if file.user_id != current_user.id and not FileShare.query.filter_by(file_id=file.id, shared_with_user_id=current_user.id).first():
        flash('You do not have permission to access this file')
        return redirect(url_for('main.index'))
    # Generate a unique token
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=10)  # Token valid for 10 minutes
    download_token = DownloadToken(
        token=token, file_id=file.id, user_id=current_user.id, expires_at=expires_at)
    db.session.add(download_token)
    db.session.commit()
    return redirect(url_for('main.download_file_token', token=token))


@main.route('/download/token/<token>')
@login_required
def download_file_token(token):
    download_token = DownloadToken.query.filter_by(token=token).first_or_404()
    if download_token.expires_at < datetime.utcnow():
        flash('Download link has expired')
        return redirect(url_for('main.index'))
    file = download_token.file
    # Only allow if current user is the token creator, file owner, or shared user
    is_owner = file.user_id == current_user.id
    is_token_user = download_token.user_id == current_user.id
    is_shared = FileShare.query.filter_by(
        file_id=file.id, shared_with_user_id=current_user.id).first() is not None
    if not (is_owner or is_token_user or is_shared):
        flash('You do not have permission to access this file')
        return redirect(url_for('main.index'))
    db.session.delete(download_token)
    db.session.commit()
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], file.filename, as_attachment=True)


@main.route('/share/<int:file_id>', methods=['GET', 'POST'])
def share_file(file_id):
    file = File.query.get_or_404(file_id)
    if request.method == 'POST':
        email = request.form.get('email')
        user_to_share_with = User.query.filter_by(email=email).first()
        if not user_to_share_with:
            flash('User not found')
            return redirect(request.url)

        # Prevent sharing with yourself
        if user_to_share_with.id == current_user.id:
            flash('You cannot share a file with yourself')
            return redirect(request.url)

        # Check if the file is already shared with this user
        existing_share = FileShare.query.filter_by(
            file_id=file.id, shared_with_user_id=user_to_share_with.id).first()
        if existing_share:
            flash('File already shared with this user')
            return redirect(request.url)

        # Create a new file share entry
        new_share = FileShare(
            file_id=file.id, shared_with_user_id=user_to_share_with.id)
        db.session.add(new_share)
        db.session.commit()

        flash('File successfully shared')
        return redirect(url_for('main.index'))

    return render_template('share.html', file=file)


@main.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    # Only the owner can delete
    if file.user_id != current_user.id:
        flash('You do not have permission to delete this file')
        return redirect(url_for('main.index'))
    # Delete file from filesystem
    file_path = os.path.join(
        current_app.config['UPLOAD_FOLDER'], file.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    # Delete related shares and tokens
    FileShare.query.filter_by(file_id=file.id).delete()
    DownloadToken.query.filter_by(file_id=file.id).delete()
    db.session.delete(file)
    db.session.commit()
    flash('File deleted successfully')
    return redirect(url_for('main.index'))


@main.route('/unshare/<int:file_id>/<int:user_id>', methods=['POST'])
@login_required
def unshare_file(file_id, user_id):
    file = File.query.get_or_404(file_id)
    # Only the owner can unshare
    if file.user_id != current_user.id:
        flash('You do not have permission to unshare this file')
        return redirect(url_for('main.index'))
    share = FileShare.query.filter_by(
        file_id=file_id, shared_with_user_id=user_id).first()
    if not share:
        flash('Share entry not found')
        return redirect(url_for('main.index'))
    db.session.delete(share)
    db.session.commit()
    flash('File access removed from user')
    return redirect(url_for('main.index'))
