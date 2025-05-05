from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, current_user, logout_user
from .models import User, File, FileShare
from . import db
import os
from werkzeug.utils import secure_filename

main = Blueprint('main', __name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

        new_user = User(email=email, username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
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
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login'))

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
            file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
            
            # Save file metadata to the database
            new_file = File(filename=filename, user_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()
            
            flash('File successfully uploaded')
            return redirect(url_for('main.index'))
    return render_template('upload.html')

@main.route('/download/<filename>')
def download_file(filename):
    file = File.query.filter_by(filename=filename).first_or_404()
    # Check if the current user is the owner or has been shared the file
    if file.user_id != current_user.id and not FileShare.query.filter_by(file_id=file.id, shared_with_user_id=current_user.id).first():
        flash('You do not have permission to access this file')
        return redirect(url_for('main.index'))
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)

@main.route('/share/<int:file_id>', methods=['GET', 'POST'])
def share_file(file_id):
    file = File.query.get_or_404(file_id)
    if request.method == 'POST':
        email = request.form.get('email')
        user_to_share_with = User.query.filter_by(email=email).first()
        if not user_to_share_with:
            flash('User not found')
            return redirect(request.url)
        
        # Check if the file is already shared with this user
        existing_share = FileShare.query.filter_by(file_id=file.id, shared_with_user_id=user_to_share_with.id).first()
        if existing_share:
            flash('File already shared with this user')
            return redirect(request.url)
        
        # Create a new file share entry
        new_share = FileShare(file_id=file.id, shared_with_user_id=user_to_share_with.id)
        db.session.add(new_share)
        db.session.commit()
        
        flash('File successfully shared')
        return redirect(url_for('main.index'))
    
    return render_template('share.html', file=file)