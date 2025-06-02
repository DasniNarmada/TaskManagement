from flask import Blueprint, render_template, redirect, url_for, flash, request
from app import db
from app.models import User, Task
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('index.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        user = User(username=username, password=password, role=role)
        db.session.add(user)
        db.session.commit()
        flash('Account created!', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login failed!', 'danger')
    return render_template('login.html')

@main.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@main.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'Admin':
        tasks = Task.query.all()
    elif current_user.role == 'Supervisor':
        tasks = Task.query.filter_by(user_id=current_user.id)
    else:
        tasks = Task.query.filter_by(user_id=current_user.id)
    return render_template('dashboard.html', tasks=tasks)

@main.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    if current_user.role not in ['Admin', 'Supervisor']:
        return redirect(url_for('main.dashboard'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        task = Task(title=title, description=description, user_id=current_user.id)
        db.session.add(task)
        db.session.commit()
        return redirect(url_for('main.dashboard'))
    return render_template('create_task.html')

@main.route('/edit_task/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_task(id):
    task = Task.query.get_or_404(id)
    if current_user.role == 'User' or task.user_id != current_user.id and current_user.role != 'Admin':
        return redirect(url_for('main.dashboard'))
    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form['description']
        db.session.commit()
        return redirect(url_for('main.dashboard'))
    return render_template('edit_task.html', task=task)

@main.route('/delete_task/<int:id>')
@login_required
def delete_task(id):
    task = Task.query.get_or_404(id)
    if current_user.role != 'Admin':
        return redirect(url_for('main.dashboard'))
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('main.dashboard'))
