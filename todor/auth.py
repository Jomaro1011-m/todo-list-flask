import functools
from todor import db
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Blueprint, render_template, request, url_for, redirect, flash, session, g

bp = Blueprint('auth', __name__, url_prefix = '/auth')

@bp.route('/register', methods = ('GET', 'POST'))
def register(): 
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User(username, generate_password_hash(password))
        error = None
        user_name = User.query.filter_by(username = username).first()
        if user_name == None:
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('auth.login'))
        error = f'El usuario {username} ya está registrado'
        flash(error)
    return render_template('auth/register.html')

@bp.route('/login', methods = ('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None
        user = User.query.filter_by(username = username).first()
        if user == None: error = 'Nombre de usuario incorrecto'
        elif not check_password_hash(user.password, password): error = 'Contraseña incorrecta'
        if error == None:
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('todo.index'))
        flash(error)
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None if user_id is None else User.query.get_or_404(user_id)
    
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapper_view(**kwargs):
        if g.user is None: return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapper_view