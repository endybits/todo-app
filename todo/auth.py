import functools

from flask import (
    Blueprint, flash, 
    g, redirect, render_template, 
    request, url_for,
    session
)
from werkzeug.security import check_password_hash, generate_password_hash

from todo.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db, c = get_db()
        error = None
        c.execute(
            'SELECT id FROM user WHERE username = %s',
            (username,)
        )
        if not username:
            error = 'Ops! username is required'
        
        if not password:
            error = 'Ops! password is required'
        elif c.fetchone() is not None:
            error = f'The username {username} is already registered'
        
        if error is None:
            secret_psw = generate_password_hash(password)
            print(secret_psw)
            print(len(secret_psw))
            c.execute(
                'INSERT INTO user (username, password) VALUES (%s, %s)',
                (username, secret_psw,)
            )
            db.commit()
            return redirect(url_for('auth.login'))
    
        flash(error)

    return render_template('auth/register.html')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db, c = get_db()
        error = None

        c.execute(
            'SELECT * FROM user WHERE username = %s', 
            (username,)
        )
        user = c.fetchone()
        if user is None:
            error = 'Invalid username or password'
        elif not check_password_hash(user['password'], password):
            error = 'Invalid username or password'
        
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('todo.index'))
        else:
            flash(error)
        
    return render_template('auth/login.html')


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        db, c = get_db()
        c.execute(
            'SELECT * FROM user WHERE id = %s',
            (user_id,)
        )
        g.user = c.fetchone()

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user == None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    
    return wrapped_view


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))
