import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecurekey')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cricktweet.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Login required to access this page.'

class User(UserMixin, db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def root():
    return redirect('home') if current_user.is_authenticated else redirect('login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        u = request.form['username'].strip()
        p = request.form['password']
        if not u or not p:
            flash('Username and password required.', 'error')
        elif User.query.filter_by(username=u).first():
            flash('Username already exists.', 'error')
        else:
            pwd = bcrypt.generate_password_hash(p).decode('utf-8')
            db.session.add(User(username=u, password=pwd))
            db.session.commit()
            flash('Account created—login now.', 'success')
            return redirect('login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        u = request.form['username'].strip()
        p = request.form['password']
        user = User.query.filter_by(username=u).first()
        if user and bcrypt.check_password_hash(user.password, p):
            login_user(user)
            return redirect('home')
        flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect('login')

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/live-score')
@login_required
def live_score():
    matches = [
        {'teams': 'IND vs AUS', 'score': '256/7 (45.2 ov)'},
        {'teams': 'ENG vs PAK', 'score': '198/3 (Day 2)'},
    ]
    return render_template('live_score.html', matches=matches)

@app.route('/follow')
@login_required
def follow():
    players = ['Virat Kohli', 'Rohit Sharma', 'MS Dhoni']
    return render_template('follow.html', players=players)

@app.route('/community', methods=['GET', 'POST'])
@login_required
def community():
    if request.method == 'POST':
        post = request.form['post'].strip()
        if post:
            flash(f'Posted: "{post}"', 'success')
    return render_template('community.html')

@app.route('/media')
@login_required
def media():
    images = ['kohli_six.jpg', 'dhoni_finish.jpg', 'rohit_thumbnail.jpg']
    return render_template('media.html', images=images)

@app.route('/fan-zone', methods=['GET', 'POST'])
@login_required
def fan_zone():
    if request.method == 'POST':
        idea = request.form['idea'].strip()
        if idea:
            flash(f'Prediction sent: "{idea}"', 'success')
    return render_template('fan_zone.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
