
from flask import Blueprint, render_template, redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db

@app.route("/signup", method=['POST'])
def signup_post():
    name=request.form.get('name')
    email=request.form.get('email')
    password=request.form.get('password')

 
    user= User.query.filter_by(email=email).first()
    if user: 
        return redirect(url_for('auth.signup'))
    
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256')
    )
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('auth.login'))
