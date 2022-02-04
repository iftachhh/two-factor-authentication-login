#!/usr/bin/env python3

import os, sqlite3, pyotp, jwt
from Crypto.Hash import SHA256
from flask import Flask, request, make_response, jsonify
from datetime import datetime, timezone

con = sqlite3.connect('users.db', check_same_thread=False)
cur = con.cursor()
SECRET_KEY = os.environ.get('SECRET_KEY')

def hash_password(username, password):
	return SHA256.new(f'{username}={password}'.encode()).hexdigest()

def lookup_user(username):
	return list(cur.execute(f"SELECT * FROM users WHERE username = '{username}' LIMIT 1"))

def generate_otp(username):
	return '' if lookup_user(username)[0][3] == '' else pyotp.TOTP(lookup_user(username)[0][3]).now()

def generate_jwt(username):
	return jwt.encode({'username': username, 'iat': datetime.now(timezone.utc)}, SECRET_KEY)

def user_login(username, password, otp):
	if lookup_user(username)[0][2] == hash_password(username, password) and otp == generate_otp(username):
		res = make_response(jsonify({"success": True}))
		res.set_cookie('token', generate_jwt(username), httponly=True)
		cur.execute(f"UPDATE users SET last_login = '{datetime.now()}' WHERE username = '{username}';")
		con.commit()
		return res
	else: return jsonify({"success": False, "error": "wrong credentials"}), 401

def user_register(username, password, totp=False):
	if lookup_user(username) == []:
		totp = pyotp.random_base32() if totp else ''
		cur.execute(f"INSERT INTO users (username, password, totp, last_login) VALUES ('{username}', '{hash_password(username, password)}', '{totp}', '{datetime.now()}')")
		con.commit()
		return True
	else:
		return False

app = Flask(__name__)

@app.route('/login')
def login():
	username = request.args.get('username')
	password = request.args.get('password')
	otp = request.args.get('otp')
	if otp == None: otp = ''
	return user_login(username, password, otp)

@app.route('/register')
def register():
	username = request.args.get('username')
	password = request.args.get('password')
	if user_register(username, password): return jsonify({"success": True})
	else: return jsonify({"success": False, "error": "user with this name is already exist"}), 422

app.run()