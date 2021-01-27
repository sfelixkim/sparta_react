from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import jwt
from datetime import datetime, timedelta
import hashlib
import json
from functools import wraps
from flask_cors import CORS, cross_origin
from pymongo import MongoClient

app = Flask(__name__)
cors = CORS(app)
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['CORS_HEADERS'] = 'Content-Type'

app.secret_key = b'SPARTA'
JWT_SECRET_KEY = 'SPARTA'
app.config['SECRET_KEY'] = JWT_SECRET_KEY


client = MongoClient("13.209.66.226", 27017, username="test", password="test")
db = client.db_react


#########################################################
#       Decorators
#########################################################
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("mytoken")
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            if "email" in payload:
                return func(*args, **kwargs)
            else:
                return redirect(url_for("home", msg="로그인 먼저 해주세요!"))
        except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
            return redirect(url_for("home"))
    return wrapper



@app.route('/')
def home():
    return "<h1>메인</h1>"


### API ###


@app.route('/api/auth', methods=["POST"])
@cross_origin()
def sign_in():
    email = request.form["email"]
    password = request.form["password"]
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    print(email, password_hash)
    user = db.users.find_one({"email": email, "password": password_hash})
    if user is not None:
        print("signing in...")
        payload = {
            'email': user["email"],
            'exp': datetime.utcnow() + timedelta(seconds=60 * 60 * 24)  # 로그인 24시간 유지
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
        return jsonify({'result': 'success', 'token': token, 'nickname': user["nickname"], "id": user["email"]})
    else:
        return '아이디/비밀번호가 일치하지 않습니다.', 401


@app.route('/api/users', methods=["POST"])
@cross_origin()
def sign_up():
    nickname = request.form["nickname"]
    email = request.form["email"]
    password = request.form["password"]

    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    doc = {
        "email": email,
        "nickname": nickname,
        "password": password_hash
    }
    db.users.insert_one(doc)
    return jsonify({"result": "success", "msg": "회원가입 성공!"})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
