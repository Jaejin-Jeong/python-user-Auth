from flask import Flask, jsonify, request, Response

# user Auth
import bcrypt
import jwt
from functools import wraps

app = Flask(__name__)

# Sample users
users = [{"userId": "user",
          "userPwd": "1111"}]


# Check whether API request is authenticated
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get Authorization in request header
        access_token = request.headers.get("Authorization")
        if access_token is not None:
            try:
                payload = jwt.decode(access_token, "secret", "HS256")
            except jwt.InvalidTokenError:
                payload = None

            if payload is None:
                return Response(status=401)
        else:
            return Response(status=401)
        return f(*args, **kwargs)

    return decorated_function


@app.route('/api/login', methods=['POST'])
def user_login():
    # Get the input parameter by the json format
    params = request.get_json(silent=True)

    # Parsing input parameters
    name = params['userId']
    password = params['userPwd']

    # Find user
    user = next((item for item in users if item["userId"] == name), None)
    print(user)
    if not user:  # check User
        return {
                   "message": "User Not Found"
               }, 404
    elif not bcrypt.checkpw(password.encode('utf-8'),
                            bcrypt.hashpw(user["userPwd"].encode("utf-8"), bcrypt.gensalt())):  # 비밀번호 일치 확인
        return {
                   "message": "Auth Failed"
               }, 500
    else:
        # jwt token create
        encoded = jwt.encode({'userId': name}, "secret", algorithm="HS256")
        request.headers.get('Authorization')

        return {
                   'Authorization': encoded  # by returning as string
               }, 200


@app.route('/')
def hello_world():
    return 'Hello World!'


if __name__ == '__main__':
    app.run()
