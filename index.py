import calendar
import time
import jwt
import datetime
import bcrypt
from getpass import getpass


def testjwt():
    expiration_datetime = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    print(expiration_datetime)
    encoded_jwt = jwt.encode({
                # issued at time
                'iat': int(time.time()),
                'user': 'srini',
                'exp': expiration_datetime}, 'masterpassword')

    try:
        decode = jwt.decode(encoded_jwt + "w".encode(), 'masterpassword', leeway=10)
        print(decode)
    except jwt.ExpiredSignatureError:
        print("Signature expired")


def create_users():
    print("Creating users")
    hashed_password = bcrypt.hashpw("password".encode(), b'$2b$12$XgggaDHU5a90PwY1I857fu')
    return hashed_password


def match_password(password, hash):
    if hash == bcrypt.hashpw(password.encode('utf-8'), hash):
        print("User is valid")
    else:
        print("Invalid user")


testjwt()