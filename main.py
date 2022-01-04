import json
import requests
from google.cloud import datastore
from flask import Flask, request, jsonify, Response, redirect, render_template, session, url_for
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = 'supersecretcookiecode'
client = datastore.Client()

ALGORITHMS = ["RS256"]
CLIENT_ID = 'nJXm5NM6w6oG8PY4emusB1aEBvjfpCZ5'
CLIENT_SECRET = '5cZt6ImrCbXkivBDPJcKWKP7Cc5mluwBrEaweC8ZeOy_9NY8716Hr1NH69jrrrp9'
DOMAIN = 'dev-wtuetw9s.us.auth0.com'
FORMAT = 'application/json'
ALL = '*/*'

BAD_REQUEST_400 = {'ERROR': 'BAD REQUEST. PLEASE VALIDATE DATA'}
UNAUTHORIZED_401 = {'ERROR': 'YOU ARE NOT LOGGED IN. PLEASE OBTAIN AUTHORIZATION.'}
FORBIDDEN_403_1 = {'ERROR': 'YOU ARE NOT ALLOWED TO ACCESS THIS RESOURCE'}
FORBIDDEN_403_2 = {'ERROR': 'THIS RESOURCE IS ALREADY STORED.'}
NOT_FOUND_404 = {'ERROR': 'ASSET NOT FOUND.'}
NOT_ACCEPTABLE_406 = {'ERROR': "ACCEPT HEADER MUST BE 'application/json'."}
UNSUPPORTED_415 = {'ERROR': 'CONTENT-TYPE SENT IS NOT SUPPORTED.'}


def val_format(accept, mimetype):

    if accept != FORMAT and accept != ALL:
        return NOT_ACCEPTABLE_406
    if mimetype != FORMAT:
        return UNSUPPORTED_415
    return None


def invalid_request(error):
    if error == NOT_ACCEPTABLE_406:
        return Response(json.dumps(error), status=406, mimetype=FORMAT)
    return Response(json.dumps(error), status=415, mimetype=FORMAT)


def make_query(key):
    query = client.query(kind=key)
    results = list(query.fetch())
    return results


def is_user():

    results = make_query('user')
    token = request.headers.get('Authorization')

    if not token:
        return False

    token = token[7:]

    for user in results:
        if user['jwt'] == token:
            return user['sub']

    return False


def val_user(owner):

    results = make_query('user')
    token = request.headers.get('Authorization')
    token = token[7:]

    for user in results:
        if user['sub'] == owner and user['jwt'] == token:
            return True

    return False


def add_user():
    new = datastore.Entity(key=client.key('user'))
    new.update({
        'name': session['jwt_payload']['name'],
        'sub': session['jwt_payload']['sub'],
        'jwt': session['token']
    })
    client.put(new)
    return new


def get_container():

    invalid = val_format(request.headers.get('Accept'), request.headers.get('Content-Type'))

    if invalid == NOT_ACCEPTABLE_406:
        return Response(json.dumps(invalid), status=406, mimetype=FORMAT)

    query = make_query('container')
    store = make_query('storage')
    user = is_user()
    per_page = 3
    results = []

    if request.args.get("start"):
        start = int(request.args.get("start"))
    else:
        start = 0

    for index in range(start, min(start + per_page, len(query))):
        if query[index]['owner'] == user:

            for result in store:
                if query[index].key.id == result['container']:
                    key = client.key('food', result['food'])
                    item = client.get(key)
                    item['id'] = result['food']
                    item['self'] = 'https://hw10-wilkiech.uc.r.appspot.com/food/' + str(item.key.id)
                    query[index]['food'].append(item)

            query[index]['id'] = query[index].key.id
            query[index]['self'] = 'https://hw10-wilkiech.uc.r.appspot.com/container/' + str(query[index]["id"])
            results.append(query[index])

    if start + 3 <= len(query):
        results.append({"next": "https://hw10-wilkiech.uc.r.appspot.com/container?start=" + str(start + 3)})

    return Response(json.dumps(results), status=200, mimetype=FORMAT)


def id_get_container(container_id):

    invalid = val_format(request.headers.get('Accept'), request.headers.get('Content-Type'))

    if invalid == NOT_ACCEPTABLE_406:
        return Response(json.dumps(invalid), status=406, mimetype=FORMAT)

    key = client.key('container', container_id)
    item = client.get(key)
    if not item:
        return Response(json.dumps(NOT_FOUND_404), status=404, mimetype=FORMAT)

    valid = val_user(item['owner'])
    if not valid:
        return Response(json.dumps(FORBIDDEN_403_1), status=403, mimetype=FORMAT)

    query = make_query('storage')

    for result in query:
        if result['container'] == container_id:
            key = client.key('food', result['food'])
            stored = client.get(key)
            stored['id'] = result['food']
            stored['self'] = 'https://hw10-wilkiech.uc.r.appspot.com/food/' + str(item.key.id)
            item['food'].append(stored)

    item['id'] = container_id
    item['self'] = 'https://hw10-wilkiech.uc.r.appspot.com/container/' + str(container_id)

    return Response(json.dumps(item), status=200, mimetype=FORMAT)


def post_container():

    data = request.json
    user = is_user()

    if all(key in data for key in ("name", "temperature", "location")):
        new = datastore.Entity(key=client.key('container'))
        new.update({"name": data["name"],
                    "temperature": data["temperature"],
                    "location": data["location"],
                    "food": [],
                    "owner": user})
        client.put(new)
        new["id"] = new.key.id
        new["self"] = 'https://hw10-wilkiech.uc.r.appspot.com/container/' + str(new.key.id)
        return Response(json.dumps(new), status=201, mimetype=FORMAT)

    return Response(json.dumps(BAD_REQUEST_400), status=400, mimetype=FORMAT)


def patch_container(container_id):

    data = request.json
    key = client.key('container', container_id)
    item = client.get(key)

    if not item:
        return Response(json.dumps(NOT_FOUND_404), status=404, mimetype=FORMAT)

    valid = val_user(item['owner'])
    if not valid:
        return Response(json.dumps(FORBIDDEN_403_1), status=403, mimetype=FORMAT)

    if any(key in data for key in ('name', 'temperature', 'location')):
        if 'name' in data:
            item['name'] = data['name']
        if 'temperature' in data:
            item['temperature'] = data['temperature']
        if 'location' in data:
            item['location'] = data ['location']
        client.put(item)
        item['id'] = container_id
        item['self'] = 'https://hw10-wilkiech.uc.r.appspot.com/container/' + str(container_id)
        return Response(json.dumps(item), status=201, mimetype=FORMAT)

    return Response(json.dumps(BAD_REQUEST_400), status=400, mimetype=FORMAT)


def delete_container(container_id):

    query = make_query('container')

    for result in query:
        if result.key.id == container_id:

            valid = val_user(result['owner'])
            if not valid:
                return Response(json.dumps(FORBIDDEN_403_1), status=403, mimetype=FORMAT)

            delete_storage_container(result.key.id)
            client.delete(result)
            return Response(status=204)

    return Response(json.dumps(NOT_FOUND_404), status=404, mimetype=FORMAT)


def get_food():

    invalid = val_format(request.headers.get('Accept'), request.headers.get('Content-Type'))

    if invalid == NOT_ACCEPTABLE_406:
        return Response(json.dumps(invalid), status=406, mimetype=FORMAT)

    query = make_query('food')
    store = make_query('storage')
    user = is_user()
    per_page = 3
    results = []

    if request.args.get("start"):
        start = int(request.args.get("start"))
    else:
        start = 0

    for index in range(start, min(start+per_page, len(query))):
        if query[index]['owner'] == user:

            for result in store:
                if query[index].key.id == result['food']:
                    query[index]['container'] = 'https://hw10-wilkiech.uc.r.appspot.com/container/' + \
                                                str(result['container'])

            query[index]['id'] = query[index].key.id
            query[index]['self'] = 'https://hw10-wilkiech.uc.r.appspot.com/food/' + str(query[index]["id"])
            results.append(query[index])

    if start + 3 <= len(query):
        results.append({"next": "https://hw10-wilkiech.uc.r.appspot.com/food?start=" + str(start + 3)})

    return Response(json.dumps(results), status=200, mimetype=FORMAT)


def id_get_food(food_id):

    invalid = val_format(request.headers.get('Accept'), request.headers.get('Content-Type'))

    if invalid == NOT_ACCEPTABLE_406:
        return Response(json.dumps(invalid), status=406, mimetype=FORMAT)

    key = client.key('food', food_id)
    item = client.get(key)
    if not item:
        return Response(json.dumps(NOT_FOUND_404), status=404, mimetype=FORMAT)

    valid = val_user(item['owner'])
    if not valid:
        return Response(json.dumps(FORBIDDEN_403_1), status=403, mimetype=FORMAT)

    query = make_query('storage')

    for result in query:
        if result['food'] == food_id:
            item['container'] = 'https://hw10-wilkiech.uc.r.appspot.com/container/' + str(result['container'])

    item['id'] = food_id
    item['self'] = 'https://hw10-wilkiech.uc.r.appspot.com/food/' + str(food_id)

    return Response(json.dumps(item), status=200, mimetype=FORMAT)


def post_food():

    data = request.json
    user = is_user()

    if all(key in data for key in ("name", "expiration", "quantity")):
        new = datastore.Entity(key=client.key('food'))
        new.update({"name": data["name"],
                    "expiration": data["expiration"],
                    "quantity": data["quantity"],
                    "container": None,
                    "owner": user})
        client.put(new)
        new["id"] = new.key.id
        new["self"] = 'https://hw10-wilkiech.uc.r.appspot.com/food/' + str(new.key.id)
        return Response(json.dumps(new), status=201, mimetype=FORMAT)

    return Response(json.dumps(BAD_REQUEST_400), status=400, mimetype=FORMAT)


def patch_food(food_id):

    data = request.json
    key = client.key('food', food_id)
    item = client.get(key)

    if not item:
        return Response(json.dumps(NOT_FOUND_404), status=404, mimetype=FORMAT)

    valid = val_user(item['owner'])
    if not valid:
        return Response(json.dumps(FORBIDDEN_403_1), status=403, mimetype=FORMAT)

    if any(key in data for key in ('name', 'expiration', 'quantity')):
        if 'name' in data:
            item['name'] = data['name']
        if 'expiration' in data:
            item['expiration'] = data['expiration']
        if 'quantity' in data:
            item['quantity'] = data['quantity']
        client.put(item)
        item['id'] = food_id
        item['self'] = 'https://hw10-wilkiech.uc.r.appspot.com/food/' + str(food_id)
        return Response(json.dumps(item), status=201, mimetype=FORMAT)

    return Response(json.dumps(BAD_REQUEST_400), status=400, mimetype=FORMAT)


def delete_food(food_id):

    query = make_query('food')

    for result in query:
        if result.key.id == food_id:

            valid = val_user(result['owner'])
            if not valid:
                return Response(json.dumps(FORBIDDEN_403_1), status=403, mimetype=FORMAT)

            delete_storage_food(result.key.id)
            client.delete(result)
            return Response(status=204)

    return Response(json.dumps(NOT_FOUND_404), status=404, mimetype=FORMAT)


def post_storage(food_id, container_id):

    query = make_query('storage')

    for result in query:
        if result['food'] == int(food_id):
            return Response(json.dumps(FORBIDDEN_403_2), status=403, mimetype=FORMAT)

    food_key = client.key("food", int(food_id))
    item = client.get(food_key)
    container_key = client.key("container", int(container_id))
    store = client.get(container_key)

    valid_1, valid_2 = val_user(item['owner']), val_user(store['owner'])
    if not valid_1 or not valid_2:
        return Response(json.dumps(FORBIDDEN_403_1), status=403, mimetype=FORMAT)

    if not item or not store:
        return Response(json.dumps(NOT_FOUND_404), status=404, mimetype=FORMAT)

    new = datastore.Entity(key=client.key('storage'))
    new.update({"food": food_id,
                "container": container_id})
    client.put(new)

    return Response(status=204)


def delete_storage(food_id, container_id):

    query = make_query('storage')

    for result in query:
        if result['food'] == food_id and result['container'] == container_id:

            food_key = client.key("food", int(food_id))
            item = client.get(food_key)
            valid = val_user(item['owner'])
            if not valid:
                return Response(json.dumps(FORBIDDEN_403_1), status=403, mimetype=FORMAT)

            client.delete(result.key)
            return Response(status=204)

    return Response(json.dumps(NOT_FOUND_404), status=404, mimetype=FORMAT)


def delete_storage_food(food_id):

    query = make_query('storage')

    for result in query:
        if result['food'] == food_id:
            client.delete(result.key)
            return


def delete_storage_container(container_id):

    query = make_query('storage')

    for result in query:
        if result['container'] == container_id:
            client.delete(result.key)
    return


########################################################################################################################
# This code is adapted from
# https://auth0.com/docs/quickstart/backend/python/
# 01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_lite(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return False

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return False
    if unverified_header["alg"] == "HS256":
        return False
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            return False
        except jwt.JWTClaimsError:
            return False
        except Exception:
            return False

        return payload
    else:
        return False


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/auth')
def auth():
    # Handles response from token endpoint
    data = auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['token'] = data['id_token']
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name']
    }

    results = make_query('user')
    new = True

    for result in results:
        if result['sub'] == session['jwt_payload']['sub']:
            new = False
            result['jwt'] = session['token']
            client.put(result)
    if new:
        add_user()

    return render_template('index.html', user=session['jwt_payload']['name'],
                           sub=session['jwt_payload']['sub'], token=session['token'])


@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('root', _external=True), 'client_id': CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return auth0.authorize_redirect(redirect_uri='https://hw10-wilkiech.uc.r.appspot.com/auth')

    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password', 'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type': 'application/json'}

########################################################################################################################


@app.route('/')
def root():
    if session.get('jwt_payload'):
        return render_template('index.html', user=session['jwt_payload']['name'],
                               sub=session['jwt_payload']['sub'], token=session['token'])

    return render_template('index.html')


@app.route('/users', methods=['GET'])
def users():
    results = make_query('user')

    for index in range(0, len(results)):
        results[index]['id'] = results[index].key.id

    return Response(json.dumps(results), status=200, mimetype=FORMAT)


@app.route('/container', methods=['GET', 'POST'])
def container():

    if is_user():
        if request.method == 'GET':
            return get_container()
        if request.method == 'POST':
            invalid = val_format(request.headers.get('Accept'), request.headers.get('Content-Type'))
            if invalid:
                return invalid_request(invalid)
            return post_container()

    return Response(json.dumps(UNAUTHORIZED_401), status=401, mimetype=FORMAT)


@app.route('/container/<int:container_id>', methods=['GET', 'PATCH', 'DELETE'])
def id_container(container_id):

    if is_user():
        if request.method == 'GET':
            return id_get_container(container_id)
        if request.method == 'DELETE':
            return delete_container(container_id)

        invalid = val_format(request.headers.get('Accept'), request.headers.get('Content-Type'))
        if invalid:
            return invalid_request(invalid)

        if request.method == 'PATCH':
            return patch_container(container_id)

    return Response(json.dumps(UNAUTHORIZED_401), status=401, mimetype=FORMAT)


@app.route('/food', methods=['GET', 'POST'])
def food():

    if is_user():
        if request.method == 'GET':
            return get_food()
        if request.method == 'POST':
            invalid = val_format(request.headers.get('Accept'), request.headers.get('Content-Type'))
            if invalid:
                return invalid_request(invalid)
            return post_food()

    return Response(json.dumps(UNAUTHORIZED_401), status=401, mimetype=FORMAT)


@app.route('/food/<int:food_id>', methods=['GET', 'PATCH', 'DELETE'])
def id_food(food_id):

    if is_user():
        if request.method == 'GET':
            return id_get_food(food_id)
        if request.method == 'DELETE':
            return delete_food(food_id)

        invalid = val_format(request.headers.get('Accept'), request.headers.get('Content-Type'))
        if invalid:
            return invalid_request(invalid)

        if request.method == 'PATCH':
            return patch_food(food_id)

    return Response(json.dumps(UNAUTHORIZED_401), status=401, mimetype=FORMAT)


@app.route('/food/<int:food_id>/container/<int:container_id>', methods=['PUT', 'DELETE'])
def storage(food_id, container_id):

    invalid = val_format(request.headers.get('Accept'), request.headers.get('Content-Type'))
    if invalid:
        return invalid_request(invalid)

    if is_user():
        if request.method == 'PUT':
            return post_storage(food_id, container_id)
        if request.method == 'DELETE':
            return delete_storage(food_id, container_id)

    return Response(json.dumps(UNAUTHORIZED_401), status=401, mimetype=FORMAT)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
