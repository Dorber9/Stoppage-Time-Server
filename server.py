from flask import Flask, request, make_response
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import pymongo
import requests
import json
from datetime import datetime, date
import secrets

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
bcrypt = Bcrypt(app)
api_token = "56243f10d28a4f3496e19f5e2ef61f50"
headers = {'X-Auth-Token': api_token}
session_user = {'username': None}


client = pymongo.MongoClient(
    "mongodb+srv://dorber9:tWHBsVAWzh6ZrMbX@stoppagetime.7iullij.mongodb.net/test")
db = client["StoppageTime"]
collection = db["users"]


@app.route("/clubs")
def clubs():
    uri = 'https://api.football-data.org/v4/competitions/PD/standings'
    headers = {'X-Auth-Token': api_token}
    response = requests.get(uri, headers=headers)
    response_json = response.json()
    if 'errorCode' in response_json:
        return {'error': response_json['errorCode'], 'message': response_json['message']}
    clubs = response_json['standings'][0]['table']
    clubs = {item['team']['id']: item['team']['crest'] for item in clubs}
#     clubs = {81: 'https://crests.football-data.org/81.svg', 86: 'https://crests.football-data.org/86.png', 92: 'https://crests.football-data.org/92.svg', 78: 'https://crests.football-data.org/78.svg', 90: 'https://crests.football-data.org/90.png', 87: 'https://crests.football-data.org/87.svg', 77: 'https://crests.football-data.org/77.png', 94: 'https://crests.football-data.org/94.png', 89: 'https://crests.football-data.org/89.png', 79: 'https://crests.football-data.org/79.svg', 298: 'https://crests.football-data.org/298.png', 80: 'https://crests.football-data.org/80.svg', 559: 'https://crests.football-data.org/559.svg', 558: 'https://crests.football-data.org/558.svg', 250: 'https://crests.football-data.org/250.png', 264: 'https://crests.football-data.org/264.png', 82: 'https://crests.football-data.org/82.png', 267: 'https://crests.football-data.org/267.png', 95: 'https://crests.football-data.org/95.svg', 285: 'https://crests.football-data.org/285.png'}
    return clubs


@app.route("/user", methods=['GET'])
def user():
    username = request.args.get("username")
    user = collection.find_one({"username": username})
    if user is None:
        # handle case where user is not found
        return "User not found", 404
    session_user['username'] = username

    returned_user = {"username": user["username"],
                     "email": user['email'], "club": user["club_id"]}
    props = {'user': returned_user}
    club_id = user['club_id']
    matches = get_matches()
    if 'error' in matches:
        return matches
    if matches:
        props['matches'] = [m for m in matches if m['status'] != 'FINISHED']
        props['results'] = [m for m in matches if m['status'] == 'FINISHED']
        todays_match = 'none'
        for match in props['matches']:
            utc_date = datetime.strptime(
                match['utcDate'], '%Y-%m-%dT%H:%M:%SZ')
            today = date.today()
            same_day = utc_date.year == today.year and utc_date.month == today.month and utc_date.day == today.day
            if same_day:
                print(
                    f'{match["homeTeam"]["id"]} ++++ {match["awayTeam"]["id"]} +++++ {club_id}')
            my_club = int(match['homeTeam']['id']) == int(
                club_id) or int(match['awayTeam']['id']) == int(club_id)
            if same_day and my_club:
                todays_match = match
                break
        props['today'] = todays_match
    return props


@app.route('/check_email', methods=['GET'])
def check_email():
    try:
        email = request.args.get('email')
        result = collection.find_one({"email": email})
        exists = True if result else False
        data = {'exists': exists}
        return data
    except Exception as e:
        return {'exists': "500"}


@app.route('/check_username', methods=['GET'])
def check_username():
    try:
        username = request.args.get('username')
        result = collection.find_one({"username": username})
        exists = True if result else False
        data = {'exists': exists}
        return data
    except Exception as e:
        return {'exists': "500"}


@app.route('/add_user', methods=['POST'])
def add_user():
    # Retrieve the data from the request body
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']
    club_id = data['club_id']

    # Hash the password
    hashed_pass = bcrypt.generate_password_hash(password)

    # Establishing the connection
    client = pymongo.MongoClient(
        "mongodb+srv://dorber9:tWHBsVAWzh6ZrMbX@stoppagetime.7iullij.mongodb.net/test")

    # Adding new user
    document = {"username": username, "email": email,
                "password": hashed_pass, "club_id": club_id}
    result = collection.insert_one(document)
    if result.acknowledged:
        resp = make_response({'result': 'success'})
        resp.set_cookie('username', username)
        return resp
    else:
        return {'result': 'failure'}


@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    username = data['username']
    password = data['password']
    result = collection.find_one({"username": username})
    to_return = {'result': ''}
    if result:
        if bcrypt.check_password_hash(result['password'], password):
            resp = make_response({"result": 'success', 'username': username})
            session_user['username'] = username
            return resp
        else:
            to_return['result'] = 'Wrong password!'
    else:
        to_return['result'] = 'We could not find this username in the system'
    return to_return


@app.route('/stats', methods=['GET'])
def stats():
    standings_uri = 'https://api.football-data.org/v4/competitions/PD/standings'
    response = requests.get(standings_uri, headers=headers)
    response_json = response.json()
    if 'errorCode' in response_json:
        return {'error': response_json['errorCode'], 'message': response_json['message']}
    standings = [m for m in response_json['standings'][0]['table']]
    scorers_uri = 'https://api.football-data.org/v4/competitions/PD/scorers?limit=20'
    response = requests.get(scorers_uri, headers=headers)
    response_json = response.json()
    if 'errorCode' in response_json:
        return {'error': response_json['errorCode'], 'message': response_json['message']}
    scorers = [p for p in response_json['scorers']]
    return {'standings': standings, 'scorers': scorers}


@app.route('/get_username', methods=['GET'])
def get_username():
    return session_user


def get_matches():
    uri = f'https://api.football-data.org/v4/competitions/2014/matches'
    response = requests.get(uri, headers=headers)
    response_json = response.json()
    if 'errorCode' in response_json:
        return {"error": response_json['errorCode'], "message": response_json['message']}
    return response.json()['matches']


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
