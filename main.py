from hmac import compare_digest
from flask import Flask, jsonify, request, json
from flask_jwt import JWT, jwt_required
from flask_restful import Resource, Api, reqparse
from security import authenticate, identity
from pymongo import MongoClient
from google.cloud import secretmanager
import os


app = Flask(__name__)
app.secret_key = 'jose'
api = Api(app)
jwt = JWT(app, authenticate, identity)  # /auth

project_id = "rheodigital-client-portal"
secret_id = "portal-db"
secret_client = secretmanager.SecretManagerServiceClient()
secret_client.access_secret_version(name=f'projects/{project_id}/secrets/{secret_id}/versions/1')
response = secret_client.access_secret_version(name=f'projects/{project_id}/secrets/{secret_id}/versions/latest')
print(response.name)
database_uri = os.environ['MONGO_URI']
client = MongoClient(database_uri)
collection = client.users
db = collection.users

userlist = list(db.find())


class Check(Resource):
    def get(self):
        try:
            data = request.get_json()
            _id = data["_id"]
            username = data["username"]
            password = data["password"]
            database = list(db.find())
            temp = next(filter(lambda x: x["_id"] == _id, database), None)
            if temp is None:
                db.insert_one(data)
                return "User successfully created", json.dumps(database)
            else:
                return jsonify({"message": "User Exists"})
        except KeyError:
            return jsonify({"message": "Wrong Syntax"})


class Login(Resource):
    # @jwt_required()
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('_id',type=int, required = True, help= '_id cannot be empty')
        parser.add_argument('password', type=str, required=True, help='password cannot be empty')
        data = parser.parse_args()
        output = next(filter(lambda x: x["_id"] == data["_id"], userlist), None)
        if output is not None and (data["_id"] and compare_digest(output['password'], data['password'])):
            return 200
        else:
            return 404


class CreateUser(Resource):
    def post(self):
        data = request.get_json()
        _id = data["_id"]
        temp = next(filter(lambda x: x["_id"] == _id, userlist), None)
        if temp is None:
            userlist.append(data)
            return jsonify({"message": userlist})
        else:
            return jsonify({"message": "User Exists"})


class ListUser(Resource):
    @jwt_required()
    def get(self):
        key = request.get_json()
        if key["key"] == "12345":
            return jsonify({"message": userlist})
        else:
            return jsonify({"message": "wrong key"})


class HelloWorld(Resource):
    def get(self):
        return jsonify({"message": "Hello World"})


api.add_resource(Login, '/login')
api.add_resource(CreateUser, '/user/create')
api.add_resource(ListUser, '/user')
api.add_resource(HelloWorld, '/')
api.add_resource(Check, '/check')


if __name__ == '__main__':
    app.run(debug=True)