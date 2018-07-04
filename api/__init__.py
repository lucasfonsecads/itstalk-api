from flask import Flask
from flask_restful import Api
import boto3
from flask_cors import CORS
from flask_jwt_extended import JWTManager


app = Flask(__name__)
api = Api(app)
CORS(app)
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
jwt = JWTManager(app)

dynamodb = boto3.resource('dynamodb', aws_access_key_id='AKIAJU5TJZFONNHVGB2A', aws_secret_access_key='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',region_name='us-east-2')
table = dynamodb.Table('loginUser')

from api import views, resources

api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.UserLogoutAccess, '/logout/access')
api.add_resource(resources.UserLogoutRefresh, '/logout/refresh')
api.add_resource(resources.TokenRefresh, '/token/refresh')
api.add_resource(resources.AllUsers, '/users')
api.add_resource(resources.SecretResource, '/secret')