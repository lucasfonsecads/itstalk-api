from flask_restful import Resource, reqparse
from api import dynamodb, table
from passlib.hash import pbkdf2_sha256 as sha256
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)


parser = reqparse.RequestParser()
parser.add_argument('username', help = 'This field cannot be blank', required = True)
parser.add_argument('password', help = 'This field cannot be blank', required = True)

class UserRegistration(Resource):
    def post(self):

        data = parser.parse_args()
        
        username = data['username']
        password = data['password'] 
        
        def generate_hash(password):
            return sha256.hash(password)

        new_password = generate_hash(password)
        
        try:
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            
            table.update_item(
                        Key={
                            'userName': username,

                        },
                        UpdateExpression='SET token = :vall, password = :valll',
                        ExpressionAttributeValues={
                            ':vall': access_token,
                            ':valll': new_password 
                            
                        })
            # return 'Work fine'
            return {'message': 'User {} was created'.format( username)}
            
        except:
            return 
            return {'message': 'Something went wrong'}, 500


class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        username = data['username']
        password = data['password'] 

        # def verify_password(password, hash)
        #     return sha256.verify(password, hash)


        return data
      
class UserLogoutAccess(Resource):
    def post(self):
        return {'message': 'User logout'}
      
      
class UserLogoutRefresh(Resource):
    def post(self):
        return {'message': 'User logout'}
      
      
class TokenRefresh(Resource):
    def post(self):
        return {'message': 'Token refresh'}
      
      
class AllUsers(Resource):
    def get(self):
        return {'message': 'List of users'}

    def delete(self):
        return {'message': 'Delete all users'}
      
      
class SecretResource(Resource):
    def get(self):
        return {
            'answer': 42
        }
