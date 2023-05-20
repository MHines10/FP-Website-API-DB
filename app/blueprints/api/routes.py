from flask import request
from . import api
from .auth import basic_auth, token_auth
from app.models import User

# login a user--- Get Token with Username/Password
@api.route('/token', methods=['GET'])
@basic_auth.login_required
def index():
    user = basic_auth.current_user()
    token = user.get_token()
    return {'token': token, 'token_expiration': user.token_expiration}



# Endpoint to get a single user by id
@api.route('/users/<int:user_id>')
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return user.to_dict()

# Endpoint to create a new user
@api.route('/users', methods=['POST'])
def create_user():
    # Check to see that the request sent a request body that is JSON
    if not request.is_json:
        return {'error': 'Your request content-type must be application/json'}, 400
    data = request.json
    for field in ['username', 'email', 'password']:
        if field not in data:
            # If the field is not in the request body, throw an error saying they are missing that field
            return {'error': f"{field} must be in request body"}, 400
    # pull individual values from the request body
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # Check to see if there is a User with that username and/or email
    existing_user = User.query.filter((User.username == username)|(User.email == email)).all()
    if existing_user:
        return {'error': 'User with this username and/or email already exists'}, 400

    # Create a new instance of User
    new_user = User(username=username, email=email, password=password)
    # Send back the new user info
    return new_user.to_dict(), 201

    # Update a user by id 
@api.route('/users/<int:id>', methods=['PUT'])
@token_auth.login_required
def updated_user(id):
    current_user = token_auth.current_user()
    if current_user.id != id:
        return {'error': 'You do not have access to update this user'}, 403
    user = User.query.get_or_404(id)
    data = request.json
    user.update(data)
    return user.to_dict()

# Delete a user by id
@api.route('/users/<int:id>', methods=['DELETE'])
@token_auth.login_required
def delete_user(id):
    current_user = token_auth.current_user()
    if current_user.id != id:
        return {'error': 'You do not have access to delete this user'}, 403
    user_to_delete = User.query.get_or_404(id)
    user_to_delete.delete()
    return {'success': f'{user_to_delete.username} has been deleted'}