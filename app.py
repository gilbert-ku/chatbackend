from flask import Flask, jsonify, request, make_response
from flask_migrate import Migrate
from flask_socketio import SocketIO
from models import db,User, Chatroom, Message, Friend
from flask_restful import Resource, Api, reqparse
from flask_jwt_extended import jwt_required, create_access_token, JWTManager, get_jwt_identity
from flask_cors import CORS
from werkzeug.security import generate_password_hash,check_password_hash
import uuid

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chatwave.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False
JWT_SECRET_KEY = 'secret'
JWT_IDENTITY_CLAIM = 'user_id'
JWT_USER_IDENTITY_LOADER = lambda sub: User.query.get(sub)
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'
jwt = JWTManager(app)
# CORS(app, resources={r"/users/*": {"origins": "http://localhost:5173"}})
# CORS(app, resources={r"/login": {"origins": "http://localhost:5173"}})
CORS(app, resources={r"/users/*": {"origins": "http://localhost:5173"}, r"/login": {"origins": "http://localhost:5173"}})


migrate = Migrate(app,db)

# socketio = SocketIO(app)
socketio = SocketIO(app, cors_allowed_origins="http://localhost:5173")


api = Api(app)

db.init_app(app)

class Users(Resource):# user routes
    def get(self):
        users = [user.to_dict() for user in User.query.all()]
        # Emit a WebSocket message to notify clients about users
        socketio.emit('users_retrieved', users)
        return make_response(jsonify(users), 200)
    def post(self):
        data = request.json

        # Check if the required fields are in the request
        if 'username' not in data or 'email' not in data or 'password' not in data:
            return make_response(jsonify({'message': 'Missing username, email, or password'}), 400)

        # Check if the username or email is already in use
        existing_user = User.query.filter_by(username=data['username']).first()
        if existing_user:
            return make_response(jsonify({'message': 'Username already exists'}), 400)

        existing_email = User.query.filter_by(email=data['email']).first()
        if existing_email:
            return make_response(jsonify({'message': 'Email already exists'}), 400)

        # Hash the password
        password_hash = generate_password_hash(data['password'])

        # Create a new user
        new_user = User(username=data['username'], email=data['email'], password_hash=password_hash)

        db.session.add(new_user)
        db.session.commit()

        new_user_dict = new_user.to_dict()
        # Emit a WebSocket message to notify clients about the new user
        socketio.emit('new_user_added', new_user_dict)

        response = make_response(
            jsonify(new_user_dict),
            201)
        return response

api.add_resource(Users,'/users') 

class User_by_id(Resource):# user by id routes

    def get(self,id):
        user_by_id = User.query.filter_by(id=id).first()
        user_dict = user_by_id.to_dict()
        # Emit a WebSocket message to notify clients about the user
        socketio.emit('user_retrieved', user_dict)
        return make_response(jsonify(user_dict), 200)
    def delete(self, id):
        user_by_id = User.query.filter_by(id=id).first()
        db.session.delete(user_by_id)
        db.session.commit()
        # Emit a WebSocket message to notify clients about the deleted user
        socketio.emit('user_deleted', user_by_id)

        response_body = {
            "delete_successful": True,
            "message": "User deleted."    
        }

        response = make_response(
            jsonify(response_body),
            200
        )

        return response
    
api.add_resource(User_by_id,'/users/<int:id>')    

class Chatrooms(Resource):#chatroom routes
    def get(self): #get method for chatrooms
        chatrooms = [chatroom.to_dict() for chatroom in Chatroom.query.all()]
        # Emit a WebSocket message to notify clients about chatrooms
        socketio.emit('chatrooms_retrieved', chatrooms)
        return make_response(jsonify(chatrooms), 200)
    
    def post(self):
        new_chatroom = Chatroom(
            chatroom_name=request.json['chatroom_name']
        )
        db.session.add(new_chatroom)
        db.session.commit()
        new_chatroom_dict = new_chatroom.to_dict()
        # Emit a WebSocket message to notify clients about the new chatroom
        socketio.emit('new_chatroom', new_chatroom_dict)

        response = make_response(
            jsonify(new_chatroom_dict),
            201)
        return response
api.add_resource(Chatrooms, '/chatrooms')

class Chatroom_by_id(Resource):# chatroom by id routes
    def get(self, id):
        chatroom_by_id = Chatroom.query.filter_by(id=id).first()
        chatroom_dict = chatroom_by_id.to_dict()
        # Emit a WebSocket message to notify clients about the chatroom
        socketio.emit('chatroom_retrieved', chatroom_dict)
        return make_response(jsonify(chatroom_dict), 200)
    def patch(self,id):
        chatroom_by_id = Chatroom.query.filter_by(id=id).first()
        data = request.get_json()
        for attr in data:
            setattr(chatroom_by_id, attr, data[attr])

        db.session.add(chatroom_by_id)
        db.session.commit()

        chatroom_dict = chatroom_by_id.to_dict()    
        socketio.emit('chatroom_updated', chatroom_dict)

        response = make_response(
            jsonify(chatroom_dict),
            200
        )    
        return response
    def delete(self,id):
        chatroom_by_id = Chatroom.query.filter_by(id=id).first()
        db.session.delete(chatroom_by_id)
        db.session.commit()

        socketio.emit('chatroom_deleted', chatroom_by_id)


        response_body = {
            "delete_successful": True,
            "message": "Chatroom deleted."    
        }

        response = make_response(
            jsonify(response_body),
            200
        )

        return response

api.add_resource(Chatroom_by_id, '/chatrooms/<int:id>')    

class Messages(Resource):#message routes
    def get(self):
        messages = [message.to_dict() for message in Message.query.all()]

        socketio.emit('messages_retrieved', messages)
        return make_response(jsonify(messages), 200)
    def post(self):
        new_message = Message(
            message_content=request.json['message_content'],
            chatroom_id=request.json['chatroom_id'],
            user_id=request.json['user_id']
        )
        db.session.add(new_message)
        db.session.commit()
        new_message_dict = new_message.to_dict()

        socketio.emit('new_message', new_message_dict)

        response = make_response(
            jsonify(new_message_dict),
            201)
        return response

api.add_resource(Messages, '/messages')    
    
class Message_by_id(Resource):#message by id routes
    def get(self, id):
        message_by_id = Message.query.filter_by(id=id).first()
        message_dict = message_by_id.to_dict()
        socketio.emit('message_retrieved', message_dict)
        return make_response(jsonify(message_dict), 200)
    def delete(self, id):
        message_by_id = Message.query.filter_by(id=id).first()
        db.session.delete(message_by_id)
        db.session.commit()
        socketio.emit('message_deleted', message_by_id)

        response_body = {
            "delete_successful": True,
            "message": "Message deleted."    
        }

        response = make_response(
            jsonify(response_body),
            200
        )

        return response

api.add_resource(Message_by_id, '/messages/<int:id>')    

class Login(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', required=True)
        parser.add_argument('password', required=True)
        args = parser.parse_args()

        # Check if the username and password are valid
        user = User.query.filter_by(username=args['username']).first()

        if not user or not check_password_hash(user.password_hash, args['password']):
            return make_response(jsonify({'message': 'Invalid credentials'}), 401)

        # Generate a unique user ID
        user_id = str(uuid.uuid4())
        # Create an access token for the user
        access_token = create_access_token(identity=user.id)

        # Return the access token to the user
        return make_response(jsonify({'access_token': access_token}), 200)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

api.add_resource(Login, '/login')

class UserFriendsResource(Resource):
    def get(self, user_id):
        user = User.query.get(user_id)
        if user is None:
            return {"message": "User not found"}, 404

        friends = Friend.query.filter_by(user_id=user_id).all()

        friend_list = [{"friend_id": friend.id, "friend_name": friend.user.username} for friend in friends]

        return {"user_id": user.id, "username": user.username, "friends": friend_list}

api.add_resource(UserFriendsResource, '/users/<int:user_id>/friends')
    

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')


@socketio.on('new_message')
def handle_new_message(data):
    print('New message:', data)

    # Save the new message to the database
    new_message = Message(
        message_content=data['message_content'],
        chatroom_id=data['chatroom_id'],
        user_id=data['user_id']
    )
    db.session.add(new_message)
    db.session.commit()

    # Fetch user information
    user = User.query.get(data['user_id'])

    if user:
        # Broadcast the new message with user information to all connected clients
        socketio.emit('new_message', {'message_content': data['message_content'], 'user': user.to_dict()})

if __name__ == '__main__':                                       
    app.run(host='0.0.0.0', port=5000, debug=True)
