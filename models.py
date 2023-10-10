from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_serializer import SerializerMixin

db = SQLAlchemy()

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    serialize_rules = ('-user_messages.user', '-user_friends.user',)
    

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False) 
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

    #define relationship between user and messages
    user_messages = db.relationship('Message', backref='user', lazy='dynamic')
    
    #define relationship between user and friends
    user_friends = db.relationship('Friend', backref='user', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.username}| email: {self.email}>'
    
class Chatroom(db.Model, SerializerMixin):
    __tablename__ = 'chatrooms'

    serialize_rules = ('-chatroom_messages.chatroom',)

    id = db.Column(db.Integer, primary_key=True)
    chatroom_name = db.Column(db.String)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())

    #define relationship between chatroom and messages
    chatroom_messages = db.relationship('Message', backref='chatroom', lazy='dynamic')

    def __repr__(self):
        return f'<Chatroom {self.chatroom_name}>'    

class Message(db.Model, SerializerMixin):
    __tablename__ ='messages'

    serialize_rules = ('-user.user_messages', '-chatroom.chatroom_messages',)

    id = db.Column(db.Integer, primary_key=True)
    message_content = db.Column(db.String)
    chatroom_id = db.Column(db.Integer, db.ForeignKey('chatrooms.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())    

    def __repr__(self):
        return f'<Message {self.message_content}>'
    
class Friend(db.Model, SerializerMixin):
    __tablename__ = 'friends'

    serialize_rules = ('-user.user_friends',)
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
