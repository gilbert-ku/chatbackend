#!/usr/bin/env python3

from app import app
from models import db, User, Chatroom, Message

with app.app_context():

    User.query.delete()
    Chatroom.query.delete()
    Message.query.delete()


    user1 = User(
        id = 1,
        username = "Okra",
        email = "felicia@gmail.com"
    )

    user2 = User(
        id=2,
        username="SlimShady",
        email="realslim@gmail.com",
    )

    user3 = User(
        id=3,
        username="Kgogstile",
        email="earlsweatshirt@gmail.com",
    )

    db.session.add_all([user1, user2, user3])
    db.session.commit()

    chatroom1 = Chatroom(
        id=1,
        chatroom_name="Generals"
    )

    chatroom2 = Chatroom(
        id=2,
        chatroom_name="Admirals"
    )

    chatroom3 = Chatroom(
        id=3,
        chatroom_name="Privateers"
    )

    db.session.add_all([chatroom1, chatroom2, chatroom3])
    db.session.commit()

    mess1 = Message(
        id=1,
        message_content="Hello",
        chatroom_id=1,
        user_id=1
    )
    mess2 = Message(
        id=2,
        message_content="Hi",
        chatroom_id=1,
        user_id=2
    )
    mess3 = Message(
        id=3,
        message_content="Hey",
        chatroom_id=1,
        user_id=3
    )   

    db.session.add_all([mess1, mess2, mess3])
    db.session.commit()


