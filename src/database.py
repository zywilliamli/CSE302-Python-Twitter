import sqlite3
from sqlite3 import Error
from datetime import datetime

databasePath = "database.db"


class Database(object):

    def __init__(self):
        self.create_tables()

    def connect_db(self):
        try:
            return sqlite3.connect(databasePath)
        except Error:
            print("database connection error")
            return None

    def create_tables(self):
        connection = self.connect_db()
        cursor = connection.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS BROADCASTS(loginserver_record text, message text, sender_created_at text, signature text)")
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS MESSAGES(loginserver_record text, target_pubkey text, target_username text, encrypted_message text, sender_created_at text, signature text)")
        connection.commit()
        connection.close()

    def insert_broadcast(self, broadcast):
        connection = self.connect_db()
        cursor = connection.cursor()
        cursor.execute("INSERT INTO BROADCASTS VALUES(?,?,?,?)", broadcast)
        connection.commit()
        connection.close()

    def insert_message(self, message):
        connection = self.connect_db()
        cursor = connection.cursor()
        cursor.execute("INSERT INTO MESSAGES VALUES(?,?,?,?,?,?)", message)
        connection.commit()
        connection.close()

    def get_broadcast(self):
        connection = self.connect_db()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM BROADCASTS b ORDER BY b.sender_created_at DESC")
        broadcasts = cursor.fetchall()
        broadcast_dict_list = []

        for broadcast in broadcasts:
            broadcast_dict = {}
            loginserver_record_list = broadcast[0].split(',')
            broadcast_dict['username'] = loginserver_record_list[0]
            broadcast_dict['pubkey'] = loginserver_record_list[1]
            broadcast_dict['server_time'] = loginserver_record_list[2]
            broadcast_dict['signature'] = loginserver_record_list[3]

            broadcast_dict['message'] = broadcast[1]
            sender_created_at = float(broadcast[2])
            formatted_sender_created_at = datetime.fromtimestamp(sender_created_at).strftime('%Y-%m-%d %H:%M:%S')
            broadcast_dict['sender_created_at'] = formatted_sender_created_at
            broadcast_dict['message_signature'] = broadcast[3]

            broadcast_dict_list.append(broadcast_dict)

        return broadcast_dict_list

    def get_message(self):
        connection = self.connect_db()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM MESSAGES ")
        messages = cursor.fetchall()
        message_dict_list = []

        for message in messages:
            message_dict = {}

            message_dict['message'] = message[3]
            message_dict['sender_username'] = message[1]
            message_dict['target_username'] = message[0]
            message_dict['sender_created_at'] = message[2]
            message_dict['target_pubkey'] = message[5]

            message_dict_list.append(message_dict)

        return message_dict_list
