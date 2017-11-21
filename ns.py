import sqlite3
import ipaddress
import struct
import socket
import threading
import sys
import select
import os
import binascii
import hashlib
import json
import math

"""
Basic structure: 666+id+data

Existing commands:

id | data | meaning
---|-----------------------------------------------------------------|--------
1  | node_token[128] ip[4] port[2]                                   | handshake
2  | token[128] filename[128]                                        | client to storage - get file chunk request
3  | filename[128] total[2] number[2] datasize[2] data               | storage to client - send file chunk
4  | token[128] filename[128]                                        | storage to ns - check client-file permissions
5  | token[128] filename[128] T/F[1]                                 | ns to storage - check result
6  | error_code[1]                                                   | for different errors
7  | size[1] login size[1] pass                                      | client to ns - auth
8  | token[128]                                                      | ns to client - auth
9  | token[128]                                                      | client to ns - request the tree
10 | total[1] number[1] datasize[2] data                             | ns to client - send the tree
11 | token[128] size[2] filepath                                     | client to ns - request file info   (not required)
12 | total[1] number[1] datasize[2] data                             | ns to client - send file info      (not required)
13 | token[128] size[2] filepath                                     | client to ns - get file request
14 | total[1] number[1] datasize[2] data                             | ns to client - send file's chunks locations
15 | token[128] size[2] filepath total[2] number[2] datasize[2] data | client to ns - upload file request (package 1 - meta, then - data)
16 | size[2] filepath T/F[1]                                         | ns to client - file upload result
17 | token[128] size[2] filepath                                     | client to ns - file delete request
18 | size[2] filepath T/F[1]                                         | ns to client - file delete result
19 | token[128] size[2] srcfilepath size[2] dstfilepath              | client to ns - rename file request
20 | size[2] srcfilepath size[2] dstfilepath T/F[1]                  | ns to client - rename file result
21 | filename[128] total[2] number[2] datasize[2] data               | ns to storage - send file chunk to storage ((????draft????__
22 | filename[128] T/F[1]                                            | storage to ns - file save result
23 | filename[128]                                                   | ns to storage - delete file
24 | filename[128] T/F[1]                                            | storage to ns - file delete result
25 | filename[128] total[2] number[2] datasize[2] data               | ns to storage - update file, draft
26 | filename[128] T/F[1]                                            | storage to ns - file update, draft, result
27 | filename[128] T/F[1]                                            | ns to storage - update file
28 | filename[128] T/F[1]                                            | storage to ns - update file result
29 |                                                                 | ns to storage - get memory information
30 | size[8] total size[8] busy                                      | storage to ns - send memory information
"""

"""
Error codes:
1: Permission denied
2: Wrong password
3: User not found
"""

MAX_CONNECTIONS_NUMBER = 1000
PORT = 9090

# List of errors
PERMISSION_DENIED = 1
WRONG_PASSWORD = 2
USER_NOT_FOUND = 3

ERROR_MSG = 6
CLIENT_REQUEST_AUTH = 7
CLIENT_SEND_AUTH = 8
CLIENT_REQUEST_TREE = 9
CLIENT_SEND_TREE = 10
CLIENT_REQUEST_GET_FILE = 13
CLIENT_SEND_FILE_INFO = 14
CLIENT_REQUEST_UPLOAD = 15
CLIENT_SEND_UPLOAD_RESULT = 16

DATA_SIZE = 4096
DATA_SIZE_PACKED = struct.pack('>h', DATA_SIZE)


def dict_factory(cur, row):
    d = {}
    for idx, col in enumerate(cur.description):
        d[col[0]] = row[idx]
    return d


def init_db():
    conn, cur = connect_to_db()
    User.create_user_table(cur)
    conn.commit()

    Entity.create_entity_table(cur)
    conn.commit()

    EntityComponent.create_entity_table(cur)
    conn.commit()

    conn.close()


def connect_to_db():
    conn = sqlite3.connect("db/nameserver.db")
    conn.row_factory = dict_factory
    cur = conn.cursor()
    return conn, cur


class NameServer(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.connections = [sys.stdin]
        self.running = True

    def run(self):
        self._bind_socket()
        self._run()

    def stop(self):
        self.running = False
        self.ns_socket.close()

    def _bind_socket(self):
        self.ns_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ns_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.ns_socket.bind(('', self.port))
        except socket.error as msg:
            print 'Cannot bind to the given host and port (%s, %i): %s' % (self.host, self.port, msg)
            sys.exit()
        else:
            print 'NS is up ([q] to exit)'
            self.ns_socket.listen(MAX_CONNECTIONS_NUMBER)
            self.connections.append(self.ns_socket)

    def _run(self):
        while self.running:
            try:
                ready_to_read, ready_to_write, in_error = select.select(self.connections, [], [])
            except socket.error as msg:
                print msg
                continue
            else:
                for sock in ready_to_read:
                    if sock == self.ns_socket:
                        try:
                            client_socket, client_address = self.ns_socket.accept()
                            print "User connected: ", client_socket, client_address
                        except socket.error as msg:
                            print msg
                            break
                        else:
                            self.connections.append(client_socket)
                    elif sock != sys.stdin:
                        self._receive(sock)
                    else:
                        command = sys.stdin.readline()
                        sys.stdout.flush()
                        command = command[-2:-1]
                        if command == 'q':
                            print "Bye bye"
                            self.stop()
        self.stop()

    def _send(self, sock, package_id, data):
        # TODO check if user still connected
        header = struct.pack('>hB', 666, package_id)
        sock.send(header + data)

    def _receive(self, sock):
        # TODO when the header is wrong - clear the buffer and send error response
        try:
            msg_start = sock.recv(3)
        except socket.error as (code, msg):
            print code, msg, sock
            if code == 104:
                self.connections.remove(sock)
        else:
            if len(msg_start) == 0:
                print "Client disconnected: ", sock
                self.connections.remove(sock)
                return

            try:
                start, package_id = struct.unpack('>hB', msg_start)
            except struct.error as msg:
                print "Wrong header in the package", msg
            else:
                print start, package_id
                if start != 666:
                    print "This is not devilish package"
                    return

                if package_id == 4:  # storage to ns - check client-file permissions
                    pass
                elif package_id == ERROR_MSG:  # errors
                    pass
                elif package_id == CLIENT_REQUEST_AUTH:  # client to ns - auth
                    self.auth_client(sock)
                elif package_id == CLIENT_REQUEST_TREE:  # client to ns - request the tree
                    self.tree_request(sock)
                elif package_id == CLIENT_REQUEST_GET_FILE:  # client to ns - get file request
                    self.get_file_request(sock)
                elif package_id == CLIENT_REQUEST_UPLOAD:  # client to ns - upload file request
                    self.upload_request(sock)
                elif package_id == 17:  # client to ns - file delete request
                    pass
                elif package_id == 19:  # client to ns - rename file request
                    pass
                elif package_id == 22:  # storage to ns - file save result
                    pass
                elif package_id == 24:  # storage to ns - file delete result
                    pass
                elif package_id == 26:  # storage to ns - file update, draft, result
                    pass
                elif package_id == 28:  # storage to ns - update file result
                    pass
                elif package_id == 30:  # storage to ns - send memory information
                    pass
                else:
                    print "Wrong command received"
                    # TODO SEND RESPONSE ABOUT WRONG COMMAND

    def auth_client(self, sock):
        """
        id: 7  | package structure: size[1] login size[1] pass | client to ns - auth
        """
        # TODO check login and password for correctness
        data = sock.recv(1)
        try:
            login_length,  = struct.unpack('>B', data)
        except struct.error as msg:
            print msg
            return

        login = sock.recv(login_length).decode()
        data = sock.recv(1)
        try:
            pass_length,  = struct.unpack('>B', data)
        except struct.error as msg:
            print msg
            return
        passwd = sock.recv(pass_length).decode()

        conn, cur = connect_to_db()

        user = User.find_by_login(cur, login)

        if user is None:
            token = binascii.b2a_hex(os.urandom(64))
            User.add_user(conn, cur, token, login, passwd)
        else:
            if not User.check_passwd(passwd, user):
                self.send_error(sock, WRONG_PASSWORD)
                return
            else:
                token = user['token']

        self.send_token(sock, token)

    def tree_request(self, sock):
        """
        9  | token[128] | client to ns - request the tree
        """

        res = self.user_check(sock)

        if not res:
            return

        conn, cur, user = res

        self.send_tree(cur, sock, user)

    def get_file_request(self, sock):
        """
        13 | token[128] size[2] filepath | client to ns - get file request
        """
        res = self.user_check(sock)

        if not res:
            return

        conn, cur, user = res

        filepath = self.filepath_retrieve(sock)

        self.send_file_info(sock, cur, user['id'], filepath)

    def upload_request(self, sock):
        """
        15 | token[128] size[2] filepath total[2] number[2] datasize[2] data | client to ns - upload file request
        """
        res = self.user_check(sock)

        if not res:
            return

        conn, cur, user = res

        filepath = self.filepath_retrieve(sock)


    def send_error(self, sock, error_code):
        """
        6  | error_code[1]  | for different errors
        """
        data = struct.pack('>B', error_code)
        self._send(sock, ERROR_MSG, data)

    def send_token(self, sock, token):
        """
        8  | token[128]  | ns to client - auth
        """
        import time
        time.sleep(2)
        self._send(sock, CLIENT_SEND_AUTH, token.encode())

    def send_tree(self, cur, sock, user):
        """
            10 | total[1] number[1] datasize[2] data | ns to client - send the tree
        """
        tree = Entity.find_entities(cur, user['id'])
        json_tree = json.dumps(tree)

        self.pack_and_send_data(sock, CLIENT_SEND_TREE, json_tree)

    def send_file_info(self, sock, cur, userid, filepath):
        """
        14 | total[1] number[1] datasize[2] data | ns to client - send file's chunks locations
        """
        entity = Entity.find_entity_by_userid_filepath(cur, userid, filepath)

        if entity is None:
            data = '{}'
            self.pack_and_send_data(sock, CLIENT_SEND_FILE_INFO, data)
            return

        entity_components = EntityComponent.find_entity_components(cur, entity['id'])
        entity.pop('id', None)
        entity['total'] = len(entity_components)
        entity['components'] = entity_components

        json_data = json.dumps(entity)
        self.pack_and_send_data(sock, CLIENT_SEND_FILE_INFO, json_data)

    def user_check(self, sock):
        data = ""
        while len(data) < 128:
            data = sock.recv(128)

        token = data.decode()

        conn, cur = connect_to_db()
        user = User.find_by_token(cur, token)

        if user is None:
            self.send_error(sock, USER_NOT_FOUND)
            return False

        return conn, cur, user

    def filepath_retrieve(self, sock):
        data = sock.recv(2)
        try:
            path_size, = struct.unpack('>h', data)
        except struct.error as msg:
            print msg, sock
            return

        data = ""
        data_block = DATA_SIZE if DATA_SIZE < path_size else path_size

        while len(data) < path_size:
            data = sock.recv(data_block)

        return data.decode()

    def pack_and_send_data(self, sock, msg_code, json_tree):
        total = int(math.ceil(len(json_tree) / float(DATA_SIZE)))
        total_pack = struct.pack('>B', total)

        for i in range(total):
            package_number = struct.pack('>B', i + 1)
            data = total_pack + package_number

            if i + 1 < total:
                data += DATA_SIZE_PACKED + json_tree[i * DATA_SIZE: i + 1 * DATA_SIZE].encode()
            else:
                block = json_tree[i * DATA_SIZE:]
                last_package_size = struct.pack('>h', len(block))
                data += last_package_size + block.encode()
            self._send(sock, msg_code, data)

    def file_download(self, sock):
        data = sock.recv(2)
        total = struct.unpack('>h', data)

    def separate_on_chunks(self, free_places, filesize):
        # TODO improve algorithm so that free space for each node would become more equal
        totaly_free = sum(free_places)
        rel_places = [int(math.floor(filesize * item / float(totaly_free))) for item in free_places]

        diff = filesize - sum(rel_places)
        i = 0
        while diff > 0 and i < len(free_places):
            if rel_places[i] < free_places[i]:
                rel_places[i] += 1
                diff -= 1
            i += 1

        return rel_places


class User:
    table_name = 'user'

    def __init__(self):
        pass

    @staticmethod
    def create_user_table(cur):
        cur.execute("CREATE TABLE IF NOT EXISTS " + User.table_name + " ("
                    "id INTEGER PRIMARY KEY, "
                    "token VARCHAR(128), "
                    "login VARCHAR(20) NOT NULL, "
                    "pass_hash VARCHAR(25) NOT NULL"
                    ")")

    @staticmethod
    def find_by_login(cur, login):
        cur.execute("SELECT * FROM " + User.table_name + " WHERE login=?", (login, ))
        return cur.fetchone()

    @staticmethod
    def find_by_token(cur, token):
        cur.execute("SELECT * FROM " + User.table_name + " WHERE token=?", (token,))
        return cur.fetchone()

    @staticmethod
    def add_user(conn, cur, token, login, passwd):
        # TODO check for successful execution
        passwd_hash = hashlib.sha512(passwd).hexdigest()
        cur.execute("INSERT INTO " + User.table_name + "(id, token, login, pass_hash) VALUES (NULL, ?, ?, ?)",
                    (token, login, passwd_hash))
        conn.commit()

    @staticmethod
    def check_passwd(passwd, user):
        return hashlib.sha512(passwd).hexdigest() == user['pass_hash']


class Entity:
    # TODO handle the situation when file should be deleted, or fully updated
    """
        Entity status:
            1: OK
            2: Deleting
            3: Uploading
            4: Downloading
    """

    table_name = 'entity'

    def __init__(self):
        pass

    @staticmethod
    def create_entity_table(cur):
        cur.execute("CREATE TABLE IF NOT EXISTS " + Entity.table_name + " ("
                    "id INTEGER PRIMARY KEY, "
                    "filepath VARCHAR(65536) NOT NULL, "
                    "userid INTEGER NOT NULL, "
                    "created REAL NOT NULL, "
                    "modified REAL NOT NULL, "
                    "accessed REAL NOT NULL, "
                    "filesize INTEGER NOT NULL, "
                    "status INTEGER NOT NULL "
                    ")")


    @staticmethod
    def find_entities(cur, user_id):
        cur.execute('SELECT filepath, created, modified, accessed, filesize FROM ' + Entity.table_name + ' WHERE userid=?', (user_id, ))
        return cur.fetchall()

    @staticmethod
    def find_entity_by_userid_filepath(cur, user_id, filepath):
        cur.execute('SELECT id, filepath, created, modified, accessed, filesize'
                    ' FROM ' + Entity.table_name +
                    ' WHERE userid=? AND filepath=?', (user_id, filepath))
        return cur.fetchone()

    @staticmethod
    def create_entity(cur, user_id, filepath, filesize, created, modified, accessed):
        cur.execute("INSERT INTO " + Entity.table_name +
                        " (id, filepath, userid, created, modified, accessed, filesize, status) "
                        "VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)",
                        (filepath, user_id, created, modified, accessed, filesize, 3))


class EntityComponent:
    table_name = 'entity_component'

    def __init__(self):
        pass

    @staticmethod
    def create_entity_table(cur):
        cur.execute("CREATE TABLE IF NOT EXISTS " + EntityComponent.table_name + " ("
                    "id INTEGER PRIMARY KEY, "
                    "token VARCHAR(128) NOT NULL, "
                    "entity_id INTEGER NOT NULL, "
                    "ip INTEGER NOT NULL, "
                    "port INTEGER NOT NULL, "
                    "file_order INTEGER NOT NULL, "
                    "status INTEGER DEFAULT 0 "
                    ")")
    @staticmethod
    def find_entity_components(cur, entity_id):
        # TODO what if some parts are not loaded
        # TODO handle the situation when the file had to be deleted

        cur.execute(
            'SELECT token, ip, port, file_order FROM ' + EntityComponent.table_name +
            ' WHERE entity_id=?',
            (entity_id,))
        return cur.fetchall()


def parse_package(package):
    pass


def main():
    init_db()

    serv = NameServer('', PORT)
    serv.start()


if __name__ == '__main__':
    main()
