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
import time
from Queue import Queue


"""
Basic structure: 666+id+data

Existing commands:

id | data | meaning
---|-----------------------------------------------------------------|--------
1  | node_token[128] ip[4] port[2]                                   | handshake
2  | token[128] filename[64]                                         | client to storage - get file chunk request
3  | filename[64] total[2] number[2] datasize[2] data                | storage to client - send file chunk
4  | token[128] filename[64]                                         | storage to ns - check client-file permissions
5  | token[128] filename[64] T/F[1]                                  | ns to storage - check result
6  | error_code[1]                                                   | for different errors
7  | size[1] login size[1] pass                                      | client to ns - auth
8  | token[128]                                                      | ns to client - auth
9  | token[128]                                                      | client to ns - request the tree
10 | total[1] number[1] datasize[2] data                             | ns to client - send the tree
11 | token[128] size[2] filepath                                     | client to ns - request file info   (not required)
12 | total[1] number[1] datasize[2] data                             | ns to client - send file info      (not required)
13 | token[128] size[2] filepath                                     | client to ns - get file request
14 | total[1] number[1] datasize[2] data                             | ns to client - send file's chunks locations
15 | token[128] size[2] filepath datasize[2] data                    | client to ns - upload file request (package 1 - meta)
16 | total[1] number[1] datasize[2] data                             | ns to client - file upload information
17 | token[128] size[2] filepath                                     | client to ns - file delete request
18 | size[2] filepath T/F[1]                                         | ns to client - file delete result
19 | token[128] size[2] srcfilepath size[2] dstfilepath              | client to ns - rename file request
20 | size[2] srcfilepath size[2] dstfilepath T/F[1]                  | ns to client - rename file result
21 | filename[64] total[2] number[2] datasize[2] data                | ns to storage - send file chunk to storage ((????draft????__
22 | filename[64] T/F[1]                                             | storage to ns - file save result
23 | token[128] filename[64]                                         | ns to storage - delete file
24 | filename[64] T/F[1]                                             | storage to ns - file delete result
25 | filename[64] total[2] number[2] datasize[2] data                | ns to storage - update file, draft
26 | filename[64] T/F[1]                                             | storage to ns - file update, draft, result
27 | filename[64] T/F[1]                                             | ns to storage - update file
28 | filename[64] T/F[1]                                             | storage to ns - update file result
29 |                                                                 | ns to storage - get memory information
30 | total[8] free[8]                                                | storage to ns - send memory information
31 | node_token[128] T/F[1]                                          | ns to storage - handshake response
32 | token[128] filename[64] total[2] number[2] datasize[2] data     | client to storage - send file chunk
33 | filename[64] T/F[1]                                             | storage to client - send file chunk response
34 | token[128]                                                      | client to ns - keep alive
37 | token[128]                                                      | client to ns - client logout
38 | token[128] total[1] number[1] datasize[2] data                  | client to ns - node failed request
"""

"""
Error codes:
1: Permission denied
2: Wrong password
3: User not found
4: Wrong data
5: Old Token
6: Not Enough Place
7: File Currently Updating
8: Already Active Account
9: No Storage Node Is Available
"""

MAX_CONNECTIONS_NUMBER = 1000
PORT = 9090

# List of errors
PERMISSION_DENIED = 1
WRONG_PASSWORD = 2
NOT_FOUND = 3
WRONG_DATA = 4
OLD_TOKEN = 5
NOT_ENOUGH_PLACE = 6
FILE_CURRENTLY_UPDATING = 7
ALREADY_ACTIVE_ACCOUNT = 8
NO_STORAGE_NODE_IS_AVAILABLE = 9


ERROR_TEXT = {
    PERMISSION_DENIED: 'Permission Denied',
    WRONG_PASSWORD: 'Wrong Password',
    NOT_FOUND: 'Not Found',
    WRONG_DATA: 'Wrong Data',
    OLD_TOKEN: 'Old Token',
    NOT_ENOUGH_PLACE: 'Not Enough Place',
    FILE_CURRENTLY_UPDATING: 'File Currently Updating',
    ALREADY_ACTIVE_ACCOUNT: 'Already Active Account',
    NO_STORAGE_NODE_IS_AVAILABLE: ' No Storage Node Is Available'
}

STORAGE_CLIENT_PERMISSION = 4
STORAGE_SEND_CLIENT_PERMISSION_RESPONSE = 5
ERROR_MSG = 6
CLIENT_REQUEST_AUTH = 7
CLIENT_SEND_AUTH = 8
CLIENT_REQUEST_TREE = 9
CLIENT_SEND_TREE = 10
CLIENT_REQUEST_GET_FILE = 13
CLIENT_SEND_FILE_INFO = 14
CLIENT_REQUEST_UPLOAD = 15
CLIENT_SEND_UPLOAD_RESULT = 16
CLIENT_DELETE_REQUEST = 17
CLIENT_SEND_DELETE_RESPONSE = 18
CLIENT_RENAME_REQUEST = 19
CLIENT_RENAME_RESPONSE = 20
CLIENT_FILE_SAVE_RESULT = 22
STORAGE_SEND_DELETE = 23
STORAGE_GET_DELETE_RESPONSE = 24
STORAGE_GET_MEMORY_INFO = 29
STORAGE_MEMORY_INFO_RESULT = 30
CLIENT_KEEP_ALIVE = 34
CLIENT_LOGOUT = 37
CLIENT_NODE_FAILED_REQUEST = 38

STORAGE_HANDSHAKE = 1
STORAGE_HANDSHAKE_RESPONSE = 31
STORAGE_SEND_FILE = 21

MEMORY_REQUEST_TIMEOUT = 20
CLIENT_TIMEOUT = 60

RESPONSE_OK = 1
RESPONSE_FAILURE =2

STATUS_UPDATING = 1
STATUS_SAVED = 2
STATUS_OLD = 3
STATUS_DELETED = 4

DATA_SIZE = 4096
DATA_SIZE_PACKED = struct.pack('<h', DATA_SIZE)

FILENAME_SIZE = 64

storage_update_thread = None

def dict_factory(cur, row):
    d = {}
    for idx, col in enumerate(cur.description):
        d[col[0]] = row[idx]
    return d


def init_db():
    conn, cur = connect_to_db()
    User.create_table(cur)
    conn.commit()

    UserToken.create_table(cur)
    conn.commit()

    Entity.create_table(cur)
    conn.commit()

    EntityComponent.create_table(cur)
    conn.commit()

    Node.create_table(cur)
    conn.commit()

    conn.close()


def connect_to_db():
    conn = sqlite3.connect("db/nameserver.db")
    conn.row_factory = dict_factory
    cur = conn.cursor()
    return conn, cur


def send_error(sock, error_code):
    """
    6  | error_code[1]  | for different errors
    """
    data = struct.pack('<B', error_code)
    send(sock, ERROR_MSG, data)


def send(sock, package_id, data):
    # TODO check if user still connected
    header = struct.pack('<hB', 666, package_id)
    sock.send(header + data)


def read_header(sock, obj):
    try:
        msg_start = sock.recv(3)
    except socket.error as (code, msg):
        print obj, code, msg, sock
        # if code == 104:
        #     self.connections.remove(sock)
        return False, False

    if len(msg_start) == 0:
        return False, False

    try:
        start, package_id = struct.unpack('<hB', msg_start)
    except struct.error as msg:
        print obj, "Wrong header in the package", msg, sock
        return False, False

    print start, package_id

    if start != 666:
        print obj, "This is not devilish package"
        return False, False

    return start, package_id


class StorageUpdate(threading.Thread):
    # TODO delete old data from storage once in an hour
    def __init__(self):
        threading.Thread.__init__(self)
        self.connections = []
        self.running = threading.Event()
        self.authorized_nodes = []
        self.memory_request_nodes = {}
        self.memory_info_received = 0
        self.timer = None

    def run(self):
        self._run()

    def close_connection(self, sock):
        print "memory, Client disconnected: ", sock
        if sock in self.authorized_nodes:
            self.authorized_nodes.remove(sock)

        if sock in self.memory_request_nodes.keys():
            conn, cur = connect_to_db()
            Node.update_node(conn, cur, self.memory_request_nodes[sock], {'alive': 0})
            self.memory_request_nodes.pop(sock, None)

        if sock in self.connections:
            self.connections.remove(sock)

        try:
            sock.close()
        except:
            pass

    def stop(self):
        self.running.set()
        for connection in self.connections:
            try:
                connection.close()
            except:
                print connection, 'memory, socket already closed'

        if self.timer:
            self.timer.set()

    def _run(self):
        while not self.running.is_set():
            self.timer = threading.Event()
            self.get_nodes_memory_info()

            try:
                ready_to_read, ready_to_write, in_error = select.select(self.connections, [], [], 2)
            except socket.error as msg:
                print msg
                continue

            for sock in ready_to_read:
                start, package_id = read_header(sock, 'StorageUpdate')

                if not (start and package_id):
                    self.close_connection(sock)
                    continue

                if package_id == STORAGE_MEMORY_INFO_RESULT:  # storage to ns - send memory information
                    self.memory_info_result(sock)
                else:
                    send_error(sock, WRONG_DATA)

            if self.timer.wait(MEMORY_REQUEST_TIMEOUT):
                return

    def memory_info_result(self, sock):
        """
        30 | total[8] free[8]  | storage to ns - send memory information
        """
        Node.check_node(sock, self.authorized_nodes)

        if sock not in self.memory_request_nodes.keys():
            send_error(sock, WRONG_DATA)
            print sock, 'memory info operation not permitted for this user/node'
            return

        total_b = sock.recv(8)
        free_b = sock.recv(8)
        try:
            total, = struct.unpack('<Q', total_b)
            free, = struct.unpack('<Q', free_b)
        except struct.error as msg:
            print sock, msg, ERROR_TEXT[WRONG_DATA]
            send_error(sock, WRONG_DATA)
            return

        conn, cur = connect_to_db()
        Node.update_node(conn, cur, self.memory_request_nodes[sock], {
            'total_memory': total, 'free_memory': free, 'alive': 1})

        self.memory_info_received -= 1

        if sock in self.authorized_nodes:
            self.authorized_nodes.remove(sock)

        if sock in self.connections:
            self.connections.remove(sock)

        if sock in self.memory_request_nodes.keys():
            self.memory_request_nodes.pop(sock, None)

        try:
            sock.close()
        except:
            print sock, 'socket already closed'

    def get_nodes_memory_info(self):
        """
        29 | node_token[128] | ns to storage - get memory information
        """
        #      TODO realisation

        conn, cur = connect_to_db()
        nodes = Node.find_nodes(cur)

        for n_socket in self.memory_request_nodes.keys():
            try:
                n_socket.close()
            except:
                print n_socket, 'socket already closed'

            if n_socket in self.connections:
                self.connections.remove(n_socket)
            if n_socket in self.authorized_nodes:
                self.authorized_nodes.remove(n_socket)

        self.memory_request_nodes = {}

        for node in nodes:
            out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                out_sock.connect((node['ip'], node['port']))
            except socket.error:
                Node.update_node(conn, cur, node['token'], {'alive': 0})
                print 'cannot connect to the node,', node['ip'], node['port']
                continue

            print out_sock, 'sent'
            self.connections.append(out_sock)
            self.authorized_nodes.append(out_sock)
            self.memory_request_nodes[out_sock] = node['token']
            data = node['token'].encode()
            send(out_sock, STORAGE_GET_MEMORY_INFO, data)

        self.memory_info_received = len(self.memory_request_nodes)



class NameServer(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.connections = [sys.stdin]
        self.running = threading.Event()
        self.authorized_nodes = []
        self.failed_node_info = {}
        self.update_event = None

    def run(self):
        self._bind_socket()
        self._run()

    def stop(self):
        self.running.set()
        for connection in self.connections:
            if connection != sys.stdin:
                try:
                    connection.close()
                except:
                    print connection, 'socket already closed'

        global storage_update_thread
        if storage_update_thread:
            storage_update_thread.stop()

    def close_connection(self, sock):
        print "Client disconnect: ", sock
        if sock in self.authorized_nodes:
            self.authorized_nodes.remove(sock)

        if sock in self.connections:
            self.connections.remove(sock)

        try:
            sock.close()
        except:
            pass

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
        while not self.running.is_set():

            try:
                ready_to_read, ready_to_write, in_error = select.select(self.connections, [], [])
            except socket.error as msg:
                print msg
                continue

            thr_list = []

            for sock in ready_to_read:
                if sock == self.ns_socket:
                    try:
                        client_socket, client_address = self.ns_socket.accept()
                        print "New connection: ", client_socket, client_address
                    except socket.error as msg:
                        print msg
                        break
                    else:
                        self.connections.append(client_socket)
                elif sock != sys.stdin:
                    thr_list.append(threading.Thread(target=self._receive, args=(sock,)))
                    thr_list[-1].start()
                    # self._receive(sock)
                else:
                    command = sys.stdin.readline()
                    sys.stdout.flush()
                    command = command[-2:-1]
                    if command == 'q':
                        print "Bye bye"
                        self.stop()

            for item in thr_list:
                item.join()

    def _receive(self, sock):
        # TODO when the header is wrong - clear the buffer and send error response
        start, package_id = read_header(sock, 'NameServer')

        if package_id == 1:  # handshake
            self.handshake_storage_request(sock)
        elif package_id == 4:  # storage to ns - check client-file permissions
            self.client_permission_request(sock)
        elif package_id == ERROR_MSG:  # errors
            self.error_received(sock)
        elif package_id == CLIENT_REQUEST_AUTH:  # client to ns - auth
            self.auth_client(sock)
        elif package_id == CLIENT_REQUEST_TREE:  # client to ns - request the tree
            self.tree_request(sock)
        elif package_id == CLIENT_REQUEST_GET_FILE:  # client to ns - get file request
            self.get_file_request(sock)
        elif package_id == CLIENT_REQUEST_UPLOAD:  # client to ns - upload file request
            self.upload_request(sock)
        elif package_id == CLIENT_DELETE_REQUEST:  # client to ns - file delete request
            self.delete_request(sock)
        elif package_id == CLIENT_RENAME_REQUEST:  # client to ns - rename file request
            self.rename_request(sock)
        elif package_id == CLIENT_FILE_SAVE_RESULT:  # storage to ns - file save result, draft
            self.file_save_result_request(sock)
        elif package_id == STORAGE_GET_DELETE_RESPONSE:  # storage to ns - file delete result
            self.delete_response_from_storage(sock)
        elif package_id == 28:  # storage to ns - update file result
            pass
        elif package_id == CLIENT_KEEP_ALIVE:  # client to ns - keep alive
            self.keep_alive_request(sock)
        elif package_id == CLIENT_LOGOUT:
            self.client_logout_request(sock)
        elif package_id == CLIENT_NODE_FAILED_REQUEST:
            self.node_failed_request(sock)
        else:
            print "Wrong command received"
            send_error(sock, WRONG_DATA)

    def handshake_storage_request(self, sock):
        """
        1  | node_token[128] ip[4] port[2]  | handshake
        """
        # TODO public/private key use
        conn, cur, node, token = self.check_by_token(sock, Node.table_name)

        if token is False:
            return

        data = sock.recv(4)
        try:
            ip = ipaddress.IPv4Address(data)
        except ipaddress.AddressValueError as msg:
            print msg, sock
            self.send_handshake_response(sock, token, RESPONSE_FAILURE)
            return

        data = sock.recv(2)
        try:
            port, = struct.unpack('<H', data)

        except struct.error as msg:
            print msg, sock
            self.send_handshake_response(sock, token, RESPONSE_FAILURE)
            return

        if node is False:
            Node.add_node(conn, cur, token, str(ip), port)
        else:
            params = {
                'ip': str(ip),
                'port': port,
                'alive': 1
            }
            Node.update_node(conn, cur, token, params)

        self.authorized_nodes.append(sock)
        self.send_handshake_response(sock, token, RESPONSE_OK)

    def client_permission_request(self, sock):
        """
        4  | client_token[128] filename[64] | storage to ns - check client-file permissions
        """
        # TODO only updated are permitted

        if not Node.check_node(sock, self.authorized_nodes):
            return

        client_token = self.string_decoding(sock, 128, 128)

        if client_token is False:
            send_error(sock, WRONG_DATA)
            print sock, ERROR_TEXT[WRONG_DATA], 'client token'
            return

        filename = self.string_decoding(sock, FILENAME_SIZE, FILENAME_SIZE)
        if filename is False:
            send_error(sock, WRONG_DATA)
            print sock, ERROR_TEXT[WRONG_DATA], 'filename'

        conn, cur = connect_to_db()
        user = User.find_by_token(cur, client_token)

        if user:
            entity_component = EntityComponent.find_entity_component(cur, filename)
            if entity_component and Entity.find_entity(cur, entity_component['entity_id'], user['id'], True):
                self.send_client_permission_response(sock, client_token, filename, True)
                print sock, client_token, filename, 'permission granted'
                return

        self.send_client_permission_response(sock, client_token, filename, False)
        print sock, client_token, filename, 'client', ERROR_TEXT[PERMISSION_DENIED]

    def error_received(self, sock):
        """
        6  | error_code[1]  | for different errors
        """
        error = sock.recv(1)
        try:
            error_code, = struct.unpack('<B', error)
        except struct.error as msg:
            print sock, msg
        else:
            if error_code in ERROR_TEXT:
                print 'The error was received: ' + ERROR_TEXT[error_code]
            else:
                print 'Some unfamiliar error was received. Code ' + str(error_code)

    def rename_request(self, sock):
        """
        19 | token[128] size[2] srcfilepath size[2] dstfilepath | client to ns - rename file request
        """

        conn, cur, user, token = self.check_by_token(sock, User.table_name)

        if user is False:
            send_error(sock, OLD_TOKEN)
            print sock, ERROR_TEXT[OLD_TOKEN]
            return

        srcfilepath = self.read_data(sock, 2)
        dstfilepath = self.read_data(sock, 2)

        entity = Entity.find_entity_by_userid_filepath(cur, user['id'], srcfilepath)

        if not entity:
            print sock, user['id'], 'file not found'
            self.rename_response(sock, srcfilepath, dstfilepath, False)
            return

        Entity.update_entity_name(conn, cur, entity['id'], dstfilepath)
        print sock, user['id'], entity['id'], 'renamed'
        self.rename_response(sock, srcfilepath, dstfilepath, True)

    def auth_client(self, sock):
        """
        id: 7  | package structure: size[1] login size[1] pass | client to ns - auth
        """
        # TODO check login and password for correctness
        # TODO user several tokens
        data = sock.recv(1)
        try:
            login_length,  = struct.unpack('<B', data)
        except struct.error as msg:
            print msg
            return

        login = self.string_decoding(sock, login_length, login_length)
        if login is False:
            return

        data = sock.recv(1)
        try:
            pass_length,  = struct.unpack('<B', data)
        except struct.error as msg:
            print msg
            return

        passwd = self.string_decoding(sock, pass_length, pass_length)

        if passwd is False:
            return

        conn, cur = connect_to_db()
        user = User.find_by_login(cur, login)

        if user is None:
            token = binascii.b2a_hex(os.urandom(FILENAME_SIZE))
            User.add_user(conn, cur, token, login, passwd)
        else:
            if not User.check_passwd(passwd, user):
                print "User", user['id'], ERROR_TEXT[WRONG_PASSWORD]
                send_error(sock, WRONG_PASSWORD)
                return

            if User.check_token_time(user):
                print "User", user['id'], ERROR_TEXT[ALREADY_ACTIVE_ACCOUNT]
                send_error(sock, ALREADY_ACTIVE_ACCOUNT)
                return

            token = binascii.b2a_hex(os.urandom(FILENAME_SIZE))
            User.update_user_token(conn, cur, user['id'], token)

        self.send_token(sock, token)

    def client_logout_request(self, sock):
        """
        37 | token[128]  | client to ns - client logout
        """

        token = self.string_decoding(sock, 128, 128)

        if token is False:
            send_error(sock, WRONG_DATA)
            print sock, ERROR_TEXT[WRONG_DATA]
            return

        conn, cur = connect_to_db()
        user = User.find_by_token(cur, token)

        if not user:
            send_error(sock, NOT_FOUND)
            print sock, ERROR_TEXT[NOT_FOUND]
            return

        User.update_user_time(conn, cur, user['id'], time.time() - 1000)
        print sock, user['id'], 'user logged out'

    def tree_request(self, sock):
        """
        9  | token[128] | client to ns - request the tree
        """

        conn, cur, user, _ = self.check_by_token(sock, User.table_name)

        if user is False:
            return

        self.send_tree(cur, sock, user)

    def get_file_request(self, sock):
        """
        13 | token[128] size[2] filepath | client to ns - get file request
        """
        conn, cur, user, _ = self.check_by_token(sock, User.table_name)

        if user is False:
            return

        filepath = self.read_data(sock, 2)

        self.send_file_info(sock, cur, user['id'], filepath)

    def upload_request(self, sock):
        """
        15 | token[128] size[2] filepath datasize[2] metadata | client to ns - upload file request
        """
        conn, cur, user, _ = self.check_by_token(sock, User.table_name)

        if user is False:
            return

        filepath = self.read_data(sock, 2)

        metadata = self.read_data(sock, 2)

        self.send_upload_file_info(sock, filepath, metadata, user)

    def node_failed_request(self, sock):
        """
        38 | token[128] total[1] number[1] datasize[2] data | client to ns - node failed request
        flag - continue, offset
        """

        conn, cur, user, token = self.check_by_token(sock, User.table_name)

        if user is False:
            return

        data = sock.recv(4)
        try:
            total, number, datasize = struct.unpack('<BBh', data)
        except struct.error as msg:
            print sock, msg
            send_error(sock, WRONG_DATA)
            return

        data_block = DATA_SIZE if DATA_SIZE < datasize else datasize
        data = self.string_decoding(sock, datasize, data_block)

        if sock not in self.failed_node_info.keys():
            self.failed_node_info[sock] = {
                'token': token,
                'total': total,
                'data': []
            }

        self.failed_node_info[sock]['data'][number] = data

        if len(self.failed_node_info['data']) == total:
            self.file_partitioning_update(sock, user, conn, cur)

    def file_save_result_request(self, sock):
        """
        22 | filename[64] T/F[1]  | storage to ns - file save result
        """
        # TODO save information about packet number, where the file uploading stopped

        filename, result = self.parse_storage_result_response(sock)

        if result == 1:
            print filename
            conn, cur = connect_to_db()
            entity_component = EntityComponent.find_entity_component(cur, filename)

            if entity_component:
                entity = Entity.find_entity_by_id(cur, entity_component['entity_id'])
                if entity:
                    EntityComponent.update_component_status(conn, cur, STATUS_SAVED, entity_component['id'])
                    print 'Entity component was saved', entity_component['id']

                    updating_components = EntityComponent.find_entity_components(cur, entity['id'], STATUS_UPDATING)

                    if len(updating_components) == 0:
                        EntityComponent.delete_old_components_by_entity_id(conn, cur, entity['id'])
                        entity_data = {
                            'modified': entity['modified_new'] if entity['modified_new'] else entity['modified'],
                            'modified_new': None,
                            'status': STATUS_SAVED,
                            'filesize': entity['filesize_new'] if entity['filesize_new'] else entity['filesize'],
                            'filesize_new': None
                        }
                        Entity.update_entity(conn, cur, entity['id'], entity_data)
                        print 'Entity was saved', entity['id']

                    self.authorized_nodes.remove(sock)
                    return

            send_error(sock, WRONG_DATA)
            print sock, filename, ERROR_TEXT[WRONG_DATA]

    def delete_response_from_storage(self, sock):
        """
        24 | filename[64] T/F[1]  | storage to ns - file delete result
        """
        filename, result = self.parse_storage_result_response(sock)

        if result == 1:
            conn, cur = connect_to_db()
            entity_component = EntityComponent.find_entity_component(cur, filename)

            if entity_component:
                EntityComponent.delete_component(conn, cur, entity_component['id'])

                self.close_connection(sock)
                return

        send_error(sock, WRONG_DATA)
        print sock, filename, ERROR_TEXT[WRONG_DATA]

    def parse_storage_result_response(self, sock):
        filename = self.string_decoding(sock, FILENAME_SIZE, FILENAME_SIZE)

        if filename is False:
            send_error(sock, WRONG_DATA)
            print sock, ERROR_TEXT[WRONG_DATA], 'filename'
            return False, False

        data = sock.recv(1)
        try:
            result, = struct.unpack('<B', data)
        except struct.error as msg:
            send_error(sock, WRONG_DATA)
            print sock, msg, ERROR_TEXT[WRONG_DATA]
            return False, False

        return filename, result

    def keep_alive_request(self, sock):
        """
        34 | token[128] | client to ns - keep alive
        """

        conn, cur, user, _ = self.check_by_token(sock, User.table_name)
        if user is False:
            return
        else:
            User.update_user_time(conn, cur, user['id'])

    def delete_request(self, sock):
        """
        17 | token[128] size[2] filepath  | client to ns - file delete request
        """

        conn, cur, user, _ = self.check_by_token(sock, User.table_name)

        if user is False:
            return

        filepath = self.read_data(sock, 2)
        entity = Entity.find_entity_by_userid_filepath(cur, user['id'], filepath, True)

        if not entity:
            print "User", user['id'], "tried to delete file", filepath, ERROR_TEXT[NOT_FOUND]
            send_error(sock, NOT_FOUND)
        elif entity['status'] == STATUS_UPDATING:
            print "User", user['id'], "tried to delete file", filepath, ERROR_TEXT[FILE_CURRENTLY_UPDATING]
            send_error(sock, FILE_CURRENTLY_UPDATING)
        else:
            self.send_delete_from_storage(conn, cur, entity['id'])
            print filepath, user['id'], sock, 'file was removed'
            Entity.delete_entity(conn, cur, entity['id'])
            self.send_delete_response(sock, filepath, True)

    def send_token(self, sock, token):
        """
        8  | token[128]  | ns to client - auth
        """
        print(token)
        send(sock, CLIENT_SEND_AUTH, token.encode())

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
        print userid, filepath
        if entity is None:
            print sock, ERROR_TEXT[NOT_FOUND], "file info request"
            data = '{}'
            self.pack_and_send_data(sock, CLIENT_SEND_FILE_INFO, data)
            return

        entity_components = EntityComponent.find_entity_components(cur, entity['id'])
        entity_list = []
        for entity_component in entity_components:
            tmp_node = Node.find_by_id(cur, entity_component['node_id'])
            if tmp_node:
                entity_list.append({
                    'port': tmp_node['port'],
                    'ip': tmp_node['ip'],
                    'filename': entity_component['token'],
                    'replica': entity_component['replica_numb'],
                    'filesize': entity_component['chunk_size'],
                    'file_order': entity_component['file_order']
                })

        entity.pop('id', None)
        entity.pop('status', None)
        entity['total'] = len(entity_list)
        entity['components'] = entity_list

        json_data = json.dumps(entity)
        self.pack_and_send_data(sock, CLIENT_SEND_FILE_INFO, json_data)

    def send_handshake_response(self, sock, token, response):
        """
        31 | node_token[128] T/F[1] | ns to storage - handshake response
        """
        data = token.encode() + struct.pack('<B', response)
        send(sock, STORAGE_HANDSHAKE_RESPONSE, data)

    def send_client_permission_response(self, sock, client_token, filename, response):
        """
        5  | token[128] filename[64] T/F[1] | ns to storage - check result
        """

        data = client_token.encode() + filename.encode() + struct.pack('<B', 1 if response else 0)
        send(sock, STORAGE_SEND_CLIENT_PERMISSION_RESPONSE, data)

    def send_delete_from_storage(self, conn, cur, entity_id):
        """
        23 | token[128] filename[64]  | ns to storage - delete file
        """

        components = EntityComponent.find_entity_components(cur, entity_id)
        for component in components:
            node = Node.find_by_id(cur, component['node_id'])
            if not node:
                EntityComponent.delete_component(conn, cur, component['id'])
                continue

            out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                out_sock.connect((node['ip'], node['port']))
            except socket.error as msg:
                print 'delete_from storage request', out_sock, msg
                continue

            self.authorized_nodes.append(out_sock)
            self.connections.append(out_sock)

            data = node['token'].encode() + component['token'].encode()
            print 'send delete component', out_sock, entity_id
            send(out_sock, STORAGE_SEND_DELETE, data)

        EntityComponent.update_components_status(conn, cur, STATUS_DELETED, entity_id)

    def send_delete_response(self, sock, filepath, success):
        """
        18 | size[2] filepath T/F[1]  | ns to client - file delete result
        """
        data = struct.pack('<h', len(filepath)) + filepath.encode() + struct.pack('<B', 1 if success else 0)

        send(sock, CLIENT_SEND_DELETE_RESPONSE, data)

    def rename_response(self, sock, srcfilepath, dsfilepath, result):
        """
        20 | size[2] srcfilepath size[2] dstfilepath T/F[1] | ns to client - rename file result
        """

        data = struct.pack('<h', len(srcfilepath)) + srcfilepath.encode() \
               + struct.pack('<h', len(dsfilepath)) + dsfilepath.encode() + struct.pack('<B', result)
        send(sock, CLIENT_RENAME_RESPONSE, data)

    def check_by_token(self, sock, class_name):
        token = self.string_decoding(sock, 128, 128)

        if token:
            conn, cur = connect_to_db()
            if class_name == User.table_name:
                obj = User.find_by_token(cur, token)
            elif class_name == Node.table_name:
                obj = Node.find_by_token(cur, token)
            else:
                raise Exception('class name ' + class_name + ' does not exist')

            if obj is None:
                send_error(sock, NOT_FOUND)
                return conn, cur, False, token
            else:
                if class_name == User.table_name and not User.check_token_time(obj):
                    print 'User', obj['id'], 'with too old token'
                    send_error(sock, OLD_TOKEN)
                    return False, False, False, False

            return conn, cur, obj, token
        return False, False, False, False

    def read_data(self, sock, b_number):
        full_size, block_size = self.stringsize_retrieve(sock, b_number)
        return self.string_decoding(sock, full_size, block_size)

    def stringsize_retrieve(self, sock, total_bytes):
        data = sock.recv(total_bytes)
        try:
            if total_bytes == 2:
                unpack_b = 'h'
            else:
                unpack_b = 'B'

            path_size, = struct.unpack('<'+unpack_b, data)
        except struct.error as msg:
            send_error(sock, WRONG_DATA)
            print msg, sock
            return

        data_block = DATA_SIZE if DATA_SIZE < path_size else path_size
        return path_size, data_block

    def pack_and_send_data(self, sock, msg_code, json_tree):
        total = int(math.ceil(len(json_tree) / float(DATA_SIZE)))
        total_pack = struct.pack('<B', total)

        for i in range(total):
            package_number = struct.pack('<B', i + 1)
            data = total_pack + package_number

            if i + 1 < total:
                data += DATA_SIZE_PACKED + json_tree[i * DATA_SIZE: i + 1 * DATA_SIZE].encode()
            else:
                block = json_tree[i * DATA_SIZE:]
                last_package_size = struct.pack('<h', len(block))
                data += last_package_size + block.encode()
            send(sock, msg_code, data)

    def file_download(self, sock):
        data = sock.recv(2)
        total = struct.unpack('<h', data)

    def separate_on_chunks(self, free_places, filesize):
        conn, cur = connect_to_db()
        nodes = Node.find_nodes(cur)

        # TODO improve algorithm so that free space for each node would become more equal
        # totally_free = sum([self.memory_request_nodes[i]['free'] for i in self.memory_request_nodes])
        totally_free = sum(free_places)
        rel_places = [int(math.floor(filesize * item / float(totally_free))) for item in free_places]

        diff = filesize - sum(rel_places)
        i = 0
        while diff > 0 and i < len(free_places):
            if rel_places[i] < free_places[i]:
                rel_places[i] += 1
                diff -= 1
            i += 1

        return rel_places

    def string_decoding(self, sock, full_size, block_size):
        data = ""

        while len(data) < full_size:
            tmp = sock.recv(block_size)
            if tmp == "":
                print sock, 'Wrong data was received'
                send_error(sock, WRONG_DATA)
                return False
            data += tmp

        try:
            res = data.decode()
        except UnicodeDecodeError as msg:
            print sock, msg
            send_error(sock, WRONG_DATA)
            return False

        return res

    def send_upload_file_info(self, sock, filepath, metadata_json, user):
        """
        16 | total[1] number[1] datasize[2] data | ns to client - file upload information
        """
        conn, cur = connect_to_db()

        try:
            metadata = json.loads(metadata_json)
        except ValueError as msg:
            print user, msg
            send_error(sock, WRONG_DATA)
            return

        print metadata

        if not type(metadata) is dict:
            print user, "the message that was sent is not dictionary"
            send_error(sock, WRONG_DATA)
            return

        if not all(item in metadata.keys()for item in Entity.keys):
            print "Not all parameters for the entity were received", sock
            send_error(sock, WRONG_DATA)
            return

        entity_file = Entity.find_entity_by_userid_filepath(cur, user["id"], filepath, True)

        if not entity_file:
            entity_id = Entity.create_entity(conn, cur, user["id"], filepath, metadata['filesize'], metadata['created'],
                                             metadata['modified'], metadata['accessed'])
        elif entity_file['status'] == STATUS_UPDATING:
            print "User", user['id'], 'cannot update file', filepath + '. File is currently updating.'
            send_error(sock, FILE_CURRENTLY_UPDATING)
            return
        else:
            entity_id = entity_file['id']
            entity_data = {
                'filesize': metadata['filesize'],
                'accessed': metadata['accessed'],
                'modified_new': metadata['modified'],
                'status':  STATUS_UPDATING
            }
            Entity.update_entity(conn, cur, entity_id, entity_data)

            EntityComponent.update_components_status(conn, cur, STATUS_OLD, entity_id)

        metadata.pop('modified', None)
        metadata.pop('accessed', None)
        metadata.pop('created', None)

        self.update_file(sock, conn, cur, entity_id, metadata)

    def update_file(self, sock, conn, cur, entity_id, metadata):
        metadata['components'] = []
        if metadata['filesize'] == 0:
            self.send_delete_from_storage(conn, cur, entity_id)
            print "0 bytes file uploaded, deleting entity components", sock, entity_id
        else:
            nodes = Node.find_nodes(cur)
            mem_available = []
            # tmp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            for node in nodes:
                # tmp_socket.connect()
                mem_available.append(2 ** 40)

            free_size, nodes = mem_available, nodes

            # if self.memory_info_received == 0:
            #     for node in self.memory_request_nodes.keys():
            #         if node in self.connections:
            #             self.connections.remove(node)
            #
            #     self.memory_request_nodes = {}
            #     print sock, ERROR_TEXT[NO_STORAGE_NODE_IS_AVAILABLE]
            #     send_error(sock, NO_STORAGE_NODE_IS_AVAILABLE)
            #
            #     return

            chunk_sizes = self.separate_on_chunks(free_size, metadata['filesize'])
            metadata.pop('filesize', None)

            for i in range(len(chunk_sizes)):
                filename = EntityComponent.add_entity_component(conn, cur, entity_id, nodes[i]['id'], i + 1,
                                                                1, STATUS_UPDATING, chunk_sizes[i])

                metadata['components'].append({
                    'filename': filename,
                    'filesize': chunk_sizes[i],
                    'ip': nodes[i]['ip'],
                    'port': nodes[i]['port'],
                    'file_order': i + 1,
                    'replica': i + 1,
                })

        json_tree = json.dumps(metadata)
        self.pack_and_send_data(sock, CLIENT_SEND_UPLOAD_RESULT, json_tree)

    def file_partitioning_update(self, sock, user, conn, cur):
        if sock not in self.failed_node_info.keys():
            print 'no such socket in failed nodes list', sock, self.failed_node_info

        info = self.failed_node_info[sock]

        data = ""
        for item in sorted(info['data'].items()):
            data += item

        try:
            file_data = json.loads(data)
        except ValueError as msg:
            print sock, msg, 'file partitioning update'
            send_error(sock, WRONG_DATA)
            return

        if not ('filepath' or 'data') in file_data:
            print sock, 'wrong data was sent (failed node request)'
            send_error(sock, WRONG_DATA)
            return

        entity = Entity.find_entity_by_userid_filepath(cur, user['id'], file_data['filepath'], True)
        if not entity:
            print sock, 'entity not found', file_data['filepath']
            send_error(sock, NOT_FOUND)
            return

        if entity['status'] == STATUS_UPDATING:
            Entity.update_entity(conn, cur, entity['id'], {})
            EntityComponent.update_components_status(conn, cur, STATUS_OLD, entity['id'])
            self.update_file(sock, conn, cur, entity['id'], {'filesize': 0})

        nodes = Node.find_nodes(cur)
        components = EntityComponent.find_entity_components(cur, entity['id'])

        # self.timer.cancel()
        # ev = threading.Event()
        # self.memory_info_update()
        # ev.wait()

class User:
    table_name = 'user'

    def __init__(self):
        pass

    @staticmethod
    def create_table(cur):
        cur.execute("CREATE TABLE IF NOT EXISTS " + User.table_name + " ("
                    "id INTEGER PRIMARY KEY, "
                    "last_login_time DOUBLE NOT NULL, "
                    "login VARCHAR(20) NOT NULL, "
                    "token VARCHAR(128), "
                    "pass_hash VARCHAR(25) NOT NULL"
                    ")")

    @staticmethod
    def find_by_login(cur, login):
        cur.execute("SELECT * FROM " + User.table_name + " WHERE login=?", (login, ))
        return cur.fetchone()

    @staticmethod
    def find_by_id(cur, user_id):
        cur.execute("SELECT * FROM " + User.table_name + " WHERE id=?", (user_id,))
        return cur.fetchone()

    @staticmethod
    def find_by_token(cur, token):
        cur.execute("SELECT * FROM " + User.table_name + " WHERE token=?", (token,))
        return cur.fetchone()

    @staticmethod
    def add_user(conn, cur, token, login, passwd):
        # TODO check for successful execution
        passwd_hash = hashlib.sha512(passwd).hexdigest()
        cur.execute("INSERT INTO " + User.table_name + "(id, login, pass_hash, last_login_time, token) VALUES (NULL, ?, ?, ?, ?)",
                    (login, passwd_hash, time.time(), token))
        conn.commit()

    @staticmethod
    def update_user_time(conn, cur, userid, new_time=False):
        # TODO check for successful execution

        cur.execute(
            "UPDATE " + User.table_name + " SET last_login_time=? WHERE id=?",
            ((new_time if new_time else time.time()), userid))

        conn.commit()

    @staticmethod
    def update_user_token(conn, cur, userid, token):
        # TODO check for successful execution
        cur.execute(
            "UPDATE " + User.table_name + " SET last_login_time=?, token=? WHERE id=?",
            (time.time(), token, userid))
        conn.commit()

    @staticmethod
    def check_passwd(passwd, user):
        return hashlib.sha512(passwd).hexdigest() == user['pass_hash']

    @staticmethod
    def check_token_time(user):
        # TODO
        return time.time() - user['last_login_time'] < CLIENT_TIMEOUT

    @staticmethod
    def drop_table(cur):
        cur.execute("DROP TABLE " + User.table_name)


class UserToken:
    table_name = 'user_token'

    def __init__(self):
        pass

    @staticmethod
    def create_table(cur):
        cur.execute("CREATE TABLE IF NOT EXISTS " + UserToken.table_name + " ("
                    "id INTEGER PRIMARY KEY, "
                    "token VARCHAR(128), "
                    "user_id INTEGER NOT NULL"
                    ")")

    @staticmethod
    def find_by_token(cur, token):
        cur.execute("SELECT * FROM " + User.table_name + " WHERE token=?", (token,))
        return cur.fetchone()

    @staticmethod
    def add_token(conn, cur, token, userid):
        # TODO check for successful execution
        cur.execute("INSERT INTO " + UserToken.table_name + "(id, token, user_id) VALUES (NULL, ?, ?)",
                    (token, userid))
        conn.commit()

    @staticmethod
    def drop_table(cur):
        cur.execute("DROP TABLE " + UserToken.table_name)


class Entity:
    # TODO handle the situation when file should be deleted, or fully updated
    """
    Statuses:
    1: uploading
    2: saved
    3: old
    """

    table_name = 'entity'

    def __init__(self):
        pass

    keys = ['filesize', 'created', 'modified', 'accessed']

    @staticmethod
    def create_table(cur):
        cur.execute("CREATE TABLE IF NOT EXISTS " + Entity.table_name + " ("
                    "id INTEGER PRIMARY KEY, "
                    "filepath VARCHAR(65536) NOT NULL, "
                    "userid INTEGER NOT NULL, "
                    "created REAL NOT NULL, "
                    "modified REAL NOT NULL, "
                    "modified_new REAL, "
                    "accessed REAL NOT NULL, "
                    "filesize INTEGER NOT NULL, "
                    "filesize_new INTEGER, "
                    "status INTEGER NOT NULL "
                    ")")

    @staticmethod
    def drop_table(cur):
        cur.execute("DROP TABLE " + Entity.table_name)

    @staticmethod
    def find_entities(cur, user_id, with_updating=False):
        if with_updating:
            cur.execute(
                'SELECT filepath, created, modified, accessed, filesize FROM ' + Entity.table_name + ' WHERE userid=?',
                (user_id,))
        else:
            cur.execute('SELECT filepath, created, modified, accessed, filesize FROM ' + Entity.table_name +
                        ' WHERE userid=? AND status<>?', (user_id, STATUS_UPDATING))
        return cur.fetchall()

    @staticmethod
    def find_entity_by_userid_filepath(cur, user_id, filepath, with_updating=False):
        if with_updating:
            cur.execute('SELECT id, status, filepath, created, modified, accessed, filesize'
                        ' FROM ' + Entity.table_name +
                        ' WHERE userid=? AND filepath=?', (user_id, filepath))
        else:
            cur.execute('SELECT id, status, filepath, created, modified, accessed, filesize'
                        ' FROM ' + Entity.table_name +
                        ' WHERE userid=? AND filepath=? AND status<>?', (user_id, filepath, STATUS_UPDATING))
        return cur.fetchone()

    @staticmethod
    def find_entity_by_id(cur, entity_id):
        cur.execute('SELECT * FROM ' + Entity.table_name +
                    ' WHERE id=?', (entity_id, ))
        return cur.fetchone()

    @staticmethod
    def find_entity(cur, entity_id, user_id, with_updating=False):
        if with_updating:
            cur.execute('SELECT id'
                        ' FROM ' + Entity.table_name +
                        ' WHERE userid=? AND id=?', (user_id, entity_id))
        else:
            cur.execute('SELECT id FROM ' + Entity.table_name +
                        ' WHERE userid=? AND id=? AND status<>?', (user_id, entity_id, STATUS_UPDATING))

        return cur.fetchone()

    @staticmethod
    def create_entity(conn, cur, user_id, filepath, filesize, created, modified, accessed):
        if filesize == 0:
            status = STATUS_SAVED
        else:
            status = STATUS_UPDATING

        cur.execute("INSERT INTO " + Entity.table_name +
                    " (id, filepath, userid, created, modified, accessed, filesize, status) "
                    "VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)",
                    (filepath, user_id, created, modified, accessed, filesize, status))
        conn.commit()
        return cur.lastrowid

    @staticmethod
    def update_entity(conn, cur, entity_id, params):

        params_list = []
        params_str = ""
        for item in params.keys():
            params_list.append(params[item])
            params_str += ', ' + item + '=?'

        if params_str and params_list:
            params_str = params_str[2:]
            params_list.append(entity_id)
            cur.execute("UPDATE " + Entity.table_name +
                        " SET " + params_str +
                        " WHERE id=?",
                        params_list)
            conn.commit()

    @staticmethod
    def update_entity_status(cur, entity_id, status):
        cur.execute("UPDATE " + Entity.table_name +
                    " SET status=? WHERE id=? ",
                    (status, entity_id))

    @staticmethod
    def delete_entity(conn, cur, entity_id):
        cur.execute("DELETE FROM " + Entity.table_name + " WHERE id=?", (entity_id,))
        conn.commit()

    @staticmethod
    def update_entity_name(conn, cur, entity_id, filename):
        cur.execute("UPDATE " + Entity.table_name + " SET filepath=? WHERE id=? ",
                    (filename, entity_id))
        conn.commit()

class EntityComponent:
    """
    Statuses:
    1: uploading
    2: saved
    3: old
    4: deleted
    """
    # TODO change table, ports and ips from node table by node_id
    table_name = 'entity_component'

    def __init__(self):
        pass

    @staticmethod
    def create_table(cur):
        cur.execute("CREATE TABLE IF NOT EXISTS " + EntityComponent.table_name + " ("
                    "id INTEGER PRIMARY KEY, "
                    "token VARCHAR(64) NOT NULL, "
                    "entity_id INTEGER NOT NULL, "
                    "node_id INTEGER NOT NULL, "
                    "file_order INTEGER NOT NULL, "
                    "replica_numb INTEGER NOT NULL, "
                    "status INTEGER DEFAULT 0, "
                    "chunk_size INTEGER NOT NULL "
                    ")")
    @staticmethod
    def find_entity_components(cur, entity_id, status=0):
        # TODO what if some parts are not loaded
        # TODO handle the situation when the file had to be deleted
        # TODO convert ip address to str

        if status != 0:
            cur.execute(
                'SELECT * FROM ' + EntityComponent.table_name +
                ' WHERE entity_id=? AND status=? AND status<>4',
                (entity_id, status))
        else:
            cur.execute(
                'SELECT * FROM ' + EntityComponent.table_name +
                ' WHERE entity_id=? AND status<>4',
                (entity_id,))
        return cur.fetchall()

    @staticmethod
    def find_entity_components(cur, entity_id, status=0):
        # TODO what if some parts are not loaded
        # TODO handle the situation when the file had to be deleted
        # TODO convert ip address to str

        if status != 0:
            cur.execute(
                'SELECT * FROM ' + EntityComponent.table_name +
                ' WHERE entity_id=? AND status=? AND status<>4',
                (entity_id, status))
        else:
            cur.execute(
                'SELECT * FROM ' + EntityComponent.table_name +
                ' WHERE entity_id=? AND status<>4',
                (entity_id,))
        return cur.fetchall()

    @staticmethod
    def find_entity_component(cur, token):
        cur.execute(
            'SELECT * FROM ' + EntityComponent.table_name +
            ' WHERE token=? AND status<>4',
            (token,))
        return cur.fetchone()

    @staticmethod
    def add_entity_component(conn, cur, entity_id, node_id, file_order, replica_numb, status, chunk_size):
        token = binascii.b2a_hex(os.urandom(32))
        cur.execute('INSERT INTO ' + EntityComponent.table_name + ' (id, token, entity_id, node_id, file_order, '
                                                                  'replica_numb, status, chunk_size) '
                                                                  'VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)',
                    (token, entity_id, node_id, file_order, replica_numb, status, chunk_size))
        conn.commit()

        return token

    @staticmethod
    def drop_table(cur):
        cur.execute("DROP TABLE " + EntityComponent.table_name)

    @staticmethod
    def update_component_status(conn, cur, status, component_id):
        cur.execute("UPDATE " + EntityComponent.table_name + " SET status=? WHERE id=?", (status, component_id))
        conn.commit()

    @staticmethod
    def update_components_status(conn, cur, status, entity_id):
        param_str = 'status=?'
        param_list = [status]

        if status == STATUS_DELETED:
            param_list.append(0)
            param_str += ', entity_id=?'

        param_list.append(entity_id)

        cur.execute("UPDATE " + EntityComponent.table_name + " SET " + param_str + " WHERE entity_id=? AND status<>4",
                    param_list)

        conn.commit()

    @staticmethod
    def delete_component(conn, cur, component_id):
        cur.execute("DELETE FROM " + EntityComponent.table_name + " WHERE id=?", (component_id,))
        conn.commit()

    @staticmethod
    def delete_old_components_by_entity_id(conn, cur, entity_id):
        cur.execute("DELETE FROM " + EntityComponent.table_name + " WHERE entity_id=? and status=3", (entity_id,))
        conn.commit()

class Node:
    table_name = 'node'

    def __init__(self):
        pass

    @staticmethod
    def create_table(cur):
        cur.execute("CREATE TABLE IF NOT EXISTS " + Node.table_name + " ("
                    "id INTEGER PRIMARY KEY, "
                    "token VARCHAR(128), "
                    "port INTEGER NOT NULL, "
                    "ip VARCHAR(15) NOT NULL, "
                    "total_memory REAL, "
                    "free_memory REAL, "
                    "alive INTEGER DEFAULT 0 "
                    ")")
    @staticmethod
    def add_node(conn, cur, token, ip, port):
        # TODO check for successful execution
        cur.execute("INSERT INTO " + Node.table_name + "(id, token, port, ip) VALUES (NULL, ?, ?, ?)",
                    (token, port, ip))
        conn.commit()

    @staticmethod
    def find_by_token(cur, token):
        cur.execute("SELECT * FROM " + Node.table_name + " WHERE token=?", (token,))
        return cur.fetchone()

    @staticmethod
    def find_by_id(cur, node_id):
        cur.execute("SELECT * FROM " + Node.table_name + " WHERE id=?", (node_id,))
        return cur.fetchone()

    @staticmethod
    def find_nodes(cur):
        cur.execute("SELECT * FROM " + Node.table_name)
        return cur.fetchall()

    @staticmethod
    def update_node(conn, cur, token, params):
        params_list = []
        params_str = ""
        for item in params.keys():
            params_list.append(params[item])
            params_str += ', ' + item + '=?'

        if params_str and params_list:
            params_str = params_str[2:]
            params_list.append(token)
            cur.execute("UPDATE " + Node.table_name +
                        " SET " + params_str +
                        " WHERE token=?",
                        params_list)
            conn.commit()

    @staticmethod
    def drop_table(cur):
        cur.execute("DROP TABLE " + Node.table_name)

    @staticmethod
    def delete_node(conn, cur, node_id):
        cur.execute("DELETE FROM " + Node.table_name + " WHERE id=?", (node_id,))
        conn.commit()

    @staticmethod
    def check_node(sock, authorized_nodes):
        if sock not in authorized_nodes:
            print sock, 'node', ERROR_TEXT[PERMISSION_DENIED]
            send_error(sock, PERMISSION_DENIED)
            return False

        return True

def parse_package(package):
    pass


def main():
    init_db()

    global storage_update_thread
    storage_update_thread = StorageUpdate()
    storage_update_thread.start()

    serv = NameServer('', PORT)
    serv.start()


if __name__ == '__main__':
    main()
