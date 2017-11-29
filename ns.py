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
import string
import re
import logging

"""
Basic structure: 666+id+data

Existing commands (partly outdated):

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
"""

MAX_CONNECTIONS_NUMBER = 1000
PORT = 9090
FILES_DIR = 'files/'
DB_NAME = "namingserver.db"
LOGFILE_NAME = "ns.log"
logging.basicConfig(filename=FILES_DIR + LOGFILE_NAME, level=logging.DEBUG)

# List of errors
PERMISSION_DENIED = 1
WRONG_PASSWORD = 2
NOT_FOUND = 3
WRONG_DATA = 4
OLD_TOKEN = 5
NOT_ENOUGH_PLACE = 6
FILE_CURRENTLY_UPDATING = 7
ALREADY_ACTIVE_ACCOUNT = 8

ERROR_TEXT = {
    PERMISSION_DENIED: 'Permission Denied',
    WRONG_PASSWORD: 'Wrong Password',
    NOT_FOUND: 'Not Found',
    WRONG_DATA: 'Wrong Data',
    OLD_TOKEN: 'Old Token',
    NOT_ENOUGH_PLACE: 'Not Enough Place',
    FILE_CURRENTLY_UPDATING: 'File Currently Updating',
    ALREADY_ACTIVE_ACCOUNT: 'Already Active Account',
}

HANDSHAKE = 1
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
STORAGE_GET_DELETE_RESPONSE = 24
STORAGE_GET_MEMORY_INFO = 29
STORAGE_MEMORY_INFO_RESULT = 30
STORAGE_HANDSHAKE_RESPONSE = 31
CLIENT_KEEP_ALIVE = 34
CLIENT_LOGOUT = 37
CLIENT_NODE_FAILED_REQUEST = 38
STORAGE_CREATE_REPLICA_REQUEST = 39
STORAGE_CREATE_REPLICA_RESPONSE = 40

MEMORY_REQUEST_TIMEOUT = 20
CLIENT_TIMEOUT = 60

RESPONSE_OK = 1
RESPONSE_FAILURE = 2

STATUS_UPDATING = 1
STATUS_SAVED = 2
STATUS_OLD = 3
STATUS_DELETED = 4
STATUS_REPLICATING = 5

DATA_SIZE = 4096
DATA_SIZE_PACKED = struct.pack('<h', DATA_SIZE)

FILENAME_SIZE = 64

NODE_TYPE_MAIN = 1
NODE_TYPE_REPLICA_1 = 2
NODE_TYPE_REPLICA_2 = 3

USER_SPACE = 20 * 2**30  # 20GB

DB_QUERY_TYPE_INSERT = 1
DB_QUERY_TYPE_SELECT_ONE = 2
DB_QUERY_TYPE_SELECT_ALL = 3
DB_QUERY_TYPE_OTHER = 4

DEBUG_MODE = True


def send(sock, package_id, data):
    # TODO check if user still connected
    header = struct.pack('<hB', 666, package_id)
    try:
        sock.send(header + data)
    except:
        print_logs('Error while message sending', DEBUG_MODE)
        return False

    return True


def send_error(sock, error_code):
        """
        6  | error_code[1]  | for different errors
        """
        data = struct.pack('<B', error_code)
        result = send(sock, ERROR_MSG, data)

        return result


def read_header(sock, obj):
    try:
        msg_start = sock.recv(3)
    except socket.error as (code, msg):
        print_logs((obj, code, msg, sock), DEBUG_MODE)
        # if code == 104:
        #     self.connections.remove(sock)
        return False, False

    if len(msg_start) == 0:
        return False, False

    try:
        start, package_id = struct.unpack('<hB', msg_start)
    except struct.error as msg:
        print_logs((obj, "Wrong header in the package", msg, sock), DEBUG_MODE)
        return False, False

    print_logs((obj, start, package_id, sock), DEBUG_MODE)

    if start != 666:
        print_logs((obj, "This is not devilish package"))
        return False, False

    return start, package_id


def string_decoding(sock, full_size, block_size):
    data = ""

    while len(data) < full_size:
        tmp = sock.recv(block_size)
        if tmp == "":
            return False
        data += tmp

    try:
        res = data.decode()
    except UnicodeDecodeError:
        return False

    return res


def parse_storage_result_response(sock):
    filename = string_decoding(sock, FILENAME_SIZE, FILENAME_SIZE)

    if filename is False:
        send_error(sock, WRONG_DATA)
        print_logs((sock, ERROR_TEXT[WRONG_DATA], 'filename'), DEBUG_MODE)
        return False, False

    data = sock.recv(1)
    try:
        result, = struct.unpack('<B', data)
    except struct.error as msg:
        send_error(sock, WRONG_DATA)
        print_logs((sock, msg, ERROR_TEXT[WRONG_DATA]), DEBUG_MODE)
        return False, False

    return filename, result


def print_logs(message, debug=True, in_file=True):
    msg = time.strftime("%Y-%m-%d %H:%M:%S: ", time.gmtime()), message
    if debug:
        if in_file:
            logging.debug(msg)
        else:
            print msg


def create_replicated_components(entity_components):

    indexed_components = {}
    for item in entity_components:
        if item[EntityComponent.ENTITY_ID] in indexed_components:
            indexed_components[EntityComponent.ENTITY_ID].append(item)
        else:
            indexed_components[EntityComponent.ENTITY_ID] = [item]

    nodes_r_1 = Node.find_many({Node.NODE_TYPE: NODE_TYPE_REPLICA_1})
    free_space_1_list = [item[Node.FREE_MEMORY] for item in nodes_r_1]
    free_space_1 = sum(free_space_1_list)

    nodes_r_2 = Node.find_many({Node.NODE_TYPE: NODE_TYPE_REPLICA_2})
    free_space_2_list = [item[Node.FREE_MEMORY] for item in nodes_r_2]
    free_space_2 = sum(free_space_2_list)

    result_list_1 = {}
    r_1_append_size_list = {}

    result_list_2 = {}
    r_2_append_size_list = {}

    for ent_file in indexed_components.values():
        chunk_sizes = sorted([comp[EntityComponent.CHUNK_SIZE] for comp in ent_file])
        required_size = sum(chunk_sizes)

        if required_size < free_space_1:
            success, tmp_size_list, tmp_result_list = \
                count_for_replica(ent_file, chunk_sizes, nodes_r_1, r_1_append_size_list, result_list_1)

            if success:
                free_space_1 -= required_size
                for sz in tmp_size_list.keys():
                    if sz not in r_1_append_size_list.keys():
                        r_1_append_size_list[sz] = 0
                    r_1_append_size_list[sz] += tmp_size_list[sz]

                for item_key in tmp_result_list.keys():
                    if item_key not in result_list_1.keys():
                        result_list_1[item_key] = []
                    result_list_1[item_key] += tmp_result_list[item_key]

        if required_size < free_space_2:
            success, tmp_size_list, tmp_result_list = \
                count_for_replica(ent_file, chunk_sizes, nodes_r_2, r_2_append_size_list, result_list_2)

            if success:
                free_space_2 -= required_size
                for sz in tmp_size_list.keys():
                    if sz not in r_1_append_size_list.keys():
                        r_1_append_size_list[sz] = 0
                    r_1_append_size_list[sz] += tmp_size_list[sz]

                for item_key in tmp_result_list.keys():
                    if item_key not in result_list_1.keys():
                        result_list_1[item_key] = []
                    result_list_1[item_key] += tmp_result_list[item_key]

    return result_list_1, result_list_2


def count_for_replica(ent_file, chunk_sizes, nodes_r, r_append_size_list, result_list_r):
    tmp_list = []
    success = True
    tmp_r_append_size_list = r_append_size_list.copy()
    tmp_result_list_r = result_list_r.copy()
    for size in chunk_sizes:
        tmp_node_id = 0
        tmp_size = 0
        for node in nodes_r:
            if node[Node.ID] not in tmp_r_append_size_list.keys():
                tmp_r_append_size_list[node[Node.ID]] = 0

            node_free = node[Node.FREE_MEMORY] - tmp_r_append_size_list[node[Node.ID]]

            if node_free > size and (node_free < tmp_size or tmp_size is 0):
                tmp_node_id = node[Node.ID]
                tmp_size = node_free

        if tmp_size == 0:
            success = False
            break

        tmp_list.append((size, tmp_node_id))
        tmp_r_append_size_list[tmp_node_id] += tmp_size

    if success:
        for comp in ent_file:
            rm_item = 0
            for size_item in tmp_list:
                if comp[EntityComponent.CHUNK_SIZE] == size_item[0]:
                    EntityComponent.add(
                        comp[EntityComponent.ENTITY_ID], size_item[1], comp[EntityComponent.FILE_ORDER],
                        NODE_TYPE_REPLICA_1, STATUS_UPDATING, size_item[0]
                    )

                    rm_item = size_item
                    if size_item[1] not in tmp_result_list_r.keys():
                        tmp_result_list_r[size_item[1]] = []

                        tmp_result_list_r[size_item[1]].append(
                            comp[EntityComponent.TOKEN].encode() +
                            ipaddress.IPv4Address(nodes_r[Node.ID][Node.IP].decode()).packed +
                            struct.pack('<H', nodes_r[Node.ID][Node.PORT])
                        )

                    break
            tmp_list.remove(rm_item)

    return success, tmp_r_append_size_list, tmp_result_list_r


class StorageUpdate(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.connections = []
        self.running = threading.Event()
        self.authorized_nodes = []
        self.memory_request_nodes = {}
        self.delete_request_nodes = {}
        self.replica_request_nodes = {}
        self.timer = None

    def run(self):
        self.connect_to_nodes()
        self._run()

    def send_error(self, sock, error_code):
        result = send_error(sock, error_code)

        if not result:
            self.close_connection(sock)

    def close_connection(self, sock, failed_node=True, clear_dict=True):
        print_logs(("memory, Client disconnected: ", sock), DEBUG_MODE)

        if sock in self.authorized_nodes:
            self.authorized_nodes.remove(sock)

        if sock in self.memory_request_nodes.keys():
            if failed_node:
                Node.update({Node.ALIVE: 0}, {Node.TOKEN: self.memory_request_nodes[sock]})

            if clear_dict:
                self.memory_request_nodes.pop(sock, None)

        if sock in self.replica_request_nodes.keys():
            if failed_node:
                Node.update({Node.ALIVE: 0}, {Node.TOKEN: self.replica_request_nodes[sock]})

            if clear_dict:
                self.replica_request_nodes.pop(sock, None)

        if sock in self.delete_request_nodes.keys():
            if failed_node:
                Node.update({Node.ALIVE: 0}, {Node.TOKEN: self.delete_request_nodes[sock]})

            if clear_dict:
                self.delete_request_nodes.pop(sock, None)

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
                print_logs((connection, 'memory, socket already closed'), DEBUG_MODE)

        if self.timer:
            self.timer.set()

    def _run(self):
        while not self.running.is_set():
            self.timer = threading.Event()
            self.connect_to_nodes()

            try:
                ready_to_read, ready_to_write, in_error = select.select(self.connections, [], [], 10)
            except socket.error as msg:
                print_logs(msg, DEBUG_MODE)
                continue

            for sock in ready_to_read:
                start, package_id = read_header(sock, 'StorageUpdate')

                if not (start and package_id):
                    self.close_connection(sock)
                    continue

                if package_id == STORAGE_MEMORY_INFO_RESULT:  # storage to ns - send memory information
                    self.memory_info_result(sock)
                elif package_id == STORAGE_GET_DELETE_RESPONSE:
                    self.delete_result(sock)
                elif package_id == STORAGE_CREATE_REPLICA_RESPONSE:
                    self.replica_result(sock)
                else:
                    print_logs(('StorageUpdate', 'wrong command'), DEBUG_MODE)
                    self.send_error(sock, WRONG_DATA)

            self.clear_connections()

            if self.timer.wait(MEMORY_REQUEST_TIMEOUT):
                return

    def memory_info_result(self, sock):
        """
        30 | total[8] free[8]  | storage to ns - send memory information
        """
        Node.check_node(sock, self.authorized_nodes)

        if sock not in self.memory_request_nodes.keys():
            self.send_error(sock, WRONG_DATA)
            print_logs((sock, 'memory info operation not permitted for this user/node'), DEBUG_MODE)
            return

        total_b = sock.recv(8)
        free_b = sock.recv(8)
        try:
            total, = struct.unpack('<Q', total_b)
            free, = struct.unpack('<Q', free_b)
        except struct.error as msg:
            print_logs((sock, msg, ERROR_TEXT[WRONG_DATA]), DEBUG_MODE)
            self.send_error(sock, WRONG_DATA)
            return

        Node.update({Node.TOTAL_MEMORY: total, Node.FREE_MEMORY: free, Node.ALIVE: 1},
                    {Node.TOKEN: self.memory_request_nodes[sock]})

        self.close_connection(sock, False)

    def replica_result(self, sock):
        """
        40 | filename[64] T/F[1] rep_ip[4] rep_port[2]
        """
        # TODO add port-ip data of the replica node in the packet
        filename, response = parse_storage_result_response(sock)

        if response == 1:
            data = sock.recv(4)
            try:
                ip = ipaddress.IPv4Address(data)
            except ipaddress.AddressValueError as msg:
                print_logs((msg, sock, 'replica result'), DEBUG_MODE)
                return

            data = sock.recv(2)
            try:
                port, = struct.unpack('<H', data)
            except struct.error as msg:
                print_logs((msg, sock, 'replica result'), DEBUG_MODE)
                return

            rep_node = Node.find_one({Node.PORT: port, Node.IP: ip})

            EntityComponent.update(
                {EntityComponent.STATUS: STATUS_SAVED},
                {
                    EntityComponent.REPLICA_NUMB: rep_node[Node.NODE_TYPE],
                    EntityComponent.NODE_ID: rep_node[Node.ID],
                    EntityComponent.STATUS: STATUS_UPDATING
                }
            )

            Node.update({Node.ALIVE: 1},
                        {Node.ID: self.replica_request_nodes[sock]})

            self.close_connection(sock, False)

    def delete_result(self, sock):
        """
        24 | filename[64] T/F[1]  | storage to ns - file delete result
        """
        filename, result = parse_storage_result_response(sock)

        if result == 1:
            print_logs('delete file', DEBUG_MODE)

            entity_component = EntityComponent.find_one({
                EntityComponent.TOKEN: filename,
            })

            if entity_component:
                EntityComponent.delete({EntityComponent.ID: entity_component[EntityComponent.ID]})
                self.close_connection(sock)
                return

            Node.update({Node.ALIVE: 1},
                        {Node.ID: self.delete_request_nodes[sock]})

            self.close_connection(sock, False)

    def connect_to_nodes(self):
        nodes = Node.find_many()

        entity_components = EntityComponent.find_many({
            EntityComponent.STATUS: STATUS_REPLICATING
        })

        r_1_list, r_2_list = create_replicated_components(entity_components)

        for node in nodes:
            out_sock = self.create_connection(node)
            if out_sock:
                """
                29 | node_token[128] | ns to storage - get memory information
                """
                data = node[Node.TOKEN].encode()
                self.send_request(out_sock, node, STORAGE_GET_MEMORY_INFO, data)

                """
                23 | token[128] filename[64]  | ns to storage - delete file
                """

                entity_components = EntityComponent.find_many({
                    EntityComponent.NODE_ID: node[Node.ID],
                    EntityComponent.STATUS: STATUS_DELETED
                })

                for component in entity_components:
                    data = node[Node.TOKEN].encode() + component[EntityComponent.TOKEN].encode() + \
                           ipaddress.IPv4Address(node[Node.IP].decode()).packed + struct.pack('<H', node[Node.PORT])
                    self.send_request(out_sock, node, STORAGE_CREATE_REPLICA_REQUEST, data)

                if node[Node.NODE_TYPE] == NODE_TYPE_MAIN:
                    """
                    39 | token[128] filename[64] node_ip[4] node_port[2]
                    """

                    if node[Node.ID] in r_1_list.keys():
                        for itm in r_1_list[node[Node.ID]]:
                            self.send_request(out_sock, node, STORAGE_CREATE_REPLICA_REQUEST, itm)

                    if node[Node.ID] in r_2_list.keys():
                        for itm in r_2_list[node[Node.ID]]:
                            self.send_request(out_sock, node, STORAGE_CREATE_REPLICA_REQUEST, itm)

    def create_connection(self, node):
        out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            out_sock.connect((node[Node.IP], node[Node.PORT]))
        except socket.error:
            Node.update({Node.ALIVE: 0}, {Node.TOKEN: node[Node.TOKEN]})
            print_logs(('cannot connect to the node,', node[Node.IP], node[Node.PORT], node[Node.TOKEN]), DEBUG_MODE)
            return False

        self.connections.append(out_sock)
        self.authorized_nodes.append(out_sock)
        self.delete_request_nodes[out_sock] = node[Node.TOKEN]
        self.replica_request_nodes[out_sock] = node[Node.TOKEN]
        self.memory_request_nodes[out_sock] = node[Node.TOKEN]

        return out_sock

    def send_request(self, out_sock, node, message_type, data):
        result = send(out_sock, message_type, data)

        if not result:
            self.close_connection(out_sock)
        else:
            print_logs((out_sock, 'sent', node['ip'], node['port'], node['token'],
                     'packet id: ' + str(message_type)), DEBUG_MODE)

    def clear_connections(self):
        for n_socket in self.memory_request_nodes.keys():
            print_logs(('close connection with', n_socket, 'memory info'))
            self.close_connection(n_socket, True, False)

        for n_socket in self.replica_request_nodes.keys():
            print_logs(('close connection with', n_socket, 'replica request'))
            self.close_connection(n_socket, True, False)

        for n_socket in self.delete_request_nodes.keys():
            print_logs(('close connection with', n_socket, 'memory info'))
            self.close_connection(n_socket, True, False)

        self.memory_request_nodes = {}
        self.replica_request_nodes = {}
        self.delete_request_nodes = {}


class NamingServer(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.connections = [sys.stdin]
        self.running = threading.Event()
        self.authorized_nodes = []
        self.failed_node_info = {}
        self.update_event = None

        self.storage_update_thread = StorageUpdate()
        self.storage_update_thread.start()

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
                    print_logs((connection, 'socket already closed'), DEBUG_MODE)

        self.storage_update_thread.stop()

    def send_error(self, sock, error_code):
        result = send_error(sock, error_code)
        if not result:
            self.close_connection(sock)

    def close_connection(self, sock):
        print_logs(("Client disconnect: ", sock), DEBUG_MODE)
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
            print_logs(('Cannot bind to the given host and port (%s, %i): %s' % (self.host, self.port, msg)), DEBUG_MODE)
            sys.exit()
        else:
            print_logs('NS is up ([q] to exit)', DEBUG_MODE)
            self.ns_socket.listen(MAX_CONNECTIONS_NUMBER)
            self.connections.append(self.ns_socket)

    def _run(self):
        while not self.running.is_set():

            try:
                ready_to_read, ready_to_write, in_error = select.select(self.connections, [], [])
            except socket.error as msg:
                print_logs(msg, DEBUG_MODE)
                continue

            for sock in ready_to_read:
                if sock == self.ns_socket:
                    try:
                        client_socket, client_address = self.ns_socket.accept()
                        print_logs(("New connection: ", client_socket, client_address), DEBUG_MODE)
                    except socket.error as msg:
                        print_logs(msg, DEBUG_MODE)
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
                    elif command == 's':
                        print_logs(self.connections)

    def _receive(self, sock):
        start, package_id = read_header(sock, 'NamingServer')

        if not (start and package_id):
            self.close_connection(sock)
            return

        if package_id == HANDSHAKE:
            self.handshake_storage_request(sock)
        elif package_id == STORAGE_CLIENT_PERMISSION:  # storage to ns - check client-file permissions
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
        elif package_id == CLIENT_KEEP_ALIVE:  # client to ns - keep alive
            self.keep_alive_request(sock)
        elif package_id == CLIENT_LOGOUT:
            self.client_logout_request(sock)
        elif package_id == CLIENT_NODE_FAILED_REQUEST:
            self.node_failed_request(sock)
        else:
            print_logs("Wrong command received", DEBUG_MODE)
            self.send_error(sock, WRONG_DATA)

    def handshake_storage_request(self, sock):
        """
        1  | node_token[128] ip[4] port[2]  | handshake
        """
        # TODO public/private key use
        node, token = self.check_by_token(sock, Node.table_name)
        print_logs(('handshake', sock), DEBUG_MODE)
        if token is False:
            return

        data = sock.recv(4)
        try:
            ip = ipaddress.IPv4Address(data)
        except ipaddress.AddressValueError as msg:
            print_logs((msg, sock), DEBUG_MODE)
            self.send_handshake_response(sock, token, RESPONSE_FAILURE)
            return

        data = sock.recv(2)
        try:
            port, = struct.unpack('<H', data)

        except struct.error as msg:
            print_logs((msg, sock), DEBUG_MODE)
            self.send_handshake_response(sock, token, RESPONSE_FAILURE)
            return

        if not node:
            nodes = Node.find_many()
            Node.add(token, str(ip), port, len(nodes) % 3 + 1)
        else:
            params = {
                Node.IP: str(ip),
                Node.PORT: port,
                Node.ALIVE: 1
            }
            Node.update(params, {Node.TOKEN: token})

        self.authorized_nodes.append(sock)
        self.send_handshake_response(sock, token, RESPONSE_OK)

    def client_permission_request(self, sock):
        """
        4  | client_token[128] filename[64] | storage to ns - check client-file permissions
        """
        if not Node.check_node(sock, self.authorized_nodes):
            return

        client_token = string_decoding(sock, 128, 128)

        if client_token is False:
            self.send_error(sock, WRONG_DATA)
            print_logs((sock, ERROR_TEXT[WRONG_DATA], 'client token'), DEBUG_MODE)
            return

        filename = string_decoding(sock, FILENAME_SIZE, FILENAME_SIZE)
        if filename is False:
            self.send_error(sock, WRONG_DATA)
            print_logs((sock, ERROR_TEXT[WRONG_DATA], 'filename'), DEBUG_MODE)
            return

        user = User.find_one({User.TOKEN: client_token})

        if user:
            entity_component = EntityComponent.find_one({
                EntityComponent.TOKEN: filename,
                EntityComponent.STATUS: {
                    '<>': STATUS_DELETED
                }
            })

            if entity_component and Entity.find_one(
                    {Entity.USER_ID: user[User.ID], EntityComponent.ID: entity_component[EntityComponent.ENTITY_ID]},
                    [Entity.ID]
            ):

                self.send_client_permission_response(sock, client_token, filename, True)
                print_logs((sock, client_token, filename, 'permission granted'), DEBUG_MODE)
                return

        self.send_client_permission_response(sock, client_token, filename, False)
        print_logs((sock, client_token, filename, 'client', ERROR_TEXT[PERMISSION_DENIED]), DEBUG_MODE)

    def error_received(self, sock):
        """
        6  | error_code[1]  | for different errors
        """
        error = sock.recv(1)
        try:
            error_code, = struct.unpack('<B', error)
        except struct.error as msg:
            print_logs((sock, msg), DEBUG_MODE)
        else:
            if error_code in ERROR_TEXT:
                print_logs(('The error was received: ' + ERROR_TEXT[error_code]))
            else:
                print_logs(('Some unfamiliar error was received. Code ' + str(error_code)))

    def rename_request(self, sock):
        """
        19 | token[128] size[2] srcfilepath size[2] dstfilepath | client to ns - rename file request
        """
        # TODO update dir name
        user, token = self.check_by_token(sock, User.table_name)

        if user is False:
            send_error(sock, OLD_TOKEN)
            print_logs((sock, ERROR_TEXT[OLD_TOKEN]), DEBUG_MODE)
            return

        srcfilepath = self.read_data(sock, 2)
        dstfilepath = self.read_data(sock, 2)

        entities = Entity.find_many(
            {
                Entity.USER_ID: user[User.ID],
                Entity.FILEPATH:
                    {' LIKE ': srcfilepath + '%'} if srcfilepath[-1] == '/' else {'=': srcfilepath},
                Entity.STATUS:
                    {
                        '<>': STATUS_UPDATING,
                    }
            },
            [Entity.ID, Entity.STATUS, Entity.FILEPATH, Entity.CREATED, Entity.MODIFIED, Entity.ACCESSED, Entity.FILESIZE]
         )

        if not entities:
            print_logs((sock, user[User.ID], 'file not found'), DEBUG_MODE)
            self.rename_response(sock, srcfilepath, dstfilepath, False)
            return

        for entity in entities:

            newfilepath = string.replace(entity[Entity.FILEPATH], srcfilepath, dstfilepath, 1)

            Entity.update(
                {Entity.FILEPATH: newfilepath},
                {Entity.ID: entity[Entity.ID]}
            )

            print_logs((sock, entity[Entity.FILEPATH], newfilepath, user[User.ID], entity[Entity.ID], 'renamed'), DEBUG_MODE)
        self.rename_response(sock, srcfilepath, dstfilepath, True)

    def auth_client(self, sock):
        """
        id: 7  | package structure: size[1] login size[1] pass | client to ns - auth
        """
        data = sock.recv(1)
        try:
            login_length,  = struct.unpack('<B', data)
        except struct.error as msg:
            print_logs(msg, DEBUG_MODE)
            return

        login = string_decoding(sock, login_length, login_length)
        if login is False:
            send_error(sock, WRONG_DATA)
            print_logs('wasnt able to read login', DEBUG_MODE)

            return

        data = sock.recv(1)
        try:
            pass_length,  = struct.unpack('<B', data)
        except struct.error as msg:
            print_logs(msg, DEBUG_MODE)
            return

        passwd = string_decoding(sock, pass_length, pass_length)

        if passwd is False:
            send_error(sock, WRONG_DATA)
            print_logs('wasnt able to read password', DEBUG_MODE)
            return

        user = User.find_one({User.LOGIN: login})

        if user is None:
            nodes = Node.find_many({Node.ALIVE: 1, Node.NODE_TYPE: NODE_TYPE_MAIN})
            free_place = sum([node[Node.FREE_MEMORY] for node in nodes if node[Node.FREE_MEMORY]])

            if free_place < USER_SPACE:
                print_logs("not enough place on nodes, auth", DEBUG_MODE)
                send_error(sock, NOT_ENOUGH_PLACE)
                return

            if login_length < 3 or pass_length < 6 or re.search("[^a-zA-Z0-9]+", login + passwd):
                print_logs("user entered inappropriate login/password", DEBUG_MODE)
                send_error(sock, WRONG_DATA)
                return

            token = binascii.b2a_hex(os.urandom(FILENAME_SIZE))
            User.add_user(token, login, passwd)
        else:
            if not User.check_passwd(passwd, user):
                print_logs(("User", user[User.ID], ERROR_TEXT[WRONG_PASSWORD]), DEBUG_MODE)
                send_error(sock, WRONG_PASSWORD)
                return

            if User.check_token_time(user):
                print_logs(("User", user[User.ID], ERROR_TEXT[ALREADY_ACTIVE_ACCOUNT]), DEBUG_MODE)
                send_error(sock, ALREADY_ACTIVE_ACCOUNT)
                return

            token = binascii.b2a_hex(os.urandom(FILENAME_SIZE))
            User.update({User.LAST_LOGIN_TIME: time.time(), User.TOKEN: token}, {User.ID: user[User.ID]})

        self.send_token(sock, token)

    def client_logout_request(self, sock):
        """
        37 | token[128]  | client to ns - client logout
        """

        token = string_decoding(sock, 128, 128)

        if token is False:
            self.send_error(sock, WRONG_DATA)
            print_logs((sock, ERROR_TEXT[WRONG_DATA]), DEBUG_MODE)
            return

        user = User.find_one({User.TOKEN: token})

        if not user:
            self.send_error(sock, NOT_FOUND)
            print_logs((sock, ERROR_TEXT[NOT_FOUND]), DEBUG_MODE)
            return

        User.update(
            {User.LAST_LOGIN_TIME: time.time() - 1000},
            {User.ID: user[User.ID]}
        )

        print_logs((sock, user['id'], 'user logged out'), DEBUG_MODE)

    def tree_request(self, sock):
        """
        9  | token[128] | client to ns - request the tree
        """

        user, _ = self.check_by_token(sock, User.table_name)

        if user is False:
            return

        self.send_tree(sock, user)

    def get_file_request(self, sock):
        """
        13 | token[128] size[2] filepath | client to ns - get file request
        """
        user, _ = self.check_by_token(sock, User.table_name)

        if user is False:
            return

        filepath = self.read_data(sock, 2)

        self.send_file_info(sock, user['id'], filepath)

    def upload_request(self, sock):
        """
        15 | token[128] size[2] filepath datasize[2] metadata | client to ns - upload file request
        """
        user, _ = self.check_by_token(sock, User.table_name)

        if user is False:
            return

        filepath = self.read_data(sock, 2)

        metadata = self.read_data(sock, 2)

        self.send_upload_file_info(sock, filepath, metadata, user)

    def node_failed_request(self, sock):
        """
        38 | token[128] total[1] number[1] datasize[2] data | client to ns - node failed request
        """

        user, token = self.check_by_token(sock, User.table_name)

        if user is False:
            return

        data = sock.recv(4)
        try:
            total, number, datasize = struct.unpack('<BBh', data)
        except struct.error as msg:
            print_logs((sock, msg), DEBUG_MODE)
            send_error(sock, WRONG_DATA)
            return

        data_block = DATA_SIZE if DATA_SIZE < datasize else datasize
        data = string_decoding(sock, datasize, data_block)

        if data is False:
            self.close_connection(sock)
            return

        if sock not in self.failed_node_info.keys():
            self.failed_node_info[sock] = {
                'token': token,
                'total': total,
                'data': []
            }

        self.failed_node_info[sock]['data'][number] = data

        if len(self.failed_node_info['data']) == total:
            self.file_partitioning_update(sock, user)

    def file_save_result_request(self, sock):
        """
        22 | filename[64] T/F[1]  | storage to ns - file save result
        """
        filename, result = parse_storage_result_response(sock)

        if result == 1:
            print_logs(filename, DEBUG_MODE)
            entity_component = EntityComponent.find_one({
                EntityComponent.TOKEN: filename,
                EntityComponent.STATUS: {
                    '<>': STATUS_DELETED
                }
            })

            if entity_component:
                entity = Entity.find_one({Entity.ID: entity_component[EntityComponent.ENTITY_ID]})

                if entity:
                    EntityComponent.update(
                        {EntityComponent.STATUS: STATUS_REPLICATING},
                        {EntityComponent.ID: entity_component[EntityComponent.ID]}
                    )

                    print_logs(('Entity component was saved', entity_component[EntityComponent.ID]), DEBUG_MODE)

                    updating_components = EntityComponent.find_many({
                        EntityComponent.ENTITY_ID: entity[Entity.ID],
                        EntityComponent.STATUS: {
                            "=": STATUS_UPDATING,
                            "<>": STATUS_DELETED
                        }
                    })

                    if len(updating_components) == 0:
                        EntityComponent.update(
                            {EntityComponent.STATUS: STATUS_DELETED},
                            {EntityComponent.STATUS: STATUS_OLD, EntityComponent.ENTITY_ID: entity[Entity.ID]}
                        )

                        entity_data = {
                            Entity.MODIFIED: entity[Entity.MODIFIED_NEW] if entity[Entity.MODIFIED_NEW] else entity[Entity.MODIFIED],
                            Entity.MODIFIED_NEW: None,
                            Entity.STATUS: STATUS_SAVED,
                            Entity.FILESIZE: entity[Entity.FILESIZE_NEW] if entity[Entity.FILESIZE_NEW] else entity[Entity.FILESIZE],
                            Entity.FILESIZE_NEW: None
                        }

                        Entity.update(
                            entity_data,
                            {Entity.ID: entity[Entity.ID]}
                        )
                        print_logs(('Entity was saved', entity[Entity.ID]), DEBUG_MODE)

                    self.close_connection(sock)
                    return

            send_error(sock, WRONG_DATA)
            print_logs((sock, filename, ERROR_TEXT[WRONG_DATA]), DEBUG_MODE)

    def keep_alive_request(self, sock):
        """
        34 | token[128] | client to ns - keep alive
        """

        user, _ = self.check_by_token(sock, User.table_name)
        if user is False:
            return
        else:
            User.update({User.LAST_LOGIN_TIME: time.time()}, {User.ID: user[User.ID]})

    def delete_request(self, sock):
        """
        17 | token[128] size[2] filepath  | client to ns - file delete request
        """
        user, _ = self.check_by_token(sock, User.table_name)

        if user is False:
            return

        filepath = self.read_data(sock, 2)

        entities = Entity.find_many(
            {Entity.USER_ID: user['id'], Entity.FILEPATH: {' LIKE ': filepath + '%'}},
            [
                Entity.ID, Entity.STATUS, Entity.FILEPATH, Entity.CREATED,
                Entity.MODIFIED, Entity.ACCESSED, Entity.FILESIZE
            ]
        )

        if not entities:
            print_logs(("User", user[User.ID], "tried to delete file", filepath, ERROR_TEXT[NOT_FOUND]), DEBUG_MODE)
            send_error(sock, NOT_FOUND)
        else:
            for entity in entities:
                if entity[Entity.STATUS] == STATUS_UPDATING:
                    print_logs(
                            ("User", user['id'], "tried to delete file", filepath, ERROR_TEXT[FILE_CURRENTLY_UPDATING]),
                            DEBUG_MODE
                         )
                    send_error(sock, FILE_CURRENTLY_UPDATING)
                else:
                    EntityComponent.update(
                        {EntityComponent.STATUS: STATUS_DELETED, EntityComponent.ENTITY_ID: 0},
                        {EntityComponent.ENTITY_ID: entity[Entity.ID], EntityComponent.STATUS: {'<>': STATUS_DELETED}}
                    )
                    print_logs((filepath, user['id'], sock, 'file was removed (and subfiles if exist)'), DEBUG_MODE)

                    User.update({User.MEMORY: user[User.MEMORY] - entity[Entity.FILESIZE]}, {User.ID: user[User.ID]})
                    Entity.delete({Entity.ID: entity[Entity.ID]})
                    self.send_delete_response(sock, filepath, True)

    def send_token(self, sock, token):
        """
        8  | token[128]  | ns to client - auth
        """
        result = send(sock, CLIENT_SEND_AUTH, token.encode())
        if not result:
            self.close_connection(sock)

    def send_tree(self, sock, user):
        """
        10 | total[1] number[1] datasize[2] data | ns to client - send the tree
        """
        tree = Entity.find_many(
            {Entity.USER_ID: user[User.ID], Entity.STATUS: STATUS_UPDATING},
            [Entity.FILEPATH, Entity.CREATED, Entity.MODIFIED, Entity.ACCESSED, Entity.FILESIZE]
        )

        tree.insert(0, {
            'total': USER_SPACE,
            'free': USER_SPACE - user[User.MEMORY]
        })

        json_tree = json.dumps(tree)

        self.pack_and_send_data(sock, CLIENT_SEND_TREE, json_tree)

    def send_file_info(self, sock, userid, filepath):
        """
        14 | total[1] number[1] datasize[2] data | ns to client - send file's chunks locations
        """
        entity = Entity.find_one(
            {Entity.USER_ID: userid, Entity.FILEPATH: filepath, Entity.STATUS: STATUS_UPDATING},
            [Entity.ID, Entity.STATUS, Entity.FILEPATH, Entity.CREATED, Entity.MODIFIED, Entity.ACCESSED, Entity.FILESIZE]
        )

        print_logs((userid, filepath), DEBUG_MODE)
        if entity is None:
            print_logs((sock, ERROR_TEXT[NOT_FOUND], "file info request"), DEBUG_MODE)
            data = '{}'
            self.pack_and_send_data(sock, CLIENT_SEND_FILE_INFO, data)
            return

        entity_components = EntityComponent.find_many({
            EntityComponent.ENTITY_ID: entity[Entity.ID],
            EntityComponent.STATUS: {
                "<>": STATUS_DELETED,
                "<>": STATUS_UPDATING
            }
        }, [], " ORDER BY " + EntityComponent.FILE_ORDER + " ASC")

        entity_list = []
        offset = 0
        count_available_replicas = {}

        for entity_component in entity_components:
            if entity_component[EntityComponent.ID] not in count_available_replicas.keys():
                entity_component[EntityComponent.ID] = 0

            tmp_node = Node.find_one({
                Node.ID: entity_component[EntityComponent.NODE_ID],
                Node.ALIVE: 1
            })

            if tmp_node:
                entity_list.append({
                    'port': tmp_node[Node.PORT],
                    'ip': tmp_node[Node.IP],
                    'filename': entity_component[EntityComponent.TOKEN],
                    'replica': entity_component[EntityComponent.REPLICA_NUMB],
                    'filesize': entity_component[EntityComponent.CHUNK_SIZE],
                    'file_order': entity_component[EntityComponent.FILE_ORDER],
                    'continue': 0,
                    'offset': offset
                })

            if count_available_replicas[entity_component[EntityComponent.ID]] == 1:
                offset += entity_component[EntityComponent.CHUNK_SIZE]

        if 0 in count_available_replicas.values():
            print_logs("File could not be downloaded. Some nodes are not available", DEBUG_MODE)
            send_error(sock, NOT_FOUND)
            return

        entity.pop(Entity.ID, None)
        entity.pop(Entity.STATUS, None)
        entity['total'] = len(entity_list)
        entity['components'] = entity_list

        json_data = json.dumps(entity)
        self.pack_and_send_data(sock, CLIENT_SEND_FILE_INFO, json_data)

    def send_handshake_response(self, sock, token, response):
        """
        31 | node_token[128] T/F[1] | ns to storage - handshake response
        """
        data = token.encode() + struct.pack('<B', response)
        result = send(sock, STORAGE_HANDSHAKE_RESPONSE, data)
        if not result:
            self.close_connection(sock)

    def send_client_permission_response(self, sock, client_token, filename, response):
        """
        5  | token[128] filename[64] T/F[1] | ns to storage - check result
        """

        data = client_token.encode() + filename.encode() + struct.pack('<B', 1 if response else 0)
        result = send(sock, STORAGE_SEND_CLIENT_PERMISSION_RESPONSE, data)

        if not result:
            self.close_connection(sock)

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
        result = send(sock, CLIENT_RENAME_RESPONSE, data)
        if not result:
            self.close_connection(sock)

    def check_by_token(self, sock, class_name):
        token = string_decoding(sock, 128, 128)

        if token:
            if class_name == User.table_name:
                obj = User.find_one({User.TOKEN: token})

            elif class_name == Node.table_name:
                obj = Node.find_one({Node.TOKEN: token})
            else:
                raise Exception('class name ' + class_name + ' does not exist')

            if obj is None and obj == User.table_name:
                send_error(sock, NOT_FOUND)
                return False, token
            else:
                if class_name == User.table_name and not User.check_token_time(obj):
                    print_logs(('User', obj['id'], 'with too old token'), DEBUG_MODE)
                    send_error(sock, OLD_TOKEN)
                    return False, False

            return obj, token

        return False, False

    def read_data(self, sock, b_number):
        full_size, block_size = self.stringsize_retrieve(sock, b_number)
        result = string_decoding(sock, full_size, block_size)
        return result

    def stringsize_retrieve(self, sock, total_bytes):
        data = sock.recv(total_bytes)
        try:
            if total_bytes == 2:
                unpack_b = 'h'
            else:
                unpack_b = 'B'

            path_size, = struct.unpack('<'+unpack_b, data)
        except struct.error as msg:
            self.send_error(sock, WRONG_DATA)
            print_logs((msg, sock), DEBUG_MODE)
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
            result = send(sock, msg_code, data)
            if not result:
                self.close_connection(sock)

    def separate_on_chunks(self, free_places, filesize):
        # !!!!! WARNING !!!!! Not clever file splitter

        totally_free = sum(free_places.values())
        if totally_free < filesize:
            return False

        rel_places = {item: int(math.floor(filesize * free_places[item] / float(totally_free))) for item in free_places}

        diff = filesize - sum(rel_places.values())

        while diff > 0:
            for item in free_places.keys():
                if rel_places[item] < free_places[item] and not rel_places[item] is 0:
                    rel_places[item] += 1

        return rel_places

    def send_upload_file_info(self, sock, filepath, metadata_json, user):
        """
        16 | total[1] number[1] datasize[2] data | ns to client - file upload information
        """
        try:
            metadata = json.loads(metadata_json)
        except ValueError as msg:
            print_logs((user, msg), DEBUG_MODE)
            send_error(sock, WRONG_DATA)
            return

        print_logs(metadata, DEBUG_MODE)

        if not type(metadata) is dict:
            print_logs((user, "the message that was sent is not dictionary"), DEBUG_MODE)
            send_error(sock, WRONG_DATA)
            return

        if not all(item in metadata.keys()for item in Entity.keys):
            print_logs(("Not all parameters for the entity were received", sock), DEBUG_MODE)
            send_error(sock, WRONG_DATA)
            return

        entity_file = Entity.find_one(
            {Entity.USER_ID: user['id'], Entity.FILEPATH: filepath},
            [Entity.ID, Entity.STATUS, Entity.FILEPATH, Entity.CREATED, Entity.MODIFIED, Entity.ACCESSED, Entity.FILESIZE]
        )

        busy_memory = user[User.MEMORY]
        if entity_file:
            busy_memory = busy_memory - entity_file[Entity.FILESIZE] + metadata['filesize']

        if busy_memory > USER_SPACE:
            print_logs(("User dont have enough place available", user[User.ID], sock), DEBUG_MODE)
            send_error(sock, NOT_ENOUGH_PLACE)
            return

        nodes = Node.find_many({Node.ALIVE: 1, Node.NODE_TYPE: NODE_TYPE_MAIN})
        free_places = {node[Node.ID]: node[Node.FREE_MEMORY] for node in nodes if node[Node.FREE_MEMORY]}
        chunk_sizes = self.separate_on_chunks(free_places, metadata['filesize'])

        if chunk_sizes is False:
            send_error(sock, NOT_ENOUGH_PLACE)
            print_logs(("No place on storages", sock), DEBUG_MODE)
            return

        if not entity_file:
            entity_id = Entity.add(
                user[User.ID], filepath, metadata['filesize'], metadata['created'],
                metadata['modified'], metadata['accessed']
            )

            if metadata['filesize']:
                user.update({User.MEMORY: busy_memory}, {User.ID: user[User.ID]})

        elif entity_file[Entity.STATUS] == STATUS_UPDATING:
            print_logs(("User", user['id'], 'cannot update file', filepath + '. File is currently updating.'), DEBUG_MODE)
            send_error(sock, FILE_CURRENTLY_UPDATING)
            return
        else:
            entity_id = entity_file[Entity.ID]

            Entity.update(
                {
                    Entity.FILESIZE: metadata['filesize'],
                    Entity.ACCESSED: metadata['accessed'],
                    Entity.MODIFIED_NEW: metadata['modified'],
                    Entity.STATUS: STATUS_UPDATING
                },
                {Entity.ID: entity_id}
            )
            user.update({User.MEMORY: busy_memory}, {User.ID: user[User.ID]})

            EntityComponent.update(
                {EntityComponent.STATUS: STATUS_OLD},
                {EntityComponent.ENTITY_ID: entity_id, EntityComponent.STATUS: {"<>": STATUS_DELETED}}
            )

        metadata.pop('modified', None)
        metadata.pop('accessed', None)
        metadata.pop('created', None)

        self.update_file(sock, entity_id, metadata, chunk_sizes, nodes)

    def update_file(self, sock, entity_id, metadata, chunk_sizes, nodes, continue_load=0):
        metadata['components'] = []
        if metadata['filesize'] == 0:
            print_logs(("0 bytes file uploaded, deleting entity components", sock, entity_id), DEBUG_MODE)
        else:
            metadata.pop('filesize', None)
            offset = 0
            i = 1
            for node_id in chunk_sizes.keys():
                filename = EntityComponent.add(
                    entity_id, node_id, i,
                    NODE_TYPE_MAIN, STATUS_UPDATING, chunk_sizes[node_id]
                )

                metadata['components'].append({
                    'filename': filename,
                    'filesize': chunk_sizes[node_id],
                    'ip': nodes[node_id][Node.IP],
                    'port': nodes[node_id][Node.PORT],
                    'file_order': i,
                    'replica': NODE_TYPE_MAIN,
                    'continue': continue_load,
                    'offset': offset
                })
                offset += chunk_sizes[node_id]
                i += 1

        json_tree = json.dumps(metadata)
        self.pack_and_send_data(sock, CLIENT_SEND_UPLOAD_RESULT, json_tree)

    def file_partitioning_update(self, sock, user):
        if sock not in self.failed_node_info.keys():
            print_logs(('no such socket in failed nodes list', sock, self.failed_node_info), DEBUG_MODE)

        info = self.failed_node_info[sock]

        data = ""
        for item in sorted(info['data'].items()):
            data += item

        try:
            file_data = json.loads(data)
        except ValueError as msg:
            print_logs((sock, msg, 'file partitioning update'), DEBUG_MODE)
            return

        if not ('filepath' or 'data' or 'node') in file_data:
            print_logs((sock, 'wrong data was sent (failed node request)'), DEBUG_MODE)
            return

        entity = Entity.find_one(
            {Entity.USER_ID: user[User.ID], Entity.FILEPATH: file_data['filepath']},
            [Entity.ID, Entity.STATUS, Entity.FILEPATH, Entity.CREATED, Entity.MODIFIED, Entity.ACCESSED, Entity.FILESIZE]
        )

        if not entity:
            print_logs((sock, 'entity not found', file_data['filepath']), DEBUG_MODE)
            return

        # TODO how nodes are sent - field name
        Node.update({Node.ALIVE: 0}, {
            Node.IP: file_data['node']['ip'], Node.PORT: file_data['node']['port'], Node.NODE_TYPE: NODE_TYPE_MAIN
        })

        nodes = Node.find_many({Node.ALIVE: 1, Node.NODE_TYPE: NODE_TYPE_MAIN})

        uploaded_components = EntityComponent.find_many({
            EntityComponent.ENTITY_ID: entity[Entity.ID],
            EntityComponent.STATUS: STATUS_SAVED
        })

        uploaded_ids = [item[EntityComponent.NODE_ID] for item in uploaded_components]
        free_memory = {node[Node.ID]: node[Node.FREE_MEMORY] for node in nodes
                       if nodes[EntityComponent.ID] not in uploaded_ids}

        not_loaded_components = EntityComponent.find_many({
            EntityComponent.ENTITY_ID: entity[Entity.ID],
            EntityComponent.STATUS: STATUS_UPDATING
        })

        not_loaded_size = sum([item[EntityComponent.CHUNK_SIZE] for item in not_loaded_components])
        chunk_sizes = self.separate_on_chunks(free_memory, not_loaded_size)

        continue_load = 1
        if not chunk_sizes:
            for comp in uploaded_components:
                EntityComponent.update({EntityComponent.STATUS: STATUS_DELETED}, {EntityComponent.ID: comp[EntityComponent.ID]})
                not_loaded_size += comp[EntityComponent.CHUNK_SIZE]

            free_memory = {node[Node.ID]: node[Node.FREE_MEMORY] for node in nodes}
            chunk_sizes = self.separate_on_chunks(free_memory, not_loaded_size)
            continue_load = 0
            if not chunk_sizes:
                # TODO possible collision, if file pointed as deleted, but actually - not yet
                user.update({User.MEMORY: user[User.MEMORY] + entity[Entity.FILESIZE]}, {User.ID: user[User.ID]})

                EntityComponent.update(
                    {EntityComponent.STATUS: STATUS_SAVED},
                    {EntityComponent.STATUS: STATUS_OLD, EntityComponent.ENTITY_ID: entity[Entity.ID]}
                )

                entity_data = {
                    Entity.MODIFIED_NEW: None,
                    Entity.STATUS: STATUS_SAVED,
                    Entity.FILESIZE_NEW: None
                }

                Entity.update(
                    entity_data,
                    {Entity.ID: entity[Entity.ID]}
                )

                send_error(sock, NOT_ENOUGH_PLACE)
                print_logs('node failed, no place available', DEBUG_MODE)
                return

        self.update_file(sock, entity[Entity.ID], {'filesize': entity[Entity.FILESIZE]}, chunk_sizes, nodes, continue_load)


class User:
    table_name = 'user'

    ID = 'id'
    LAST_LOGIN_TIME = 'last_login_time'
    LOGIN = 'login'
    TOKEN = 'token'
    MEMORY = 'memory'
    PASS_HASH = 'pass_hash'

    def __init__(self):
        pass

    @staticmethod
    def create_table():
        command = "CREATE TABLE IF NOT EXISTS " + User.table_name + \
                  " (" \
                    + User.ID + " INTEGER PRIMARY KEY, " \
                    + User.LAST_LOGIN_TIME + " DOUBLE NOT NULL, " \
                    + User.LOGIN + " VARCHAR(20) NOT NULL, " \
                    + User.TOKEN + " VARCHAR(128), " \
                    + User.MEMORY + " REAL NOT NULL, " \
                    + User.PASS_HASH + " VARCHAR(25) NOT NULL" \
                  ")"

        DBRequests.connect_to_db(command)

    @staticmethod
    def add_user(token, login, passwd):
        passwd_hash = hashlib.sha512(passwd).hexdigest()
        command = "INSERT INTO " + User.table_name + \
                  "(id, login, pass_hash, last_login_time, token, memory) VALUES (NULL, ?, ?, ?, ?, 0)"
        args = (login, passwd_hash, time.time(), token)
        return DBRequests.connect_to_db(command, args, DB_QUERY_TYPE_INSERT)

    @staticmethod
    def find_one(params={}, select_values=[]):
        return DBRequests.find_one(User.table_name, params, select_values)

    @staticmethod
    def find_many(params={}, select_values=[]):
        return DBRequests.find_many(User.table_name, params, select_values)

    @staticmethod
    def update(change_to, find_by={}):
        DBRequests.update(User.table_name, change_to, find_by)

    @staticmethod
    def drop_table():
        DBRequests.drop_table(User.table_name)

    @staticmethod
    def check_passwd(passwd, user):
        return hashlib.sha512(passwd).hexdigest() == user['pass_hash']

    @staticmethod
    def check_token_time(user):
        # TODO
        return time.time() - user['last_login_time'] < CLIENT_TIMEOUT


class Entity:
    table_name = 'entity'

    def __init__(self):
        pass

    keys = ['filesize', 'created', 'modified', 'accessed']

    ID = 'id'
    FILEPATH = 'filepath'
    USER_ID = 'userid'
    CREATED = 'created'
    MODIFIED = 'modified'
    MODIFIED_NEW = 'modified_new'
    ACCESSED = 'accessed'
    FILESIZE = 'filesize'
    FILESIZE_NEW = 'filesize_new'
    STATUS = 'status'

    @staticmethod
    def create_table():
        command = "CREATE TABLE IF NOT EXISTS " + Entity.table_name + " (" \
                                                                      + Entity.ID + " INTEGER PRIMARY KEY, " \
                                                                      + Entity.FILEPATH + " VARCHAR(65536) NOT NULL, " \
                                                                      + Entity.USER_ID + " INTEGER NOT NULL, " \
                                                                      + Entity.CREATED + " REAL NOT NULL, " \
                                                                      + Entity.MODIFIED + " REAL NOT NULL, " \
                                                                      + Entity.MODIFIED_NEW + " REAL, " \
                                                                      + Entity.ACCESSED + " REAL NOT NULL, " \
                                                                      + Entity.FILESIZE + " INTEGER NOT NULL, " \
                                                                      + Entity.FILESIZE_NEW + " INTEGER, " \
                                                                      + Entity.STATUS + " INTEGER NOT NULL " \
                                                                      ")"
        DBRequests.connect_to_db(command)

    @staticmethod
    def add(user_id, filepath, filesize, created, modified, accessed):
        status = STATUS_UPDATING if filesize else STATUS_SAVED
        command = "INSERT INTO " + Entity.table_name +\
                  " (id, filepath, userid, created, modified, accessed, filesize, status) " \
                  "VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)"

        args = (filepath, user_id, created, modified, accessed, filesize, status)
        return DBRequests.connect_to_db(command, args, DB_QUERY_TYPE_INSERT)

    @staticmethod
    def find_one(params={}, select_values=[]):
        return DBRequests.find_one(Entity.table_name, params, select_values)

    @staticmethod
    def find_many(params={}, select_values=[]):
        return DBRequests.find_many(Entity.table_name, params, select_values)

    @staticmethod
    def update(change_to, find_by={}):
        DBRequests.update(Entity.table_name, change_to, find_by)

    @staticmethod
    def delete(params):
        DBRequests.delete(Entity.table_name, params)

    @staticmethod
    def drop_table():
        DBRequests.drop_table(Entity.table_name)


class EntityComponent:
    table_name = 'entity_component'

    ID = 'id'
    TOKEN = 'token'
    ENTITY_ID = 'entity_id'
    NODE_ID = 'node_id'
    FILE_ORDER = 'file_order'
    REPLICA_NUMB = 'replica_numb'
    STATUS = 'status'
    CHUNK_SIZE = 'chunk_size'

    def __init__(self):
        pass

    @staticmethod
    def create_table():
        command = "CREATE TABLE IF NOT EXISTS " + EntityComponent.table_name + \
                  " (" \
                   + EntityComponent.ID + " INTEGER PRIMARY KEY, " \
                   + EntityComponent.TOKEN + " VARCHAR(64) NOT NULL, " \
                   + EntityComponent.ENTITY_ID + " INTEGER NOT NULL, " \
                   + EntityComponent.NODE_ID + " INTEGER NOT NULL, " \
                   + EntityComponent.FILE_ORDER + " INTEGER NOT NULL, " \
                   + EntityComponent.REPLICA_NUMB + " INTEGER NOT NULL, " \
                   + EntityComponent.STATUS + " INTEGER DEFAULT 0, " \
                   + EntityComponent.CHUNK_SIZE + " INTEGER NOT NULL " \
                  ")"

        DBRequests.connect_to_db(command)


    @staticmethod
    def add(entity_id, node_id, file_order, replica_numb, status, chunk_size):
        token = binascii.b2a_hex(os.urandom(32))
        command = 'INSERT INTO ' + EntityComponent.table_name + ' (id, token, entity_id, node_id, file_order, ' \
                                                                'replica_numb, status, chunk_size) ' \
                                                                'VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)'
        args = (token, entity_id, node_id, file_order, replica_numb, status, chunk_size)
        DBRequests.connect_to_db(command, args, DB_QUERY_TYPE_INSERT)
        return token

    @staticmethod
    def find_many(params, select_values=[], additional_command=""):
        return DBRequests.find_many(EntityComponent.table_name, params, select_values, additional_command)

    @staticmethod
    def find_one(params, select_values=[], additional_command=""):
        return DBRequests.find_one(EntityComponent.table_name, params, select_values, additional_command)

    @staticmethod
    def drop_table():
        DBRequests.drop_table(EntityComponent.table_name)

    @staticmethod
    def update(change_to, find_by={}):
        DBRequests.update(EntityComponent.table_name, change_to, find_by)

    @staticmethod
    def delete(params):
        DBRequests.delete(EntityComponent.table_name, params)


class Node:
    table_name = 'node'

    ID = 'id'
    TOKEN = 'token'
    PORT = 'port'
    IP = 'ip'
    TOTAL_MEMORY = 'total_memory'
    FREE_MEMORY = 'free_memory'
    ALIVE = 'alive'
    NODE_TYPE = 'node_type'

    def __init__(self):
        pass

    @staticmethod
    def create_table():
        command = "CREATE TABLE IF NOT EXISTS " + Node.table_name + " (" \
                                                                    + Node.ID + " INTEGER PRIMARY KEY, " \
                                                                    + Node.TOKEN + " VARCHAR(128) NOT NULL, " \
                                                                    + Node.PORT + " INTEGER NOT NULL, " \
                                                                    + Node.IP + " VARCHAR(15) NOT NULL, " \
                                                                    + Node.TOTAL_MEMORY + " REAL, " \
                                                                    + Node.FREE_MEMORY + " REAL, " \
                                                                    + Node.ALIVE + " INTEGER DEFAULT 0, " \
                                                                    + Node.NODE_TYPE + " INTEGER NOT NULL " \
                                                                    ")"
        DBRequests.connect_to_db(command)

    @staticmethod
    def add(token, ip, port, node_type):
        command = "INSERT INTO " + Node.table_name + "(id, token, port, ip, node_type) " \
                                                     "VALUES (NULL, ?, ?, ?, ?)"
        args = (token, port, ip, node_type)
        DBRequests.connect_to_db(command, args, DB_QUERY_TYPE_INSERT)

    @staticmethod
    def find_one(params={}, select_values=[]):
        return DBRequests.find_one(Node.table_name, params, select_values)

    @staticmethod
    def find_many(params={}, select_values=[]):
        return DBRequests.find_many(Node.table_name, params, select_values)

    @staticmethod
    def update(change_to, find_by={}):
        DBRequests.update(Node.table_name, change_to, find_by)

    @staticmethod
    def drop_table():
        DBRequests.drop_table(Node.table_name)

    @staticmethod
    def delete(params):
        DBRequests.delete(Node.table_name, params)

    @staticmethod
    def check_node(sock, authorized_nodes):
        if sock not in authorized_nodes:
            print_logs((sock, 'node', ERROR_TEXT[PERMISSION_DENIED]), DEBUG_MODE)
            return False

        return True


class DBRequests:

    def __init__(self):
        pass

    @staticmethod
    def dict_factory(cur, row):
        d = {}
        for idx, col in enumerate(cur.description):
            d[col[0]] = row[idx]
        return d

    @staticmethod
    def init_db():
        User.create_table()
        Entity.create_table()
        EntityComponent.create_table()
        Node.create_table()

    @staticmethod
    def connect_to_db(command, args=(), command_type=DB_QUERY_TYPE_OTHER):
        conn = sqlite3.connect(FILES_DIR + DB_NAME)
        conn.row_factory = DBRequests.dict_factory
        cur = conn.cursor()

        cur.execute(command, args)

        result = None
        if command_type is DB_QUERY_TYPE_INSERT:
            conn.commit()
            result = cur.lastrowid
        elif command_type is DB_QUERY_TYPE_SELECT_ONE:
            result = cur.fetchone()
        elif command_type is DB_QUERY_TYPE_SELECT_ALL:
            result = cur.fetchall()
        elif command_type is DB_QUERY_TYPE_OTHER:
            conn.commit()
        else:
            raise Exception('DB connection, wrong command type')

        conn.close()

        return result

    @staticmethod
    def find_command(table_name, params={}, select_values=[]):
        command, args = DBRequests.params_list(params, "AND ", "? ", " WHERE")

        if select_values:
            select_str = ""
            for value in select_values:
                select_str += ", " + value
            select_str = select_str[1:]
        else:
            select_str = " *"

        command = "SELECT" + select_str + " FROM " + table_name + command
        return command, args

    @staticmethod
    def find_one(table_name, params={}, select_values=[], additional_command=""):
        command, args = DBRequests.find_command(table_name, params, select_values)

        return DBRequests.connect_to_db(command + additional_command, args, DB_QUERY_TYPE_SELECT_ONE)

    @staticmethod
    def find_many(table_name, params={}, select_values=[], additional_command=""):
        command, args = DBRequests.find_command(table_name, params, select_values)

        return DBRequests.connect_to_db(command + additional_command, args, DB_QUERY_TYPE_SELECT_ALL)

    @staticmethod
    def update(table_name, change_to, find_by={}):
        set_command, set_args = DBRequests.params_list(change_to, ", ", "? ", " SET")
        where_command, where_args = DBRequests.params_list(find_by, "AND ", "? ", " WHERE")

        DBRequests.connect_to_db("UPDATE " + table_name + set_command + where_command, set_args + where_args)

    @staticmethod
    def drop_table(table_name):
        DBRequests.connect_to_db("DROP TABLE " + table_name)

    @staticmethod
    def delete(table_name, params):
        delete_command, delete_args = DBRequests.params_list(params, "AND ", "? ", " WHERE")
        DBRequests.connect_to_db("DELETE FROM " + table_name + delete_command, delete_args)

    @staticmethod
    def params_list(params, separator_start, separator_end, start_command):
        command = ""
        args = []

        if params:
            for key in params.keys():
                if type(params[key]) is dict:
                    for operator in params[key]:
                        value = params[key][operator]
                        command += separator_start + key + operator + separator_end
                        args.append(str(value))
                else:
                    command += separator_start + key + "=" + separator_end
                    args.append(str(params[key]))

            command = start_command + command[len(separator_start) - 1:]

        return command, args


def main():
    DBRequests.init_db()

    serv = NamingServer('', PORT)
    serv.start()


if __name__ == '__main__':
    main()
