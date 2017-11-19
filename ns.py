import sqlite3
import ipaddress
import struct
import socket
import threading
import sys
import select

"""
Basic structure: 666+id+data

Existing commands:

id | data | meaning
---|--------------------------------------------------------------|--------
1  |                                                              | handshake
2  | token[128] filename[128]                                     | client to storage - get file chunk request
3  | filename[128] total[2] number[2] datasize[2] data            | storage to client - send file chunk
4  | token[128] filename[128]                                     | storage to ns - check client-file permissions
5  | token[128] filename[128] T/F[1]                              | ns to storage - check result
6  | error_code[1]                                                | for different errors
7  | size[1] login size[1] pass                                   | client to ns - auth
8  | token[128]                                                   | ns to client - auth
9  | token[128]                                                   | client to ns - request the tree
10 | total[1] number[1] datasize[2] data                          | ns to client - send the tree
11 | token[128] size[2] filepath                                  | client to ns - request file info   (not required)
12 | total[1] number[1] datasize[2] data                          | ns to client - send file info      (not required)
13 | token[128] size[2] filepath                                  | client to ns - get file request
14 | total[1] number[1] datasize[2] data                          | ns to client - send file's chunks locations
15 | token[128] filename[128] total[2] number[2] datasize[2] data | client to ns - update file request
16 | size[2] filepath T/F[1]                                      | ns to client - file update result
17 | token[128] size[2] filepath                                  | client to ns - file delete request
18 | size[2] filepath T/F[1]                                      | ns to client - file delete result
19 | token[128] size[2] srcfilepath size[2] dstfilepath           | client to ns - rename file request
20 | size[2] srcfilepath size[2] dstfilepath T/F[1]               | ns to client - rename file result
21 | filename[128] total[2] number[2] datasize[2] data            | ns to storage - send file chunk to storage ((????draft????__
22 | filename[128] T/F[1]                                         | storage to ns - file save result
23 | filename[128]                                                | ns to storage - delete file
24 | filename[128] T/F[1]                                         | storage to ns - file delete result
25 | filename[128] total[2] number[2] datasize[2] data            | ns to storage - update file, draft
26 | filename[128] T/F[1]                                         | storage to ns - file update, draft, result
27 | filename[128] T/F[1]                                         | ns to storage - update file
28 | filename[128] T/F[1]                                         | storage to ns - update file result
29 |                                                              | ns to storage - get memory information
30 | size[8] total size[8] busy                                   | storage to ns - send memory information
"""

"""
Error codes:
1: Permission denied
2: Wrong password
"""

conn = None
cur = None
MAX_CONNECTIONS_NUMBER = 1000
PORT = 9090

def init_db():
    cur.execute("CREATE TABLE IF NOT EXISTS user ("
                    "id INTEGER PRIMARY KEY, "
                    "token VARCHAR(128), "
                    "login VARCHAR(20) NOT NULL, "
                    "pass_hash VARCHAR(25) NOT NULL"
                ")")
    conn.commit()

    cur.execute("CREATE TABLE IF NOT EXISTS entity ("
                    "id INTEGER PRIMARY KEY, "
                    "filepath VARCHAR(65536) NOT NULL, "
                    "userid INTEGER NOT NULL, "
                    "created INTEGER NOT NULL, "
                    "modified INTEGER NOT NULL, "
                    "filesize INTEGER NOT NULL"
                ")")
    conn.commit()

    cur.execute("CREATE TABLE IF NOT EXISTS entity_components ("
                    "id INTEGER PRIMARY KEY, "
                    "token VARCHAR(128) NOT NULL, "
                    "entity_id INTEGER NOT NULL, "
                    "ip INTEGER NOT NULL, "
                    "port INTEGER NOT NULL, "
                    "file_order INTEGER NOT NULL, "
                    "to_remove INTEGER DEFAULT 0 "
                ")")


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

    def _receive(self, sock):
        msg_start = sock.recv(3)
        try:
            start, package_id = struct.unpack('>HB', msg_start)
        except struct.error:
            print "Wrong header in the package"
        else:
            if start != 666:
                print "This is not devilish package"
                return

            if package_id == 4:  # storage to ns - check client-file permissions
                pass
            elif package_id == 6:  # errors
                pass
            elif package_id == 7:  # client to ns - auth

                pass
            elif package_id == 9:  # client to ns - request the tree
                pass
            elif package_id == 13:  # client to ns - get file request
                pass
            elif package_id == 15:  # client to ns - update file request
                pass
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
        msg = sock.recv(1)
        login_length = struct.unpack('>B', msg)


def parse_package(package):
    pass


def main():
    global conn
    conn = sqlite3.connect("db/nameserver.db")
    global cur
    cur = conn.cursor()

    init_db()

    serv = NameServer('', PORT)
    serv.start()

    conn.close()


if __name__ == '__main__':
    main()
