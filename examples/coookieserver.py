#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from http import cookies
import json

# User table.
users = {}


def addUsers(l):
    for u in l:
        users[u.get("sub")] = u

        # Add numeric user ID.
        u["id"] = len(users)


addUsers([
    {
        "sub": "arthur",
        "name": "Arthur Dent",
        "email": "arthur@earth.local",
    },
    {
        "sub": "trillian",
        "name": "Trillian",
        "email": "trillian@galaxy.local",
    },
    {
        "sub": "ford",
        "name": "Ford Perfect",
        "email": "ford@betelgeuse.local",
    }
])


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        cookie = cookies.SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        id = cookie.get("minioidc-simple", None)
        if id is None:
            self.send_response(401)
            self.end_headers()
            return

        user = users.get(id.value, None)
        if user is None:
            self.send_response(403)
            self.end_headers()
            return

        self.send_response(202)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        self.wfile.write(json.dumps(user, indent=4, sort_keys=True).encode())
        return


def run(server_class=HTTPServer, handler_class=Handler, port=8080):
    address = ('127.0.0.1', port)
    server = server_class(address, handler_class)
    print('Starting HTTP server ...')
    server.serve_forever()


if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
