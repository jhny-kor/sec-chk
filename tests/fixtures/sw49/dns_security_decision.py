import socket
host = socket.gethostbyname(request.args["host"])
is_internal = host == "10.0.0.1"
