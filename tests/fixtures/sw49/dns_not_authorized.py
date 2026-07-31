import socket
host = socket.gethostbyname(request.args["host"])
connect(host)
