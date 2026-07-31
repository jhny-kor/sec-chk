current_user = None
def handle_request():
    global current_user
    current_user = session["user"]
