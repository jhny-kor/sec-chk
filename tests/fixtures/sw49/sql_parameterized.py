def find_user(request):
    return db.execute("SELECT * FROM users WHERE id = %s", (request.args["id"],))
