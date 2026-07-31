def read(request):
    return open(secure_filename(request.args["file"])).read()
