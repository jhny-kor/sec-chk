def read(request):
    return open(request.args["file"]).read()
