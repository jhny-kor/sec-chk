def upload(request):
    request.files["file"].save(request.files["file"].filename)
