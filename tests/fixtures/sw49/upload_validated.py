def upload(request):
    store_validated_upload(secure_filename(request.files["file"].filename))
