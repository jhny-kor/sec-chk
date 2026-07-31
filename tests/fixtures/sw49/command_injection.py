def ping(request):
    subprocess.run("ping " + request.args["host"], shell=True)
