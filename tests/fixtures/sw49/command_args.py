def ping(request):
    subprocess.run(["ping", "--", request.args["host"]], shell=False, check=True)
