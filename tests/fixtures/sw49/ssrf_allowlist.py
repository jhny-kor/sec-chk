def fetch(request): return requests.get(validateUrl(request.args["url"]), timeout=5)
