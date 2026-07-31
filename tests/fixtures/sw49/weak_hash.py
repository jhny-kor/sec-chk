import hashlib
def digest(password): return hashlib.md5(password.encode()).hexdigest()
