import hashlib
def digest(file_bytes): return hashlib.sha256(file_bytes).hexdigest()
