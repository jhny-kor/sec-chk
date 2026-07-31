import os
def publish(path):
    os.chmod(path, 0o600)
