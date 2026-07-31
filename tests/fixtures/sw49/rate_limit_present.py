from fastapi import FastAPI
from slowapi import Limiter
app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.add_middleware(SlowAPIMiddleware)

@app.post("/login")
@limiter.limit("5/minute")
def login(password: str):
    return authenticate(password)
