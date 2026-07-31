from fastapi import FastAPI
app = FastAPI()

@app.post("/login")
def login(password: str):
    return authenticate(password)
