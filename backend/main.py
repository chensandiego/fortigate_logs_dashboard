from fastapi import FastAPI, Depends, HTTPException
from models import LoginRequest, LogSearchRequest
from auth import authenticate_user, create_access_token, verify_token
from es_service import search_logs

app = FastAPI()

# ------------------------------
# Login → returns JWT token
# ------------------------------
@app.post("/login")
def login(data: LoginRequest):
    if not authenticate_user(data.username, data.password):
        raise HTTPException(status_code=401, detail="Invalid username/password")

    token = create_access_token({"sub": data.username})
    return {"access_token": token, "token_type": "bearer"}


# ------------------------------
# Protected Elasticsearch endpoint
# ------------------------------
@app.post("/es/search")
def es_search(query: LogSearchRequest, token=Depends(verify_token)):
    results = search_logs(query.query, query.days, query.limit)
    return {"results": results}
