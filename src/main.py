from fastapi import FastAPI
from routes import installation_router


app = FastAPI(title="TGRAFY Dashboard Service")

app.include_router(router=installation_router, prefix="/api/v1")

@app.get("/health")
def health():
    return {"status": "OK"}
