from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.scans import router as scans_router


app = FastAPI(
    title="Zyncle Port Scanner API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans_router)


@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "service": "zyncle-port-scanner",
    }