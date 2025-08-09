from fastapi import FastAPI
from app.database import engine, Base
from app import auth

app = FastAPI(title="Async Auth API")

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

app.include_router(auth.router, prefix="/auth", tags=["auth"])