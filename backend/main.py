from fastapi import FastAPI
from settings import settings

app = FastAPI(title=settings.APP_NAME)


@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/health")
async def health():
    return {"status": "ok"}
