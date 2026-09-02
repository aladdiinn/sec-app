from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(
    title="SecurePulse SOC API Gateway",
    description="Central entry point for the SOC platform services",
    version="1.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    return {"status": "online", "service": "api-gateway"}

# Placeholder for sub-service routers
# app.include_router(incident_router, prefix="/incidents", tags=["Incidents"])
# app.include_router(detection_router, prefix="/detection", tags=["Detection"])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
