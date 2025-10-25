"""
Thin entrypoint for the Webhook Security Scanner web UI.
The FastAPI application is defined in the modular package `webui`.
"""

from webui.app import app

if __name__ == "__main__":
    import uvicorn
    print("\n🚀 Starting Webhook Security Scanner Web Interface...")
    print("📍 Open your browser at: http://localhost:8080")
    print("📚 API docs at: http://localhost:8080/docs")
    print("\n")
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
