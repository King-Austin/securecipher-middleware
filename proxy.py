import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import httpx
import ssl
import logging

app = FastAPI()

# --- Logging setup ---
logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

def is_valid_envelope(data: dict) -> bool:
    required = {"encrypted_payload", "iv", "auth_tag", "client_public_key"}
    return all(k in data and data[k] for k in required)

@app.post("/api/transact")
async def proxy_transact(request: Request):
    client_ip = request.client.host
    try:
        envelope = await request.json()
    except Exception:
        logging.info(f"{client_ip} INVALID_JSON {request.method}")
        return JSONResponse({"error": "Malformed JSON"}, status_code=400)

    if not is_valid_envelope(envelope):
        logging.info(f"{client_ip} INVALID_ENVELOPE {request.method}")
        return JSONResponse({"error": "Malformed envelope"}, status_code=400)

    # Forward to banking API (port 6000)
    try:
        async with httpx.AsyncClient(verify="cert.pem", http2=True) as client:
            resp = await client.post(
                "https://localhost:6000/api/transact",
                json=envelope,
                headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
                timeout=15.0,
            )
        # Log metadata (never log decrypted data or keys)
        logging.info(f"{client_ip} {request.method} {resp.status_code}")
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=resp.headers,
            media_type=resp.headers.get("content-type", "application/json"),
        )
    except httpx.RequestError as e:
        logging.error(f"{client_ip} BANKING_API_ERROR {str(e)}")
        return JSONResponse({"error": "Banking API unreachable"}, status_code=502)

@app.get("/health")
def health():
    return {"status": "ok"}

# --- TLS 1.3 context for uvicorn ---
def get_tls_context():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")  # Use your certs
    return context

if __name__ == "__main__":
    uvicorn.run(
        "proxy:app",
        host="0.0.0.0",
        port=5000,
        ssl_context=get_tls_context(),
        log_level="info",
    )
