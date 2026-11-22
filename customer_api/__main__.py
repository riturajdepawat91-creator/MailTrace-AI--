"""Run the Customer API in the foreground for the desktop host to supervise."""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("customer_api.main:app", host="127.0.0.1", port=8100, log_level="warning", access_log=False)
