from fastapi import FastAPI
from pydantic import BaseModel

from security import validate_file, validate_url
from tools import read_file, fetch_url

app = FastAPI()


class Request(BaseModel):
    tool: str
    arguments: dict


@app.post("/check")
def check(req: Request):

    if req.tool == "read_file":
        
        print("=" * 50)
        print("READ_FILE REQUEST")
        print("Raw path:", req.arguments.get("path"))
        print("=" * 50)
        ok, value = validate_file(req.arguments["path"])

        if not ok:
            return {
                "action": "block",
                "reason": value,
                "result": None,
            }

        text = read_file(value)

        return {
            "action": "allow",
            "reason": "inside sandbox",
            "result": text,
        }

    elif req.tool == "fetch_url":

        ok, value = validate_url(req.arguments["url"])

        if not ok:
            return {
                "action": "block",
                "reason": value,
                "result": None,
            }

        body = fetch_url(value)

        return {
            "action": "allow",
            "reason": "allowed host",
            "result": body,
        }

    return {
        "action": "block",
        "reason": "unknown tool",
        "result": None,
    }