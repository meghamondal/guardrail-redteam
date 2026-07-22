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
        raw_path = req.arguments["path"]

        print("=" * 60)
        print("READ_FILE")
        print("RAW PATH :", raw_path)

        ok, value = validate_file(raw_path)

        print("VALID    :", ok)
        print("VALUE    :", value)

        if not ok:

            print("ACTION   : BLOCK")
            print("=" * 60)

            return {
                "action": "block",
                "reason": value,
                "result": None,
            }

        try:

            text = read_file(value)

            print("ACTION   : ALLOW")
            print("=" * 60)

            return {
                "action": "allow",
                "reason": "inside sandbox",
                "result": text,
            }

        except Exception as e:

            print("READ ERROR:", e)
            print("=" * 60)

            return {
                "action": "block",
                "reason": str(e),
                "result": None,
            }

    elif req.tool == "fetch_url":
        raw_url = req.arguments["url"]

        print("=" * 60)
        print("FETCH_URL")
        print("RAW URL :", raw_url)

        ok, value = validate_url(raw_url)

        print("VALID   :", ok)
        print("VALUE   :", value)

        if not ok:

            print("ACTION  : BLOCK")
            print("=" * 60)

            return {
                "action": "block",
                "reason": value,
                "result": None,
            }

        try:

            body = fetch_url(value)

            print("ACTION  : ALLOW")
            print("=" * 60)

            return {
                "action": "allow",
                "reason": "allowed host",
                "result": body,
            }

        except Exception as e:

            print("FETCH ERROR:", e)
            print("=" * 60)

            return {
                "action": "block",
                "reason": str(e),
                "result": None,
            }