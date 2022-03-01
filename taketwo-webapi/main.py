""" MAIN CLASS """
import base64
import os
from typing import Optional

import couchdb
import httpx
import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

load_dotenv()

clear_token = os.getenv("CLEAR_TOKEN")
db_name = os.getenv("DB_NAME")
db_host = os.getenv("DB_HOST")
db_port = os.getenv("DB_PORT")
db_username = os.getenv("DB_USERNAME")
db_password = os.getenv("DB_PASSWORD")

CLIENT = None
DB = None
CREDS = None

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def retrieve_token(username, password):
    """
    Gets token if password is valid for username
        @param username:
        @param password:
        @return:
    """
    client_id = os.getenv("CLIENT_ID")
    secret = os.getenv("SECRET")
    url = os.getenv("OAUTH_SERVER_URL") + "/token"
    grant_type = "password"

    user_pass_header = client_id + ":" + secret
    base_64_header = base64.b64encode(user_pass_header.encode()).decode()
    headers = {"accept": "application/json", "Authorization": f"Basic {base_64_header}"}

    data = {
        "grant_type": grant_type,
        "username": username,
        "password": password,
        "scope": "all",
    }

    response = httpx.post(url, headers=headers, data=data)

    if response.status_code == httpx.codes.OK:
        return response.json()
    raise HTTPException(status_code=response.status_code, detail=response.text)


def validate(token: str = Depends(oauth2_scheme)):
    """
    Validate IBM token
    @param token: token to validate
    @return:
    """
    res = validate_token_ibm(
        token,
        os.getenv("OAUTH_SERVER_URL"),
        os.getenv("CLIENT_ID"),
        os.getenv("SECRET"),
    )
    return res


def validate_token_ibm(
    token, auth_url, client_id, client_secret=Depends(oauth2_scheme)
):
    """
    Validate IBM token
    @param token: token to authenticate
    @param auth_url: authentication server URL
    @param client_id: client id to validate
    @param client_secret: client secret
    @return:
    """
    user_pass_header = client_id + ":" + client_secret
    base64_header = base64.b64encode(user_pass_header.encode()).decode()
    # headers = {'accept': 'application/json', 'Authorization': 'Basic %s' % base64_header}
    headers = {
        "accept": "application/json",
        "cache-control": "no-cache",
        "content-type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {base64_header}",
    }
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "token": token,
    }
    url = auth_url + "/introspect"

    response = httpx.post(url, headers=headers, data=data)

    if response.status_code == httpx.codes.OK and response.json()["active"]:
        return jwt.decode(token, options={"verify_signature": False})

    raise HTTPException(status_code=403, detail="Authorisation failure")


CLIENT = couchdb.Server(f"http://{db_username}:{db_password}@{db_host}:{db_port}/")
try:
    DB = CLIENT.create(db_name)
except couchdb.PreconditionFailed:
    DB = CLIENT[db_name]


class Flagged(BaseModel):
    # pylint: disable=too-few-public-methods
    """Attributes for flagged pieces of text"""
    _id: Optional[str]
    user_id: str
    flagged_string: str
    category: str
    info: Optional[str]
    url: str


class Text(BaseModel):
    # pylint: disable=too-few-public-methods
    """Text attributes"""
    content: str


@app.get("/", response_class=HTMLResponse)
def read_root():
    """
    Read template.html
    @return:
    """
    return open("template.html").read()  # pylint: disable=unspecified-encoding


# Get auth token
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Gets a token from IBM APP ID, given a username and a password. Depends on OAuth2PasswordRequestForm.
    Parameters
    ----------
    OAuth2PasswordRequestForm.form_data.username: str, required
    OAuth2PasswordRequestForm.form_data.password: str, required
    Returns
    -------
    token: str
    """
    # print(retrieve_token(form_data.username,form_data.password))
    return retrieve_token(form_data.username, form_data.password)


# noinspection PyUnusedLocal
@app.get("/mark")
def get_marks(user: dict = Depends(validate)):
    # pylint: disable=unused-argument
    """
    Get all marks
    @param user:
    @return:
    """
    return list(
        map(
            lambda item: dict(item.doc.items()), DB.view("_all_docs", include_docs=True)
        )
    )


@app.post("/mark")
def save_mark(item: Flagged, user: dict = Depends(validate)):
    """
    Save a mark
    @param item: item to save
    @param user: user who added the mark
    @return:
    """
    item.user_id = user["sub"]
    data = item.dict()
    _id, _ = DB.save(data)
    return data


# noinspection PyUnusedLocal
@app.put("/mark/{_id}")
def update_mark(_id: str, item: Flagged, user: dict = Depends(validate)):
    # pylint: disable=unused-argument
    """
    Update category of mark
    @param _id: ID of mark to update
    @param item:
    @param user:
    @return:
    """
    doc = DB[_id]
    doc["category"] = item.category
    DB[doc.id] = doc
    return {"status": "success"}


# noinspection PyUnusedLocal
@app.delete("/mark")
def delete_mark(_id: str, user: dict = Depends(validate)):
    # pylint: disable=unused-argument
    """
    Delete mark
    @param _id: ID of mark to delete
    @param user:
    @return:
    """
    my_document = DB[_id]
    DB.delete(my_document)
    return {"status": "success"}


@app.get("/categories")
def read_categories():
    """
    Names and descriptions of all categories of biased language
    @return:
    """
    # fmt: off
    return [
        # IBM colour-blindness palette used below https://davidmathlogic.com/colorblind/
        {
            "name": "appropriation",
            "colour": "#648FFF",
            "description": "To adopt or claim elements of one or more cultures to which you do not belong, "
                           "consequently causing offence to members of said culture(s) or otherwise achieving some "
                           "sort of personal gain at the expense of other members of the culture(s). "
        },
        {
            "name": "stereotyping",
            "colour": "#785EF0",
            "description": "To perpetuate a system of beliefs about superficial characteristics of members of a given "
                           "ethnic group or nationality, their status, society and cultural norms.",
        },
        {
            "name": "under-representation",
            "colour": "#DC267F",
            "description": "To have Insufficient or disproportionately low representation of Black, Indigenous, "
                           "People of Color (BIPOC) individuals, for example in mediums such as media and TV adverts.",
        },
        {
            "name": "gaslighting",
            "colour": "#FE6100",
            "description": "To use tactics, whether by a person or entity, in order to gain more power by making a "
                           "victim question their reality.  To deny or refuse to see racial bias, which may also "
                           "include the act of convincing a person that an event/slur/idea is not racist or not as "
                           "bad as one claims it to be through means of psychological manipulation. "
        },
        {
            "name": "racial-slur",
            "colour": "#FFB000",
            "description": "To insult, or use offensive or hurtful language designed to degrade a person because of "
                           "their race or culture. This is intentional use of words or phrases to speak of or to "
                           "members of ethnical groups in a derogatory manor. ",
        },
        {
            "name": "othering",
            "colour": "#5DDB2B",
            "description": "To label and define a person/group as someone who belongs to a 'socially subordinate' "
                           "category of society. The practice of othering persons means to use the characteristics of "
                           "a person's race to exclude and displace such person from the 'superior' social group and "
                           "separate them from what is classed as normal. "
        },
    ]
    # fmt: on


@app.put("/analyse")
def analyse_text(text: Text):
    """
    Analyse text for biased language
    @param text: text to analyse
    @return:
    """
    res = []
    for item in DB.view("_all_docs", include_docs=True):
        doc = item.doc
        if doc["flagged_string"] in text.content:
            res.append(
                {
                    "flag": doc["flagged_string"],
                    "category": doc["category"],
                    "info": doc["info"],
                }
            )
    return {"biased": res}


@app.put("/check")
def check_words(text: Text):
    """
    Checks text against known racial slurs
    @param text: text to check
    @return:
    """
    results = []
    for item in DB.view("_all_docs", include_docs=True):
        doc = item.doc
        if (
            doc["category"] == "racial slur"
            and doc["flagged_string"].lower() in text.content.lower()
        ):
            results.append(
                {
                    "flag": doc["flagged_string"],
                    "category": doc["category"],
                    "info": doc["info"],
                }
            )

    line_by_line = []
    for i, line in enumerate(text.content.splitlines(), 1):
        for result in results:
            if result["flag"].lower() in line.lower():
                line_by_line.append(
                    {
                        "line": i,
                        "word": result["flag"],
                        "additional_info": result["info"],
                    }
                )

    return line_by_line
