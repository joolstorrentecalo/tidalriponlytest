"""The clients that interact with the streaming service APIs."""

import base64
import binascii
import concurrent.futures
import hashlib
import json
import logging
import re
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Generator, Optional, Sequence, Tuple, Union
from click import launch, secho
from Cryptodome.Cipher import AES

from .constants import (
    AGENT,
    AVAILABLE_QUALITY_IDS,
    TIDAL_AUTH_URL,
    TIDAL_BASE,
    TIDAL_CLIENT_INFO,
    TIDAL_MAX_Q,
)
from .exceptions import (
    AuthenticationError,
    IneligibleError,
    InvalidAppIdError,
    InvalidAppSecretError,
    InvalidQuality,
    MissingCredentials,
    NonStreamable,
)
from .spoofbuz import Spoofer
from .utils import SRSession, gen_threadsafe_session, get_quality, safe_get

logger = logging.getLogger("streamrip")


class Client(ABC):
    """Common API for clients of all platforms.

    This is an Abstract Base Class. It cannot be instantiated;
    it is merely a template.
    """

    source: str
    max_quality: int
    logged_in: bool

    @abstractmethod
    def login(self, **kwargs):
        """Authenticate the client.

        :param kwargs:
        """
        pass

    @abstractmethod
    def search(self, query: str, media_type="album"):
        """Search API for query.

        :param query:
        :type query: str
        :param type_:
        """
        pass

    @abstractmethod
    def get(self, item_id, media_type="album"):
        """Get metadata.

        :param meta_id:
        :param type_:
        """
        pass

    @abstractmethod
    def get_file_url(self, track_id, quality=3) -> dict:
        """Get the direct download url dict for a file.

        :param track_id: id of the track
        """
        pass

class TidalClient(Client):
    """TidalClient."""

    source = "tidal"
    max_quality = 3

    # ----------- Public Methods --------------

    def __init__(self):
        """Create a TidalClient."""
        self.logged_in = False

        self.device_code = None
        self.user_code = None
        self.verification_url = None
        self.auth_check_timeout = None
        self.auth_check_interval = None
        self.user_id = None
        self.country_code = None
        self.access_token = None
        self.refresh_token = None
        self.expiry = None

    def login(
        self,
        user_id=None,
        country_code=None,
        access_token=None,
        token_expiry=None,
        refresh_token=None,
        **kwargs,
    ):
        """Login to Tidal using the browser.

        Providing information from previous logins will allow a user
        to stay logged in.

        :param user_id:
        :param country_code:
        :param access_token:
        :param token_expiry:
        :param refresh_token:
        """
        self.session = SRSession(
            requests_per_min=kwargs.get("requests_per_min"),
        )
        if access_token:
            self.token_expiry = float(token_expiry)
            self.refresh_token = refresh_token

            if self.token_expiry - time.time() < 86400:  # 1 day
                logger.debug("Refreshing access token")
                self._refresh_access_token()
            else:
                logger.debug("Logging in with access token")
                self._login_by_access_token(access_token, user_id)
        else:
            logger.debug("Logging in as a new user")
            self._login_new_user()

        self.logged_in = True
        secho("Logged into Tidal", fg="green")

    def get(self, item_id, media_type):
        """Public method that internally calls _api_get.

        :param item_id:
        :param media_type:
        """
        resp = self._api_get(item_id, media_type)
        logger.debug(resp)
        return resp

    def search(self, query: str, media_type: str = "album", limit: int = 100) -> dict:
        """Search for a query.

        :param query:
        :type query: str
        :param media_type: track, album, playlist, or video.
        :type media_type: str
        :param limit: max is 100
        :type limit: int
        :rtype: dict
        """
        params = {
            "query": query,
            "limit": limit,
        }
        return self._api_request(f"search/{media_type}s", params=params)

    def get_file_url(self, track_id, quality: int = 3, video=False):
        """Get the file url for a track or video given an id.

        :param track_id: or video id
        :param quality: 0, 1, 2, or 3. It is irrelevant for videos.
        :type quality: int
        :param video:
        """
        if video:
            return self._get_video_stream_url(track_id)

        params = {
            "audioquality": get_quality(min(quality, TIDAL_MAX_Q), self.source),
            "playbackmode": "STREAM",
            "assetpresentation": "FULL",
        }
        resp = self._api_request(f"tracks/{track_id}/playbackinfopostpaywall", params)
        try:
            manifest = json.loads(base64.b64decode(resp["manifest"]).decode("utf-8"))
        except KeyError:
            raise Exception(resp["userMessage"])

        logger.debug(manifest)
        return {
            "url": manifest["urls"][0],
            "enc_key": manifest.get("keyId"),
            "codec": manifest["codecs"],
        }

    def get_tokens(self) -> dict:
        """Return tokens to save for later use.

        :rtype: dict
        """
        return {
            k: getattr(self, k)
            for k in (
                "user_id",
                "country_code",
                "access_token",
                "refresh_token",
                "token_expiry",
            )
        }

    # ------------ Utilities to login -------------

    def _login_new_user(self, launch_url: bool = True):
        """Create app url where the user can log in.

        :param launch: Launch the browser.
        :type launch: bool
        """
        login_link = f"https://{self._get_device_code()}"

        secho(
            f"Go to {login_link} to log into Tidal within 5 minutes.",
            fg="blue",
        )
        if launch_url:
            launch(login_link)

        start = time.time()
        elapsed = 0.0
        while elapsed < 600:  # 5 mins to login
            elapsed = time.time() - start
            status = self._check_auth_status()
            if status == 2:
                # pending
                time.sleep(4)
                continue
            elif status == 0:
                # successful
                break
            else:
                raise Exception

        self._update_authorization()

    def _get_device_code(self):
        """Get the device code that will be used to log in on the browser."""
        data = {
            "client_id": TIDAL_CLIENT_INFO["id"],
            "scope": "r_usr+w_usr+w_sub",
        }
        resp = self._api_post(f"{TIDAL_AUTH_URL}/device_authorization", data)

        if resp.get("status", 200) != 200:
            raise Exception(f"Device authorization failed {resp}")

        self.device_code = resp["deviceCode"]
        self.user_code = resp["userCode"]
        self.user_code_expiry = resp["expiresIn"]
        self.auth_interval = resp["interval"]
        return resp["verificationUriComplete"]

    def _check_auth_status(self):
        """Check if the user has logged in inside the browser."""
        data = {
            "client_id": TIDAL_CLIENT_INFO["id"],
            "device_code": self.device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "scope": "r_usr+w_usr+w_sub",
        }
        logger.debug(data)
        resp = self._api_post(
            f"{TIDAL_AUTH_URL}/token",
            data,
            (TIDAL_CLIENT_INFO["id"], TIDAL_CLIENT_INFO["secret"]),
        )
        logger.debug(resp)

        if resp.get("status", 200) != 200:
            if resp["status"] == 400 and resp["sub_status"] == 1002:
                return 2
            else:
                return 1

        self.user_id = resp["user"]["userId"]
        self.country_code = resp["user"]["countryCode"]
        self.access_token = resp["access_token"]
        self.refresh_token = resp["refresh_token"]
        self.token_expiry = resp["expires_in"] + time.time()
        return 0

    def _verify_access_token(self, token: str):
        """Verify that the access token is valid.

        :param token:
        :type token: str
        """
        headers = {
            "authorization": f"Bearer {token}",
        }
        r = self.session.get(
            "https://api.tidal.com/v1/sessions", headers=headers
        ).json()
        if r.status != 200:
            raise Exception("Login failed")

        return True

    def _refresh_access_token(self):
        """Refresh the access token given a refresh token.

        The access token expires in a week, so it must be refreshed.
        Requires a refresh token.
        """
        data = {
            "client_id": TIDAL_CLIENT_INFO["id"],
            "refresh_token": self.refresh_token,
            "grant_type": "refresh_token",
            "scope": "r_usr+w_usr+w_sub",
        }
        resp = self._api_post(
            f"{TIDAL_AUTH_URL}/token",
            data,
            (TIDAL_CLIENT_INFO["id"], TIDAL_CLIENT_INFO["secret"]),
        )

        if resp.get("status", 200) != 200:
            raise Exception("Refresh failed")

        self.user_id = resp["user"]["userId"]
        self.country_code = resp["user"]["countryCode"]
        self.access_token = resp["access_token"]
        self.token_expiry = resp["expires_in"] + time.time()
        self._update_authorization()

    def _login_by_access_token(self, token, user_id=None):
        """Login using the access token.

        Used after the initial authorization.

        :param token:
        :param user_id: Not necessary.
        """
        headers = {"authorization": f"Bearer {token}"}  # temporary
        resp = self.session.get(
            "https://api.tidal.com/v1/sessions", headers=headers
        ).json()
        if resp.get("status", 200) != 200:
            raise Exception(f"Login failed {resp}")

        if str(resp.get("userId")) != str(user_id):
            raise Exception(f"User id mismatch {resp['userId']} v {user_id}")

        self.user_id = resp["userId"]
        self.country_code = resp["countryCode"]
        self.access_token = token
        self._update_authorization()

    def _update_authorization(self):
        """Update the requests session headers with the auth token."""
        self.session.update_headers(self.authorization)

    @property
    def authorization(self):
        """Get the auth header."""
        return {"authorization": f"Bearer {self.access_token}"}

    # ------------- Fetch data ------------------

    def _api_get(self, item_id: str, media_type: str) -> dict:
        """Send a request to the api for information.

        :param item_id:
        :type item_id: str
        :param media_type: track, album, playlist, or video.
        :type media_type: str
        :rtype: dict
        """
        url = f"{media_type}s/{item_id}"
        item = self._api_request(url)
        if media_type in ("playlist", "album"):

            resp = self._api_request(f"{url}/items")
            if (tracks_left := item["numberOfTracks"]) > 100:
                offset = 0
                while tracks_left > 0:
                    offset += 100
                    tracks_left -= 100
                    resp["items"].extend(
                        self._api_request(f"{url}/items", {"offset": offset})["items"]
                    )

            item["tracks"] = [item["item"] for item in resp["items"]]
        elif media_type == "artist":
            logger.debug("filtering eps")
            album_resp = self._api_request(f"{url}/albums")
            ep_resp = self._api_request(
                f"{url}/albums", params={"filter": "EPSANDSINGLES"}
            )

            item["albums"] = album_resp["items"]
            item["albums"].extend(ep_resp["items"])

        logger.debug(item)
        return item

    def _api_request(self, path: str, params=None) -> dict:
        """Handle Tidal API requests.

        :param path:
        :type path: str
        :param params:
        :rtype: dict
        """
        if params is None:
            params = {}

        params["countryCode"] = self.country_code
        params["limit"] = 100
        r = self.session.get(f"{TIDAL_BASE}/{path}", params=params)
        r.raise_for_status()
        return r.json()

    def _get_video_stream_url(self, video_id: str) -> str:
        """Get the HLS video stream url.

        The stream is downloaded using ffmpeg for now.

        :param video_id:
        :type video_id: str
        :rtype: str
        """
        params = {
            "videoquality": "HIGH",
            "playbackmode": "STREAM",
            "assetpresentation": "FULL",
        }
        resp = self._api_request(
            f"videos/{video_id}/playbackinfopostpaywall", params=params
        )
        manifest = json.loads(base64.b64decode(resp["manifest"]).decode("utf-8"))
        available_urls = self.session.get(manifest["urls"][0])
        available_urls.encoding = "utf-8"

        STREAM_URL_REGEX = re.compile(
            r"#EXT-X-STREAM-INF:BANDWIDTH=\d+,AVERAGE-BANDWIDTH=\d+,CODECS=\"(?!jpeg)[^\"]+\",RESOLUTION=\d+x\d+\n(.+)"
        )

        # Highest resolution is last
        *_, last_match = STREAM_URL_REGEX.finditer(available_urls.text)

        return last_match.group(1)

    def _api_post(self, url, data, auth=None):
        """Post to the Tidal API.

        :param url:
        :param data:
        :param auth:
        """
        return self.session.post(url, data=data, auth=auth, verify=False).json()
