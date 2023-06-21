"""Utility functions for RipCore."""

import re
from typing import Tuple

from streamrip.constants import AGENT
from streamrip.utils import gen_threadsafe_session

interpreter_artist_id_regex = re.compile(
    r"https?://www\.qobuz\.com/\w\w-\w\w/interpreter/[-\w]+/(?P<artistId>[0-9]+)"
)
interpreter_artist_regex = re.compile(r"getSimilarArtist\(\s*'(\w+)'")


def extract_interpreter_url(url: str) -> str:
    """Extract artist ID from a Qobuz interpreter url.

    :param url: Urls of the form "https://www.qobuz.com/us-en/interpreter/{artist}/download-streaming-albums"
    or "https://www.qobuz.com/us-en/interpreter/the-last-shadow-puppets/{artistId}}"
    :type url: str
    :rtype: str
    """
    url_match = interpreter_artist_id_regex.search(url)
    if url_match:
        return url_match.group("artistId")

    session = gen_threadsafe_session({"User-Agent": AGENT})
    r = session.get(url)
    match = interpreter_artist_regex.search(r.text)
    if match:
        return match.group(1)

    raise Exception(
        "Unable to extract artist id from interpreter url. Use a "
        "url that contains an artist id."
    )
