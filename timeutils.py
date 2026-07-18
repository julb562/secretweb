"""
Shared time helpers. Every timestamp stored or compared internally in
this project is UTC - conversion to a user's local time, if ever needed,
happens only at the point of display, never internally.
"""
import datetime


def utc_now_iso() -> str:
    """Current time in UTC as an ISO-8601 string, for storing as a
    last_updated field (or any other stored timestamp) in data files."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()
