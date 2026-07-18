import datetime

import timeutils


def test_utc_now_iso_is_utc_and_parseable():
    before = datetime.datetime.now(datetime.timezone.utc)
    value = timeutils.utc_now_iso()
    after = datetime.datetime.now(datetime.timezone.utc)

    parsed = datetime.datetime.fromisoformat(value)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == datetime.timedelta(0)
    assert before <= parsed <= after
