from sentinel.orchestration.events import StreamEvent


def test_stream_event_serializes_timestamp_and_data() -> None:
    event = StreamEvent.create("engagement-1", "fixtures", "Static fixtures returned", count=4)
    serialized = event.as_dict()
    assert serialized["engagement_id"] == "engagement-1"
    assert serialized["phase"] == "fixtures"
    assert serialized["data"] == {"count": 4}
    assert serialized["timestamp"].endswith("+00:00")
