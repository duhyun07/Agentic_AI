from app.broadcaster import CrashBroadcaster


def test_subscribers_receive_published_event():
    broadcaster = CrashBroadcaster()
    queue = broadcaster.subscribe()

    broadcaster.publish({"crash_id": 1, "bug_type": "use-after-free"})

    event = queue.get(timeout=1)
    assert event["crash_id"] == 1


def test_unsubscribe_removes_queue():
    broadcaster = CrashBroadcaster()
    queue = broadcaster.subscribe()
    broadcaster.unsubscribe(queue)

    broadcaster.publish({"crash_id": 2})

    assert queue.empty()
