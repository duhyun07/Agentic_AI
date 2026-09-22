import asyncio
import json
import queue

from fastapi import APIRouter, Request
from sse_starlette.sse import EventSourceResponse

from app.broadcaster import broadcaster

router = APIRouter()

# q.get()을 이 시간(초)만큼만 블로킹해 executor 스레드를 주기적으로 반납한다.
# 그 사이에 클라이언트 연결 해제를 감지해 구독을 정리할 수 있고, 아무 이벤트도
# 없으면 SSE keepalive(ping)를 보내 죽은 연결을 오래 붙들지 않는다.
POLL_TIMEOUT_SECONDS = 15.0


@router.get("/events/crashes")
async def crash_events(request: Request):
    async def event_generator():
        q = broadcaster.subscribe()
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.to_thread(q.get, True, POLL_TIMEOUT_SECONDS)
                except queue.Empty:
                    yield {"event": "ping", "data": ""}
                    continue
                yield {"event": "crash", "data": json.dumps(event)}
        finally:
            broadcaster.unsubscribe(q)

    return EventSourceResponse(event_generator())
