import queue
import threading

# 구독자 큐 하나가 무한정 커지지 않도록 상한을 둔다. 클라이언트가 연결을
# 끊었는데도 unsubscribe가 늦게 도달하는 구간(예: 스레드가 블로킹된 get()에
# 머무는 동안)에 이벤트가 쌓여도 메모리가 무한히 증가하지 않게 하기 위함이다.
MAX_QUEUE_SIZE = 1000


class CrashBroadcaster:
    def __init__(self):
        self._subscribers: list[queue.Queue] = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, event: dict) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                # 느린/죽은 구독자 때문에 publish 전체가 막히면 안 되므로
                # 그 구독자의 이벤트만 흘리고 계속 진행한다.
                continue


broadcaster = CrashBroadcaster()
