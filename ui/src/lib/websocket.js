const WS_PROTO = () => (window.location.protocol === 'https:' ? 'wss' : 'ws');
const MAX_RETRIES = 10;
const RETRY_DELAY = 3000;

/**
 * createWS — WebSocket 연결 헬퍼
 *
 * @param {function} onMessage - 수신 콜백 (parsed JSON)
 * @param {function} onStatusChange - 연결 상태 콜백 (boolean)
 * @returns {{ close: function }} 핸들
 */
export function createWS(onMessage, onStatusChange) {
  let ws = null;
  let retries = 0;
  let closed = false;

  function connect() {
    if (closed) return;
    ws = new WebSocket(`${WS_PROTO()}://${window.location.host}/ws`);

    ws.onopen = () => {
      retries = 0;
      onStatusChange(true);
    };

    ws.onclose = () => {
      onStatusChange(false);
      if (!closed && retries < MAX_RETRIES) {
        retries++;
        setTimeout(connect, RETRY_DELAY);
      }
    };

    ws.onerror = () => ws.close();

    ws.onmessage = (e) => {
      try {
        onMessage(JSON.parse(e.data));
      } catch (_) {}
    };
  }

  connect();

  return {
    close() {
      closed = true;
      ws?.close();
    },
  };
}
