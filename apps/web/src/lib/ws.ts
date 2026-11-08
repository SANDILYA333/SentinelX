export function getWebSocketUrl(): string {
  if (typeof window === "undefined") {
    return "ws://127.0.0.1:8000/ws/stream";
  }
  try {
    const wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.hostname || "127.0.0.1";
    return `${wsProto}//${host}:8000/ws/stream`;
  } catch {
    return "ws://127.0.0.1:8000/ws/stream";
  }
}
