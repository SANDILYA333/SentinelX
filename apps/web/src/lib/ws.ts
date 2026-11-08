import { API_BASE_URL } from "./api";

export function getWebSocketUrl(): string {
  if (typeof window === "undefined") {
    return "ws://localhost:8000/ws/stream";
  }
  try {
    const url = new URL(API_BASE_URL, window.location.href);
    const wsProto = url.protocol === "https:" ? "wss:" : "ws:";
    return `${wsProto}//${url.host}/ws/stream`;
  } catch {
    return "ws://localhost:8000/ws/stream";
  }
}

