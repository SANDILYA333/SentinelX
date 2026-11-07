"use client";

import { useEffect, useRef } from "react";
import type { Event, WSMessage } from "@contracts/index";
import { fetchEvents } from "@/lib/api";
import { useEventStore } from "@/lib/store";
import { getWebSocketUrl } from "@/lib/ws";

export function useEventStream() {
  const { events, status, setStatus, addEvent, setEvents } = useEventStore();
  const reconnectDelayRef = useRef<number>(500);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const isHydratedRef = useRef<boolean>(false);

  // Initial event hydration from REST API
  useEffect(() => {
    if (isHydratedRef.current) return;
    isHydratedRef.current = true;

    fetchEvents(50)
      .then((initialEvents) => {
        setEvents(initialEvents);
      })
      .catch((err) => {
        console.error("Failed to hydrate events from REST API:", err);
      });
  }, [setEvents]);

  // WebSocket lifecycle with exponential backoff reconnect
  useEffect(() => {
    let unmounted = false;

    function connect() {
      if (unmounted) return;
      setStatus("connecting");

      const wsUrl = getWebSocketUrl();
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (unmounted) {
          ws.close();
          return;
        }
        setStatus("open");
        reconnectDelayRef.current = 500; // Reset backoff on successful connect
      };

      ws.onmessage = (messageEvent) => {
        try {
          if (messageEvent.data === "pong") return;
          const msg = JSON.parse(messageEvent.data) as WSMessage;
          if (msg.type === "event" && msg.payload) {
            addEvent(msg.payload as unknown as Event);
          }
        } catch (err) {
          console.error("Error parsing WebSocket message:", err);
        }
      };

      ws.onerror = () => {
        // ws.onclose handles state and reconnect
      };

      ws.onclose = () => {
        if (unmounted) return;
        setStatus("closed");

        // Exponential backoff capped at 5000ms
        const delay = reconnectDelayRef.current;
        reconnectDelayRef.current = Math.min(delay * 2, 5000);

        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, delay);
      };
    }

    connect();

    return () => {
      unmounted = true;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [setStatus, addEvent]);

  return { events, status };
}
