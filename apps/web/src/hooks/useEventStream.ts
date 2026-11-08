"use client";

import { useCallback, useEffect, useRef } from "react";
import type { Event, GuardDecision, Incident, Signal, WSMessage } from "@contracts/index";
import { fetchEvents, fetchGuardDecisions, fetchIncidents, fetchSignals } from "@/lib/api";
import { useEventStore } from "@/lib/store";
import { getWebSocketUrl } from "@/lib/ws";

export function useEventStream() {
  const {
    events,
    signals,
    incidents,
    guardDecisions,
    status,
    setStatus,
    addEvent,
    setEvents,
    addSignal,
    setSignals,
    addIncident,
    setIncidents,
    addGuardDecision,
    setGuardDecisions,
  } = useEventStore();

  const reconnectDelayRef = useRef<number>(1000);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const isHydratedRef = useRef<boolean>(false);

  // Helper to hydrate store from REST API
  const hydrateFromApi = useCallback(async () => {
    try {
      const [initialEvents, initialSignals, initialIncidents, initialDecisions] = await Promise.allSettled([
        fetchEvents(50),
        fetchSignals(50),
        fetchIncidents(),
        fetchGuardDecisions(20),
      ]);

      if (initialEvents.status === "fulfilled") {
        setEvents(initialEvents.value);
      }
      if (initialSignals.status === "fulfilled") {
        setSignals(initialSignals.value);
      }
      if (initialIncidents.status === "fulfilled") {
        setIncidents(initialIncidents.value);
      }
      if (initialDecisions.status === "fulfilled") {
        setGuardDecisions(initialDecisions.value);
      }
      isHydratedRef.current = true;
    } catch {
      // Quietly ignore network offline errors during hydration
    }
  }, [setEvents, setSignals, setIncidents, setGuardDecisions]);

  // Initial event, signal, and incident hydration
  useEffect(() => {
    if (!isHydratedRef.current) {
      hydrateFromApi();
    }
  }, [hydrateFromApi]);

  // Connect helper
  const connect = useCallback(() => {
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    setStatus("connecting");
    const wsUrl = getWebSocketUrl();
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus("open");
      reconnectDelayRef.current = 1000;
      // Re-hydrate store now that backend is available
      hydrateFromApi();
    };

    ws.onmessage = (messageEvent) => {
      try {
        if (messageEvent.data === "pong") return;
        const msg = JSON.parse(messageEvent.data) as WSMessage;
        if (msg.type === "event" && msg.payload) {
          addEvent(msg.payload as unknown as Event);
        }
        if (msg.type === "signal" && msg.payload) {
          addSignal(msg.payload as unknown as Signal);
        }
        if (msg.type === "incident" && msg.payload) {
          addIncident(msg.payload as unknown as Incident);
        }
        if (msg.type === "guard" && msg.payload) {
          addGuardDecision(msg.payload as unknown as GuardDecision);
        }
      } catch (err) {
        console.error("Error parsing WebSocket message:", err);
      }
    };

    ws.onerror = () => {
      // Browser handles errors silently, onclose will fire next
    };

    ws.onclose = () => {
      setStatus("closed");
      const delay = reconnectDelayRef.current;
      reconnectDelayRef.current = Math.min(delay * 1.5, 5000);

      reconnectTimeoutRef.current = setTimeout(() => {
        connect();
      }, delay);
    };
  }, [setStatus, addEvent, addSignal, addIncident, addGuardDecision, hydrateFromApi]);

  // WebSocket lifecycle
  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect]);

  const forceReconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    reconnectDelayRef.current = 1000;
    if (wsRef.current) {
      try {
        wsRef.current.close();
      } catch {
        // Ignore
      }
    }
    connect();
  }, [connect]);

  return { events, signals, incidents, guardDecisions, status, forceReconnect };
}
