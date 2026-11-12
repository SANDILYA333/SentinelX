"use client";

import { useCallback, useEffect } from "react";
import type { Event, GuardDecision, Incident, Signal, WSMessage } from "@contracts/index";
import { fetchEvents, fetchGuardDecisions, fetchIncidents, fetchSignals } from "@/lib/api";
import { useEventStore } from "@/lib/store";
import { getWebSocketUrl } from "@/lib/ws";

// Module-level singleton state across route transitions
let globalWs: WebSocket | null = null;
let globalReconnectTimeout: NodeJS.Timeout | null = null;
let globalReconnectDelay = 1000;
let isHydrated = false;
let activeSubscribers = 0;

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

  const hydrateFromApi = useCallback(async () => {
    try {
      const [initialEvents, initialSignals, initialIncidents, initialDecisions] =
        await Promise.allSettled([
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
      isHydrated = true;
    } catch {
      // Quietly ignore network offline errors during hydration
    }
  }, [setEvents, setSignals, setIncidents, setGuardDecisions]);

  const connect = useCallback(() => {
    if (
      globalWs &&
      (globalWs.readyState === WebSocket.OPEN ||
        globalWs.readyState === WebSocket.CONNECTING)
    ) {
      return;
    }

    setStatus("connecting");
    const wsUrl = getWebSocketUrl();
    const ws = new WebSocket(wsUrl);
    globalWs = ws;

    ws.onopen = () => {
      setStatus("open");
      globalReconnectDelay = 1000;
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
      // Handled by onclose
    };

    ws.onclose = () => {
      setStatus("closed");
      globalWs = null;
      const delay = globalReconnectDelay;
      globalReconnectDelay = Math.min(delay * 1.5, 5000);

      if (globalReconnectTimeout) clearTimeout(globalReconnectTimeout);
      globalReconnectTimeout = setTimeout(() => {
        if (activeSubscribers > 0) {
          connect();
        }
      }, delay);
    };
  }, [setStatus, addEvent, addSignal, addIncident, addGuardDecision, hydrateFromApi]);

  useEffect(() => {
    activeSubscribers += 1;
    if (!isHydrated) {
      hydrateFromApi();
    }
    connect();

    return () => {
      activeSubscribers = Math.max(0, activeSubscribers - 1);
      // We keep the singleton socket alive across route transitions
    };
  }, [connect, hydrateFromApi]);

  const forceReconnect = useCallback(() => {
    if (globalReconnectTimeout) {
      clearTimeout(globalReconnectTimeout);
    }
    globalReconnectDelay = 1000;
    if (globalWs) {
      try {
        globalWs.close();
      } catch {
        // Ignore
      }
      globalWs = null;
    }
    connect();
  }, [connect]);

  return { events, signals, incidents, guardDecisions, status, forceReconnect };
}
