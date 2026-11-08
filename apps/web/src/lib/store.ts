import { create } from "zustand";
import type { Event, GuardDecision, Incident, Signal } from "@contracts/index";

export type WsStatus = "connecting" | "open" | "closed";

interface AppStore {
  events: Event[];
  signals: Signal[];
  incidents: Incident[];
  guardDecisions: GuardDecision[];
  presenterMode: boolean;
  status: WsStatus;
  setStatus: (status: WsStatus) => void;
  setPresenterMode: (val: boolean) => void;
  togglePresenterMode: () => void;
  addEvent: (event: Event) => void;
  setEvents: (events: Event[]) => void;
  addSignal: (signal: Signal) => void;
  setSignals: (signals: Signal[]) => void;
  addIncident: (incident: Incident) => void;
  setIncidents: (incidents: Incident[]) => void;
  addGuardDecision: (decision: GuardDecision) => void;
  setGuardDecisions: (decisions: GuardDecision[]) => void;
}

export const useEventStore = create<AppStore>((set) => ({
  events: [],
  signals: [],
  incidents: [],
  guardDecisions: [],
  presenterMode: false,
  status: "connecting",
  setStatus: (status) => set({ status }),
  setPresenterMode: (presenterMode) => set({ presenterMode }),
  togglePresenterMode: () => set((state) => ({ presenterMode: !state.presenterMode })),
  addEvent: (event) =>
    set((state) => {
      if (state.events.some((e) => e.event_id === event.event_id)) {
        return state;
      }
      const updated = [event, ...state.events].slice(0, 200);
      return { events: updated };
    }),
  setEvents: (events) =>
    set(() => ({
      events: events.slice(0, 200),
    })),
  addSignal: (signal) =>
    set((state) => {
      if (state.signals.some((s) => s.signal_id === signal.signal_id)) {
        return state;
      }
      const updated = [signal, ...state.signals].slice(0, 200);
      return { signals: updated };
    }),
  setSignals: (signals) =>
    set(() => ({
      signals: signals.slice(0, 200),
    })),
  addIncident: (incident) =>
    set((state) => {
      // Upsert incident
      const filtered = state.incidents.filter((i) => i.incident_id !== incident.incident_id);
      const updated = [incident, ...filtered].sort((a, b) => b.score - a.score);
      return { incidents: updated };
    }),
  setIncidents: (incidents) =>
    set(() => ({
      incidents: [...incidents].sort((a, b) => b.score - a.score),
    })),
  addGuardDecision: (decision) =>
    set((state) => {
      if (state.guardDecisions.some((d) => d.decision_id === decision.decision_id)) {
        return state;
      }
      const updated = [decision, ...state.guardDecisions].slice(0, 50);
      return { guardDecisions: updated };
    }),
  setGuardDecisions: (decisions) =>
    set(() => ({
      guardDecisions: decisions.slice(0, 50),
    })),
}));
