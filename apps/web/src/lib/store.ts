import { create } from "zustand";
import type { Event, Signal } from "@contracts/index";

export type WsStatus = "connecting" | "open" | "closed";

interface AppStore {
  events: Event[];
  signals: Signal[];
  status: WsStatus;
  setStatus: (status: WsStatus) => void;
  addEvent: (event: Event) => void;
  setEvents: (events: Event[]) => void;
  addSignal: (signal: Signal) => void;
  setSignals: (signals: Signal[]) => void;
}

export const useEventStore = create<AppStore>((set) => ({
  events: [],
  signals: [],
  status: "connecting",
  setStatus: (status) => set({ status }),
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
}));
