"use client";

import React, { createContext, useContext, useState } from "react";
import type { Event } from "@contracts/index";
import { fetchEventById, fetchSignalById, type SignalWithEvidence } from "@/lib/api";
import { getDetectorStyle, getDomainStyle } from "@/lib/theme";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Check,
  Clock,
  Copy,
  Cpu,
  ExternalLink,
  FileCode,
  Radio,
  Server,
  User,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface EvidenceDrawerContextType {
  openEvidence: (id: string, type?: "event" | "signal") => void;
  closeEvidence: () => void;
}

const EvidenceDrawerContext = createContext<EvidenceDrawerContextType>({
  openEvidence: () => {},
  closeEvidence: () => {},
});

export function useEvidenceDrawer() {
  return useContext(EvidenceDrawerContext);
}

export function EvidenceDrawerProvider({ children }: { children: React.ReactNode }) {
  const [isOpen, setIsOpen] = useState(false);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [activeType, setActiveType] = useState<"event" | "signal">("event");
  const [eventData, setEventData] = useState<Event | null>(null);
  const [signalData, setSignalData] = useState<SignalWithEvidence | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const openEvidence = async (id: string, type?: "event" | "signal") => {
    const resolvedType = type || (id.startsWith("sig_") ? "signal" : "event");
    setActiveId(id);
    setActiveType(resolvedType);
    setIsOpen(true);
    setLoading(true);
    setEventData(null);
    setSignalData(null);

    try {
      if (resolvedType === "signal") {
        const sig = await fetchSignalById(id);
        setSignalData(sig);
      } else {
        const ev = await fetchEventById(id);
        setEventData(ev);
      }
    } catch (err) {
      console.error(`Failed to fetch evidence for ${id}:`, err);
    } finally {
      setLoading(false);
    }
  };

  const closeEvidence = () => {
    setIsOpen(false);
    setActiveId(null);
  };

  const handleCopyRaw = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <EvidenceDrawerContext.Provider value={{ openEvidence, closeEvidence }}>
      {children}

      {/* Slide-over Drawer Backdrop */}
      {isOpen && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity animate-in fade-in">
          <div
            className="fixed inset-0"
            onClick={closeEvidence}
            aria-hidden="true"
          />

          <aside className="relative z-10 w-full max-w-2xl bg-slate-950 border-l border-slate-800 shadow-2xl flex flex-col h-full animate-in slide-in-from-right duration-200">
            {/* Header */}
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
              <div className="flex items-center gap-2.5">
                {activeType === "signal" ? (
                  <Radio className="w-5 h-5 text-purple-400" />
                ) : (
                  <FileCode className="w-5 h-5 text-sky-400" />
                )}
                <div>
                  <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                    <span>
                      {activeType === "signal" ? "Detection Signal Evidence" : "Normalized Telemetry Event"}
                    </span>
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {activeId}
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Forensic provenance &amp; underlying raw log context
                  </p>
                </div>
              </div>

              <Button
                variant="ghost"
                size="icon"
                onClick={closeEvidence}
                className="text-slate-400 hover:text-slate-100 hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </Button>
            </div>

            {/* Content Area */}
            <ScrollArea className="flex-1 p-6 space-y-6">
              {loading && (
                <div className="flex flex-col items-center justify-center py-24 text-slate-500 space-y-3">
                  <div className="w-8 h-8 border-2 border-slate-700 border-t-blue-500 rounded-full animate-spin" />
                  <p className="text-xs">Fetching provenance record from store...</p>
                </div>
              )}

              {!loading && activeType === "event" && eventData && (
                <div className="space-y-6">
                  {/* Event Overview Card */}
                  <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={getDomainStyle(eventData.domain).badge}>
                          {eventData.domain.toUpperCase()} Domain
                        </Badge>
                        <Badge variant="outline" className="bg-slate-800/80 text-slate-300 border-slate-700">
                          {eventData.source_tool}
                        </Badge>
                        <Badge variant="outline" className="bg-slate-800/80 text-slate-300 border-slate-700">
                          {eventData.category}
                        </Badge>
                      </div>
                      <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5" />
                        {new Date(eventData.ts).toISOString()}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1">
                        <span className="text-slate-500 font-medium flex items-center gap-1.5">
                          <Server className="w-3.5 h-3.5" /> Host Target
                        </span>
                        <div className="font-mono text-slate-200">
                          {eventData.host || "N/A"}
                        </div>
                      </div>

                      <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1">
                        <span className="text-slate-500 font-medium flex items-center gap-1.5">
                          <User className="w-3.5 h-3.5" /> User / Identity
                        </span>
                        <div className="font-mono text-slate-200">
                          {eventData.user || "N/A"}
                        </div>
                      </div>

                      <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1">
                        <span className="text-slate-500 font-medium">Source IP &amp; Port</span>
                        <div className="font-mono text-slate-200">
                          {eventData.src_ip || "N/A"}{eventData.src_port ? `:${eventData.src_port}` : ""}
                        </div>
                      </div>

                      <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1">
                        <span className="text-slate-500 font-medium">Destination IP &amp; Port</span>
                        <div className="font-mono text-slate-200">
                          {eventData.dst_ip || "N/A"}{eventData.dst_port ? `:${eventData.dst_port}` : ""}
                        </div>
                      </div>
                    </div>

                    {/* Action & Outcome */}
                    <div className="flex items-center justify-between text-xs pt-1 border-t border-slate-800/60">
                      <span className="text-slate-400">
                        Action: <strong className="text-slate-200">{eventData.action}</strong>
                      </span>
                      <span className={cn(
                        "font-semibold uppercase tracking-wider text-[11px]",
                        eventData.outcome === "success" ? "text-emerald-400" : "text-rose-400"
                      )}>
                        Outcome: {eventData.outcome}
                      </span>
                    </div>

                    {/* OT Fields if present */}
                    {eventData.ot && (
                      <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-800/40 text-xs space-y-2">
                        <span className="font-semibold text-amber-400 flex items-center gap-1.5">
                          <Cpu className="w-3.5 h-3.5" /> Modbus OT Command Payload
                        </span>
                        <div className="grid grid-cols-4 gap-2 font-mono text-slate-300">
                          <div>
                            <span className="text-slate-500 text-[10px] block">Function</span>
                            {eventData.ot.function_code ?? "N/A"}
                          </div>
                          <div>
                            <span className="text-slate-500 text-[10px] block">Register</span>
                            {eventData.ot.register ?? "N/A"}
                          </div>
                          <div>
                            <span className="text-slate-500 text-[10px] block">Value</span>
                            {eventData.ot.value !== null ? String(eventData.ot.value) : "N/A"}
                          </div>
                          <div>
                            <span className="text-slate-500 text-[10px] block">Is Write</span>
                            {eventData.ot.is_write ? "TRUE" : "FALSE"}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Raw Forensic Log Payload */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-slate-300">
                        Raw Collected Log Record
                      </span>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7 text-xs border-slate-800 bg-slate-900 hover:bg-slate-800"
                        onClick={() => handleCopyRaw(JSON.stringify(eventData.raw, null, 2))}
                      >
                        {copied ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-400 mr-1" /> Copied
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5 mr-1" /> Copy JSON
                          </>
                        )}
                      </Button>
                    </div>

                    <pre className="p-4 rounded-xl bg-[#070b12] border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-72 leading-relaxed">
                      {JSON.stringify(eventData.raw, null, 2)}
                    </pre>
                  </div>
                </div>
              )}

              {!loading && activeType === "signal" && signalData && (
                <div className="space-y-6">
                  {/* Signal Card */}
                  <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={getDetectorStyle(signalData.detector).badge}>
                          {signalData.detector.toUpperCase()}
                        </Badge>
                        <span className="font-mono text-xs font-semibold text-purple-300">
                          {signalData.rule_id}
                        </span>
                      </div>
                      <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5" />
                        {new Date(signalData.ts).toISOString()}
                      </span>
                    </div>

                    <h4 className="text-sm font-semibold text-slate-100">
                      {signalData.title}
                    </h4>

                    <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
                      {signalData.explanation}
                    </p>

                    <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
                      <div>
                        Confidence: <strong className="text-slate-200">{(signalData.confidence * 100).toFixed(0)}%</strong>
                      </div>
                      <div>
                        Score: <strong className="text-slate-200">{signalData.score.toFixed(2)}</strong>
                      </div>
                    </div>

                    {/* MITRE Techniques */}
                    {signalData.techniques && signalData.techniques.length > 0 && (
                      <div className="space-y-1.5 pt-2 border-t border-slate-800">
                        <span className="text-[11px] font-semibold text-slate-400 block">
                          Mapped MITRE ATT&amp;CK Techniques
                        </span>
                        <div className="flex flex-wrap gap-1.5">
                          {signalData.techniques.map((t) => (
                            <Badge
                              key={t.technique_id}
                              variant="outline"
                              className="text-[10px] bg-slate-950 text-slate-300 border-slate-700"
                            >
                              {t.technique_id} - {t.name} ({t.tactic})
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Underlying Evidence Events */}
                  <div className="space-y-3">
                    <span className="text-xs font-semibold text-slate-300 block">
                      Underlying Evidence Telemetry Events ({signalData.evidence_event_ids.length})
                    </span>

                    <div className="space-y-2">
                      {signalData.evidence_events && signalData.evidence_events.length > 0 ? (
                        signalData.evidence_events.map((ev) => (
                          <div
                            key={ev.event_id}
                            className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition flex items-center justify-between cursor-pointer"
                            onClick={() => openEvidence(ev.event_id, "event")}
                          >
                            <div className="space-y-0.5">
                              <div className="flex items-center gap-2">
                                <Badge variant="outline" className={getDomainStyle(ev.domain).badge}>
                                  {ev.domain}
                                </Badge>
                                <span className="text-xs font-medium text-slate-200">
                                  {ev.action} on {ev.host || "unknown"}
                                </span>
                              </div>
                              <div className="text-[11px] font-mono text-slate-500">
                                {ev.event_id} &bull; {new Date(ev.ts).toISOString()}
                              </div>
                            </div>

                            <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
                          </div>
                        ))
                      ) : (
                        <div className="flex flex-wrap gap-1.5">
                          {signalData.evidence_event_ids.map((eid) => (
                            <button
                              key={eid}
                              onClick={() => openEvidence(eid, "event")}
                              className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-xs font-mono text-sky-400 hover:bg-slate-800 transition flex items-center gap-1"
                            >
                              <span>{eid}</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </ScrollArea>
          </aside>
        </div>
      )}
    </EvidenceDrawerContext.Provider>
  );
}
