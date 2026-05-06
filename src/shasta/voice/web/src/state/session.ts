import { create } from "zustand";
import type { ActiveCard, ConnectionState, TranscriptLine } from "../tools/types";

interface SessionState {
  connection: ConnectionState;
  errorMessage: string | null;
  transcript: TranscriptLine[];
  activeCard: ActiveCard;
  micMuted: boolean;

  setConnection: (s: ConnectionState) => void;
  setError: (msg: string | null) => void;
  appendTranscript: (line: TranscriptLine) => void;
  updatePartialTranscript: (id: string, text: string) => void;
  finalizeTranscript: (id: string) => void;
  setActiveCard: (card: ActiveCard) => void;
  toggleMicMute: () => void;
  reset: () => void;
}

export const useSession = create<SessionState>((set) => ({
  connection: "idle",
  errorMessage: null,
  transcript: [],
  activeCard: { kind: "none" },
  micMuted: false,

  setConnection: (connection) => set({ connection }),
  setError: (errorMessage) => set({ errorMessage, connection: errorMessage ? "error" : "idle" }),
  appendTranscript: (line) =>
    set((s) => ({ transcript: [...s.transcript, line] })),
  updatePartialTranscript: (id, text) =>
    set((s) => ({
      transcript: s.transcript.map((l) =>
        l.id === id ? { ...l, text, partial: true } : l
      ),
    })),
  finalizeTranscript: (id) =>
    set((s) => ({
      transcript: s.transcript.map((l) =>
        l.id === id ? { ...l, partial: false } : l
      ),
    })),
  setActiveCard: (activeCard) => set({ activeCard }),
  toggleMicMute: () => set((s) => ({ micMuted: !s.micMuted })),
  reset: () =>
    set({
      connection: "idle",
      errorMessage: null,
      transcript: [],
      activeCard: { kind: "none" },
      micMuted: false,
    }),
}));
