import { useEffect, useRef } from "react";
import { useSession } from "./state/session";
import { connectVoice, type VoiceConnection } from "./voice/connection";
import {
  buildFunctionCallOutput,
  buildResponseCreate,
  type RealtimeServerEvent,
} from "./voice/events";
import { executeToolCall } from "./tools/relay";
import { dispatchCard } from "./voice/cardDispatcher";
import { Header } from "./components/Header";
import { MicChrome } from "./components/MicChrome";
import { Transcript } from "./components/Transcript";
import { CardSlot } from "./components/CardSlot";

export default function App() {
  const connRef = useRef<VoiceConnection | null>(null);
  const assistantTextRef = useRef<Map<string, string>>(new Map());
  const userInputItemRef = useRef<string | null>(null);

  const setConnection = useSession((s) => s.setConnection);
  const setError = useSession((s) => s.setError);
  const appendTranscript = useSession((s) => s.appendTranscript);
  const updatePartialTranscript = useSession((s) => s.updatePartialTranscript);
  const finalizeTranscript = useSession((s) => s.finalizeTranscript);
  const setActiveCard = useSession((s) => s.setActiveCard);
  const reset = useSession((s) => s.reset);

  useEffect(() => {
    return () => {
      connRef.current?.close();
    };
  }, []);

  const handleEvent = async (event: RealtimeServerEvent) => {
    const conn = connRef.current;
    if (!conn) return;

    switch (event.type) {
      case "session.created":
        setConnection("connected");
        break;

      case "input_audio_buffer.speech_started":
        setConnection("listening");
        break;

      case "input_audio_buffer.speech_stopped":
        setConnection("thinking");
        break;

      case "conversation.item.input_audio_transcription.completed": {
        const e = event as { item_id: string; transcript: string };
        appendTranscript({
          id: `user-${e.item_id}`,
          who: "user",
          text: e.transcript,
          timestamp: Date.now(),
        });
        userInputItemRef.current = e.item_id;
        break;
      }

      case "response.audio_transcript.delta": {
        const e = event as { item_id: string; delta: string };
        const existing = assistantTextRef.current.get(e.item_id) ?? "";
        const next = existing + e.delta;
        assistantTextRef.current.set(e.item_id, next);
        const id = `assistant-${e.item_id}`;
        const state = useSession.getState();
        if (!state.transcript.find((l) => l.id === id)) {
          appendTranscript({ id, who: "assistant", text: next, timestamp: Date.now(), partial: true });
        } else {
          updatePartialTranscript(id, next);
        }
        setConnection("speaking");
        break;
      }

      case "response.audio_transcript.done": {
        const e = event as { item_id: string };
        finalizeTranscript(`assistant-${e.item_id}`);
        assistantTextRef.current.delete(e.item_id);
        break;
      }

      case "response.function_call_arguments.done": {
        const e = event as { call_id: string; name: string; arguments: string };
        const result = await executeToolCall(e.name, e.arguments);
        // Send result back to model
        conn.send(buildFunctionCallOutput(e.call_id, result.output));
        // Trigger response generation
        conn.send(buildResponseCreate());
        // Dispatch card if applicable
        const card = dispatchCard(e.name, result.parsed);
        if (card) setActiveCard(card);
        break;
      }

      case "response.done":
        setConnection("connected");
        break;

      case "error": {
        const e = event as { error: { message: string } };
        setError(e.error?.message ?? "Unknown realtime error");
        break;
      }
    }
  };

  const handleConnectionStateChange = (state: RTCPeerConnectionState) => {
    if (state === "failed" || state === "disconnected" || state === "closed") {
      setConnection("idle");
    }
  };

  const handleConnect = async () => {
    setError(null);
    setConnection("connecting");
    try {
      const conn = await connectVoice({
        onEvent: handleEvent,
        onConnectionStateChange: handleConnectionStateChange,
      });
      connRef.current = conn;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      connRef.current?.close();
      connRef.current = null;
    }
  };

  const handleDisconnect = () => {
    connRef.current?.close();
    connRef.current = null;
    reset();
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh" }}>
      <Header />
      <main
        style={{
          flex: 1,
          display: "grid",
          gridTemplateColumns: "minmax(0, 7fr) minmax(280px, 3fr)",
          gap: "var(--space-5)",
          padding: "var(--space-5)",
          minHeight: 0,
        }}
      >
        <CardSlot />
        <Transcript />
      </main>
      <footer
        style={{
          padding: "var(--space-5) 0 var(--space-6) 0",
          display: "flex",
          justifyContent: "center",
          borderTop: "1px solid var(--border-subtle)",
        }}
      >
        <MicChrome onConnect={handleConnect} onDisconnect={handleDisconnect} />
      </footer>
    </div>
  );
}
