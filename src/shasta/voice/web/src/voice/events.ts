// Subset of OpenAI Realtime server event types we care about.
// Full reference: https://platform.openai.com/docs/api-reference/realtime-server-events

export type RealtimeServerEvent =
  | { type: "session.created"; [k: string]: unknown }
  | { type: "session.updated"; [k: string]: unknown }
  | { type: "input_audio_buffer.speech_started"; item_id?: string; [k: string]: unknown }
  | { type: "input_audio_buffer.speech_stopped"; item_id?: string; [k: string]: unknown }
  | {
      type: "conversation.item.input_audio_transcription.completed";
      item_id: string;
      transcript: string;
      [k: string]: unknown;
    }
  | { type: "response.created"; response: { id: string }; [k: string]: unknown }
  | {
      type: "response.audio_transcript.delta";
      response_id: string;
      item_id: string;
      delta: string;
      [k: string]: unknown;
    }
  | {
      type: "response.audio_transcript.done";
      response_id: string;
      item_id: string;
      transcript: string;
      [k: string]: unknown;
    }
  | {
      type: "response.function_call_arguments.delta";
      response_id: string;
      item_id: string;
      call_id: string;
      delta: string;
      [k: string]: unknown;
    }
  | {
      type: "response.function_call_arguments.done";
      response_id: string;
      item_id: string;
      call_id: string;
      name: string;
      arguments: string;
      [k: string]: unknown;
    }
  | { type: "response.done"; response: { id: string; status: string }; [k: string]: unknown }
  | { type: "error"; error: { message: string; type?: string }; [k: string]: unknown }
  | { type: string; [k: string]: unknown };

export function parseEvent(raw: string): RealtimeServerEvent | null {
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed?.type === "string") {
      return parsed as RealtimeServerEvent;
    }
    return null;
  } catch {
    return null;
  }
}

// Helpers for sending events back to the model

export function buildFunctionCallOutput(callId: string, output: string): object {
  return {
    type: "conversation.item.create",
    item: {
      type: "function_call_output",
      call_id: callId,
      output,
    },
  };
}

export function buildResponseCreate(): object {
  return { type: "response.create" };
}
