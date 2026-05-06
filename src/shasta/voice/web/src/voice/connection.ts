import { parseEvent, type RealtimeServerEvent } from "./events";

const REALTIME_BASE = "https://api.openai.com/v1/realtime";

export interface VoiceConnection {
  pc: RTCPeerConnection;
  dataChannel: RTCDataChannel;
  audioElement: HTMLAudioElement;
  micTrack: MediaStreamTrack;
  send: (obj: object) => void;
  close: () => void;
}

export interface VoiceConnectionHooks {
  onEvent: (event: RealtimeServerEvent) => void;
  onConnectionStateChange: (state: RTCPeerConnectionState) => void;
}

interface TokenResponse {
  client_secret: string;
  expires_at: number;
  model: string;
}

async function fetchEphemeralToken(): Promise<TokenResponse> {
  const resp = await fetch("/session/token", { method: "POST" });
  if (!resp.ok) {
    const detail = await resp.text();
    throw new Error(`Failed to mint session token: ${resp.status} ${detail}`);
  }
  return resp.json();
}

export async function connectVoice(
  hooks: VoiceConnectionHooks
): Promise<VoiceConnection> {
  const token = await fetchEphemeralToken();

  // 1. Get mic
  const mediaStream = await navigator.mediaDevices.getUserMedia({
    audio: {
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true,
    },
  });
  const micTrack = mediaStream.getAudioTracks()[0];

  // 2. Create peer connection
  const pc = new RTCPeerConnection();
  pc.addTrack(micTrack, mediaStream);

  // 3. Audio sink — model's voice plays here
  const audioElement = document.createElement("audio");
  audioElement.autoplay = true;
  audioElement.style.display = "none";
  document.body.appendChild(audioElement);
  pc.ontrack = (event) => {
    audioElement.srcObject = event.streams[0];
  };

  // 4. Data channel for events
  const dataChannel = pc.createDataChannel("oai-events");
  dataChannel.onmessage = (msg) => {
    const event = parseEvent(msg.data);
    if (event) hooks.onEvent(event);
  };

  pc.onconnectionstatechange = () => hooks.onConnectionStateChange(pc.connectionState);

  // 5. SDP offer
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);

  // 6. Send offer to OpenAI, receive answer
  const sdpResponse = await fetch(`${REALTIME_BASE}?model=${encodeURIComponent(token.model)}`, {
    method: "POST",
    body: offer.sdp ?? "",
    headers: {
      Authorization: `Bearer ${token.client_secret}`,
      "Content-Type": "application/sdp",
    },
  });

  if (!sdpResponse.ok) {
    pc.close();
    throw new Error(
      `OpenAI SDP exchange failed: ${sdpResponse.status} ${await sdpResponse.text()}`
    );
  }

  const answerSdp = await sdpResponse.text();
  await pc.setRemoteDescription({ type: "answer", sdp: answerSdp });

  const send = (obj: object) => {
    if (dataChannel.readyState === "open") {
      dataChannel.send(JSON.stringify(obj));
    }
  };

  const close = () => {
    micTrack.stop();
    dataChannel.close();
    pc.close();
    audioElement.srcObject = null;
    audioElement.remove();
  };

  return { pc, dataChannel, audioElement, micTrack, send, close };
}
