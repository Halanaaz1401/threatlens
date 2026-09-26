"use client";

import { useEffect, useState } from "react";
import { AlertItem } from "@/components/analyst/AlertQueue";
import { getAuthToken } from "@/lib/auth";

export function useAlertStream() {
  const [liveAlerts, setLiveAlerts] = useState<AlertItem[]>([]);
  const [isConnected, setIsConnected] = useState<boolean>(false);

  useEffect(() => {
    const token = getAuthToken();
    const baseWsUrl = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/api/v1/ws/alerts";
    const wsUrl = token ? `${baseWsUrl}?token=${encodeURIComponent(token)}` : baseWsUrl;
    
    let socket: WebSocket | null = null;
    try {
      socket = new WebSocket(wsUrl);

      socket.onopen = () => setIsConnected(true);
      socket.onclose = () => setIsConnected(false);

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === "NEW_ALERT") {
            setLiveAlerts((prev) => [payload.data, ...prev]);
          }
        } catch (err) {
          console.error("WS Parse Error:", err);
        }
      };
    } catch (e) {
      console.warn("WebSocket connection initialization failed:", e);
    }

    return () => {
      if (socket) {
        socket.close();
      }
    };
  }, []);

  return { liveAlerts, isConnected };
}