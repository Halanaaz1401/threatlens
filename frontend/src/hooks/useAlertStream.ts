"use client";

import { useEffect, useState } from "react";
import { AlertItem } from "@/components/analyst/AlertQueue";

export function useAlertStream() {
  const [liveAlerts, setLiveAlerts] = useState<AlertItem[]>([]);
  const [isConnected, setIsConnected] = useState<boolean>(false);

  useEffect(() => {
    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/api/v1/ws/alerts";
    const socket = new WebSocket(wsUrl);

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

    return () => {
      socket.close();
    };
  }, []);

  return { liveAlerts, isConnected };
}