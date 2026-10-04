"use client";

import { useEffect, useState, useRef } from "react";
import { AlertItem } from "@/components/analyst/AlertQueue";
import { getAuthToken } from "@/lib/auth";
import { getWsBaseUrl } from "@/lib/api";

export function useAlertStream() {
  const [liveAlerts, setLiveAlerts] = useState<AlertItem[]>([]);
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let isMounted = true;

    function connect() {
      const token = getAuthToken();
      const baseWsUrl = getWsBaseUrl();
      const wsUrl = token
        ? `${baseWsUrl}${baseWsUrl.includes("?") ? "&" : "?"}token=${encodeURIComponent(token)}`
        : baseWsUrl;


      try {
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
          if (!isMounted) return;
          setIsConnected(true);
          setConnectionError(null);
        };

        socket.onclose = (event) => {
          if (!isMounted) return;
          setIsConnected(false);
          if (event.code === 1008) {
            setConnectionError("Unauthorized WebSocket connection (Code 1008)");
          } else {
            // Reconnect after 5 seconds if connection lost
            reconnectTimeoutRef.current = setTimeout(() => {
              if (isMounted) connect();
            }, 5000);
          }
        };

        socket.onerror = () => {
          if (!isMounted) return;
          setIsConnected(false);
        };

        socket.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data);
            const alertData = payload.data || payload;
            if (
              payload.type === "NEW_ALERT" ||
              payload.event === "NEW_CRITICAL_ALERT" ||
              alertData.title
            ) {
              setLiveAlerts((prev) => {
                // Deduplicate by ID or indicator
                const exists = prev.some(
                  (a) => a.id === alertData.id || (alertData.indicator && a.indicator === alertData.indicator)
                );
                if (exists) {
                  return prev.map((a) =>
                    a.id === alertData.id ? { ...a, ...alertData } : a
                  );
                }
                return [alertData, ...prev].slice(0, 50);
              });
            }
          } catch (err) {
            console.error("WS Parse Error:", err);
          }
        };
      } catch (e) {
        console.warn("WebSocket connection initialization failed:", e);
        if (isMounted) {
          setIsConnected(false);
          setConnectionError("Failed to initialize WebSocket");
        }
      }
    }

    connect();

    return () => {
      isMounted = false;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (socket) {
        socket.close();
      }
    };
  }, []);

  return { liveAlerts, isConnected, connectionError };
}