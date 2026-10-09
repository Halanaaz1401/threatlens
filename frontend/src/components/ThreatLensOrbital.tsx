"use client";

import React, { useRef, useEffect, useState, useCallback } from "react";

interface ThreatLensOrbitalProps {
  className?: string;
  height?: number | string;
  seed?: string;
  tag?: string;
  accentMode?: "cyan" | "monochrome";
}

interface Particle {
  u: number;        // angle along orbit [0, 2*PI]
  vOffset: number;  // offset across band width [-1, 1]
  bandIndex: number;
  speed: number;
  size: number;
  baseAlpha: number;
  isAccent: boolean;
}

export default function ThreatLensOrbital({
  className = "",
  seed = "00042",
  tag = "THREAT • 3D",
  accentMode = "cyan",
}: ThreatLensOrbitalProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [coords, setCoords] = useState("N 148°");
  const [isInteracting, setIsInteracting] = useState(false);
  const [pulseWave, setPulseWave] = useState(0);

  // Rotation angles
  const rotXRef = useRef(0.35);
  const rotYRef = useRef(0.45);
  const targetRotXRef = useRef(0.35);
  const targetRotYRef = useRef(0.45);
  const isDraggingRef = useRef(false);
  const dragStartRef = useRef({ x: 0, y: 0 });
  const pulseRef = useRef(0);

  // Initialize and run animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = container.clientWidth);
    let height = (canvas.height = container.clientHeight);

    const resizeObserver = new ResizeObserver((entries) => {
      for (const entry of entries) {
        if (entry.contentRect.width && entry.contentRect.height) {
          const dpr = Math.min(window.devicePixelRatio || 1, 2);
          width = entry.contentRect.width;
          height = entry.contentRect.height;
          canvas.width = width * dpr;
          canvas.height = height * dpr;
          ctx.resetTransform?.();
          ctx.scale(dpr, dpr);
        }
      }
    });
    resizeObserver.observe(container);

    // Band configurations (Euler orientations in radians)
    const bands = [
      { rx: 0.8, ry: 0.3, rz: 0.4, a: 160, b: 85, c: 50, particles: 280 },
      { rx: -0.6, ry: 1.1, rz: -0.5, a: 175, b: 95, c: 60, particles: 300 },
      { rx: 1.2, ry: -0.7, rz: 0.9, a: 150, b: 80, c: 55, particles: 260 },
      { rx: -0.3, ry: -1.3, rz: 0.2, a: 185, b: 70, c: 45, particles: 240 },
    ];

    // Seeded random for deterministic visual
    let seedVal = 1234567;
    const rnd = () => {
      seedVal = (seedVal * 16807) % 2147483647;
      return (seedVal - 1) / 2147483646;
    };

    // Generate particles
    const particles: Particle[] = [];
    bands.forEach((band, bandIdx) => {
      for (let i = 0; i < band.particles; i++) {
        particles.push({
          u: rnd() * Math.PI * 2,
          vOffset: (rnd() - 0.5) * 18,
          bandIndex: bandIdx,
          speed: 0.003 + rnd() * 0.004,
          size: 0.75 + rnd() * 1.5,
          baseAlpha: 0.25 + rnd() * 0.7,
          isAccent: rnd() < 0.08, // 8% restrained cyan or brighter silver
        });
      }
    });

    // Check prefers-reduced-motion
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // Vector 3D rotation helper
    function rotate3D(
      x: number,
      y: number,
      z: number,
      rx: number,
      ry: number,
      rz: number
    ): [number, number, number] {
      // Rotation around X
      let y1 = y * Math.cos(rx) - z * Math.sin(rx);
      let z1 = y * Math.sin(rx) + z * Math.cos(rx);
      let x1 = x;

      // Rotation around Y
      let x2 = x1 * Math.cos(ry) + z1 * Math.sin(ry);
      let z2 = -x1 * Math.sin(ry) + z1 * Math.cos(ry);
      let y2 = y1;

      // Rotation around Z
      let x3 = x2 * Math.cos(rz) - y2 * Math.sin(rz);
      let y3 = x2 * Math.sin(rz) + y2 * Math.cos(rz);
      let z3 = z2;

      return [x3, y3, z3];
    }

    let lastTime = performance.now();

    const render = (time: number) => {
      const delta = Math.min((time - lastTime) / 1000, 0.1);
      lastTime = time;

      // Clear with slight trailing fade
      ctx.clearRect(0, 0, width, height);

      const cx = width / 2;
      const cy = height / 2;
      const scaleBase = Math.min(width, height) / 420;

      // Continuous auto-rotation when not dragging
      if (!isDraggingRef.current && !prefersReducedMotion) {
        targetRotYRef.current += 0.005;
        targetRotXRef.current = 0.35 + Math.sin(time * 0.0008) * 0.12;
      }

      // Smooth damping interpolation
      rotXRef.current += (targetRotXRef.current - rotXRef.current) * 0.08;
      rotYRef.current += (targetRotYRef.current - rotYRef.current) * 0.08;

      // Pulse wave decay
      if (pulseRef.current > 0) {
        pulseRef.current = Math.max(0, pulseRef.current - delta * 1.5);
      }

      // Draw subtle background compass / crosshairs
      ctx.save();
      ctx.strokeStyle = "rgba(43, 44, 48, 0.4)";
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 6]);

      // Crosshair horizontal and vertical
      ctx.beginPath();
      ctx.moveTo(cx - 140 * scaleBase, cy);
      ctx.lineTo(cx + 140 * scaleBase, cy);
      ctx.moveTo(cx, cy - 140 * scaleBase);
      ctx.lineTo(cx, cy + 140 * scaleBase);
      ctx.stroke();

      // Outer target ring
      ctx.beginPath();
      ctx.arc(cx, cy, 130 * scaleBase, 0, Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.restore();

      // Core 3D Sphere (back illumination and body)
      const sphereRadius = 38 * scaleBase * (1 + pulseRef.current * 0.15);

      // Central Sphere radial gradient
      const sphereGrad = ctx.createRadialGradient(
        cx - sphereRadius * 0.35,
        cy - sphereRadius * 0.35,
        sphereRadius * 0.1,
        cx,
        cy,
        sphereRadius
      );
      sphereGrad.addColorStop(0, "#F2F2F0");
      sphereGrad.addColorStop(0.2, "#A5A6AA");
      sphereGrad.addColorStop(0.55, "#2B2C30");
      sphereGrad.addColorStop(0.85, "#17181B");
      sphereGrad.addColorStop(1, "#090A0C");

      // Draw Sphere Core
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, sphereRadius, 0, Math.PI * 2);
      ctx.fillStyle = sphereGrad;
      ctx.fill();

      // Rim glow on sphere
      ctx.strokeStyle = "rgba(242, 242, 240, 0.4)";
      ctx.lineWidth = 1.2;
      ctx.stroke();

      // Internal latitude rings on sphere for high-tech look
      ctx.beginPath();
      ctx.ellipse(cx, cy, sphereRadius * 0.85, sphereRadius * 0.35, rotXRef.current, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(255, 255, 255, 0.15)";
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.restore();

      // Project and sort particles by depth Z
      interface ProjectedPoint {
        x2d: number;
        y2d: number;
        z: number;
        size: number;
        alpha: number;
        isAccent: boolean;
      }

      const projected: ProjectedPoint[] = [];
      const focalLength = 400 * scaleBase;

      for (const p of particles) {
        if (!prefersReducedMotion) {
          p.u += p.speed;
          if (p.u > Math.PI * 2) p.u -= Math.PI * 2;
        }

        const band = bands[p.bandIndex];
        const pulseExpand = 1 + pulseRef.current * 0.25;

        // Parametric ellipse in band local space
        const lx = band.a * scaleBase * pulseExpand * Math.cos(p.u);
        const ly = band.b * scaleBase * pulseExpand * Math.sin(p.u) + p.vOffset * scaleBase;
        const lz = band.c * scaleBase * Math.sin(p.u * 2);

        // Apply intrinsic band orientation
        const [bx, by, bz] = rotate3D(lx, ly, lz, band.rx, band.ry, band.rz);

        // Apply global interactive view rotation
        const [wx, wy, wz] = rotate3D(bx, by, bz, rotXRef.current, rotYRef.current, 0);

        // Perspective projection
        const persp = focalLength / (focalLength + wz + 200);
        const x2d = cx + wx * persp;
        const y2d = cy + wy * persp;

        // Depth-based size and opacity
        const depthNorm = (wz + 180) / 360; // 0 (far) to 1 (near)
        const size = p.size * scaleBase * Math.max(0.6, persp * 1.1);
        const alpha = Math.min(1, Math.max(0.1, p.baseAlpha * depthNorm * (1 + pulseRef.current * 0.5)));

        projected.push({
          x2d,
          y2d,
          z: wz,
          size,
          alpha,
          isAccent: p.isAccent,
        });
      }

      // Sort by depth (far first)
      projected.sort((a, b) => a.z - b.z);

      // Render ribbon connecting trails and particles
      for (let i = 0; i < projected.length; i++) {
        const pt = projected[i];

        // Draw particle dot
        ctx.beginPath();
        ctx.arc(pt.x2d, pt.y2d, pt.size, 0, Math.PI * 2);

        if (pt.isAccent && accentMode === "cyan") {
          ctx.fillStyle = `rgba(25, 213, 229, ${pt.alpha * 0.95})`;
          ctx.shadowColor = "#19D5E5";
          ctx.shadowBlur = 4;
        } else {
          ctx.fillStyle = `rgba(242, 242, 240, ${pt.alpha * 0.85})`;
          ctx.shadowColor = "transparent";
          ctx.shadowBlur = 0;
        }
        ctx.fill();

        // Connect nearby points in same slice to form ribbon sheen
        if (i % 4 === 0 && i + 1 < projected.length) {
          const next = projected[i + 1];
          const distSq = (pt.x2d - next.x2d) ** 2 + (pt.y2d - next.y2d) ** 2;
          if (distSq < 120 * scaleBase) {
            ctx.beginPath();
            ctx.moveTo(pt.x2d, pt.y2d);
            ctx.lineTo(next.x2d, next.y2d);
            ctx.strokeStyle = `rgba(200, 205, 215, ${pt.alpha * 0.12})`;
            ctx.lineWidth = 0.75;
            ctx.stroke();
          }
        }
      }

      // Reset shadows
      ctx.shadowColor = "transparent";
      ctx.shadowBlur = 0;

      // Pulse shockwave circle
      if (pulseRef.current > 0.05) {
        ctx.beginPath();
        const shockRadius = (1 - pulseRef.current) * 190 * scaleBase;
        ctx.arc(cx, cy, shockRadius, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(25, 213, 229, ${pulseRef.current * 0.4})`;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      // Update coordinate readout state periodically
      const deg = Math.round(((rotYRef.current * 180) / Math.PI) % 360);
      const normalizedDeg = deg < 0 ? deg + 360 : deg;
      setCoords(`N ${String(normalizedDeg).padStart(3, "0")}°`);

      animationFrameId = requestAnimationFrame(render);
    };

    animationFrameId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animationFrameId);
      resizeObserver.disconnect();
    };
  }, [accentMode]);

  // Pointer event handlers for 3D rotation
  const handlePointerDown = (e: React.PointerEvent) => {
    isDraggingRef.current = true;
    dragStartRef.current = { x: e.clientX, y: e.clientY };
    setIsInteracting(true);
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  };

  const handlePointerMove = (e: React.PointerEvent) => {
    if (!isDraggingRef.current) return;
    const dx = e.clientX - dragStartRef.current.x;
    const dy = e.clientY - dragStartRef.current.y;
    dragStartRef.current = { x: e.clientX, y: e.clientY };

    targetRotYRef.current += dx * 0.007;
    targetRotXRef.current = Math.max(-1.2, Math.min(1.2, targetRotXRef.current - dy * 0.007));
  };

  const handlePointerUp = (e: React.PointerEvent) => {
    isDraggingRef.current = false;
    setIsInteracting(false);
    try {
      (e.target as HTMLElement).releasePointerCapture(e.pointerId);
    } catch {
      // safe fallback
    }
  };

  // Click to pulse / reforge
  const handleClick = () => {
    pulseRef.current = 1.0;
    setPulseWave((prev) => prev + 1);
  };

  return (
    <div
      ref={containerRef}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUp}
      onPointerCancel={handlePointerUp}
      onClick={handleClick}
      className={`relative w-full h-full min-h-[340px] sm:min-h-[400px] select-none cursor-grab active:cursor-grabbing overflow-hidden bg-[#090A0C] border border-[#2B2C30] rounded-xl ${className}`}
      role="region"
      aria-label="ThreatLens 3D Orbital Threat Topology Visualization"
    >
      {/* Corner Technical Coordinate Badges (matches reference screenshot) */}
      <div className="absolute top-3 left-4 text-[10px] font-mono tracking-wider text-[#A5A6AA] z-10 pointer-events-none flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-[#19D5E5] animate-pulse" />
        <span>{coords}</span>
      </div>

      <div className="absolute top-3 right-4 text-[10px] font-mono tracking-wider text-[#72747A] z-10 pointer-events-none">
        {tag}
      </div>

      <div className="absolute bottom-3 left-4 text-[10px] font-mono text-[#72747A] z-10 pointer-events-none flex items-center gap-2">
        <span>Drag to rotate</span>
        <span>•</span>
        <span className="text-[#A5A6AA]">Click to pulse</span>
      </div>

      <div className="absolute bottom-3 right-4 text-[10px] font-mono text-[#72747A] z-10 pointer-events-none">
        seed {seed}
      </div>

      {/* Canvas Element */}
      <canvas
        ref={canvasRef}
        className="w-full h-full block"
        style={{ touchAction: "none" }}
      />
    </div>
  );
}
