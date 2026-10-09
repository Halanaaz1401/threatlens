import type { Metadata, Viewport } from "next";
import "./globals.css";
import Navbar from "@/components/Navbar";
import { RoleProvider } from "@/context/RoleContext";

export const metadata: Metadata = {
  title: "ThreatLens - Enterprise CTI Platform",
  description: "Cyber Threat Intelligence & Incident Correlation Platform",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark scroll-smooth">
      <body className="bg-[#090d16] text-slate-100 min-h-screen flex flex-col antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
        <RoleProvider>
          <Navbar />
          <main className="flex-1 w-full max-w-7xl mx-auto px-3 sm:px-6 lg:px-8 py-4 sm:py-6 overflow-x-hidden">
            {children}
          </main>
        </RoleProvider>
      </body>
    </html>
  );
}