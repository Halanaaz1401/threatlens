import type { Metadata, Viewport } from "next";
import "./globals.css";
import Navbar from "@/components/Navbar";
import { RoleProvider } from "@/context/RoleContext";

export const metadata: Metadata = {
  title: "ThreatLens - Enterprise CTI Platform",
  description: "Cyber Threat Intelligence, Security Operations & Incident Correlation Platform",
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
      <head>
        <link
          rel="preload"
          href="/fonts/space-mono-400.woff2"
          as="font"
          type="font/woff2"
          crossOrigin="anonymous"
        />
        <link
          rel="preload"
          href="/fonts/space-mono-700.woff2"
          as="font"
          type="font/woff2"
          crossOrigin="anonymous"
        />
      </head>
      <body className="bg-[#090A0C] text-[#F2F2F0] min-h-screen flex flex-col antialiased selection:bg-[#19D5E5]/20 selection:text-[#19D5E5]">
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