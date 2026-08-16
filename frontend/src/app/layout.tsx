import type { Metadata } from "next";
import "./globals.css";
import Navbar from "@/components/Navbar";
import { RoleProvider } from "@/context/RoleContext";

export const metadata: Metadata = {
  title: "ThreatLens - Enterprise CTI Platform",
  description: "Cyber Threat Intelligence & Incident Correlation Platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#090d16] text-slate-100 min-h-screen">
        <RoleProvider>
          <Navbar />
          <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
            {children}
          </main>
        </RoleProvider>
      </body>
    </html>
  );
}