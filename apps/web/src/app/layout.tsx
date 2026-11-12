import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "@/components/providers";
import { Sidebar } from "@/components/sidebar";

export const metadata: Metadata = {
  title: "SentinelX | Cyber-Physical IT/OT Threat Detection & Response Safety",
  description:
    "Autonomous IT/OT threat detection, attack graph reconstruction, deception intelligence, and Response Safety Guard.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#090d16] text-slate-100 antialiased min-h-screen flex">
        <Providers>
          <Sidebar />
          <main className="flex-1 flex flex-col min-h-screen overflow-x-hidden pt-14 md:pt-0">
            {children}
          </main>
        </Providers>
      </body>
    </html>
  );
}
