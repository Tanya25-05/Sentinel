import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: "SENTINEL - AI Security Platform",
  description: "Isolated security testing platform with AI-powered analysis",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-gray-50 min-h-screen">{children}</body>
    </html>
  );
}
