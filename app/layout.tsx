import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Scavibe | Pre-launch audit",
  description: "A safer way to ship vibe-coded products.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
