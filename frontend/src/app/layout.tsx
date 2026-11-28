import "./globals.css";
import "./console.css";

import { Nav } from "@/components/nav";

export const metadata = { title: "TRAPSIG", description: "IoT honeypot and cybersecurity research platform" };

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Nav />
        <main id="main">{children}</main>
      </body>
    </html>
  );
}
