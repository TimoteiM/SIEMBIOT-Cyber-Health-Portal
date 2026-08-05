import type { Metadata } from "next";
import type { ReactNode } from "react";

import AppShell from "./shell";
import "./styles.css";

export const metadata: Metadata = {
  title: "SIEMBIOT Cyber Health Portal",
  description: "Evaluare comunitară a sănătății cibernetice",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="ro">
      <body>
        <a className="skip-link" href="#main">
          Sari la conținut
        </a>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
