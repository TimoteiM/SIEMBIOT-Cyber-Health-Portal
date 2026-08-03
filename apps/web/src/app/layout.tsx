import type { Metadata } from "next";
import type { ReactNode } from "react";

import "./styles.css";

export const metadata: Metadata = {
  title: "SIEMBIOT Cyber Health Portal",
  description: "Evaluare comunitară a sănătății cibernetice",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="ro">
      <body>
        <a className="skip-link" href="#main">Sari la conținut</a>
        <header className="site-header">
          <a href="/" className="brand" aria-label="SIEMBIOT, pagina principală">
            <span aria-hidden="true">S</span> SIEMBIOT
          </a>
          <span className="environment">Portal privat</span>
        </header>
        <main id="main">{children}</main>
      </body>
    </html>
  );
}
