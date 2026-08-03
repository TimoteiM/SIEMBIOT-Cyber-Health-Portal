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
        <div
          className="fixture-banner"
          role="status"
          aria-label="Mod de validare cu date fixture"
        >
          <strong>MOD FIXTURE — NU ESTE O EVALUARE LIVE</strong>
          <span>
            Rezultatele folosesc exclusiv date locale sintetice și nu pot fi publicate ca
            rezultate reale.
          </span>
        </div>
        <header className="site-header">
          <a href="/" className="brand" aria-label="SIEMBIOT, pagina principală">
            <span aria-hidden="true">S</span> SIEMBIOT
          </a>
          <span className="environment">Validare locală cu date fixture</span>
        </header>
        <main id="main">{children}</main>
      </body>
    </html>
  );
}
