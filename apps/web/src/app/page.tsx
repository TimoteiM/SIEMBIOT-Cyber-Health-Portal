export default function LandingPage() {
  return (
    <section className="hero" aria-labelledby="landing-title">
      <p className="eyebrow">Securitate măsurabilă, acces controlat</p>
      <h1 id="landing-title">Bine ai venit în SIEMBIOT Cyber Health Portal</h1>
      <p>
        Autentificarea este asigurată de platforma de identitate a organizației, înainte ca
        cererea să ajungă la acest portal. Odată autentificat, ești condus direct în spațiul
        de lucru.
      </p>
      <a className="button primary" href="/onboarding">
        Continuă către spațiul de lucru
      </a>
      <p className="hint">
        Portalul nu stochează parole și nu emite tokenuri proprii. Drepturile de acces rămân
        verificate la fiecare cerere, pentru fiecare organizație.
      </p>
    </section>
  );
}
