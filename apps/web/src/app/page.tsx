export default function LoginPage() {
  return (
    <section className="hero" aria-labelledby="login-title">
      <p className="eyebrow">Securitate măsurabilă, acces controlat</p>
      <h1 id="login-title">Bine ai venit în SIEMBIOT</h1>
      <p>
        Autentificarea este realizată prin furnizorul OIDC configurat. Sesiunea rămâne pe server,
        iar browserul primește doar un cookie opac protejat.
      </p>
      <a className="button primary" href="/api/v1/auth/login?return_path=/onboarding">
        Autentifică-te în siguranță
      </a>
      <p className="hint">Nu stocăm tokenuri de acces sau reîmprospătare în browser.</p>
    </section>
  );
}
