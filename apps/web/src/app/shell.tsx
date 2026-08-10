"use client";

import { useState, type ReactNode } from "react";
import { usePathname } from "next/navigation";

import { useLocalization } from "../lib/i18n/provider";
import LanguageSwitcher from "./language-switcher";

import type { MessageKey } from "../lib/i18n";

type NavItem = { href: string; labelKey: MessageKey; icon: ReactNode };

function Icon({ path }: { path: string }) {
  return (
    <svg
      className="nav-icon"
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={path} />
    </svg>
  );
}

const OVERVIEW = "M3 10.5 10 4l7 6.5M5.5 9.5V16h9V9.5";
const DOMAINS = "M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14ZM3 10h14M10 3c2 2.3 2 11.7 0 14";
const TEAM = "M7 9a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Zm6.5 0a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM3 16v-1a4 4 0 0 1 8 0v1m2-4.5a4 4 0 0 1 4 4V16";
const AUDIT = "M6 3h8l2 2v12H4V5l2-2Zm1 6h6M7 12h6M7 15h4";
const ASSESSMENTS = "M4 16V8m4 8V5m4 11v-6m4 6V9M3 17h14";
const MATURITY = "M6 3h8l2 2v12H4V5l2-2Zm1 5.5 1.5 1.5L12 6.5M7 13h6";

/**
 * The shell is hidden on unauthenticated routes: a visitor who is not signed in has
 * nothing to navigate to, and showing a workspace nav would misrepresent their access.
 */
const PUBLIC_ROUTES = new Set(["/", "/sign-in"]);

/**
 * The observatory is readable by anybody, so it gets no workspace chrome either. Matched
 * as a prefix rather than an exact path because a profile page carries a domain name.
 */
const PUBLIC_PREFIXES = ["/observatory"];

function isPublicRoute(pathname: string): boolean {
  return (
    PUBLIC_ROUTES.has(pathname) ||
    PUBLIC_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`))
  );
}

function navItems(organizationId: string | null): NavItem[] {
  if (!organizationId) return [];
  const base = `/organizations/${organizationId}`;
  return [
    { href: "/onboarding", labelKey: "nav.overview", icon: <Icon path={OVERVIEW} /> },
    { href: `${base}/domains`, labelKey: "nav.domains", icon: <Icon path={DOMAINS} /> },
    { href: `${base}/assessments`, labelKey: "nav.assessments", icon: <Icon path={ASSESSMENTS} /> },
    { href: `${base}/maturity`, labelKey: "nav.maturity", icon: <Icon path={MATURITY} /> },
    { href: `${base}/team`, labelKey: "nav.team", icon: <Icon path={TEAM} /> },
    { href: `${base}/audit`, labelKey: "nav.audit", icon: <Icon path={AUDIT} /> },
  ];
}

function organizationFromPath(pathname: string): string | null {
  const match = /^\/organizations\/([0-9a-f-]{36})(\/|$)/.exec(pathname);
  return match ? match[1] : null;
}

export default function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname() ?? "/";
  const { t } = useLocalization();
  const [collapsed, setCollapsed] = useState(false);
  const [open, setOpen] = useState(false);

  const isPublic = isPublicRoute(pathname);
  const organizationId = organizationFromPath(pathname);
  const items = navItems(organizationId);
  const current = items.find((item) => pathname.startsWith(item.href));

  if (isPublic) {
    return (
      <div className="app-shell" data-chrome="none">
        <div>
          <header className="top-bar">
            <span className="brand-mark" aria-hidden="true">
              S
            </span>
            <span className="top-bar-title">SIEMBIOT Cyber Health Portal</span>
            <span className="top-bar-spacer" />
            <LanguageSwitcher />
            <span className="environment">{t("app.privatePortal")}</span>
          </header>
          <main id="main">
            <div className="content">{children}</div>
          </main>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell" data-collapsed={collapsed} data-open={open}>
      <nav className="sidebar" aria-label={t("app.workspace")}>
        <a className="brand" href="/onboarding">
          <span className="brand-mark" aria-hidden="true">
            S
          </span>
          <span className="brand-name">SIEMBIOT</span>
        </a>

        <p className="nav-group-label">{t("app.workspace")}</p>
        {items.length > 0 ? (
          items.map((item) => (
            <a
              key={item.href}
              className="nav-link"
              href={item.href}
              aria-current={item === current ? "page" : undefined}
            >
              {item.icon}
              <span className="nav-label">{t(item.labelKey)}</span>
            </a>
          ))
        ) : (
          <p className="nav-empty nav-label">{t("nav.empty")}</p>
        )}

        <div className="sidebar-footer">
          <button
            type="button"
            className="nav-link"
            onClick={() => setCollapsed((value) => !value)}
            aria-expanded={!collapsed}
          >
            <Icon path={collapsed ? "M7 4l6 6-6 6" : "M13 4l-6 6 6 6"} />
            <span className="nav-label">
              {collapsed ? t("app.expandMenu") : t("app.collapseMenu")}
            </span>
          </button>
        </div>
      </nav>

      <div>
        <header className="top-bar">
          <button
            type="button"
            className="icon-button"
            onClick={() => setOpen((value) => !value)}
            aria-expanded={open}
            aria-controls="main"
          >
            <Icon path="M3 6h14M3 10h14M3 14h14" />
            <span className="sr-only">{t("app.toggleNavigation")}</span>
          </button>
          <span className="top-bar-title">{current ? t(current.labelKey) : t("app.workspace")}</span>
          <span className="top-bar-spacer" />
          <LanguageSwitcher />
          <span className="environment">{t("app.privatePortal")}</span>
        </header>
        <main id="main">
          <div className="content">{children}</div>
        </main>
      </div>
    </div>
  );
}
