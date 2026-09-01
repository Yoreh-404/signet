import { useState } from "react";

import type { QuickLink } from "../../types";

export function QuickJump({ links }: { links: QuickLink[] }) {
  if (links.length === 0) return null;
  return (
    <div className="quick-jump">
      {links.map((link) => <QuickJumpLink key={`${link.id}:${link.url}`} link={link} />)}
    </div>
  );
}

function QuickJumpLink({ link }: { link: QuickLink }) {
  const faviconUrl = quickLinkFaviconUrl(link.url);
  const [faviconState, setFaviconState] = useState<"loading" | "loaded" | "failed">(
    faviconUrl ? "loading" : "failed"
  );

  return (
    <a className="quick-jump-link" href={link.url} target="_blank" rel="noreferrer" title={link.label} aria-label={link.label}>
      <span className={`quick-jump-icon${faviconState === "loaded" ? " has-favicon" : ""}`} aria-hidden="true">
        <span className="quick-jump-fallback">{quickLinkInitial(link.label)}</span>
        {faviconUrl && (
          <img
            src={faviconUrl}
            alt=""
            referrerPolicy="no-referrer"
            onLoad={() => setFaviconState("loaded")}
            onError={() => setFaviconState("failed")}
          />
        )}
      </span>
    </a>
  );
}

function quickLinkFaviconUrl(url: string): string | null {
  try {
    const target = new URL(url);
    return new URL("/favicon.ico", target.origin).toString();
  } catch {
    return null;
  }
}

function quickLinkInitial(label: string): string {
  return Array.from(label.trim())[0]?.toLocaleUpperCase() ?? "?";
}
