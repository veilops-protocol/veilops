'use client';
import { useState } from 'react';
import { SITE } from '@/lib/site';

/** The one official token contract address, with copy + pump.fun link. */
export function ContractAddress({ compact = false }: { compact?: boolean }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(SITE.ca); setCopied(true); setTimeout(() => setCopied(false), 1600); } catch { /* ignore */ }
  };
  return (
    <div className={`flex flex-wrap items-center gap-x-4 gap-y-2 font-mono ${compact ? 'text-[11px]' : 'text-[12px]'}`}>
      <span className="uppercase tracking-[0.16em] text-mute/70">CA</span>
      <button onClick={copy} className="min-w-0 break-all text-left text-paper/90 hover:text-paper" aria-label="Copy contract address" title="Copy">
        {SITE.ca}
      </button>
      <button onClick={copy} className="uppercase tracking-[0.14em] text-jade hover:text-paper">{copied ? 'Copied' : 'Copy'}</button>
      <a href={`https://pump.fun/coin/${SITE.ca}`} className="uppercase tracking-[0.14em] text-mute hover:text-paper" target="_blank" rel="noopener noreferrer">pump.fun ↗</a>
    </div>
  );
}
