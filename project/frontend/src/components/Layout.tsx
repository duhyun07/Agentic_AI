import type { ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import Threads from './Threads';

export default function Layout({ children }: { children: ReactNode }) {
  const location = useLocation();

  const linkClass = (path: string) =>
    `rounded-md px-3 py-1 text-[13px] font-medium transition-colors ${
      location.pathname === path ? 'bg-[#26262a] text-neutral-50' : 'text-neutral-500 hover:text-neutral-200'
    }`;

  return (
    <div className="relative min-h-screen bg-[#0b0b0c] text-neutral-100">
      <div className="fixed inset-0 -z-10 opacity-60">
        <Threads color={[0.4, 0.8, 0.6]} amplitude={1.2} distance={0} enableMouseInteraction />
      </div>
      <nav className="flex items-center gap-3 border-b border-[#1f1f23] bg-[#0b0b0c]/90 px-6 py-3 backdrop-blur">
        <div className="flex h-[22px] w-[22px] items-center justify-center rounded-md bg-violet-500 text-[11px] font-extrabold text-white">
          K
        </div>
        <span className="text-[13.5px] font-semibold tracking-tight text-neutral-50">Kernel Crash RAG</span>
        <span className="h-3.5 w-px bg-[#2e2e33]" />
        <div className="flex gap-1">
          <Link to="/" className={linkClass('/')}>
            대시보드
          </Link>
          <Link to="/search" className={linkClass('/search')}>
            RAG 검색
          </Link>
        </div>
      </nav>
      <main className="px-6 py-8">{children}</main>
    </div>
  );
}
