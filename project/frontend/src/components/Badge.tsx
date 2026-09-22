import type { ReactNode } from 'react';

export type BadgeColor = 'red' | 'orange' | 'emerald' | 'violet' | 'blue' | 'neutral';

const COLOR_CLASSES: Record<BadgeColor, string> = {
  red: 'bg-red-500/[.14] text-red-400',
  orange: 'bg-amber-500/[.14] text-amber-400',
  emerald: 'bg-emerald-500/[.14] text-emerald-400',
  violet: 'bg-violet-500/[.14] text-violet-400',
  blue: 'bg-blue-500/[.14] text-blue-400',
  neutral: 'bg-neutral-500/[.14] text-neutral-400'
};

export const SEVERITY_BADGE_COLOR: Record<string, BadgeColor> = {
  high: 'red',
  medium: 'orange',
  low: 'emerald'
};

export default function Badge({ color = 'neutral', children }: { color?: BadgeColor; children: ReactNode }) {
  return (
    <span
      className={`inline-flex h-5 items-center rounded-[5px] px-[7px] font-mono text-[10.5px] font-semibold uppercase tracking-wide ${COLOR_CLASSES[color]}`}
    >
      {children}
    </span>
  );
}
