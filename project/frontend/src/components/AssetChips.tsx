import type { ReactElement } from 'react';
import type { Crash } from '../api/types';

interface AssetDef {
  key: 'vmlinux' | 'disk_image' | 'kernel_image';
  label: string;
  sizeEstimate: string;
  color: string;
  icon: ReactElement;
}

const ASSET_DEFS: AssetDef[] = [
  {
    key: 'vmlinux',
    label: 'vmlinux',
    sizeEstimate: '~820MB',
    color: '#8b5cf6',
    icon: (
      <>
        <path d="M3 7l9-4 9 4v10l-9 4-9-4V7z" />
        <path d="M3 7l9 4 9-4" />
        <path d="M12 21V11" />
      </>
    ),
  },
  {
    key: 'disk_image',
    label: '디스크 이미지',
    sizeEstimate: '~1.1GB',
    color: '#3b82f6',
    icon: (
      <>
        <rect x="2.5" y="6" width="19" height="12" rx="2" />
        <circle cx="17" cy="12" r="1.4" />
        <path d="M6 12h6" />
      </>
    ),
  },
  {
    key: 'kernel_image',
    label: '커널 이미지',
    sizeEstimate: '~9MB',
    color: '#34d399',
    icon: (
      <>
        <rect x="7" y="7" width="10" height="10" rx="2" />
        <path d="M12 3v4M12 17v4M3 12h4M17 12h4" />
      </>
    ),
  },
];

function assetUrl(crash: Crash, key: AssetDef['key']): string | null {
  if (key === 'vmlinux') return crash.vmlinux_url;
  if (key === 'disk_image') return crash.disk_image_url;
  return crash.kernel_image_url;
}

export default function AssetChips({ crash }: { crash: Crash }) {
  const available = ASSET_DEFS.map(def => ({ def, url: assetUrl(crash, def.key) })).filter(
    (entry): entry is { def: AssetDef; url: string } => entry.url !== null
  );

  if (available.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-2" onClick={e => e.stopPropagation()}>
      {available.map(({ def, url }) => (
        <a
          key={def.key}
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          title={`${def.label} 다운로드 (용량 추정치, 실측 아님)`}
          className="inline-flex items-center gap-[7px] whitespace-nowrap rounded-lg border border-[#2e2e33] bg-[#18181b] px-[11px] py-0 text-xs font-medium text-[#e4e4e7] no-underline transition-colors hover:border-[#3f3f46] hover:bg-[#212126]"
          style={{ height: 32 }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={def.color} strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
            {def.icon}
          </svg>
          {def.label}
          <span className="font-mono text-[11px] text-[#71717a]">{def.sizeEstimate} 추정</span>
        </a>
      ))}
    </div>
  );
}
