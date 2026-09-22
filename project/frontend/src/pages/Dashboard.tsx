import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import AnimatedList from '../components/AnimatedList';
import AssetChips from '../components/AssetChips';
import Badge, { SEVERITY_BADGE_COLOR } from '../components/Badge';
import { ApiError, getStats, listCrashes, subscribeCrashEvents } from '../api/client';
import type { Crash, CrashEvent, Stats } from '../api/types';

const PAGE_SIZE = 20;
const SEVERITY_OPTIONS = ['', 'high', 'medium', 'low'] as const;
const PATCH_FILTER_OPTIONS = ['', 'fixed', 'unfixed', 'unknown'] as const;
const ASSET_FILTER_OPTIONS = [
  { value: '', label: '전체' },
  { value: 'true', label: '자산 있음' }
] as const;

const PATCH_COLOR: Record<string, string> = {
  fixed: 'text-emerald-400',
  unfixed: 'text-red-400',
  unknown: 'text-neutral-400'
};

function formatRelativeTime(iso: string | null): string {
  if (!iso) return '-';
  const diffMs = Date.now() - new Date(iso).getTime();
  const minutes = Math.floor(diffMs / 60000);
  if (minutes < 1) return '방금 전';
  if (minutes < 60) return `${minutes}분 전`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}시간 전`;
  return `${Math.floor(hours / 24)}일 전`;
}

function StatsBar({ stats }: { stats: Stats | null }) {
  const items = [
    { label: '수집된 크래시', value: stats ? String(stats.total_crashes) : '-' },
    {
      label: '재현 자산 보유',
      value: stats ? (
        <>
          {stats.crashes_with_assets}
          <span className="ml-1 text-sm font-normal text-[#52525b]">/ {stats.total_crashes}</span>
        </>
      ) : (
        '-'
      )
    },
    { label: '임베딩된 CVE', value: stats ? stats.embedded_cve_count.toLocaleString() : '-' },
    { label: '마지막 수집', value: stats ? formatRelativeTime(stats.last_collected_at) : '-' }
  ];

  return (
    <div className="flex divide-x divide-[#1f1f23] rounded-xl border border-[#1f1f23] bg-[#0b0b0c]">
      {items.map(item => (
        <div key={item.label} className="flex-1 px-5 py-3">
          <div className="text-[10.5px] uppercase tracking-wide text-[#71717a]">{item.label}</div>
          <div className="mt-1.5 text-xl font-semibold text-neutral-50">{item.value}</div>
        </div>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [crashes, setCrashes] = useState<Crash[]>([]);
  const [severity, setSeverity] = useState('');
  const [assetFilter, setAssetFilter] = useState('');
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [liveFeed, setLiveFeed] = useState<CrashEvent[]>([]);
  const [patchFilter, setPatchFilter] = useState('');
  const [stats, setStats] = useState<Stats | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    listCrashes({
      severity: severity || undefined,
      hasAssets: assetFilter ? true : undefined,
      limit: PAGE_SIZE,
      offset
    })
      .then(setCrashes)
      .catch(err =>
        setError(err instanceof ApiError ? err.message : '크래시 목록을 불러오지 못했습니다.')
      )
      .finally(() => setLoading(false));
  }, [severity, assetFilter, offset]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    getStats().catch(() => setStats(null)).then(result => {
      if (result) setStats(result);
    });
  }, []);

  useEffect(() => {
    const unsubscribe = subscribeCrashEvents(event => {
      setLiveFeed(prev => [event, ...prev].slice(0, 10));
    });
    return unsubscribe;
  }, []);

  const goToDetailSearch = (query: string) => {
    const trimmed = query.trim();
    if (!trimmed) return;
    navigate(`/search?q=${encodeURIComponent(trimmed)}`);
  };

  const filteredLiveFeed = patchFilter
    ? liveFeed.filter(event => event.patch_status === patchFilter)
    : liveFeed;

  return (
    <div className="flex flex-col gap-10">
      <h1 className="text-4xl font-bold tracking-tight text-neutral-50">커널 크래시 대시보드</h1>

      <StatsBar stats={stats} />

      <section>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-semibold text-neutral-300">
            실시간 피드{liveFeed.length > 0 && <span className="ml-2 text-emerald-400">({liveFeed.length})</span>}
          </h2>
          <div className="ml-2 flex gap-2">
            {PATCH_FILTER_OPTIONS.map(option => (
              <button
                key={option || 'all'}
                type="button"
                onClick={() => setPatchFilter(option)}
                className={`rounded-md border px-2 py-0.5 text-xs transition-colors ${
                  patchFilter === option
                    ? 'border-emerald-500 bg-emerald-600/20 text-emerald-400'
                    : 'border-[#2e2e33] text-[#71717a] hover:text-neutral-200'
                }`}
              >
                {option || '전체'}
              </button>
            ))}
          </div>
        </div>
        {filteredLiveFeed.length === 0 ? (
          <p className="text-sm text-[#71717a]">
            {liveFeed.length === 0
              ? '아직 새로 들어온 크래시가 없습니다.'
              : '이 패치 상태에 해당하는 항목이 없습니다.'}
          </p>
        ) : (
          <AnimatedList
            items={filteredLiveFeed.map(event => (
              <div key={`${event.crash_id}-${event.summary ?? ''}`} className="text-sm">
                <span className="font-mono text-emerald-400">#{event.crash_id}</span>{' '}
                <Badge color={SEVERITY_BADGE_COLOR[event.severity ?? ''] ?? 'neutral'}>
                  {event.bug_type ?? 'unknown'}
                </Badge>{' '}
                <span className="text-[#a1a1aa]">{event.summary}</span>{' '}
                <span className={`text-xs ${PATCH_COLOR[event.patch_status] ?? 'text-neutral-400'}`}>
                  [{event.patch_status}]
                </span>
              </div>
            ))}
            onItemSelect={(_, index) => {
              const event = filteredLiveFeed[index];
              if (event) goToDetailSearch(event.summary ?? event.bug_type ?? '');
            }}
            showGradients={false}
            enableArrowNavigation={false}
            displayScrollbar={false}
          />
        )}
      </section>

      <section>
        <div className="mb-4 flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-[#71717a]">심각도</span>
            {SEVERITY_OPTIONS.map(option => (
              <button
                key={option || 'all'}
                type="button"
                onClick={() => {
                  setOffset(0);
                  setSeverity(option);
                }}
                className={`rounded-md border px-3 py-1 text-sm transition-colors ${
                  severity === option
                    ? 'border-emerald-500 bg-emerald-600/20 text-emerald-400'
                    : 'border-[#2e2e33] text-[#71717a] hover:text-neutral-200'
                }`}
              >
                {option || '전체'}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 rounded-lg border border-[#26262a] bg-[#141417] p-1">
            {ASSET_FILTER_OPTIONS.map(option => (
              <button
                key={option.value || 'all'}
                type="button"
                onClick={() => {
                  setOffset(0);
                  setAssetFilter(option.value);
                }}
                className={`rounded-md px-3 py-1 text-sm transition-colors ${
                  assetFilter === option.value
                    ? 'bg-[#26262a] text-neutral-50'
                    : 'text-[#71717a] hover:text-neutral-300'
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>

        {loading && <p className="text-sm text-[#71717a]">불러오는 중...</p>}
        {error && <p className="text-sm text-red-400">{error}</p>}
        {!loading && !error && crashes.length === 0 && (
          <p className="text-sm text-[#71717a]">표시할 크래시가 없습니다.</p>
        )}

        <div className="flex flex-col gap-2">
          {crashes.map(crash => (
            <div
              key={crash.id}
              onClick={() => navigate(`/crashes/${crash.id}`)}
              className="cursor-pointer rounded-xl border border-[#232327] bg-[#111113] px-[18px] py-4 transition-colors hover:border-[#3f3f46] hover:bg-[#141417]"
            >
              <div className="flex flex-wrap items-center gap-2">
                <Badge color={SEVERITY_BADGE_COLOR[crash.severity ?? ''] ?? 'neutral'}>
                  {crash.severity ?? '-'}
                </Badge>
                <span className="font-mono text-[10.5px] text-[#71717a]">
                  #{crash.id} · {crash.source}
                </span>
                <span className="ml-auto font-mono text-[10.5px] text-[#52525b]">
                  {crash.first_seen ? new Date(crash.first_seen).toLocaleDateString('ko-KR') : '-'}
                </span>
              </div>
              <p className="mt-2 font-semibold tracking-tight text-neutral-50">
                {crash.bug_type ?? '분석 대기'}
              </p>
              <div className="mt-1 flex flex-wrap items-center gap-3 text-xs">
                <span className="text-[#a1a1aa]">{crash.summary}</span>
                <span className="text-[#52525b]">{crash.status}</span>
                <span className={PATCH_COLOR[crash.patch_status] ?? 'text-neutral-400'}>
                  {crash.patch_status}
                </span>
                <button
                  type="button"
                  onClick={e => {
                    e.stopPropagation();
                    goToDetailSearch(crash.summary ?? crash.bug_type ?? '');
                  }}
                  className="text-emerald-500 underline"
                >
                  RAG로 상세 검색 →
                </button>
              </div>
              <div className="mt-3">
                <AssetChips crash={crash} />
              </div>
            </div>
          ))}
        </div>

        <div className="mt-6 flex gap-3">
          <button
            type="button"
            disabled={offset === 0}
            onClick={() => setOffset(prev => Math.max(0, prev - PAGE_SIZE))}
            className="rounded-md border border-[#2e2e33] px-3 py-1 text-sm text-neutral-300 disabled:opacity-40"
          >
            이전
          </button>
          <button
            type="button"
            disabled={crashes.length < PAGE_SIZE}
            onClick={() => setOffset(prev => prev + PAGE_SIZE)}
            className="rounded-md border border-[#2e2e33] px-3 py-1 text-sm text-neutral-300 disabled:opacity-40"
          >
            다음
          </button>
        </div>
      </section>
    </div>
  );
}
