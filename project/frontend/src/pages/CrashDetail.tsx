import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import AssetChips from '../components/AssetChips';
import Badge, { SEVERITY_BADGE_COLOR } from '../components/Badge';
import { ApiError, getCrash, getSimilar } from '../api/client';
import type { CrashDetail as CrashDetailType, RagResult } from '../api/types';

export default function CrashDetail() {
  const { id } = useParams<{ id: string }>();
  const [crash, setCrash] = useState<CrashDetailType | null>(null);
  const [similar, setSimilar] = useState<RagResult[] | null>(null);
  const [similarLoading, setSimilarLoading] = useState(false);
  const [similarError, setSimilarError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshSimilar = useCallback(() => {
    if (!id) return;
    setSimilarLoading(true);
    setSimilarError(null);
    getSimilar(Number(id))
      .then(res => setSimilar(res.results))
      .catch(() => setSimilarError('유사 취약점을 다시 불러오지 못했습니다.'))
      .finally(() => setSimilarLoading(false));
  }, [id]);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    setError(null);
    setSimilar(null);
    getCrash(Number(id))
      .then(result => {
        setCrash(result);
        return getSimilar(Number(id)).then(res => setSimilar(res.results));
      })
      .catch(err => {
        setError(
          err instanceof ApiError && err.status === 404
            ? '해당 크래시를 찾을 수 없습니다.'
            : '크래시 정보를 불러오지 못했습니다.'
        );
      })
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <p className="text-sm text-[#71717a]">불러오는 중...</p>;
  if (error || !crash) return <p className="text-sm text-red-400">{error ?? '크래시를 찾을 수 없습니다.'}</p>;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2 text-xs text-[#52525b]">
        <Link to="/" className="hover:text-neutral-300">
          대시보드
        </Link>
        <span>/</span>
        <span className="font-mono">#{crash.id}</span>
      </div>

      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#1f1f23] pb-6">
        <div>
          <div className="mb-2 flex items-center gap-2">
            <Badge color={SEVERITY_BADGE_COLOR[crash.severity ?? ''] ?? 'neutral'}>{crash.severity ?? '-'}</Badge>
            <span className="font-mono text-[11px] text-[#71717a]">
              {crash.source} · {crash.first_seen ? new Date(crash.first_seen).toLocaleDateString('ko-KR') : '-'}
            </span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-neutral-50">
            {crash.bug_type ?? '분석 대기'}
          </h1>
          {crash.summary && <p className="mt-1 text-sm text-[#a1a1aa]">{crash.summary}</p>}
        </div>
        <button
          type="button"
          onClick={refreshSimilar}
          disabled={similarLoading}
          className="rounded-lg bg-neutral-50 px-4 py-2 text-sm font-semibold text-neutral-900 transition-colors hover:bg-neutral-300 disabled:opacity-50"
        >
          {similarLoading ? '재검색 중...' : '유사 취약점 재검색'}
        </button>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_360px]">
        <div className="flex flex-col gap-3">
          <h2 className="text-sm font-semibold text-neutral-300">크래시 로그</h2>
          <pre className="max-h-[600px] overflow-auto whitespace-pre-wrap rounded-xl border border-[#232327] bg-[#101012] p-4 font-mono text-[11px] leading-relaxed text-[#a1a1aa]">
            {crash.raw_log}
          </pre>
        </div>

        <div className="flex flex-col gap-6 lg:sticky lg:top-6 lg:self-start">
          <div>
            <div className="mb-2 flex items-baseline justify-between">
              <h2 className="text-sm font-semibold text-neutral-300">재현 자산</h2>
            </div>
            {crash.vmlinux_url || crash.disk_image_url || crash.kernel_image_url ? (
              <div className="flex flex-col gap-2">
                <AssetChips crash={crash} />
                <p className="mt-1 text-[10.5px] leading-relaxed text-[#52525b]">
                  Google 공개 버킷에서 새 탭으로 열립니다. 크기는 추정치이며 실제 파일 크기와 다를 수 있습니다.
                </p>
              </div>
            ) : (
              <p className="text-xs text-[#52525b]">이 크래시에는 syzbot이 생성한 재현 자산이 없습니다.</p>
            )}
          </div>

          <div>
            <h2 className="mb-2 text-sm font-semibold text-neutral-300">유사 CVE / PoC</h2>
            {similar === null && !similarError && <p className="text-xs text-[#52525b]">불러오는 중...</p>}
            {similarError && <p className="text-xs text-red-400">{similarError}</p>}
            {similar !== null && similar.length === 0 && !similarError && (
              <p className="text-xs text-[#52525b]">
                {crash.status === '분석 완료' ? '유사한 CVE/PoC를 찾지 못했습니다.' : '아직 분석이 완료되지 않았습니다.'}
              </p>
            )}
            <div className={`flex flex-col gap-2 transition-opacity ${similarLoading ? 'opacity-50' : ''}`}>
              {similar?.map((result, index) => (
                <div key={index} className="rounded-lg border border-[#232327] bg-[#101012] p-3">
                  <Badge color={result.type === 'cve' ? 'blue' : 'violet'}>{result.type}</Badge>
                  {result.type === 'cve' ? (
                    <>
                      <p className="mt-1 font-mono text-sm font-semibold text-neutral-200">{result.cve_id}</p>
                      <p className="mt-0.5 line-clamp-2 text-xs text-[#71717a]">{result.description}</p>
                    </>
                  ) : (
                    <>
                      <p className="mt-1 break-all font-mono text-sm font-semibold text-neutral-200">{result.repo_url}</p>
                      <p className="mt-0.5 text-xs text-[#71717a]">{result.cve_ref}</p>
                    </>
                  )}
                  <p className="mt-1.5 text-[11px] text-emerald-400">
                    유사도 {Math.max(0, (1 - result.distance) * 100).toFixed(1)}%
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
