import { useEffect, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import Badge from '../components/Badge';
import SpotlightCard from '../components/SpotlightCard';
import { ApiError, ragQuery } from '../api/client';
import type { RagResult } from '../api/types';

const MAX_QUERY_LENGTH = 2000;

export default function Search() {
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<RagResult[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runSearch = async (rawQuery: string) => {
    const trimmed = rawQuery.trim();
    if (!trimmed) {
      setError('검색어를 입력해주세요.');
      return;
    }
    if (trimmed.length > MAX_QUERY_LENGTH) {
      setError(`검색어는 ${MAX_QUERY_LENGTH}자를 넘을 수 없습니다.`);
      return;
    }

    setLoading(true);
    setError(null);
    setResults(null);
    try {
      const response = await ragQuery(trimmed);
      setResults(response.results);
    } catch (err) {
      if (err instanceof ApiError && err.status === 503) {
        setError('임베딩 서비스에 연결할 수 없습니다. 잠시 후 다시 시도해주세요.');
      } else if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('알 수 없는 오류가 발생했습니다.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const initialQuery = searchParams.get('q');
    if (initialQuery) {
      setQuery(initialQuery);
      runSearch(initialQuery);
    }
    // 마운트 시 URL의 ?q=만 한 번 반영하면 되므로 의도적으로 빈 deps 배열을 쓴다 —
    // 이후 폼 제출은 handleSubmit이 처리하며, searchParams가 바뀌어도 재실행하지 않는다.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    runSearch(query);
  };

  return (
    <div className="flex flex-col gap-8">
      <h1 className="text-4xl font-bold tracking-tight text-neutral-50">RAG 검색</h1>

      <form onSubmit={handleSubmit} className="flex gap-3">
        <input
          type="text"
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="예: ext4 use-after-free 관련 CVE"
          maxLength={MAX_QUERY_LENGTH}
          className="flex-1 rounded-lg border border-[#26262a] bg-[#141417] px-3 py-2 text-sm text-neutral-100 placeholder:text-[#52525b] focus:border-[#3f3f46] focus:outline-none"
        />
        <button
          type="submit"
          disabled={loading}
          className="rounded-lg bg-neutral-50 px-4 py-2 text-sm font-semibold text-neutral-900 transition-colors hover:bg-neutral-300 disabled:opacity-50"
        >
          {loading ? '검색 중...' : '검색'}
        </button>
      </form>

      {error && <p className="text-sm text-red-400">{error}</p>}

      {results !== null && results.length === 0 && !error && (
        <p className="text-sm text-[#71717a]">일치하는 결과가 없습니다.</p>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {results?.map((result, index) => (
          <SpotlightCard key={index} spotlightColor="rgba(16, 185, 129, 0.2)">
            <Badge color={result.type === 'cve' ? 'blue' : 'violet'}>{result.type}</Badge>
            {result.type === 'cve' ? (
              <>
                <p className="mt-2 font-mono text-sm font-semibold text-neutral-50">{result.cve_id}</p>
                <p className="mt-1 text-sm text-[#a1a1aa]">{result.description}</p>
              </>
            ) : (
              <>
                <p className="mt-2 break-all font-mono text-sm font-semibold text-neutral-50">{result.repo_url}</p>
                <p className="mt-1 text-sm text-[#a1a1aa]">{result.cve_ref}</p>
              </>
            )}
            <p className="mt-3 text-xs text-emerald-400">
              유사도 {Math.max(0, (1 - result.distance) * 100).toFixed(1)}%
            </p>
          </SpotlightCard>
        ))}
      </div>
    </div>
  );
}
