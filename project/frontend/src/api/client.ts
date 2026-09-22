import type { Crash, CrashDetail, CrashEvent, RagQueryResponse, Stats } from './types';

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function parseErrorDetail(response: Response): Promise<string> {
  try {
    const body = await response.json();
    if (typeof body.detail === 'string') return body.detail;
    if (Array.isArray(body.detail)) {
      return body.detail
        .map((entry: { msg?: string }) => entry.msg ?? JSON.stringify(entry))
        .join(', ');
    }
    return response.statusText;
  } catch {
    return response.statusText;
  }
}

export interface ListCrashesParams {
  severity?: string;
  hasAssets?: boolean;
  limit?: number;
  offset?: number;
}

export async function listCrashes(params: ListCrashesParams = {}): Promise<Crash[]> {
  const search = new URLSearchParams();
  if (params.severity) search.set('severity', params.severity);
  if (params.hasAssets !== undefined) search.set('has_assets', String(params.hasAssets));
  if (params.limit !== undefined) search.set('limit', String(params.limit));
  if (params.offset !== undefined) search.set('offset', String(params.offset));

  const response = await fetch(`/api/crashes?${search.toString()}`);
  if (!response.ok) throw new ApiError(response.status, await parseErrorDetail(response));
  return (await response.json()) as Crash[];
}

export async function getCrash(id: number): Promise<CrashDetail> {
  const response = await fetch(`/api/crashes/${id}`);
  if (!response.ok) throw new ApiError(response.status, await parseErrorDetail(response));
  return (await response.json()) as CrashDetail;
}

export async function getSimilar(id: number, topK = 5): Promise<RagQueryResponse> {
  const response = await fetch(`/api/crashes/${id}/similar?top_k=${topK}`);
  if (!response.ok) throw new ApiError(response.status, await parseErrorDetail(response));
  return (await response.json()) as RagQueryResponse;
}

export async function getStats(): Promise<Stats> {
  const response = await fetch('/api/stats');
  if (!response.ok) throw new ApiError(response.status, await parseErrorDetail(response));
  return (await response.json()) as Stats;
}

export async function ragQuery(query: string, topK = 5): Promise<RagQueryResponse> {
  const response = await fetch('/api/rag/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, top_k: topK }),
  });
  if (!response.ok) throw new ApiError(response.status, await parseErrorDetail(response));
  return (await response.json()) as RagQueryResponse;
}

export function subscribeCrashEvents(onCrash: (event: CrashEvent) => void): () => void {
  const source = new EventSource('/events/crashes');

  const handleCrash = (event: MessageEvent<string>) => {
    onCrash(JSON.parse(event.data) as CrashEvent);
  };

  source.addEventListener('crash', handleCrash);

  return () => {
    source.removeEventListener('crash', handleCrash);
    source.close();
  };
}
