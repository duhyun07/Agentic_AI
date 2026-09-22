export interface Crash {
  id: number;
  source: string;
  bug_type: string | null;
  summary: string | null;
  severity: string | null;
  status: string;
  patch_status: string;
  first_seen: string | null;
  vmlinux_url: string | null;
  disk_image_url: string | null;
  kernel_image_url: string | null;
}

export interface CrashDetail extends Crash {
  raw_log: string;
}

export interface Stats {
  total_crashes: number;
  crashes_with_assets: number;
  embedded_cve_count: number;
  last_collected_at: string | null;
}

export interface RagResult {
  type: 'cve' | 'poc';
  cve_id?: string;
  description?: string;
  repo_url?: string;
  cve_ref?: string;
  distance: number;
}

export interface RagQueryResponse {
  results: RagResult[];
}

export interface CrashEvent {
  crash_id: number;
  bug_type: string | null;
  severity: string | null;
  summary: string | null;
  patch_status: string;
}
