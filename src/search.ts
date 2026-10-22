import { newRequestId, toolError, type Status, type ToolError } from "./result.js";

export interface SearchHit {
  title: string;
  url: string;
  snippet?: string;
  source: Record<string, string>;
}

/**
 * A search provider. Providers are registered only from startup configuration
 * after an egress/retention/licence/cost review; tool input can never add one.
 */
export interface SearchProvider {
  id: string;
  version: string;
  search(query: string, limit: number): Promise<SearchHit[]>;
}

export interface SearchResult {
  status: Status;
  request_id: string;
  provider: string | null;
  provider_version: string | null;
  retrieved_at: string;
  results: SearchHit[];
  warnings: string[];
  error?: ToolError;
}

const PROTECTED_DATA = [
  /\b\d{3}-\d{2}-\d{4}\b/, // SSN-like
  // Requires an actual numeric identifier, so research about record systems still passes.
  /\b(mrn|medical record(?: number| no\.?)?|patient id)\b[\s:#.=-]*[a-z]{0,4}-?\d{3,}/i,
  /\b(api[_-]?key|password|passwd|secret|bearer)\s*[:=]\s*\S+/i,
  /\bsk-[A-Za-z0-9]{16,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b/,
];

export class ProviderRegistry {
  private readonly providers: ReadonlyMap<string, SearchProvider>;

  constructor(providers: SearchProvider[] = [], private readonly defaultLimit = 5) {
    this.providers = new Map(providers.map((p) => [p.id, p]));
  }

  get enabledIds(): string[] {
    return [...this.providers.keys()];
  }

  async search(query: string, limit: number | undefined, providerId: string | undefined): Promise<SearchResult> {
    const request_id = newRequestId();
    const out = (status: Status, code: string, message: string, provider: SearchProvider | null = null): SearchResult => ({
      status,
      request_id,
      provider: provider?.id ?? null,
      provider_version: provider?.version ?? null,
      retrieved_at: new Date().toISOString(),
      results: [],
      warnings: [],
      error: toolError(status, code, message),
    });

    if (PROTECTED_DATA.some((re) => re.test(query))) {
      return out("policy_denied", "protected_data_in_query", "Query appears to contain credentials or protected record identifiers");
    }
    if (providerId !== undefined && !this.providers.has(providerId)) {
      return out("invalid_input", "unknown_provider", "Provider is not in the enabled allowlist");
    }
    const provider = providerId !== undefined ? this.providers.get(providerId)! : this.providers.values().next().value;
    if (!provider) {
      return out("provider_unavailable", "no_provider_enabled", "No search provider is enabled; providers require an egress and retention review before activation");
    }
    try {
      const hits = await provider.search(query, limit ?? this.defaultLimit);
      return {
        status: "success",
        request_id,
        provider: provider.id,
        provider_version: provider.version,
        retrieved_at: new Date().toISOString(),
        results: hits.slice(0, limit ?? this.defaultLimit),
        warnings: ["snippets_are_unverified_leads"],
      };
    } catch {
      // Never fall back to a different provider.
      return out("provider_unavailable", "provider_failed", "Search provider request failed", provider);
    }
  }
}
