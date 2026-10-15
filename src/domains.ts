/**
 * Wildcard domains (`*.example.com`) match exactly one extra label, like DNS wildcards and
 * wildcard certificates: `a.example.com` matches, `example.com` and `a.b.example.com` do not.
 */

const WILDCARD_PREFIX = '*.'

export function isWildcardDomain(domain: string): boolean {
  return domain.startsWith(WILDCARD_PREFIX)
}

/** The wildcard pattern a host would match, e.g. `a.example.com` → `*.example.com`; null for single-label hosts. */
export function wildcardFor(host: string): string | null {
  const dot = host.indexOf('.')
  if (dot <= 0 || dot === host.length - 1) return null
  return `${WILDCARD_PREFIX}${host.slice(dot + 1)}`
}

/** Whether `host` is covered by the wildcard `pattern`. */
export function matchesWildcard(host: string, pattern: string): boolean {
  return isWildcardDomain(pattern) && wildcardFor(host) === pattern
}

/**
 * Rejects malformed wildcards. Only a leading `*.` followed by at least two labels is allowed
 * (`*.example.com`); `*` anywhere else and bare `*.com` are refused.
 */
export function validateDomain(domain: string): void {
  if (!domain.includes('*')) return
  const rest = domain.slice(WILDCARD_PREFIX.length)
  if (!isWildcardDomain(domain) || rest.includes('*') || rest.split('.').filter(Boolean).length < 2) {
    throw new Error(`Invalid wildcard domain "${domain}": use the form *.example.com`)
  }
}
