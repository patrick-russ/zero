import { describe, expect, it } from 'vitest'
import { isWildcardDomain, matchesWildcard, validateDomain, wildcardFor } from './domains.ts'

describe('wildcard domains', () => {
  it('recognizes a wildcard domain', () => {
    expect(isWildcardDomain('*.example.com')).toBe(true)
    expect(isWildcardDomain('example.com')).toBe(false)
  })

  it('derives the wildcard a host would match', () => {
    expect(wildcardFor('a.example.com')).toBe('*.example.com')
    expect(wildcardFor('a.b.example.com')).toBe('*.b.example.com')
    expect(wildcardFor('localhost')).toBeNull()
  })

  it('matches exactly one extra label', () => {
    expect(matchesWildcard('a.example.com', '*.example.com')).toBe(true)
    expect(matchesWildcard('example.com', '*.example.com')).toBe(false)
    expect(matchesWildcard('a.b.example.com', '*.example.com')).toBe(false)
    expect(matchesWildcard('a.example.org', '*.example.com')).toBe(false)
    expect(matchesWildcard('a.example.com', 'a.example.com')).toBe(false)
  })

  it('accepts regular domains and well-formed wildcards', () => {
    expect(() => validateDomain('example.com')).not.toThrow()
    expect(() => validateDomain('*.example.com')).not.toThrow()
    expect(() => validateDomain('*.apps.example.com')).not.toThrow()
  })

  it('rejects malformed wildcards', () => {
    for (const domain of ['*', '*.com', 'a.*.example.com', '*example.com', '*.*.example.com', 'app.example.*']) {
      expect(() => validateDomain(domain)).toThrow('Invalid wildcard domain')
    }
  })
})
