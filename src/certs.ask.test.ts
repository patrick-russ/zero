import { afterEach, describe, expect, it, vi } from 'vitest'

// ON_DEMAND_TLS_ASK is read once at startup, so this module gets its own import with the URL set.
process.env.NODE_ENV = 'production'
process.env.EMAIL = 'test@example.com'
process.env.ON_DEMAND_TLS_ASK = 'https://tenants.example.com/allow'

const certs = await import('./certs.ts')

describe('askOnDemand with ON_DEMAND_TLS_ASK', () => {
  afterEach(() => vi.unstubAllGlobals())

  function reply(status: number) {
    const cancel = vi.fn().mockResolvedValue(undefined)
    const fetch = vi.fn().mockResolvedValue({ ok: status >= 200 && status < 300, status, body: { cancel } })
    vi.stubGlobal('fetch', fetch)
    return { fetch, cancel }
  }

  it('asks with the host as ?domain= and approves on 2xx', async () => {
    const { fetch, cancel } = reply(204)
    await expect(certs.askOnDemand('club1.example.com')).resolves.toBe('approved')
    expect(String(fetch.mock.calls[0]![0])).toBe('https://tenants.example.com/allow?domain=club1.example.com')
    expect(cancel).toHaveBeenCalled()
  })

  it('denies on 4xx', async () => {
    const { cancel } = reply(404)
    await expect(certs.askOnDemand('random.example.com')).resolves.toBe('denied')
    expect(cancel).toHaveBeenCalled()
  })

  it('throws when the endpoint cannot decide (5xx or network error)', async () => {
    reply(503)
    await expect(certs.askOnDemand('club1.example.com')).rejects.toThrow('answered 503')
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')))
    await expect(certs.askOnDemand('club1.example.com')).rejects.toThrow('ECONNREFUSED')
  })
})
