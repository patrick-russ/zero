import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import tls from 'node:tls'
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AskVerdict } from './certs.ts'

const tmpDir = path.join(os.tmpdir(), `zero-test-certs-${process.pid}`)
process.env.NODE_ENV = 'production'
process.env.EMAIL = 'test@example.com'
process.env.DOMAIN = 'example.com'
process.env.CERTS_PATH = tmpDir
process.env.CERT_RENEW_BEFORE_DAYS = '30'

const fixtureCert = fs.readFileSync('node_modules/ssh2/test/fixtures/https_cert.pem', 'utf8')

const certs = await import('./certs.ts')
const dummyContext = tls.createSecureContext()

function writeCert(domain: string, pem = fixtureCert) {
  fs.mkdirSync(tmpDir, { recursive: true })
  fs.writeFileSync(path.join(tmpDir, `${domain}.crt`), pem)
}

describe('cert renewal', () => {
  beforeEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
    vi.restoreAllMocks()
  })

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  it('includes the host domain alongside app domains', () => {
    const apps = [{ domains: ['app1.example.com'] }, { domains: ['app2.example.com'] }]
    expect(certs.managedDomains(apps, 'c1.example.com')).toEqual([
      'c1.example.com',
      'app1.example.com',
      'app2.example.com'
    ])
  })

  it('omits the host domain when none is configured (IP-only install)', () => {
    const apps = [{ domains: ['app1.example.com'] }]
    expect(certs.managedDomains(apps, '')).toEqual(['app1.example.com'])
  })

  it('skips domains whose cert is not close to expiry', async () => {
    writeCert('stable.example.com')

    const renew = vi.fn().mockResolvedValue(dummyContext)
    const renewed = await certs.renewExpiringCerts(['stable.example.com'], renew)

    expect(renewed).toEqual([])
    expect(renew).not.toHaveBeenCalled()
  })

  it('renews domains whose cert expires within the configured window', async () => {
    writeCert('renew.example.com')

    const now = new Date('2030-12-01T00:00:00Z').getTime()
    const renew = vi.fn().mockResolvedValue(dummyContext)
    const renewed = await certs.renewExpiringCerts(['renew.example.com'], renew, now)

    expect(renewed).toEqual(['renew.example.com'])
    expect(renew).toHaveBeenCalledWith('renew.example.com')
  })
})

describe('on-demand certificates under a wildcard', () => {
  beforeEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
    certs.resetOnDemandState()
  })

  const allow = async (): Promise<AskVerdict> => 'approved'

  it('issues a certificate for an approved host', async () => {
    const issue = vi.fn().mockResolvedValue(dummyContext)
    await expect(certs.obtainOnDemandCert('a.example.com', issue, allow)).resolves.toBe(dummyContext)
    expect(issue).toHaveBeenCalledWith('a.example.com')
  })

  it('refuses a host the ask endpoint does not approve, and does not ask again for an hour', async () => {
    const issue = vi.fn().mockResolvedValue(dummyContext)
    const ask = vi.fn().mockResolvedValue('denied')
    const now = Date.now()
    await expect(certs.obtainOnDemandCert('evil.example.com', issue, ask, now)).rejects.toThrow('not approved')
    await expect(certs.obtainOnDemandCert('evil.example.com', issue, ask, now + 1000)).rejects.toThrow(
      'denied recently'
    )
    expect(ask).toHaveBeenCalledTimes(1)
    expect(issue).not.toHaveBeenCalled()
  })

  it('backs off for an hour after a failed issuance', async () => {
    const issue = vi.fn().mockRejectedValue(new Error('acme down'))
    const now = Date.now()
    await expect(certs.obtainOnDemandCert('b.example.com', issue, allow, now)).rejects.toThrow('acme down')
    await expect(certs.obtainOnDemandCert('b.example.com', issue, allow, now + 59 * 60 * 1000)).rejects.toThrow(
      'failed or was denied recently'
    )
    issue.mockResolvedValue(dummyContext)
    await expect(certs.obtainOnDemandCert('b.example.com', issue, allow, now + 61 * 60 * 1000)).resolves.toBe(
      dummyContext
    )
  })

  it('issues at most ON_DEMAND_TLS_PER_HOUR new certificates per hour', async () => {
    const issue = vi.fn().mockResolvedValue(dummyContext)
    const now = Date.now()
    for (let i = 0; i < 20; i++) await certs.obtainOnDemandCert(`h${i}.example.com`, issue, allow, now)
    await expect(certs.obtainOnDemandCert('h20.example.com', issue, allow, now)).rejects.toThrow('limit reached')
    await expect(certs.obtainOnDemandCert('h20.example.com', issue, allow, now + 60 * 60 * 1000)).resolves.toBe(
      dummyContext
    )
  })

  it('shares one issuance between concurrent handshakes for the same host', async () => {
    let finish: (ctx: tls.SecureContext) => void = () => {}
    const issue = vi.fn(() => new Promise<tls.SecureContext>((resolve) => (finish = resolve)))
    const ask = vi.fn(allow)
    const first = certs.obtainOnDemandCert('c.example.com', issue, ask)
    const second = certs.obtainOnDemandCert('c.example.com', issue, ask)
    await vi.waitFor(() => expect(issue).toHaveBeenCalledTimes(1))
    finish(dummyContext)
    await expect(Promise.all([first, second])).resolves.toEqual([dummyContext, dummyContext])
    expect(ask).toHaveBeenCalledTimes(1)
  })

  it('lists the hosts issued under a wildcard', () => {
    writeCert('a.example.com')
    writeCert('b.example.com')
    writeCert('deep.a.example.com')
    writeCert('other.org')
    // Preview labels are never covered by a wildcard (left over from a destroyed preview).
    writeCert('preview-pr-1.example.com')
    expect(certs.onDemandHosts('*.example.com').sort()).toEqual(['a.example.com', 'b.example.com'])
  })

  it('renews hosts issued under a wildcard while the ask endpoint still approves them', async () => {
    writeCert('keep.example.com')
    writeCert('drop.example.com')
    const now = new Date('2030-12-01T00:00:00Z').getTime()
    const renew = vi.fn().mockResolvedValue(dummyContext)
    const ask = vi.fn(
      async (host: string): Promise<AskVerdict> => (host === 'keep.example.com' ? 'approved' : 'denied')
    )

    const renewed = await certs.renewExpiringCerts(['example.com', '*.example.com'], renew, now, ask)

    expect(renewed).toEqual(['keep.example.com'])
    expect(renew).toHaveBeenCalledTimes(1)
    expect(renew).not.toHaveBeenCalledWith('*.example.com')
  })

  it('renews exact domains of other apps even if they sit below the wildcard and ask denies them', async () => {
    writeCert('api.example.com')
    writeCert('tenant.example.com')
    const now = new Date('2030-12-01T00:00:00Z').getTime()
    const renew = vi.fn().mockResolvedValue(dummyContext)
    const ask = vi.fn(async (): Promise<AskVerdict> => 'denied')

    const renewed = await certs.renewExpiringCerts(['api.example.com', '*.example.com'], renew, now, ask)

    expect(renewed).toEqual(['api.example.com'])
    expect(ask).toHaveBeenCalledTimes(1)
    expect(ask).toHaveBeenCalledWith('tenant.example.com')
  })

  it('skips a renewal for this run when the ask endpoint is unreachable', async () => {
    writeCert('flaky.example.com')
    const now = new Date('2030-12-01T00:00:00Z').getTime()
    const renew = vi.fn().mockResolvedValue(dummyContext)
    const ask = vi.fn().mockRejectedValue(new Error('timeout'))

    await expect(certs.renewExpiringCerts(['*.example.com'], renew, now, ask)).resolves.toEqual([])
    expect(renew).not.toHaveBeenCalled()
  })

  it('does not lock a host out for an hour when the ask endpoint is unreachable, only for a minute', async () => {
    const issue = vi.fn().mockResolvedValue(dummyContext)
    const ask = vi.fn().mockRejectedValueOnce(new Error('ECONNREFUSED')).mockResolvedValue('approved')
    const now = Date.now()
    await expect(certs.obtainOnDemandCert('new.example.com', issue, ask, now)).rejects.toThrow('ECONNREFUSED')
    await expect(certs.obtainOnDemandCert('new.example.com', issue, ask, now + 30 * 1000)).rejects.toThrow(
      'unreachable'
    )
    await expect(certs.obtainOnDemandCert('new.example.com', issue, ask, now + 61 * 1000)).resolves.toBe(dummyContext)
    expect(ask).toHaveBeenCalledTimes(2)
  })

  it('checks the hourly cap before asking, so a flood of names costs no ask calls', async () => {
    const issue = vi.fn().mockResolvedValue(dummyContext)
    const ask = vi.fn(allow)
    const now = Date.now()
    for (let i = 0; i < 20; i++) await certs.obtainOnDemandCert(`f${i}.example.com`, issue, ask, now)
    ask.mockClear()
    await expect(certs.obtainOnDemandCert('f20.example.com', issue, ask, now)).rejects.toThrow('limit reached')
    expect(ask).not.toHaveBeenCalled()
  })
})

describe('askOnDemand without ON_DEMAND_TLS_ASK', () => {
  it('approves everything', async () => {
    await expect(certs.askOnDemand('x.example.com')).resolves.toBe('approved')
  })
})
