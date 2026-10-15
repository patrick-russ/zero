import http from 'node:http'
import net from 'node:net'
import { describe, expect, it } from 'vitest'

// Don't load ACME module
process.env.EMAIL = ''
// Use port 0 so each startDevProxy gets a free port
process.env.DEV_PORT = '0'

import { vi } from 'vitest'

vi.mock('./certs.ts', () => ({
  getCachedCert: vi.fn().mockReturnValue(undefined),
  loadCachedCert: vi.fn().mockReturnValue(null),
  obtainCert: vi.fn().mockRejectedValue(new Error('No cert')),
  handleAcmeChallenge: vi.fn().mockReturnValue(false),
  isTLSEnabled: vi.fn().mockReturnValue(false)
}))

const { updateProxyRoute, removeProxyRoute, startDevProxy, restoreRoutes, resolveRoute, isOnDemandHost } = await import(
  './proxy.ts'
)

function makeRequest(port: number, host: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: '/',
        headers: { Host: host }
      },
      (res) => {
        let data = ''
        res.on('data', (chunk) => (data += chunk))
        res.on('end', () => resolve({ status: res.statusCode!, body: data }))
      }
    )
    req.on('error', reject)
    req.end()
  })
}

describe('proxy route management', () => {
  it('forwards HTTP traffic to the correct backend port', async () => {
    const upstream = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      res.end('hello from upstream')
    })
    await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve))
    const upstreamPort = (upstream.address() as net.AddressInfo).port

    const proxy = startDevProxy()
    await new Promise<void>((resolve) => {
      if (proxy.listening) return resolve()
      proxy.on('listening', resolve)
    })
    const proxyPort = (proxy.address() as net.AddressInfo).port

    updateProxyRoute('test.local', upstreamPort)

    const res = await makeRequest(proxyPort, 'test.local')
    expect(res.status).toBe(200)
    expect(res.body).toBe('hello from upstream')

    removeProxyRoute('test.local')
    proxy.close()
    upstream.close()
  })

  it('returns 502 when no route exists for host', async () => {
    const proxy = startDevProxy()
    await new Promise<void>((resolve) => {
      if (proxy.listening) return resolve()
      proxy.on('listening', resolve)
    })
    const proxyPort = (proxy.address() as net.AddressInfo).port

    const res = await makeRequest(proxyPort, 'unknown.local')
    expect(res.status).toBe(502)
    expect(res.body).toContain('Bad gateway')

    proxy.close()
  })

  it('restoreRoutes handles apps without previews field', () => {
    const apps = [{ domains: ['old.local'], deployments: [{ port: 3000 }], previews: undefined as any }]
    expect(() => restoreRoutes(apps)).not.toThrow()
  })

  it('removeProxyRoute stops forwarding', async () => {
    const upstream = http.createServer((_req, res) => {
      res.writeHead(200)
      res.end('ok')
    })
    await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve))
    const upstreamPort = (upstream.address() as net.AddressInfo).port

    const proxy = startDevProxy()
    await new Promise<void>((resolve) => {
      if (proxy.listening) return resolve()
      proxy.on('listening', resolve)
    })
    const proxyPort = (proxy.address() as net.AddressInfo).port

    updateProxyRoute('remove.local', upstreamPort)
    removeProxyRoute('remove.local')

    const res = await makeRequest(proxyPort, 'remove.local')
    expect(res.status).toBe(502)

    proxy.close()
    upstream.close()
  })
})

describe('wildcard routes', () => {
  it('routes a host covered by a wildcard, exactly one label deep', () => {
    updateProxyRoute('*.wild.local', 4100)
    expect(resolveRoute('a.wild.local')).toBe(4100)
    expect(resolveRoute('wild.local')).toBeUndefined()
    expect(resolveRoute('a.b.wild.local')).toBeUndefined()
    removeProxyRoute('*.wild.local')
    expect(resolveRoute('a.wild.local')).toBeUndefined()
  })

  it('prefers an exact domain over the wildcard', () => {
    updateProxyRoute('*.mixed.local', 4200)
    updateProxyRoute('api.mixed.local', 4201)
    expect(resolveRoute('api.mixed.local')).toBe(4201)
    expect(resolveRoute('web.mixed.local')).toBe(4200)
    expect(isOnDemandHost('api.mixed.local')).toBe(false)
    expect(isOnDemandHost('web.mixed.local')).toBe(true)
    expect(isOnDemandHost('other.local')).toBe(false)
    removeProxyRoute('*.mixed.local')
    removeProxyRoute('api.mixed.local')
  })

  it('forwards HTTP traffic for a wildcard host to the backend, keeping the Host header', async () => {
    const upstream = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      res.end(`host=${req.headers.host}`)
    })
    await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve))
    const upstreamPort = (upstream.address() as net.AddressInfo).port

    const proxy = startDevProxy()
    await new Promise<void>((resolve) => {
      if (proxy.listening) return resolve()
      proxy.on('listening', resolve)
    })
    const proxyPort = (proxy.address() as net.AddressInfo).port

    updateProxyRoute('*.tables.local', upstreamPort)

    const res = await makeRequest(proxyPort, 'pssc1.tables.local')
    expect(res.status).toBe(200)
    expect(res.body).toBe('host=pssc1.tables.local')
    expect((await makeRequest(proxyPort, 'a.b.tables.local')).status).toBe(502)

    removeProxyRoute('*.tables.local')
    proxy.close()
    upstream.close()
  })

  it('restoreRoutes does not load a certificate for a wildcard domain', async () => {
    const { loadCachedCert } = await import('./certs.ts')
    vi.mocked(loadCachedCert).mockClear()
    restoreRoutes([{ domains: ['app.local', '*.app.local'], deployments: [{ port: 4300 }], previews: {} }])
    expect(vi.mocked(loadCachedCert).mock.calls).toEqual([['app.local']])
    expect(resolveRoute('x.app.local')).toBe(4300)
    removeProxyRoute('app.local')
    removeProxyRoute('*.app.local')
  })
})
