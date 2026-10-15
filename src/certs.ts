import { X509Certificate } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import tls from 'node:tls'
import * as acme from 'acme-client'
import { isWildcardDomain, matchesWildcard } from './domains.ts'
import { CERT_RENEW_BEFORE_DAYS, CERTS_DIR, EMAIL, IS_DEV, ON_DEMAND_TLS_ASK, ON_DEMAND_TLS_PER_HOUR } from './env.ts'
import { getErrorMessage } from './errors.ts'
import { ensureDir, writeFileAtomic } from './fs.ts'
import { isTLSEnabled } from './url.ts'

const certCache = new Map<string, tls.SecureContext>()
const certInFlight = new Map<string, Promise<tls.SecureContext>>()
const challengeTokens = new Map<string, string>()

const ACCOUNT_KEY_FILE = 'account.pem'

async function getOrCreateAccountKey(): Promise<Buffer> {
  ensureDir(CERTS_DIR)
  const keyPath = path.join(CERTS_DIR, ACCOUNT_KEY_FILE)
  if (fs.existsSync(keyPath)) {
    return fs.readFileSync(keyPath)
  }
  const key = await acme.crypto.createPrivateEcdsaKey()
  fs.writeFileSync(keyPath, key, { mode: 0o600 })
  return key
}

export function certPath(domain: string) {
  return {
    cert: path.join(CERTS_DIR, `${domain}.crt`),
    key: path.join(CERTS_DIR, `${domain}.key`)
  }
}

export function loadCachedCert(domain: string): tls.SecureContext | null {
  const { cert, key } = certPath(domain)
  if (fs.existsSync(cert) && fs.existsSync(key)) {
    const context = tls.createSecureContext({
      cert: fs.readFileSync(cert),
      key: fs.readFileSync(key)
    })
    certCache.set(domain, context)
    return context
  }
  return null
}

export function getCachedCert(domain: string): tls.SecureContext | undefined {
  return certCache.get(domain)
}

function getCertExpiry(domain: string): Date | null {
  const { cert } = certPath(domain)
  if (!fs.existsSync(cert)) return null

  try {
    const pem = fs.readFileSync(cert, 'utf8')
    return new Date(new X509Certificate(pem).validTo)
  } catch (err) {
    console.warn(`[acme] Failed to inspect cert for ${domain}:`, getErrorMessage(err))
    return null
  }
}

export function shouldRenewCert(domain: string, now = Date.now()): boolean {
  const expiresAt = getCertExpiry(domain)
  if (!expiresAt) return false

  const renewBeforeMs = CERT_RENEW_BEFORE_DAYS * 24 * 60 * 60 * 1000
  return expiresAt.getTime() - now <= renewBeforeMs
}

export function managedDomains(apps: Array<{ domains: string[] }>, hostDomain: string): string[] {
  const appDomains = apps.flatMap((app) => app.domains)
  return hostDomain ? [hostDomain, ...appDomains] : appDomains
}

/** Hosts with a certificate on disk that a wildcard covers (issued on demand earlier). */
export function onDemandHosts(wildcard: string): string[] {
  if (!fs.existsSync(CERTS_DIR)) return []
  return fs
    .readdirSync(CERTS_DIR)
    .filter((file) => file.endsWith('.crt'))
    .map((file) => file.slice(0, -'.crt'.length))
    .filter((host) => matchesWildcard(host, wildcard))
}

export async function renewExpiringCerts(
  domains: string[],
  renew: (domain: string) => Promise<tls.SecureContext> = obtainCert,
  now = Date.now(),
  ask: (host: string) => Promise<boolean> = askOnDemand
): Promise<string[]> {
  if (!isTLSEnabled()) return []

  // A wildcard has no certificate of its own: renew the hosts issued under it instead.
  const onDemand = new Set(domains.filter(isWildcardDomain).flatMap(onDemandHosts))
  const uniqueDomains = [...new Set([...domains.filter((d) => d && !isWildcardDomain(d)), ...onDemand])]
  const renewed: string[] = []

  for (const domain of uniqueDomains) {
    if (!shouldRenewCert(domain, now)) continue
    // A host the ask endpoint no longer approves keeps its certificate until it expires.
    if (onDemand.has(domain) && !(await ask(domain))) {
      console.log(`[acme] not renewing ${domain}: no longer approved by ON_DEMAND_TLS_ASK`)
      continue
    }

    console.log(`[acme] renewing cert for ${domain}`)
    try {
      await renew(domain)
      renewed.push(domain)
    } catch (err) {
      console.error(`[acme] Failed to renew cert for ${domain}:`, getErrorMessage(err))
    }
  }

  return renewed
}

export function obtainCert(domain: string): Promise<tls.SecureContext> {
  if (certInFlight.has(domain)) return certInFlight.get(domain)!

  const promise = _doObtainCert(domain).catch((err) => {
    console.error(`[acme] Failed to obtain cert for ${domain}:`, getErrorMessage(err))
    throw err
  })
  certInFlight.set(domain, promise)
  promise.then(
    () => certInFlight.delete(domain),
    () => certInFlight.delete(domain)
  )
  return promise
}

const ON_DEMAND_RETRY_AFTER_MS = 60 * 60 * 1000
const ON_DEMAND_ASK_TIMEOUT_MS = 5000
const onDemandIssued: number[] = []
const onDemandFailedAt = new Map<string, number>()
const onDemandInFlight = new Map<string, Promise<tls.SecureContext>>()

/**
 * Asks ON_DEMAND_TLS_ASK whether a host may get a certificate (`GET <url>?domain=<host>`, 2xx = yes).
 * Without an ask URL every host under the wildcard is allowed.
 */
export async function askOnDemand(host: string): Promise<boolean> {
  if (!ON_DEMAND_TLS_ASK) return true
  try {
    const url = new URL(ON_DEMAND_TLS_ASK)
    url.searchParams.set('domain', host)
    const res = await fetch(url, { signal: AbortSignal.timeout(ON_DEMAND_ASK_TIMEOUT_MS) })
    return res.ok
  } catch (err) {
    console.warn(`[acme] ON_DEMAND_TLS_ASK failed for ${host}:`, getErrorMessage(err))
    return false
  }
}

/**
 * Certificate for a host that is only routed through a wildcard, issued during its first TLS handshake.
 * Anyone can point a name under a wildcard DNS record at the server, so issuance is guarded: the optional
 * ask endpoint must approve the host, at most ON_DEMAND_TLS_PER_HOUR new certificates are issued per hour,
 * and a host whose issuance failed is not retried for an hour (protects the Let's Encrypt rate limits).
 */
export function obtainOnDemandCert(
  host: string,
  issue: (domain: string) => Promise<tls.SecureContext> = obtainCert,
  ask: (host: string) => Promise<boolean> = askOnDemand,
  now = Date.now()
): Promise<tls.SecureContext> {
  // Concurrent handshakes for a new host share one issuance (and count once against the limit).
  const inFlight = onDemandInFlight.get(host)
  if (inFlight) return inFlight
  const promise = issueOnDemand(host, issue, ask, now)
  onDemandInFlight.set(host, promise)
  promise.then(
    () => onDemandInFlight.delete(host),
    () => onDemandInFlight.delete(host)
  )
  return promise
}

async function issueOnDemand(
  host: string,
  issue: (domain: string) => Promise<tls.SecureContext>,
  ask: (host: string) => Promise<boolean>,
  now: number
): Promise<tls.SecureContext> {
  const failedAt = onDemandFailedAt.get(host)
  if (failedAt !== undefined && now - failedAt < ON_DEMAND_RETRY_AFTER_MS) {
    throw new Error(`On-demand certificate for ${host} failed recently, retrying later`)
  }
  if (!(await ask(host))) {
    onDemandFailedAt.set(host, now)
    throw new Error(`On-demand certificate for ${host} not approved by ON_DEMAND_TLS_ASK`)
  }
  while (onDemandIssued.length > 0 && now - onDemandIssued[0]! >= ON_DEMAND_RETRY_AFTER_MS) onDemandIssued.shift()
  if (onDemandIssued.length >= ON_DEMAND_TLS_PER_HOUR) {
    throw new Error(`On-demand certificate limit reached (${ON_DEMAND_TLS_PER_HOUR}/hour), not issuing for ${host}`)
  }
  onDemandIssued.push(now)
  try {
    return await issue(host)
  } catch (err) {
    onDemandFailedAt.set(host, now)
    throw err
  }
}

/** Test helper: forget issued and failed on-demand hosts. */
export function resetOnDemandState(): void {
  onDemandIssued.length = 0
  onDemandFailedAt.clear()
}

let _acmeClient: acme.Client | null = null

async function getOrCreateClient(): Promise<acme.Client> {
  if (_acmeClient) return _acmeClient

  const directoryUrl = IS_DEV ? acme.directory.letsencrypt.staging : acme.directory.letsencrypt.production

  const accountKey = await getOrCreateAccountKey()

  _acmeClient = new acme.Client({ directoryUrl, accountKey })
  await _acmeClient.createAccount({
    termsOfServiceAgreed: true,
    contact: [`mailto:${EMAIL}`]
  })

  return _acmeClient
}

async function _doObtainCert(domain: string): Promise<tls.SecureContext> {
  console.log(`[acme] obtaining cert for ${domain}`)
  ensureDir(CERTS_DIR)

  const client = await getOrCreateClient()
  const [serverKey, serverCsr] = await acme.crypto.createCsr({ commonName: domain })

  const cert = await client.auto({
    csr: serverCsr,
    termsOfServiceAgreed: true,
    challengeCreateFn: async (_authz, _challenge, keyAuthorization) => {
      challengeTokens.set(_challenge.token, keyAuthorization)
    },
    challengeRemoveFn: async (_authz, _challenge) => {
      challengeTokens.delete(_challenge.token)
    }
  })

  const { cert: certFile, key: keyFile } = certPath(domain)
  writeFileAtomic(keyFile, serverKey)
  writeFileAtomic(certFile, cert)
  console.log(`[acme] cert saved for ${domain}`)

  const ctx = tls.createSecureContext({ cert, key: serverKey })
  certCache.set(domain, ctx)
  return ctx
}

/** Responds to ACME HTTP-01 challenges. Returns true if the request was handled. */
export function handleAcmeChallenge(url: string, res: import('node:http').ServerResponse): boolean {
  if (!url.startsWith('/.well-known/acme-challenge/')) return false

  const token = url.split('/').pop() ?? ''
  const keyAuth = challengeTokens.get(token)

  if (keyAuth) {
    res.writeHead(200, { 'Content-Type': 'text/plain' })
    res.end(keyAuth)
  } else {
    res.writeHead(404)
    res.end('Not found')
  }
  return true
}
