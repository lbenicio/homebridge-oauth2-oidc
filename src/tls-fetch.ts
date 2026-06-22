/**
 * HTTP fetch helpers with optional TLS certificate verification skip.
 */

import https from 'node:https';

let _insecureAgent: https.Agent | null = null;

function getInsecureAgent(): https.Agent {
  if (!_insecureAgent) {
    _insecureAgent = new https.Agent({
      rejectUnauthorized: false,
      keepAlive: true,
    });
  }
  return _insecureAgent;
}

function readBody(res: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    res.on('data', (chunk: Buffer) => chunks.push(chunk));
    res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    res.on('error', reject);
  });
}

async function wrapNativeFetch(promise: Promise<Response>): Promise<TLSResponse> {
  const res = await promise;
  const bodyText = await res.text();
  return makeResponse(res.status, res.headers, bodyText);
}

function httpsRequest(urlStr: string, init?: RequestInit): Promise<TLSResponse> {
  const parsedUrl = new URL(urlStr);
  const method = init?.method ?? 'GET';
  const headers = init?.headers as Record<string, string> | undefined;
  const body = init?.body as string | undefined;

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 443,
        path: parsedUrl.pathname + parsedUrl.search,
        method,
        headers: { Accept: 'application/json', ...headers },
        agent: getInsecureAgent(),
        timeout: 30_000,
      },
      async (res) => {
        try {
          const bodyText = await readBody(res);
          resolve(makeResponse(res.statusCode ?? 500, hdrs(res.headers), bodyText));
        } catch (err) { reject(err); }
      }
    );
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`Request timed out: ${urlStr}`)); });
    if (body) req.write(body);
    req.end();
  });
}

export interface TLSResponse {
  ok: boolean;
  status: number;
  headers: HeadersLike;
  json<T = unknown>(): Promise<T>;
  text(): Promise<string>;
}

interface HeadersLike {
  get(name: string): string | null;
}

function hdrs(h: NodeJS.Dict<string | string[]>): HeadersLike {
  return {
    get(name: string): string | null {
      const v = h[name.toLowerCase()];
      return Array.isArray(v) ? v[0] ?? null : v ?? null;
    },
  };
}

function makeResponse(status: number, headers: HeadersLike, body: string): TLSResponse {
  let consumed = false;
  return {
    get ok() { return status >= 200 && status < 300; },
    status,
    headers,
    async json<T>(): Promise<T> {
      if (consumed) throw new Error('Body already consumed');
      consumed = true;
      return JSON.parse(body) as T;
    },
    async text(): Promise<string> {
      if (consumed) throw new Error('Body already consumed');
      consumed = true;
      return body;
    },
  };
}

export async function fetchWithTLS(
  url: string | URL,
  init?: RequestInit,
  rejectUnauthorized = true
): Promise<TLSResponse> {
  const urlStr = typeof url === 'string' ? url : url.toString();
  if (rejectUnauthorized || urlStr.startsWith('http://')) {
    return wrapNativeFetch(fetch(urlStr, init));
  }
  return httpsRequest(urlStr, init);
}
