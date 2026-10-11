import http from 'http';
import type { AddressInfo } from 'net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { loadConfig } from '../src/config';

const secret = 'e'.repeat(32);

describe('live forward auth', () => {
    let upstream: http.Server;
    let server: http.Server;
    let base: string;

    beforeAll(async () => {
        upstream = http.createServer((req, res) => {
            const url = new URL(req.url || '/', 'http://127.0.0.1');
            if (url.pathname === '/token') {
                res.setHeader('content-type', 'application/json');
                res.end(JSON.stringify({ access_token: 'provider-token' }));
                return;
            }
            if (url.pathname === '/userinfo') {
                res.setHeader('content-type', 'application/json');
                res.end(JSON.stringify({ email: url.searchParams.get('email') || 'user@example.com' }));
                return;
            }
            res.statusCode = 404;
            res.end();
        });
        await listen(upstream);
        const providerPort = (upstream.address() as AddressInfo).port;
        const config = loadConfig({
            PUBLIC_URL: 'http://127.0.0.1:3000',
            JWT_SECRET: secret,
            COOKIE_SECRET: 'c'.repeat(32),
            ALLOWED_USERS: 'user@example.com',
            ALLOWED_REDIRECT_ORIGINS: 'http://app.lab.example:8080',
            TRUST_PROXY: '1',
            GOOGLE_CLIENT_ID: 'id',
            GOOGLE_CLIENT_SECRET: 'secret',
            GOOGLE_AUTH_URL: `http://127.0.0.1:${providerPort}/authorize`,
            GOOGLE_TOKEN_URL: `http://127.0.0.1:${providerPort}/token`,
            GOOGLE_PROFILE_URL: `http://127.0.0.1:${providerPort}/userinfo`,
        });
        server = http.createServer(createApp(config));
        await listen(server);
        const port = (server.address() as AddressInfo).port;
        base = `http://127.0.0.1:${port}`;
    });

    afterAll(async () => {
        await close(server);
        await close(upstream);
    });

    it('should complete login over HTTP and answer a forward-auth check', async () => {
        const health = await fetch(`${base}/health`);
        expect(health.status).toBe(200);
        expect(await health.text()).toBe('ok');

        const anonymous = await fetch(`${base}/auth/session`, {
            redirect: 'manual',
            headers: {
                'x-forwarded-proto': 'http',
                'x-forwarded-host': 'app.lab.example:8080',
                'x-forwarded-uri': '/board',
            },
        });
        expect(anonymous.status).toBe(302);
        expect(anonymous.headers.get('location')).toBe('http://127.0.0.1:3000/auth/login?redirect=http%3A%2F%2Fapp.lab.example%3A8080%2Fboard');

        const jar = new CookieJar();
        const started = await jar.send(`${base}/auth/google/url?redirect=${encodeURIComponent('http://app.lab.example:8080/board')}`);
        expect(started.status).toBe(200);
        const authUrl = new URL(await started.text());
        const callback = await jar.send(`${base}/auth/google/callback?code=good-code&state=${encodeURIComponent(authUrl.searchParams.get('state') || '')}`);
        expect(callback.status).toBe(302);
        expect(callback.headers.get('location')).toBe('http://app.lab.example:8080/board');
        expect(jar.get('authom-authorization')).toMatch(/^s:/);

        const session = await jar.send(`${base}/auth/session`);
        expect(session.status).toBe(200);
        expect(session.headers.get('x-forwarded-user')).toBe('user@example.com');
        expect(await session.json()).toEqual({ user: { email: 'user@example.com' } });

        const logout = await jar.send(`${base}/auth/logout`, { method: 'POST', headers: { origin: 'http://127.0.0.1:3000' } });
        expect(logout.status).toBe(302);
        const after = await jar.send(`${base}/auth/session`, { headers: { accept: 'application/json' } });
        expect(after.status).toBe(401);
    });
});

class CookieJar {
    private cookies = new Map<string, { value: string; path: string }>();

    async send(url: string, init: RequestInit = {}): Promise<Response> {
        const headers = new Headers(init.headers);
        const path = new URL(url).pathname;
        const cookie = [...this.cookies.entries()]
            .filter(([, item]) => path.startsWith(item.path))
            .map(([name, item]) => `${name}=${item.value}`)
            .join('; ');
        if (cookie) {
            headers.set('cookie', cookie);
        }
        const response = await fetch(url, { ...init, headers, redirect: 'manual' });
        for (const line of response.headers.getSetCookie()) {
            const [pair, ...attrs] = line.split(';').map((part) => part.trim());
            const eq = pair?.indexOf('=') ?? -1;
            if (!pair || eq < 1) {
                continue;
            }
            const name = pair.slice(0, eq);
            const value = decodeURIComponent(pair.slice(eq + 1));
            const pathAttr = attrs.find((attr) => attr.toLowerCase().startsWith('path='));
            const expired = attrs.some((attr) => attr.toLowerCase().startsWith('expires=') && attr.includes('1970'));
            if (!value || expired) {
                this.cookies.delete(name);
                continue;
            }
            this.cookies.set(name, { value, path: pathAttr?.slice(5) || '/' });
        }
        return response;
    }

    get(name: string): string | undefined {
        return this.cookies.get(name)?.value;
    }
}

function listen(server: http.Server): Promise<void> {
    return new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
}

function close(server: http.Server): Promise<void> {
    return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
