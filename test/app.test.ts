import http from 'http';
import type { AddressInfo } from 'net';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app';
import { loadConfig, type Config } from '../src/config';
import { issueToken } from '../src/common';

const secret = 'j'.repeat(32);

describe('auth app', () => {
    let upstream: http.Server;
    let config: Config;

    beforeAll(async () => {
        upstream = http.createServer((req, res) => {
            if (req.url?.startsWith('/token')) {
                res.setHeader('content-type', 'application/json');
                res.end(JSON.stringify({ access_token: 'provider-token' }));
                return;
            }
            if (req.url?.startsWith('/userinfo')) {
                const email = new URL(req.url, 'http://127.0.0.1').searchParams.get('email') || 'user@example.com';
                res.setHeader('content-type', 'application/json');
                res.end(JSON.stringify({ email }));
                return;
            }
            res.statusCode = 404;
            res.end();
        });
        await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
        const { port } = upstream.address() as AddressInfo;
        config = loadConfig({
            PUBLIC_URL: 'http://127.0.0.1:3000',
            JWT_SECRET: secret,
            COOKIE_SECRET: 'c'.repeat(32),
            ALLOWED_USERS: 'user@example.com',
            COOKIE_EXPIRES_IN: '1h',
            GOOGLE_CLIENT_ID: 'id',
            GOOGLE_CLIENT_SECRET: 'secret',
            GOOGLE_AUTH_URL: `http://127.0.0.1:${port}/authorize`,
            GOOGLE_TOKEN_URL: `http://127.0.0.1:${port}/token`,
            GOOGLE_PROFILE_URL: `http://127.0.0.1:${port}/userinfo`,
        });
    });

    afterAll(async () => {
        await new Promise<void>((resolve, reject) => upstream.close((error) => error ? reject(error) : resolve()));
    });

    it('should expose a health check without a session', async () => {
        const response = await request(createApp(config)).get('/health');
        expect(response.status).toBe(200);
        expect(response.text).toBe('ok');
    });

    it('should deny forward auth without a session', async () => {
        const response = await request(createApp(config))
            .get('/auth/session')
            .set('Accept', 'application/json');
        expect(response.status).toBe(401);
        expect(response.headers['x-forwarded-user']).toBeUndefined();
    });

    it('should not place an external redirect in the login link', async () => {
        const response = await request(createApp(config))
            .get('/auth/login')
            .query({ redirect: 'https://evil.example/phish' });
        expect(response.status).toBe(200);
        expect(response.text).toContain('redirect=%2F');
        expect(response.text).not.toContain('evil.example');
        expect(response.text).not.toContain('unpkg.com');
    });

    it('should set an HttpOnly cookie and ignore an open redirect after login', async () => {
        const agent = request.agent(createApp(config));
        const started = await agent.get('/auth/google/url').query({ redirect: 'https://evil.example/phish' });
        expect(started.status).toBe(200);
        const authUrl = new URL(started.text);
        const callback = await agent.get('/auth/google/callback').query({
            code: 'good-code',
            state: authUrl.searchParams.get('state'),
        });
        expect(callback.status).toBe(302);
        expect(callback.headers.location).toBe('/');
        const cookie = String(callback.headers['set-cookie']);
        expect(cookie).toContain('HttpOnly');
        expect(cookie).not.toContain('Domain=');
        expect(cookie).toContain('Max-Age=3600');
        const session = await agent.get('/auth/session');
        expect(session.status).toBe(200);
        expect(session.headers['x-forwarded-user']).toBe('user@example.com');
    });

    it('should reject a user who is not on the allow list', async () => {
        const denied = loadConfig({
            PUBLIC_URL: 'http://127.0.0.1:3000',
            JWT_SECRET: secret,
            COOKIE_SECRET: 'c'.repeat(32),
            ALLOWED_USERS: 'user@example.com',
            GOOGLE_CLIENT_ID: 'id',
            GOOGLE_CLIENT_SECRET: 'secret',
            GOOGLE_AUTH_URL: config.providers.google?.authUrl || '',
            GOOGLE_TOKEN_URL: config.providers.google?.tokenUrl || '',
            GOOGLE_PROFILE_URL: `${config.providers.google?.profileUrl}?email=other@example.com`,
        });
        const agent = request.agent(createApp(denied));
        const started = await agent.get('/auth/google/url').query({ redirect: '/auth/profile' });
        const authUrl = new URL(started.text);
        const callback = await agent.get('/auth/google/callback').query({
            code: 'good-code',
            state: authUrl.searchParams.get('state'),
        });
        expect(callback.status).toBe(403);
        expect(String(callback.headers['set-cookie'] || '')).not.toContain('authom-authorization=');
    });

    it('should reject a bearer token signed with another secret', async () => {
        const other = issueToken({ ...config, jwtSecret: 'z'.repeat(32) }, 'user@example.com');
        const response = await request(createApp(config))
            .get('/auth/session')
            .set('Accept', 'application/json')
            .set('Authorization', `Bearer ${other}`);
        expect(response.status).toBe(401);
    });
});
