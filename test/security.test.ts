import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config';
import { createState, safeRedirect, safeReturnURL, verifyState } from '../src/security';

const secret = 's'.repeat(40);

describe('safeRedirect', () => {
    it('should keep a same-site path', () => {
        expect(safeRedirect('/auth/profile?tab=1')).toBe('/auth/profile?tab=1');
    });

    it('should reject absolute and protocol-relative targets', () => {
        expect(safeRedirect('https://evil.example/phish')).toBe('/');
        expect(safeRedirect('//evil.example')).toBe('/');
        expect(safeRedirect('/\\evil.example')).toBe('/');
    });

    it('should allow an absolute return only for a configured origin', () => {
        expect(safeReturnURL('https://app.lab.example/dash?x=1', ['https://app.lab.example'])).toBe('https://app.lab.example/dash?x=1');
        expect(safeReturnURL('https://evil.example/phish', ['https://app.lab.example'])).toBe('/');
    });
});

describe('state', () => {
    it('should round-trip a signed state and ignore an external redirect', () => {
        const token = createState('google', 'https://evil.example', secret);
        expect(verifyState(token, secret, 'google').redirect).toBe('/');
    });

    it('should reject a tampered state', () => {
        const token = createState('google', '/ok', secret);
        const tampered = `${token.slice(0, -1)}${token.endsWith('a') ? 'b' : 'a'}`;
        expect(() => verifyState(tampered, secret, 'google')).toThrow(/invalid state/);
    });

    it('should reject an expired state', () => {
        const token = createState('google', '/ok', secret);
        const [body, signature] = token.split('.');
        const payload = JSON.parse(Buffer.from(body || '', 'base64url').toString('utf8')) as { exp: number };
        payload.exp = Date.now() - 1000;
        const expiredBody = Buffer.from(JSON.stringify(payload)).toString('base64url');
        expect(() => verifyState(`${expiredBody}.${signature}`, secret, 'google')).toThrow(/invalid state/);
    });
});

describe('loadConfig', () => {
    const baseEnv = {
        PUBLIC_URL: 'http://127.0.0.1:3000',
        JWT_SECRET: 'j'.repeat(32),
        COOKIE_SECRET: 'c'.repeat(32),
        ALLOWED_USERS: 'User@Example.com',
        GOOGLE_CLIENT_ID: 'id',
        GOOGLE_CLIENT_SECRET: 'secret',
    };

    it('should reject a short JWT secret', () => {
        expect(() => loadConfig({ ...baseEnv, JWT_SECRET: 'short' })).toThrow(/JWT_SECRET/);
    });

    it('should reject an empty allow list', () => {
        expect(() => loadConfig({ ...baseEnv, ALLOWED_USERS: '' })).toThrow(/ALLOWED_USERS/);
    });

    it('should normalize allowlisted emails and enable only configured providers', () => {
        const config = loadConfig(baseEnv);
        expect(config.allowedUsers).toEqual(['user@example.com']);
        expect(config.providers.google?.enabled).toBe(true);
        expect(config.providers.github?.enabled).toBe(false);
        expect(config.bindHost).toBe('127.0.0.1');
        expect(config.maxAgeMs).toBe(8 * 60 * 60 * 1000);
    });

    it('should reject sessions longer than 24 hours', () => {
        expect(() => loadConfig({ ...baseEnv, COOKIE_EXPIRES_IN: '30d' })).toThrow(/COOKIE_EXPIRES_IN/);
    });

    it('should share a cookie only with a parent of the public host', () => {
        const config = loadConfig({
            ...baseEnv,
            PUBLIC_URL: 'https://auth.lab.example',
            COOKIE_DOMAIN: '.lab.example',
            ALLOWED_REDIRECT_ORIGINS: 'https://app.lab.example',
        });
        expect(config.cookieDomain).toBe('lab.example');
        expect(config.allowedRedirectOrigins).toEqual(['https://app.lab.example']);
        expect(() => loadConfig({ ...baseEnv, COOKIE_DOMAIN: 'evil.example' })).toThrow(/COOKIE_DOMAIN/);
    });
});
