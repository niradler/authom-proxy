import { createHmac, createHash, randomBytes, timingSafeEqual } from 'crypto';
import type { CookieOptions } from 'express';
import type { Config } from './config';

const stateLifetimeMs = 10 * 60 * 1000;

export type StatePayload = {
    redirect: string;
    exp: number;
    provider: string;
    nonce: string;
};

export function safeRedirect(value: unknown): string {
    if (typeof value !== 'string' || value.length === 0 || value.length > 2048) {
        return '/';
    }
    if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\') || value.includes('\0') || value.includes('\r') || value.includes('\n')) {
        return '/';
    }
    let parsed: URL;
    try {
        parsed = new URL(value, 'http://localhost');
    } catch {
        return '/';
    }
    if (parsed.origin !== 'http://localhost') {
        return '/';
    }
    return `${parsed.pathname}${parsed.search}`;
}

export function emailAllowed(email: string, allowed: string[]): boolean {
    return allowed.includes(email.trim().toLowerCase());
}

export function createCodeVerifier(): string {
    return randomBytes(32).toString('base64url');
}

export function codeChallenge(verifier: string): string {
    return createHash('sha256').update(verifier).digest('base64url');
}

export function signState(payload: StatePayload, secret: string): string {
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = createHmac('sha256', secret).update(body).digest('base64url');
    return `${body}.${signature}`;
}

export function createState(provider: string, redirect: unknown, secret: string): string {
    return signState({
        redirect: safeRedirect(redirect),
        exp: Date.now() + stateLifetimeMs,
        provider,
        nonce: randomBytes(16).toString('base64url'),
    }, secret);
}

export function verifyState(token: string, secret: string, provider: string): StatePayload {
    const parts = token.split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
        throw new Error('invalid state');
    }
    const [body, signature] = parts;
    const expected = createHmac('sha256', secret).update(body).digest('base64url');
    const actualBuffer = Buffer.from(signature);
    const expectedBuffer = Buffer.from(expected);
    if (actualBuffer.length !== expectedBuffer.length || !timingSafeEqual(actualBuffer, expectedBuffer)) {
        throw new Error('invalid state');
    }
    const parsed: unknown = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!isStatePayload(parsed) || parsed.provider !== provider || parsed.exp < Date.now()) {
        throw new Error('invalid state');
    }
    return {
        ...parsed,
        redirect: safeRedirect(parsed.redirect),
    };
}

function isStatePayload(value: unknown): value is StatePayload {
    if (!value || typeof value !== 'object') {
        return false;
    }
    const record = value as Record<string, unknown>;
    return typeof record.redirect === 'string'
        && typeof record.exp === 'number'
        && typeof record.provider === 'string'
        && typeof record.nonce === 'string';
}

export function clearCookieOptions(options: CookieOptions): CookieOptions {
    const copy = { ...options };
    delete copy.maxAge;
    return copy;
}

export function sessionCookieOptions(config: Config): CookieOptions {
    return {
        httpOnly: true,
        secure: config.publicURL.startsWith('https://'),
        sameSite: 'lax',
        path: '/',
        maxAge: config.maxAgeMs,
        signed: true,
    };
}

export function pkceCookieOptions(config: Config): CookieOptions {
    return {
        httpOnly: true,
        secure: config.publicURL.startsWith('https://'),
        sameSite: 'lax',
        path: '/auth',
        maxAge: stateLifetimeMs,
        signed: true,
    };
}
