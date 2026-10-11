import type { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { normalizeEmail, type Config } from './config';
import { clearCookieOptions, emailAllowed, safeRedirect, safeReturnURL, sessionCookieOptions } from './security';

export type JwtPayload = {
    email: string;
    createdAt: string;
};

export type AuthenticatedRequest = Request & {
    user?: JwtPayload;
};

const jwtOptions: jwt.VerifyOptions = {
    algorithms: ['HS256'],
    issuer: 'authom-proxy',
    audience: 'authom-proxy',
};

export function loginURL(config: Config, redirect: unknown): string {
    const next = safeReturnURL(redirect, config.allowedRedirectOrigins);
    return `${config.publicURL}/auth/login?redirect=${encodeURIComponent(next)}`;
}

export function returnTarget(config: Config, req: Request): string {
    const forwarded = forwardedAppURL(config, req);
    if (forwarded) {
        return forwarded;
    }
    const trusted = trustsForwarded(config, req);
    const host = trusted ? headerValue(req.headers['x-forwarded-host']) : undefined;
    const foreignHost = Boolean(host) && !samePublicHost(config, host, headerValue(req.headers['x-forwarded-proto']));
    if (foreignHost) {
        return '/';
    }
    if (typeof req.query.redirect === 'string') {
        return safeReturnURL(req.query.redirect, config.allowedRedirectOrigins);
    }
    if (trusted) {
        return safeRedirect(headerValue(req.headers['x-forwarded-uri']));
    }
    return '/';
}

export function readSession(config: Config, req: Request): JwtPayload | undefined {
    const token = readToken(config, req);
    if (!token) {
        return undefined;
    }
    try {
        const decoded: unknown = jwt.verify(token, config.jwtSecret, jwtOptions);
        if (!decoded || typeof decoded !== 'object') {
            return undefined;
        }
        const claims = decoded as Record<string, unknown>;
        if (typeof claims.email !== 'string') {
            return undefined;
        }
        const email = normalizeEmail(claims.email);
        if (!email || !emailAllowed(email, config.allowedUsers)) {
            return undefined;
        }
        const createdAt = typeof claims.createdAt === 'string' ? claims.createdAt : '';
        return { email, createdAt };
    } catch {
        return undefined;
    }
}

export function issueToken(config: Config, email: string): string {
    const normalized = normalizeEmail(email);
    if (!normalized) {
        throw new Error('invalid email');
    }
    return jwt.sign(
        { email: normalized, createdAt: new Date().toISOString() },
        config.jwtSecret,
        {
            algorithm: 'HS256',
            expiresIn: config.expiresInSeconds,
            issuer: 'authom-proxy',
            audience: 'authom-proxy',
        },
    );
}

export function shouldLogin(config: Config, req: Request, res: Response): void {
    const accept = typeof req.headers.accept === 'string' ? req.headers.accept : '';
    const wantsJSON = req.query.api === 'true' || accept.split(',').some((part) => part.split(';')[0]?.trim().toLowerCase() === 'application/json');
    const redirect = loginURL(config, returnTarget(config, req));
    res.clearCookie(config.cookieName, clearCookieOptions(sessionCookieOptions(config)));
    if (wantsJSON) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
    }
    res.redirect(redirect);
}

export function isAuthenticatedMiddleware(config: Config) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        const user = readSession(config, req);
        if (!user) {
            shouldLogin(config, req, res);
            return;
        }
        req.user = user;
        next();
    };
}

function samePublicHost(config: Config, host: string | undefined, proto: string | undefined): boolean {
    if (!host || (proto !== 'http' && proto !== 'https') || host.includes('@') || host.includes('/') || host.includes('\\') || host.includes(' ')) {
        return false;
    }
    try {
        return new URL(`${proto}://${host}`).origin === config.publicURL;
    } catch {
        return false;
    }
}

function forwardedAppURL(config: Config, req: Request): string | undefined {
    if (!trustsForwarded(config, req)) {
        return undefined;
    }
    const proto = headerValue(req.headers['x-forwarded-proto']);
    const host = headerValue(req.headers['x-forwarded-host']);
    const uri = headerValue(req.headers['x-forwarded-uri']);
    if (!proto || !host || uri === undefined) {
        return undefined;
    }
    if ((proto !== 'https' && proto !== 'http') || host.includes('@') || host.includes('/') || host.includes('\\') || host.includes(' ')) {
        return undefined;
    }
    let origin: string;
    try {
        const parsed = new URL(`${proto}://${host}`);
        if (parsed.host.toLowerCase() !== host.toLowerCase()) {
            return undefined;
        }
        origin = parsed.origin;
    } catch {
        return undefined;
    }
    if (origin === config.publicURL) {
        return undefined;
    }
    if (!config.allowedRedirectOrigins.includes(origin)) {
        return undefined;
    }
    return safeReturnURL(`${origin}${safeRedirect(uri)}`, config.allowedRedirectOrigins);
}

function trustsForwarded(config: Config, req: Request): boolean {
    if (config.trustProxy === false || config.trustProxy === 0) {
        return false;
    }
    if (config.trustProxy === 'loopback') {
        const address = req.socket.remoteAddress || '';
        return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
    }
    return true;
}

function headerValue(value: string | string[] | undefined): string | undefined {
    const raw = Array.isArray(value) ? value[0] : value;
    if (typeof raw !== 'string') {
        return undefined;
    }
    const first = raw.split(',')[0]?.trim() || '';
    return first.length > 0 ? first : undefined;
}

function readToken(config: Config, req: Request): string | undefined {
    const cookie = req.signedCookies?.[config.cookieName];
    if (typeof cookie === 'string' && cookie.length > 0) {
        return cookie;
    }
    const header = req.headers.authorization;
    if (typeof header === 'string' && header.startsWith('Bearer ')) {
        const token = header.slice('Bearer '.length).trim();
        return token.length > 0 ? token : undefined;
    }
    return undefined;
}
