import type { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import type { Config } from './config';
import { clearCookieOptions, emailAllowed, safeRedirect, sessionCookieOptions } from './security';

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
    const next = safeRedirect(redirect);
    return `${config.publicURL}/auth/login?redirect=${encodeURIComponent(next)}`;
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
        const email = claims.email.trim().toLowerCase();
        if (!emailAllowed(email, config.allowedUsers)) {
            return undefined;
        }
        const createdAt = typeof claims.createdAt === 'string' ? claims.createdAt : '';
        return { email, createdAt };
    } catch {
        return undefined;
    }
}

export function issueToken(config: Config, email: string): string {
    return jwt.sign(
        { email, createdAt: new Date().toISOString() },
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
    const wantsJSON = req.headers.accept === 'application/json' || req.query.api === 'true';
    const redirect = loginURL(config, req.headers['x-forwarded-uri'] || req.query.redirect || '/');
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
