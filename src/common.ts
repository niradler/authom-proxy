import { config } from './config';
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

const { jwtSecret, cookieName } = config;

export type JwtPayload = {
    email: string;
    createdAt: string;
};

export interface AuthenticatedRequest extends Request {
    user?: jwt.JwtPayload;
}

export const getHost = (req: AuthenticatedRequest) => {
    const { 'x-forwarded-proto': proto, 'x-forwarded-host': host } = req.headers;
    const forwardedHost = proto && host ? `${proto}://${host}` : req.get('host');

    return config.customHost || forwardedHost;
}

export const isAuthenticated = (req: AuthenticatedRequest): JwtPayload | false => {
    const token = req.signedCookies?.[cookieName] || req.headers['authorization'];
    if (!token) {
        return false;
    }
    try {
        const decoded = jwt.verify(token, jwtSecret) as jwt.JwtPayload;
        return decoded as JwtPayload;
    } catch (error) {
        return false;
    }
};

export const shouldLogin = (req: AuthenticatedRequest, res: Response) => {
    const apiRequest = req.headers['accept'] === 'application/json' || req.query.api === 'true';
    const originalUrl = req.headers['x-forwarded-uri'] || req.originalUrl || req.query.redirect;
    const redirect = getHost(req) + `/auth/login?redirect=${encodeURIComponent(originalUrl as string)}`;

    if (req.path === '/auth/login') {
        return;
    }
    res.clearCookie(cookieName);

    if (apiRequest) {
        return res.status(401).send({ error: 'Unauthorized', redirect });
    }

    return res.redirect(redirect)
}

export const isAuthenticatedMiddleware = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const user = isAuthenticated(req);
    if (user) {
        req.user = user;
        next();
    } else {
        shouldLogin(req, res);
    }
};