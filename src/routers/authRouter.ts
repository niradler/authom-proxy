import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import type { Request, Response } from 'express';
import type { Config } from '../config';
import { issueToken, isAuthenticatedMiddleware, readSession, shouldLogin, type AuthenticatedRequest } from '../common';
import { exchangeCode, fetchEmail } from '../oauth';
import { clearCookieOptions, codeChallenge, createCodeVerifier, createState, emailAllowed, pkceCookieOptions, safeRedirect, sessionCookieOptions, verifyState } from '../security';

export function createAuthRouter(config: Config): Router {
    const authRouter = Router();
    const authLimiter = rateLimit({
        windowMs: config.rateLimitWindowMs,
        max: config.authRateLimitMax,
        standardHeaders: true,
        legacyHeaders: false,
    });

    authRouter.get('/health', (_req: Request, res: Response) => {
        res.type('text/plain').send('ok');
    });

    authRouter.get('/:type/url', authLimiter, (req: Request, res: Response) => {
        const provider = enabledProvider(config, req.params.type);
        if (!provider) {
            res.status(400).send('Unsupported provider');
            return;
        }
        const redirect = safeRedirect(req.query.redirect);
        const state = createState(provider.name, redirect, config.jwtSecret);
        const verifier = createCodeVerifier();
        res.cookie(config.pkceCookieName, verifier, pkceCookieOptions(config));
        const redirectUri = callbackURL(config, provider.name);
        const authUrl = new URL(provider.authUrl);
        authUrl.searchParams.set('client_id', provider.clientId);
        authUrl.searchParams.set('redirect_uri', redirectUri);
        authUrl.searchParams.set('scope', provider.scope);
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('state', state);
        authUrl.searchParams.set('code_challenge', codeChallenge(verifier));
        authUrl.searchParams.set('code_challenge_method', 'S256');
        if (req.query.follow === 'true') {
            res.redirect(authUrl.toString());
            return;
        }
        res.type('text/plain').send(authUrl.toString());
    });

    authRouter.get('/:type/callback', authLimiter, async (req: Request, res: Response) => {
        const provider = enabledProvider(config, req.params.type);
        const code = typeof req.query.code === 'string' ? req.query.code : '';
        const state = typeof req.query.state === 'string' ? req.query.state : '';
        const verifier = typeof req.signedCookies?.[config.pkceCookieName] === 'string'
            ? req.signedCookies[config.pkceCookieName]
            : '';
        if (!provider || !code || !state || !verifier) {
            res.status(400).send('Invalid request');
            return;
        }
        res.clearCookie(config.pkceCookieName, clearCookieOptions(pkceCookieOptions(config)));
        try {
            const verified = verifyState(state, config.jwtSecret, provider.name);
            const accessToken = await exchangeCode({
                tokenUrl: provider.tokenUrl,
                clientId: provider.clientId,
                clientSecret: provider.clientSecret,
                code,
                redirectUri: callbackURL(config, provider.name),
                codeVerifier: verifier,
            });
            const email = await fetchEmail(provider.name, provider.profileUrl, accessToken);
            if (!email || !emailAllowed(email, config.allowedUsers)) {
                console.error(`Authentication rejected for provider ${provider.name}`);
                res.status(403).send('Authentication failed');
                return;
            }
            const token = issueToken(config, email);
            res.cookie(config.cookieName, token, sessionCookieOptions(config));
            res.redirect(verified.redirect);
        } catch (error) {
            const message = error instanceof Error ? error.message : 'authentication failed';
            console.error(`Authentication failed for provider ${provider.name}: ${message}`);
            res.status(500).send('Authentication failed');
        }
    });

    authRouter.get('/profile', isAuthenticatedMiddleware(config), (req: AuthenticatedRequest, res: Response) => {
        res.render('profile', { email: req.user?.email || '' });
    });

    authRouter.get('/session', (req: AuthenticatedRequest, res: Response) => {
        const user = readSession(config, req);
        if (!user) {
            shouldLogin(config, req, res);
            return;
        }
        res.setHeader('X-Forwarded-User', user.email);
        res.json({ user: { email: user.email } });
    });

    authRouter.get('/login', (req: Request, res: Response) => {
        const redirect = safeRedirect(req.query.redirect);
        const user = readSession(config, req);
        if (user) {
            res.redirect(redirect);
            return;
        }
        const providerList = Object.entries(config.providers)
            .filter(([, provider]) => provider.enabled)
            .map(([name]) => ({
                name,
                url: `/auth/${name}/url?follow=true&redirect=${encodeURIComponent(redirect)}`,
            }));
        res.render('login', { providers: providerList });
    });

    authRouter.get('/logout', (req: Request, res: Response) => {
        res.clearCookie(config.cookieName, clearCookieOptions(sessionCookieOptions(config)));
        res.redirect(`${config.publicURL}/auth/login`);
    });

    return authRouter;
}

function callbackURL(config: Config, provider: string): string {
    return `${config.publicURL}/auth/${provider}/callback`;
}

function enabledProvider(config: Config, type: string | undefined): (Config['providers'][string] & { name: string }) | undefined {
    if (!type) {
        return undefined;
    }
    const provider = config.providers[type];
    if (!provider?.enabled) {
        return undefined;
    }
    return { ...provider, name: type };
}
