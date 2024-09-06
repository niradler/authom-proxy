import express, { Request, Response } from 'express';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { getHost, isAuthenticatedMiddleware, isAuthenticated, shouldLogin, AuthenticatedRequest } from '../common';
import ms from 'ms';

const { providers } = config;
const authRouter = express.Router();

authRouter.get('/:type/url', (req: Request, res: Response) => {
    const { type } = req.params;
    const { redirect } = req.query;
    const provider = config.providers[type];

    if (!provider) {
        return res.status(400).send('Unsupported provider');
    }

    const state = Buffer.from(JSON.stringify({ redirect })).toString('base64url');
    const authUrl = `${provider.authUrl}?client_id=${provider.clientId}&redirect_uri=${encodeURIComponent(`${req.protocol}://${getHost(req)}/auth/${type}/callback`)}&scope=${encodeURIComponent(provider.scope)}&response_type=code&state=${state}`;
    if (req.query.follow === 'true') {
        res.redirect(authUrl);
    } else {
        res.send(authUrl);
    }
});

authRouter.get('/:type/callback', async (req: Request, res: Response) => {
    const { type } = req.params;
    const { code, state } = req.query;
    const provider = config.providers[type];

    if (!provider || !code || typeof code !== 'string' || typeof state !== 'string') {
        return res.status(400).send('Invalid request');
    }

    try {
        // Exchange code for token
        const tokenResponse = await axios.post(provider.tokenUrl, {
            client_id: provider.clientId,
            client_secret: provider.clientSecret,
            code,
            redirect_uri: `${req.protocol}://${getHost(req)}/auth/${type}/callback`,
            grant_type: 'authorization_code',
        });

        const accessToken = tokenResponse.data.access_token;

        // Get user profile
        const profileResponse = await axios.get(provider.profileUrl, {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        const userEmail = profileResponse.data.email;

        if (!config.allowedUsers.includes(userEmail)) {
            return res.status(403).send('User not authorized');
        }

        // Create JWT
        const token = jwt.sign({ email: userEmail, createdAt: new Date().toUTCString() }, config.jwtSecret, { expiresIn: config.expiresIn });

        // Set cookie
        res.cookie(config.cookieName, token, {
            httpOnly: true,
            secure: process.env.NODE_ENV !== 'dev',
            sameSite: 'lax',
            domain: process.env.NODE_ENV !== 'dev' ? new URL(getHost(req) || '').hostname.split('.').slice(-2).join('.') : undefined,
            maxAge: ms(config.expiresIn) / 1000,
            signed: true
        });

        // Redirect to original URL if provided
        const decodedState = JSON.parse(Buffer.from(state, 'base64url').toString());
        res.setHeader('X-Forwarded-User', userEmail);
        res.setHeader('Authorization', `Bearer ${token}`);
        res.redirect(decodedState.redirect || '/');
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).send('Authentication failed');
    }
});

authRouter.get('/profile', isAuthenticatedMiddleware, (req: Request, res: Response) => {
    // @ts-expect-error
    res.render('profile', { email: req.user.email });
});

authRouter.get('/session', isAuthenticatedMiddleware, (req: AuthenticatedRequest, res: Response) => {
    res.setHeader('X-Forwarded-User', req.user?.email);
    res.json({ user: req.user });
});

authRouter.get('/login', (req: Request, res: Response) => {
    const user = isAuthenticated(req);
    const redirect = req.query.redirect || '/auth/profile';
    if (user) {
        res.redirect(redirect as string);
    } else {
        const providerList = Object.keys(providers)
            .filter(provider => config.providers[provider].enabled)
            .map(provider => ({
                name: provider,
                url: `/auth/${provider}/url?follow=true&redirect=${redirect}`
            }));

        res.render('login', { providers: providerList });
    }
});

authRouter.get('/logout', (req: Request, res: Response) => {
    shouldLogin(req, res);
});

export default authRouter;