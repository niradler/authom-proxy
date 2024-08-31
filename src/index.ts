import express, { Request, Response, NextFunction } from 'express';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import ms from 'ms';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser'
import morgan from 'morgan';
import helmet from 'helmet';
import { config } from './config';
import packageJson from '../package.json';
import path from 'path';

dotenv.config();

const app = express();
app.set('trust proxy', 'loopback');
const port = process.env.PORT || 3000;
const authRouter = express.Router();

// Set view engine and views folder
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
// Serve static files from the 'assets' directory
app.use('/assets', express.static(path.join(__dirname, '..', 'assets')));
app.use(morgan(':method :url :status :response-time ms'));
type JwtPayload = {
    email: string;
    createdAt: string;
};

const providers = config.providers;
const allowedUsers = config.allowedUsers;
const jwtSecret = config.jwtSecret;
const cookieName = 'authom-authorization';

// Extend the Request type to include the user property
interface AuthenticatedRequest extends Request {
    user?: jwt.JwtPayload;
}

// Add Helmet middleware
app.use(helmet());

app.use(cookieParser(config.cookieSecret))

// Add rate limiter
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Middleware to add version header to all responses
app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Authom-Proxy-Version', packageJson.version);
    next();
});

const isAuthenticated = (token?: string): JwtPayload | false => {
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

const shouldLogin = (req: AuthenticatedRequest, res: Response) => {
    const originalUrl = req.headers['x-forwarded-uri'] || req.originalUrl;
    const redirect = `/auth/login?redirect=${encodeURIComponent(originalUrl as string)}`;

    if (req.path === '/auth/login') {
        return;
    }
    res.clearCookie(cookieName);

    return res.redirect(redirect)
}

// Middleware to check if the user is authenticated
const isAuthenticatedMiddleware = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const token = req.signedCookies?.[cookieName];
    if (!token) {
        return shouldLogin(req, res);
    }
    const user = isAuthenticated(token);
    if (user) {
        req.user = user;
        next();
    } else {
        shouldLogin(req, res);
    }
};

authRouter.get('/:type/url', (req: Request, res: Response) => {
    const { type } = req.params;
    const { redirect } = req.query;
    const provider = providers[type];

    if (!provider) {
        return res.status(400).send('Unsupported provider');
    }

    const state = Buffer.from(JSON.stringify({ redirect })).toString('base64url');
    const authUrl = `${provider.authUrl}?client_id=${provider.clientId}&redirect_uri=${encodeURIComponent(`${req.protocol}://${req.get('host')}/auth/${type}/callback`)}&scope=${encodeURIComponent(provider.scope)}&response_type=code&state=${state}`;
    if (req.query.follow === 'true') {
        res.redirect(authUrl);
    } else {
        res.send(authUrl);
    }
});

authRouter.get('/:type/callback', async (req: Request, res: Response) => {
    const { type } = req.params;
    const { code, state } = req.query;
    const provider = providers[type];

    if (!provider || !code || typeof code !== 'string' || typeof state !== 'string') {
        return res.status(400).send('Invalid request');
    }

    try {
        // Exchange code for token
        const tokenResponse = await axios.post(provider.tokenUrl, {
            client_id: provider.clientId,
            client_secret: provider.clientSecret,
            code,
            redirect_uri: `${req.protocol}://${req.get('host')}/auth/${type}/callback`,
            grant_type: 'authorization_code',
        });

        const accessToken = tokenResponse.data.access_token;

        // Get user profile
        const profileResponse = await axios.get(provider.profileUrl, {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        const userEmail = profileResponse.data.email;

        if (!allowedUsers.includes(userEmail)) {
            return res.status(403).send('User not authorized');
        }

        // Create JWT
        const token = jwt.sign({ email: userEmail, createdAt: new Date().toUTCString() }, jwtSecret, { expiresIn: config.expiresIn });

        // Set cookie
        res.cookie(cookieName, token, {
            httpOnly: true,
            secure: process.env.NODE_ENV !== 'dev',
            sameSite: 'lax',
            domain: process.env.NODE_ENV !== 'dev' ? new URL(req.get('host') || '').hostname.split('.').slice(-2).join('.') : undefined,
            maxAge: ms(config.expiresIn) / 1000,
            signed: true
        });

        // Redirect to original URL if provided
        const decodedState = JSON.parse(Buffer.from(state, 'base64url').toString());
        res.setHeader('X-Forwarded-User', userEmail);
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

authRouter.get('/login', (req: Request, res: Response) => {
    const token = req.signedCookies?.[cookieName];
    const redirect = req.query.redirect || '/auth/profile';
    if (token) {
        res.redirect('/auth/profile');
    } else {
        const providerList = Object.keys(providers)
            .filter(provider => providers[provider].enabled)
            .map(provider => ({
                name: provider,
                url: `/auth/${provider}/url?follow=true&redirect=${redirect}`
            }));

        res.render('login', { providers: providerList });
    }
});

authRouter.get('/session', isAuthenticatedMiddleware, (req: AuthenticatedRequest, res: Response) => {
    res.setHeader('X-Forwarded-User', req.user?.email);
    res.json({ user: req.user });
});

authRouter.get('/logout', (req: Request, res: Response) => {
    shouldLogin(req, res);
});

app.use('/auth', authRouter);

// Redirect all other routes to / auth / login
app.use('*', (req: Request, res: Response) => {
    shouldLogin(req, res);
});

app.listen(port, () => {
    console.log(`Server running on port http://localhost:${port}`);
});