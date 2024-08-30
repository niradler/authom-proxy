import express, { Request, Response, NextFunction } from 'express';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import ms from 'ms';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { config } from './config';
import packageJson from '../package.json';

dotenv.config();

const app = express();
// app.set('trust proxy', 'loopback')
const port = process.env.PORT || 3000;
const authRouter = express.Router();

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

// Add Helmet middleware
app.use(helmet());

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

// Middleware to check if the user is authenticated
const isAuthenticatedMiddleware = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const token = req.cookies?.[cookieName];
    if (!token) {
        return res.redirect('/auth/providers');
    }
    const user = isAuthenticated(token);
    if (user) {
        req.user = user;
        next();
    } else {
        res.clearCookie(cookieName);
        res.redirect('/auth/providers');
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

    if (req.query.redirect === 'true') {
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
            expires: new Date(Date.now() + ms(config.expiresIn)),
            sameSite: 'lax',
            domain: new URL(req.get('host') || '').hostname.split('.').slice(-2).join('.'),
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

authRouter.get('/providers', (req: Request, res: Response) => {
    const token = req.cookies?.[cookieName];
    const user = isAuthenticated(token);

    if (user) {
        // User is logged in
        res.send(`
        <html>
          <body>
            <h1>Logged In: ${user.email}</h1>
            <a href="/auth/logout">Logout</a>
          </body>
        </html>
      `);
    } else {
        // User is not logged in
        const providerList = Object.keys(providers).filter(provider => providers[provider].enabled).map(provider =>
            `<li><a href="/auth/${provider}/url?redirect=true">${provider}</a></li>`
        ).join('');

        res.send(`
        <html>
          <body>
            <h1>Available Providers</h1>
            <ul>${providerList}</ul>
          </body>
        </html>
      `);
    }
});

authRouter.get('/session', isAuthenticatedMiddleware, (req: AuthenticatedRequest, res: Response) => {
    res.setHeader('X-Forwarded-User', req.user?.email);
    res.json({ user: req.user });
});

authRouter.get('/logout', (req: Request, res: Response) => {
    res.clearCookie(cookieName);
    res.redirect('/auth/providers');
});

app.use('/auth', authRouter);

// Redirect all other routes to /auth/providers
app.use('*', (req: Request, res: Response) => {
    res.redirect('/auth/providers');
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});