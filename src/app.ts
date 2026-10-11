import path from 'path';
import express, { type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import type { Config } from './config';
import { shouldLogin } from './common';
import { createAuthRouter } from './routers/authRouter';

export function createApp(config: Config): express.Express {
    const app = express();
    app.disable('x-powered-by');
    app.set('trust proxy', config.trustProxy);
    app.set('view engine', 'ejs');
    app.set('views', path.join(__dirname, '..', 'views'));
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'"],
                scriptSrc: ["'self'"],
                imgSrc: ["'self'"],
                formAction: ["'self'"],
                frameAncestors: ["'none'"],
                baseUri: ["'self'"],
                objectSrc: ["'none'"],
            },
        },
        crossOriginEmbedderPolicy: false,
    }));
    app.use(cookieParser(config.cookieSecret));
    app.use(rateLimit({
        windowMs: config.rateLimitWindowMs,
        max: config.rateLimitMax,
        standardHeaders: true,
        legacyHeaders: false,
    }));
    app.use('/assets', express.static(path.join(__dirname, '..', 'assets'), { index: false, dotfiles: 'deny' }));
    app.get('/health', (_req: Request, res: Response) => {
        res.type('text/plain').send('ok');
    });
    app.use('/auth', createAuthRouter(config));
    app.use((req: Request, res: Response) => {
        shouldLogin(config, req, res);
    });
    return app;
}
