import express, { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser'
import morgan from 'morgan';
import helmet from 'helmet';
import { config } from './config';
import { shouldLogin } from './common';
import authRouter from './routers/authRouter';
import packageJson from '../package.json';
import path from 'path';

const app = express();
app.set('trust proxy', 'loopback');
const port = config.port || 3000;
const limiter = rateLimit({
    windowMs: config.rateLimitWindow,
    max: config.rateLimitMax // limit per windowMs
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

app.use('/assets', express.static(path.join(__dirname, '..', 'assets')));
app.use(morgan(':method :url :status :response-time ms'));
app.use(helmet());
app.use(cookieParser(config.cookieSecret))
app.use(limiter);
app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Authom-Proxy-Version', packageJson.version);
    next();
});

app.use('/auth', authRouter);

// Redirect all other routes to /auth/login
app.use('*', (req: Request, res: Response) => {
    shouldLogin(req, res);
});

app.listen(port, () => {
    console.log(`Server running on port http://localhost:${port}`);
});