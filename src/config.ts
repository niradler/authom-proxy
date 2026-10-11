import dotenv from 'dotenv';
import fs from 'fs';
import providers from './providers';

export type ProviderConfig = {
    enabled: boolean;
    authUrl: string;
    tokenUrl: string;
    profileUrl: string;
    clientId: string;
    clientSecret: string;
    scope: string;
};

export type Config = {
    publicURL: string;
    bindHost: string;
    expiresInSeconds: number;
    maxAgeMs: number;
    port: number;
    providers: Record<string, ProviderConfig>;
    allowedUsers: string[];
    jwtSecret: string;
    cookieSecret: string;
    cookieName: string;
    pkceCookieName: string;
    rateLimitWindowMs: number;
    rateLimitMax: number;
    authRateLimitMax: number;
    trustProxy: boolean | number | string;
};

type FileConfig = {
    expiresIn?: unknown;
    publicURL?: unknown;
    port?: unknown;
    providers?: Record<string, Partial<ProviderConfig>>;
    allowedUsers?: unknown;
    jwtSecret?: unknown;
    cookieSecret?: unknown;
    cookieName?: unknown;
    rateLimitWindow?: unknown;
    rateLimitMax?: unknown;
    bindHost?: unknown;
};

const durationUnits: Record<string, number> = {
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
};

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
    dotenv.config();
    const fileConfig = readFileConfig();
    const expiresIn = readString(env.COOKIE_EXPIRES_IN || env.EXPIRES_IN, fileConfig?.expiresIn, '8h');
    const maxAgeMs = parseDuration(expiresIn);
    const publicURL = parsePublicURL(readString(env.PUBLIC_URL, fileConfig?.publicURL, ''));
    const jwtSecret = readString(env.JWT_SECRET, fileConfig?.jwtSecret, '');
    const cookieSecret = readString(env.COOKIE_SECRET, fileConfig?.cookieSecret, '');
    requireSecret('JWT_SECRET', jwtSecret);
    requireSecret('COOKIE_SECRET', cookieSecret);

    const config: Config = {
        publicURL,
        bindHost: readString(env.BIND_HOST, fileConfig?.bindHost, '127.0.0.1'),
        expiresInSeconds: Math.floor(maxAgeMs / 1000),
        maxAgeMs,
        port: readPort(env.PORT, fileConfig?.port),
        providers: {},
        allowedUsers: readUsers(env.ALLOWED_USERS, fileConfig?.allowedUsers),
        jwtSecret,
        cookieSecret,
        cookieName: readString(env.COOKIE_NAME, fileConfig?.cookieName, 'authom-authorization'),
        pkceCookieName: 'authom-pkce',
        rateLimitWindowMs: readNumber(env.RATE_LIMIT_WINDOW, fileConfig?.rateLimitWindow, 5 * 60 * 1000),
        rateLimitMax: readNumber(env.RATE_LIMIT_MAX, fileConfig?.rateLimitMax, 300),
        authRateLimitMax: readNumber(env.AUTH_RATE_LIMIT_MAX, undefined, 30),
        trustProxy: readTrustProxy(env.TRUST_PROXY),
    };

    for (const [providerName, providerDetails] of Object.entries(providers)) {
        const upper = providerName.toUpperCase();
        const fileProvider = fileConfig?.providers?.[providerName];
        const clientId = readString(env[`${upper}_CLIENT_ID`], fileProvider?.clientId, '');
        const clientSecret = readString(env[`${upper}_CLIENT_SECRET`], fileProvider?.clientSecret, '');
        const authUrl = readString(env[`${upper}_AUTH_URL`], fileProvider?.authUrl, providerDetails.authUrl);
        const tokenUrl = readString(env[`${upper}_TOKEN_URL`], fileProvider?.tokenUrl, providerDetails.tokenUrl);
        const profileUrl = readString(env[`${upper}_PROFILE_URL`], fileProvider?.profileUrl, providerDetails.profileUrl);
        const scope = readString(env[`${upper}_SCOPE`], fileProvider?.scope, providerDetails.scope);
        const enabled = Boolean(clientId && clientSecret && !isPlaceholder(authUrl) && !isPlaceholder(tokenUrl) && !isPlaceholder(profileUrl));
        if (enabled) {
            assertHttpsURL(`${upper}_AUTH_URL`, authUrl);
            assertHttpsURL(`${upper}_TOKEN_URL`, tokenUrl);
            assertHttpsURL(`${upper}_PROFILE_URL`, profileUrl);
        }
        config.providers[providerName] = {
            enabled,
            clientId,
            clientSecret,
            authUrl,
            tokenUrl,
            profileUrl,
            scope,
        };
    }

    if (!Object.values(config.providers).some((provider) => provider.enabled)) {
        throw new Error('At least one OAuth provider must be configured');
    }
    return config;
}

function readFileConfig(): FileConfig | undefined {
    try {
        return JSON.parse(fs.readFileSync('authom-proxy.json', 'utf8')) as FileConfig;
    } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== 'ENOENT') {
            throw new Error('authom-proxy.json could not be parsed');
        }
        return undefined;
    }
}

function readString(envValue: string | undefined, fileValue: unknown, fallback: string): string {
    if (typeof envValue === 'string' && envValue.trim() !== '') {
        return envValue.trim();
    }
    if (typeof fileValue === 'string' && fileValue.trim() !== '') {
        return fileValue.trim();
    }
    return fallback;
}

function readNumber(envValue: string | undefined, fileValue: unknown, fallback: number): number {
    const candidate = envValue !== undefined && envValue.trim() !== '' ? envValue : fileValue;
    if (typeof candidate === 'number' && Number.isFinite(candidate)) {
        return candidate;
    }
    if (typeof candidate === 'string' && candidate.trim() !== '') {
        const parsed = Number(candidate);
        if (Number.isFinite(parsed)) {
            return parsed;
        }
    }
    return fallback;
}

function readPort(envValue: string | undefined, fileValue: unknown): number {
    const port = readNumber(envValue, fileValue, 3000);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error('PORT must be an integer from 1 to 65535');
    }
    return port;
}

function readUsers(envValue: string | undefined, fileValue: unknown): string[] {
    let source: string[] = [];
    if (typeof envValue === 'string' && envValue.trim() !== '') {
        source = envValue.split(',');
    } else if (Array.isArray(fileValue)) {
        source = fileValue.filter((item): item is string => typeof item === 'string');
    } else if (typeof fileValue === 'string') {
        source = fileValue.split(',');
    }
    const users = source.map((user) => user.trim().toLowerCase()).filter(Boolean);
    if (users.length === 0) {
        throw new Error('ALLOWED_USERS must list at least one email');
    }
    return users;
}

function requireSecret(name: string, value: string): void {
    if (value.length < 32) {
        throw new Error(`${name} must be at least 32 characters`);
    }
}

function parseDuration(value: string): number {
    const match = /^(\d+)([smhd])$/.exec(value.trim());
    if (!match || !match[1] || !match[2]) {
        throw new Error('COOKIE_EXPIRES_IN must look like 8h');
    }
    const unit = durationUnits[match[2]];
    if (!unit) {
        throw new Error('COOKIE_EXPIRES_IN must look like 8h');
    }
    const duration = Number(match[1]) * unit;
    if (duration < 60 * 1000 || duration > 24 * 60 * 60 * 1000) {
        throw new Error('COOKIE_EXPIRES_IN must be between 1m and 24h');
    }
    return duration;
}

function parsePublicURL(value: string): string {
    let parsed: URL;
    try {
        parsed = new URL(value);
    } catch {
        throw new Error('PUBLIC_URL must be an absolute http(s) URL');
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
        throw new Error('PUBLIC_URL must be an absolute http(s) URL');
    }
    if (parsed.username || parsed.password || (parsed.pathname !== '/' && parsed.pathname !== '')) {
        throw new Error('PUBLIC_URL must be an origin without a path, user, or password');
    }
    return parsed.origin;
}

function assertHttpsURL(name: string, value: string): void {
    let parsed: URL;
    try {
        parsed = new URL(value);
    } catch {
        throw new Error(`${name} must be an absolute https URL`);
    }
    const local = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
    if (parsed.protocol === 'https:' || (parsed.protocol === 'http:' && local)) {
        return;
    }
    throw new Error(`${name} must be an absolute https URL`);
}

function isPlaceholder(value: string): boolean {
    return value.includes('customdomain.com');
}

function readTrustProxy(value: string | undefined): boolean | number | string {
    if (value === undefined || value.trim() === '' || value === 'loopback') {
        return 'loopback';
    }
    if (value === 'true') {
        return 1;
    }
    if (value === 'false') {
        return false;
    }
    const hops = Number(value);
    if (Number.isInteger(hops) && hops >= 0 && hops <= 5) {
        return hops;
    }
    throw new Error('TRUST_PROXY must be loopback, false, or a hop count from 0 to 5');
}
