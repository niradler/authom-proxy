import dotenv from 'dotenv';
import fs from 'fs';
import providers from './providers';

dotenv.config();

type Provider = {
    enabled: boolean;
    authUrl: string;
    tokenUrl: string;
    profileUrl: string;
    clientId: string;
    clientSecret: string;
    scope: string;
};

type Config = {
    expiresIn: string;
    port: number;
    providers: Record<string, Provider>;
    allowedUsers: string[];
    jwtSecret: string;
};

class ConfigManager {
    private config: Config;

    constructor() {
        this.config = this.loadConfig();
    }

    private loadConfig(): Config {
        let configFile: Config | null = null;
        let providersFile: Record<string, Omit<Provider, 'enabled' | 'clientId' | 'clientSecret'>> | null = null;

        // Try to load config from file
        try {
            const rawConfig = fs.readFileSync('authom-proxy.json', 'utf8');
            configFile = JSON.parse(rawConfig);
        } catch (error) {
            console.warn('Could not load config from file, using environment variables', (error as Error).message);
        }

        const config: Config = {
            expiresIn: this.getConfigValue({ key: 'COOKIE_EXPIRES_IN', fileValue: configFile?.expiresIn, defaultValue: '6h' }),
            port: this.getConfigValue({ key: 'PORT', fileValue: configFile?.port, defaultValue: 3000 }),
            providers: {},
            allowedUsers: this.getConfigValue({
                key: 'ALLOWED_USERS',
                fileValue: configFile?.allowedUsers,
                defaultValue: [],
                transform: (value) => typeof value === 'string' ? value.split(',') : value as string[],
                required: true
            }),
            jwtSecret: this.getConfigValue({ key: 'JWT_SECRET', fileValue: configFile?.jwtSecret, defaultValue: '', required: true }),
        };

        // Fill in provider details
        for (const [providerName, providerDetails] of Object.entries(providers)) {
            const upperProviderName = providerName.toUpperCase();
            config.providers[providerName] = {
                enabled: this.getConfigValue({ key: `${upperProviderName}_CLIENT_ID`, fileValue: configFile?.providers?.[providerName]?.enabled, defaultValue: false }) ? true : false,
                authUrl: providerDetails.authUrl,
                tokenUrl: providerDetails.tokenUrl,
                profileUrl: providerDetails.profileUrl,
                clientId: this.getConfigValue({ key: `${upperProviderName}_CLIENT_ID`, fileValue: configFile?.providers?.[providerName]?.clientId, defaultValue: '' }),
                clientSecret: this.getConfigValue({ key: `${upperProviderName}_CLIENT_SECRET`, fileValue: configFile?.providers?.[providerName]?.clientSecret, defaultValue: '' }),
                scope: providerDetails.scope,
            };
        }

        return config;
    }

    private getConfigValue<T>({
        key,
        fileValue,
        defaultValue,
        transform,
        required = false
    }: {
        key: string,
        fileValue: T | undefined,
        defaultValue: T,
        transform?: (value: unknown) => T,
        required?: boolean
    }): T {
        const value = process.env[key] || fileValue || defaultValue;

        if (required && value === undefined) {
            throw new Error(`Missing required configuration value: ${key}`);
        }

        if (transform) {
            return transform(value);
        }

        return value as unknown as T;
    }

    public getConfig(): Config {
        return this.config;
    }
}

export const configManager = new ConfigManager();
export const config = configManager.getConfig();
