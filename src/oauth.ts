export async function exchangeCode(input: {
    tokenUrl: string;
    clientId: string;
    clientSecret: string;
    code: string;
    redirectUri: string;
    codeVerifier: string;
}): Promise<string> {
    const body = new URLSearchParams({
        client_id: input.clientId,
        client_secret: input.clientSecret,
        code: input.code,
        redirect_uri: input.redirectUri,
        grant_type: 'authorization_code',
        code_verifier: input.codeVerifier,
    });
    const payload = await requestJSON(input.tokenUrl, {
        method: 'POST',
        headers: {
            'content-type': 'application/x-www-form-urlencoded',
            accept: 'application/json',
        },
        body,
    });
    const accessToken = readStringField(payload, 'access_token');
    if (!accessToken) {
        throw new Error('token response did not include an access token');
    }
    return accessToken;
}

export async function fetchEmail(providerName: string, profileUrl: string, accessToken: string): Promise<string | undefined> {
    const profile = await requestJSON(profileUrl, {
        method: 'GET',
        headers: authHeaders(accessToken),
    });
    const direct = findEmail(profile);
    if (direct) {
        return direct;
    }
    if (providerName !== 'github') {
        return undefined;
    }
    const emails = await requestJSON('https://api.github.com/user/emails', {
        method: 'GET',
        headers: authHeaders(accessToken),
    });
    return githubPrimaryEmail(emails);
}

async function requestJSON(url: string, init: RequestInit): Promise<unknown> {
    const response = await fetch(url, {
        ...init,
        redirect: 'error',
        signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) {
        throw new Error(`upstream returned ${response.status}`);
    }
    const text = await response.text();
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        return JSON.parse(text) as unknown;
    }
    return Object.fromEntries(new URLSearchParams(text));
}

function authHeaders(accessToken: string): Record<string, string> {
    return {
        authorization: `Bearer ${accessToken}`,
        accept: 'application/json',
        'user-agent': 'authom-proxy',
    };
}

function findEmail(value: unknown, depth = 0): string | undefined {
    if (!value || typeof value !== 'object' || depth > 2) {
        return undefined;
    }
    const record = value as Record<string, unknown>;
    for (const key of ['email', 'mail', 'userPrincipalName', 'confirmed_email']) {
        const item = record[key];
        if (typeof item === 'string' && item.includes('@')) {
            return item.trim().toLowerCase();
        }
    }
    if (record.data) {
        return findEmail(record.data, depth + 1);
    }
    return undefined;
}

function githubPrimaryEmail(value: unknown): string | undefined {
    if (!Array.isArray(value)) {
        return undefined;
    }
    const primary = value.find((item) => {
        if (!item || typeof item !== 'object') {
            return false;
        }
        const record = item as Record<string, unknown>;
        return record.primary === true && record.verified === true && typeof record.email === 'string';
    }) as Record<string, unknown> | undefined;
    if (!primary || typeof primary.email !== 'string') {
        return undefined;
    }
    return primary.email.trim().toLowerCase();
}

function readStringField(value: unknown, key: string): string | undefined {
    if (!value || typeof value !== 'object') {
        return undefined;
    }
    const item = (value as Record<string, unknown>)[key];
    return typeof item === 'string' && item.length > 0 ? item : undefined;
}
