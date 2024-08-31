export default {
    "google": {
        "authUrl": "https://accounts.google.com/o/oauth2/v2/auth",
        "tokenUrl": "https://oauth2.googleapis.com/token",
        "profileUrl": "https://www.googleapis.com/oauth2/v1/userinfo",
        "scope": "https://www.googleapis.com/auth/userinfo.email"
    },
    "github": {
        "authUrl": "https://github.com/login/oauth/authorize",
        "tokenUrl": "https://github.com/login/oauth/access_token",
        "profileUrl": "https://api.github.com/user",
        "scope": "user:email"
    },
    "facebook": {
        "authUrl": "https://www.facebook.com/v12.0/dialog/oauth",
        "tokenUrl": "https://graph.facebook.com/v12.0/oauth/access_token",
        "profileUrl": "https://graph.facebook.com/me?fields=id,email",
        "scope": "email"
    },
    "twitter": {
        "authUrl": "https://twitter.com/i/oauth2/authorize",
        "tokenUrl": "https://api.twitter.com/2/oauth2/token",
        "profileUrl": "https://api.twitter.com/2/users/me",
        "scope": "users.read email"
    },
    "linkedin": {
        "authUrl": "https://www.linkedin.com/oauth/v2/authorization",
        "tokenUrl": "https://www.linkedin.com/oauth/v2/accessToken",
        "profileUrl": "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
        "scope": "r_emailaddress"
    },
    "microsoft": {
        "authUrl": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "tokenUrl": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "profileUrl": "https://graph.microsoft.com/v1.0/me",
        "scope": "user.read"
    },
    "apple": {
        "authUrl": "https://appleid.apple.com/auth/authorize",
        "tokenUrl": "https://appleid.apple.com/auth/authorize",
        "profileUrl": "https://appleid.apple.com/auth/userinfo",
        "scope": "email"
    },
    "amazon": {
        "authUrl": "https://www.amazon.com/ap/oa",
        "tokenUrl": "https://api.amazon.com/auth/o2/token",
        "profileUrl": "https://api.amazon.com/user/profile",
        "scope": "profile"
    },
    "yahoo": {
        "authUrl": "https://api.login.yahoo.com/oauth2/request_auth",
        "tokenUrl": "https://api.login.yahoo.com/oauth2/get_token",
        "profileUrl": "https://api.login.yahoo.com/openid/v1/userinfo",
        "scope": "openid email"
    },
    "discord": {
        "authUrl": "https://discord.com/api/oauth2/authorize",
        "tokenUrl": "https://discord.com/api/oauth2/token",
        "profileUrl": "https://discord.com/api/users/@me",
        "scope": "identify email"
    },
    "custom": {
        "authUrl": "https://customdomain.com/authorize",
        "tokenUrl": "https://customdomain.com/oauth2/token",
        "profileUrl": "https://customdomain.com/api/auth/userinfo",
        "scope": "email"
    },
}