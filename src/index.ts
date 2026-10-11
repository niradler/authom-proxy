import { createApp } from './app';
import { loadConfig } from './config';

const config = loadConfig();
const app = createApp(config);
const server = app.listen(config.port, config.bindHost, () => {
    console.log(`listening on ${config.bindHost}:${config.port}`);
});
server.requestTimeout = 30_000;
server.headersTimeout = 10_000;
server.keepAliveTimeout = 65_000;

function shutdown(): void {
    const timer = setTimeout(() => process.exit(1), 10_000);
    timer.unref();
    server.close(() => process.exit(0));
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
