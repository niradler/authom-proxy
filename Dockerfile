# Build stage
FROM node:lts-alpine AS build
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json .
COPY src ./src
RUN npm run build

# Production stage
FROM node:lts-alpine
WORKDIR /usr/src/app
COPY package*.json ./
COPY views ./views
COPY assets ./assets
RUN npm ci --only=production
COPY --from=build /usr/src/app/build ./build
EXPOSE 3000
RUN chown -R node /usr/src/app
USER node
CMD ["node", "build/index.js"]
