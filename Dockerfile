FROM node:18-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY src/ ./src/
COPY public/ ./public/
RUN mkdir -p /app/data
EXPOSE 4001
CMD ["node", "src/server.js"]
