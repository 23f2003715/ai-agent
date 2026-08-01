FROM node:22-alpine
WORKDIR /app
COPY package.json server.js ./
RUN mkdir -p /data && chown -R node:node /data
USER node
ENV PORT=8080 DATA_DIR=/data
EXPOSE 8080
CMD ["node", "server.js"]
