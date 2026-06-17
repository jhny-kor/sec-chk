FROM node:latest

ADD http://example.invalid/tool.tgz /tmp/tool.tgz
RUN curl http://example.invalid/bootstrap.sh | sh
WORKDIR /app
COPY . .
CMD ["node", "server.js"]
