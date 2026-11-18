FROM node:20-alpine
WORKDIR /app
RUN npm config set fund false && npm config set audit false
CMD ["sh","-lc","npm init -y >/dev/null 2>&1 && npm install"]
