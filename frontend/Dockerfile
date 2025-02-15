FROM node:14-alpine

WORKDIR /app

COPY package.json yarn.lock ./
RUN yarn install --frozen-lock-file

COPY . .

EXPOSE 3000

CMD ["yarn", "start"]
