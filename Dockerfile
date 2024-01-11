# Prepare
# FROM node:18.16.0-bullseye AS builder
# WORKDIR /home/node/app

# Install necessary packages
FROM node:18.16.0-bullseye AS installer
USER root
RUN apt-get update
RUN apt-get install -y g++ make python3
USER node
RUN mkdir -p /home/node/app
WORKDIR /home/node/app
COPY --chown=node:node package.json ./
RUN npm install --omit=dev

# Run app
FROM node:18.16.0-bullseye AS runner
USER root
RUN apt-get update
RUN apt-get install -y vim
RUN update-alternatives --config vi
RUN mkdir -p /usr/local/etc/utimaco
RUN chown node:node /usr/local/etc/utimaco
COPY --chown=node:node config/cs_pkcs11_r3.cfg /usr/local/etc/utimaco/cs_pkcs11_R3.cfg
# COPY --chown=node:node x86-64-2 ./x86-64-2
USER node
RUN mkdir -p /home/node/app
WORKDIR /home/node/app
COPY --from=installer /home/node/app .
