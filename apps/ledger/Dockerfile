# Build the Kokuin Ledger app using the official Ledger app builder
#
# Usage:
#   docker build -t kokuin-ledger-app .
#   docker run --rm -v $(pwd)/bin:/app/bin kokuin-ledger-app
#
# Build for a specific device:
#   docker run --rm -e BOLOS_SDK=$NANOSP_SDK kokuin-ledger-app
#   docker run --rm -e BOLOS_SDK=$STAX_SDK kokuin-ledger-app

FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest

WORKDIR /app
COPY . .

RUN git init .
CMD ["bash", "-c", "BOLOS_SDK=$NANOSP_SDK COIN=KOK make"]
