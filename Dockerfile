FROM golang:bookworm AS build-stage
WORKDIR /go/src/app
COPY . .

RUN apt-get -y update && apt-get -y install wget gpg lsb-release && \
    wget -O - https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list && \
    apt-get -y update && apt-get -y install vault

RUN go get -v ./...
RUN go install -v ./...

FROM debian:bookworm AS export-stage
COPY --from=build-stage /go/bin/pgcustodian /usr/bin/pgcustodian
COPY --from=build-stage /usr/bin/vault /usr/bin/vault

CMD /usr/bin/pgcustodian
