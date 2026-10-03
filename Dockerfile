FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /out/mattermost-agent-registrar .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/mattermost-agent-registrar /mattermost-agent-registrar
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/mattermost-agent-registrar"]
