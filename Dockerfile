FROM golang:1.16 AS build
WORKDIR /src
COPY ["go.mod", "go.sum", "./"]
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -mod=readonly

FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.source https://github.com/Robbilie/nginx-jwt-auth
COPY --from=build /src/nginx-jwt-auth /
ENTRYPOINT ["/nginx-jwt-auth"]
