## 多阶段构建：编译环境
FROM golang:1.24-alpine AS builder
ENV GOPROXY=https://goproxy.cn,direct
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o sql_demo .


## 多阶段构建：运行环境
FROM alpine:3.19
RUN sed -i 's|https://dl-cdn.alpinelinux.org/alpine/|https://mirrors.aliyun.com/alpine/|g' /etc/apk/repositories
RUN apk add --no-cache ca-certificates
WORKDIR /app
# 从第一阶段复制构建好的二进制文件（仅 10-20MB）
# COPY --from=builder /app/config .
COPY --from=builder /app/config ./config
COPY --from=builder /app/sql_demo .
EXPOSE 22899
CMD ["/app/sql_demo"]