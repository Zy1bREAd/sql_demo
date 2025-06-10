FROM golang:1.24-alpine
WORKDIR /app
COPY go.mod go.sum ./
## 设置国内加速源下载依赖
RUN go env -w GOPROXY=https://goproxy.cn,direct && go mod download
COPY . .
RUN go build -o sql_demo .
EXPOSE 22899
ENTRYPOINT ["/app/sql_demo"]