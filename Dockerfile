# 使用官方Go镜像作为基础镜像
FROM golang:1.24-alpine
 
# 设置工作目录
WORKDIR /app
 
# 单独复制mod和sum文件，去下载依赖
COPY go.mod go.sum ./
RUN go env -w GOPROXY=https://goproxy.cn,direct && go mod download
 
# 复制源代码到容器中
COPY . .
 
# 编译Go程序并将其创建为一个静态链接的二进制文件
RUN go build -o sql_demo .
EXPOSE 22899
# 设置容器在运行时默认执行的命令
ENTRYPOINT ["/app/sql_demo"]