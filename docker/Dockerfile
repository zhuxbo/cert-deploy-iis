# escape=`

# Docker IIS 兼容性测试镜像
# 用法（在仓库根目录执行）:
#   docker build -f docker/Dockerfile --build-arg WINDOWS_VERSION=ltsc2022 -t sslctlw-test:2022 .

ARG WINDOWS_VERSION=ltsc2022
FROM mcr.microsoft.com/windows/servercore:${WINDOWS_VERSION}

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

# 安装 IIS
RUN Install-WindowsFeature Web-Server, Web-Mgmt-Tools; `
    if (!(Get-WindowsFeature Web-Server).Installed) { throw 'IIS installation failed' }

# 安装 Go
ARG GO_VERSION=1.26.8
RUN $url = \"https://go.dev/dl/go${env:GO_VERSION}.windows-amd64.zip\"; `
    Write-Host \"Downloading Go $env:GO_VERSION ...\"; `
    Invoke-WebRequest -Uri $url -OutFile C:\go.zip; `
    Expand-Archive C:\go.zip -DestinationPath C:\; `
    Remove-Item C:\go.zip; `
    [Environment]::SetEnvironmentVariable('PATH', \"C:\go\bin;$env:PATH\", 'Machine')

# 设置 Go 环境变量
ENV GOPATH=C:\gopath
ENV PATH="C:\go\bin;C:\gopath\bin;${PATH}"

# 先复制依赖文件，利用层缓存
WORKDIR C:\app
COPY go.mod go.sum ./
RUN go mod download

# 复制项目源码
COPY . .

# 复制脚本到固定位置
COPY docker/setup-iis.ps1 C:\scripts\setup-iis.ps1
COPY docker/entrypoint.ps1 C:\scripts\entrypoint.ps1

# 创建测试结果目录
RUN New-Item -ItemType Directory -Path C:\test-results -Force | Out-Null

ENTRYPOINT ["powershell", "-File", "C:\\scripts\\entrypoint.ps1"]
