# 1. 依赖安装 & 构建阶段
FROM node:20-alpine AS builder

# 启用 corepack 管理 pnpm
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

WORKDIR /app

# 只复制依赖文件，利用缓存
COPY package.json pnpm-lock.yaml* ./

# 安装依赖（包含 devDependencies，便于构建）
RUN pnpm install --frozen-lockfile

# 复制全部源码
COPY . .

# 构建 Next.js 应用
RUN pnpm build

# 2. 运行阶段（更小的镜像，只含运行所需）
FROM node:20-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
ENV NEXT_TELEMETRY_DISABLED=1

# 复制仅运行所需的文件
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/pnpm-lock.yaml ./pnpm-lock.yaml

# 安装 pnpm 并仅安装生产依赖
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable && pnpm install --prod --frozen-lockfile

# 暴露端口
EXPOSE 3000

# 启动 Next.js 生产服务器
CMD ["pnpm", "start"]