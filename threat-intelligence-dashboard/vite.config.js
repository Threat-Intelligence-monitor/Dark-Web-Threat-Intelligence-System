import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

const apiTarget = process.env.VITE_API_TARGET || process.env.DARKWEB_API_TARGET || 'http://127.0.0.1:8000'
const frontendPort = Number(process.env.VITE_FRONTEND_PORT || process.env.DARKWEB_FRONTEND_PORT || 5174)
const allowedHosts = ['darkweb-monitor.threatbook-inc.cn']
const proxy = {
  '/healthcheck': {
    target: apiTarget,
    changeOrigin: true,
  },
  '/api': {
    target: apiTarget,
    changeOrigin: true,
    ws: true,
  },
  '/collector-output': {
    target: apiTarget,
    changeOrigin: true,
  },
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  server: {
    host: '0.0.0.0',
    port: frontendPort,
    allowedHosts,
    proxy,
  },
  preview: {
    host: '0.0.0.0',
    port: frontendPort,
    strictPort: true,
    allowedHosts,
    proxy,
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  css: {
    preprocessorOptions: {
      scss: {
        additionalData: `@use "@/styles/variables.scss" as *;`,
      },
    },
  },
})
