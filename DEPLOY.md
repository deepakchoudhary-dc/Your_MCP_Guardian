# MCP Guardian Enterprise - Deployment Guide

## 🚀 Free Hosting Platforms

Your MCP Guardian project is ready to deploy! Here are the best free platforms:

### 1. **Cloudflare Pages** (Recommended)
- **Best for**: Static sites with global CDN
- **Free tier**: Unlimited sites, 500 builds/month, 100GB bandwidth
- **Deploy**: Connect GitHub repo, build command: `none`, output: `/`
- **URL**: https://dash.cloudflare.com/

### 2. **Vercel**
- **Best for**: Static + serverless functions
- **Free tier**: 100GB bandwidth, unlimited sites
- **Deploy**: Import from GitHub, framework: "Other", output: `/`
- **URL**: https://vercel.com/

### 3. **Netlify**
- **Best for**: JAMstack sites with forms/functions
- **Free tier**: 100GB bandwidth, 300 build minutes
- **Deploy**: Drag & drop or connect GitHub, publish dir: `/`
- **URL**: https://netlify.com/

### 4. **GitHub Pages**
- **Best for**: Simple static hosting
- **Free tier**: 1GB storage, 100GB bandwidth/month
- **Deploy**: Enable in repo Settings > Pages > Deploy from branch: master
- **URL**: Automatic at `https://deepakchoudhary-dc.github.io/Your_MCP_Guardian`

### 5. **Railway** (if you need Node.js server)
- **Best for**: Full-stack apps with databases
- **Free tier**: $5/month credits, sleeps after inactivity
- **Deploy**: Connect GitHub, auto-detects Node.js
- **URL**: https://railway.app/

## 📋 Quick Deploy Steps

### Option A: Static Hosting (Recommended)
1. Choose Cloudflare Pages or Vercel
2. Connect your GitHub repo: `deepakchoudhary-dc/Your_MCP_Guardian`
3. Build command: `none` (it's already built)
4. Output directory: `/` (serve from root)
5. Deploy!

### Option B: Node.js Hosting
1. Choose Railway or Render
2. Connect GitHub repo
3. Start command: `node live_server.js`
4. Environment: `PORT=3000`
5. Deploy!

## 🔧 Project Structure
- `index.html` - Entry point (redirects to main dashboard)
- `mcp_security_hub.html` - Primary dashboard
- `enterprise_security_hub.html` - Advanced enterprise dashboard
- `*.js` - Security scanner modules and AI components
- `live_server.js` - Local development server

## ⚡ Local Testing
```bash
node live_server.js
# Visit: http://localhost:3000
```

## 🌐 Production URLs (after deployment)
- Cloudflare Pages: `https://your-project.pages.dev`
- Vercel: `https://your-project.vercel.app`
- Netlify: `https://your-project.netlify.app`
- GitHub Pages: `https://deepakchoudhary-dc.github.io/Your_MCP_Guardian`

Choose your preferred platform and follow the deploy steps above!
