# Team Secret Store — VPS + Cloudflare Tunnel build

This build runs the storefront and API from one Node/Express process on the VPS.

## URLs

- Storefront: `https://shop.teamsecret.in/`
- Admin login/dashboard: `https://shop.teamsecret.in/admin`
- API health: `https://shop.teamsecret.in/api/health`

The public storefront contains no Admin button or admin UI. The admin URL is intentionally not linked from the storefront. Admin API routes still require a valid admin JWT, so hiding the URL is not treated as security.

## Project structure

```text
public/
  index.html       customer storefront
  admin.html       separate admin login/dashboard
  404.html
  config.js        public browser config
backend/
  server.js        Express + MongoDB API
  package.json
  .env.example
README.md
```

Only `public/` is served as static web content. The `backend/` source is not exposed by Express.

## Backend environment

Create `/root/e-com/backend/.env`:

```env
PORT=3000
HOST=127.0.0.1
MONGODB_URI=YOUR_MONGODB_URI
MONGODB_DB=team_secret_store
ADMIN_PASSWORD=YOUR_STRONG_ADMIN_PASSWORD
JWT_SECRET=YOUR_32_PLUS_CHARACTER_SECRET
FRONTEND_ORIGINS=https://shop.teamsecret.in,http://127.0.0.1:3000,http://localhost:3000
GOOGLE_CLIENT_ID=
```

For same-domain hosting, `public/config.js` should keep:

```js
API_BASE_URL: ""
```

## Run on VPS

```bash
cd /root/e-com/backend
npm install
npm start
```

Test:

```bash
curl http://127.0.0.1:3000/api/health
curl -I http://127.0.0.1:3000/
curl -I http://127.0.0.1:3000/admin
```

## Run permanently with PM2

```bash
cd /root/e-com/backend
pm2 start server.js --name e-com
pm2 save
pm2 startup
```

After editing `.env` or backend code:

```bash
pm2 restart e-com
```

## Cloudflare Tunnel

Point the public hostname to:

```text
shop.teamsecret.in -> http://127.0.0.1:3000
```

No Nginx is required.

## Admin features

The separate admin dashboard includes:

- dashboard counters for products, orders, pending orders, and users
- full order list with status filter
- order status update: pending / paid / delivered / rejected
- product add / edit / delete
- user list with order count and ordered value
- UPI setting
- admin password change

## Order security

- MongoDB URI and JWT secret stay only in `backend/.env`
- admin password is verified by the backend
- `/api/admin/*` routes require a signed admin JWT
- product price is recalculated on the server from MongoDB
- download links are returned to customers only after an order is `paid` or `delivered`

## MongoDB collections

The backend uses:

```text
products
users
orders
settings
admin_config
```

## Google login

The backend already supports Google credential verification through `GOOGLE_CLIENT_ID`. Google Sign-In still needs a real Google Client ID configured before it becomes active.
