# Team Secret Store — VPS + Cloudflare Tunnel hardened build

This build serves the storefront and API from one Node/Express process on the VPS.

## URLs

- Storefront: `https://shop.teamsecret.in/`
- Admin login/dashboard: `https://shop.teamsecret.in/admin`
- API health: `https://shop.teamsecret.in/api/health`

The public storefront contains no Admin button or admin UI. The admin URL is intentionally not linked from the storefront. Hiding the URL is not treated as security: every admin API remains authenticated on the backend.

## Project structure

```text
public/
  index.html       customer storefront
  admin.html       separate admin login/dashboard
  404.html
  config.js        public browser config
  uploads/products/ generated product images (created automatically)
backend/
  server.js        Express + MongoDB API
  package.json
  .env.example
README.md
```

Only `public/` is served as static web content. `backend/`, `.env`, MongoDB credentials and source code are not exposed by Express.

## Backend environment

Create `/root/e-com/backend/.env`:

```env
PORT=3000
HOST=127.0.0.1

MONGODB_URI=YOUR_MONGODB_URI
MONGODB_DB=team_secret_store

ADMIN_PASSWORD=YOUR_STRONG_ADMIN_PASSWORD
ADMIN_MAX_LOGIN_ATTEMPTS=5
ADMIN_LOCK_MINUTES=15

JWT_SECRET=YOUR_32_PLUS_CHARACTER_SECRET

FRONTEND_ORIGINS=https://shop.teamsecret.in,http://127.0.0.1:3000,http://localhost:3000
GOOGLE_CLIENT_ID=

API_RATE_LIMIT_PER_MINUTE=180
AUTH_RATE_LIMIT_PER_15_MIN=20
ORDER_RATE_LIMIT_PER_10_MIN=10
ADMIN_READ_PAGE_SIZE=50
PRODUCT_IMAGE_MAX_MB=2
```

Do not put `.env` in GitHub.

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

## PM2

```bash
cd /root/e-com/backend
pm2 start server.js --name e-com
pm2 save
pm2 startup
```

After changing `.env` or backend code:

```bash
pm2 restart e-com
```

If you changed environment variables that PM2 itself provided, use:

```bash
pm2 restart e-com --update-env
```

## Cloudflare Tunnel

Point the public hostname to:

```text
shop.teamsecret.in -> http://127.0.0.1:3000
```

No Nginx is required. Keep Node bound to `127.0.0.1`; do not expose port 3000 publicly in the VPS firewall/security group.

## Security protections included

### Request / DoS hardening

- global `/api` rate limit (default 180 requests/IP/minute)
- stricter authentication rate limit
- order creation limit (default 10 attempts/IP/10 minutes)
- admin write/action limiter
- JSON request body capped at 32 KB
- URL-encoded body capped at 16 KB
- max form parameter count
- unsafe `$...`, dotted, prototype-pollution style body keys rejected
- deeply nested / excessive body structures rejected
- request/header/keep-alive timeouts configured
- MongoDB connection pool and socket timeouts capped
- DB queries use short `maxTimeMS` limits where practical
- admin orders/users are paginated rather than loading hundreds/thousands at once

### Admin protection

- public store has no admin link
- admin is a separate `/admin` page
- 5 wrong passwords (configurable) lock that source for 15 minutes (configurable)
- failed-login lock data is stored in MongoDB, so PM2 restart does not clear it
- additional network-level admin login rate limiter
- admin JWT is stored in an **HttpOnly + SameSite=Strict cookie**, not JavaScript/sessionStorage
- admin password change increments a token version and invalidates old admin sessions
- admin responses are `no-store`
- `/admin` is `noindex/nofollow`

### Input/data protection

- names, emails, UTRs, product titles/descriptions, UPI IDs, prices, quantities and URLs have server-side length/type validation
- product types and order statuses use allowlists
- download links must be HTTPS
- UTR reuse is rejected by application logic
- cart price is ignored from the browser; current product prices are recalculated from MongoDB
- download links are only returned to customers for `paid` or `delivered` orders
- MongoDB query objects are constructed server-side instead of accepting raw filters from clients

### Browser/security headers

- Helmet security headers
- Content Security Policy with only the required Google Sign-In/font origins
- clickjacking blocked (`frame-ancestors 'none'` / frame headers)
- MIME sniffing protections
- HSTS
- restrictive Permissions-Policy
- exact browser-origin CORS allowlist
- mutation endpoints require `application/json`

## Important DDoS note

Application limits protect Node/MongoDB from ordinary abuse and many Layer-7 attacks, but no Node code can absorb a large volumetric DDoS by itself. Keep the site behind Cloudflare Tunnel and enable Cloudflare WAF/rate-limit/bot protections as appropriate. The origin stays private because Node listens only on `127.0.0.1`.

## Admin dashboard

- real total product/order/pending/user counters
- paginated orders with server-side status filter
- paginated users
- order status update: pending / paid / delivered / rejected
- product add / edit / delete
- product image upload (JPG/PNG/WebP, 2 MB default) with preview/remove
- exact-amount UPI QR generated from a server-verified checkout quote
- UPI setting
- admin password change

## MongoDB collections

```text
products
users
orders
settings
admin_config
admin_login_attempts
checkout_quotes
```

## Google login

The backend supports Google credential verification through `GOOGLE_CLIENT_ID`. Google Sign-In becomes active after a real Web OAuth Client ID is configured in both backend `.env` and `public/config.js`.

## Product images

Admin → Products now accepts JPG, PNG and WebP images. The server validates the file signature, ignores the original filename, generates a random safe filename and stores it under `public/uploads/products/`. Replacing or deleting a product also removes its old locally-uploaded image.

Before replacing the whole project directory on the VPS, back up `public/uploads/products/` if it already contains live product images. Normal in-place ZIP extraction/update does not require deleting this folder.

## UPI QR checkout

Checkout no longer trusts the browser's displayed cart amount. The browser sends only product IDs/quantities to `/api/checkout/quote`; the backend reloads current prices from MongoDB, calculates the total, creates a 15-minute checkout quote, and generates the UPI QR for that exact amount. The final order must reference the same unused quote, which prevents a changed client-side amount from being submitted as the order total.

The UPI ID is configured in Admin → Settings. There is still no automatic payment-gateway verification: the buyer enters the UTR and the admin verifies the payment manually.


## 2026-09-07 complete storefront update

This build includes:
- Server-generated UPI QR with exact MongoDB-verified cart amount.
- Buy Now beside Add to cart.
- Product image upload from Admin -> Products (JPG/PNG/WebP, max 2 MB by default).
- Admin-configurable support contact + support link, shown on the customer store.
- Google-only login.
- `/config.js` generated dynamically from `backend/.env`; keep `GOOGLE_CLIENT_ID` only in `.env`.

### Upgrade on VPS
Preserve `backend/.env` and `public/uploads/products/`, then replace tracked files and run:

```bash
cd /root/e-com/backend
npm install
pm2 restart e-com --update-env
```

Verify the new build actually reached the VPS:

```bash
grep -n "Buy now" /root/e-com/public/index.html
grep -n "Product image" /root/e-com/public/admin.html
curl -s http://127.0.0.1:3000/config.js
curl -s http://127.0.0.1:3000/api/health
```

Admin settings must contain a valid UPI ID before checkout can generate a QR.
