# Team Secret Store — MongoDB Upgrade

This version fixes the main problem in the old GitHub Pages build: shared data is no longer stored in browser-only `window.storage`.

## What is included

- MongoDB-backed products
- MongoDB-backed users
- MongoDB-backed orders
- User **My Orders** page with live status
- Order statuses: `pending`, `paid`, `delivered`, `rejected`
- Download links are returned to users only after an order becomes `paid` or `delivered`
- Admin order list from MongoDB
- Admin user list with join date, last seen, order count and ordered value
- Admin product add/edit/delete through backend API
- UPI ID stored in MongoDB
- Admin password checked only on backend
- JWT-based admin session
- Guest user session token stored in the user's browser
- Google credential verification endpoint is included for when Google Sign-In is configured
- Server recalculates order prices from MongoDB so browser-side price tampering does not control the final order total

## Project structure

```text
index.html          GitHub Pages frontend
404.html            GitHub Pages fallback (also supports /admin-style URL)
config.js           Public frontend config
backend/
  server.js         Express API
  package.json
  .env.example      Backend environment variable template
```

## 1. Create MongoDB Atlas database

Create a MongoDB Atlas cluster and database user. Copy the MongoDB connection string.

Use a database name such as:

```text
team_secret_store
```

The backend automatically creates these collections as they are needed:

```text
products
users
orders
settings
admin_config
```

## 2. Deploy `backend` to Render / Railway

Use the `backend` folder as the service root.

Build command:

```bash
npm install
```

Start command:

```bash
npm start
```

Add these environment variables:

```env
MONGODB_URI=your_mongodb_atlas_connection_string
MONGODB_DB=team_secret_store
ADMIN_PASSWORD=your_initial_admin_password
JWT_SECRET=a_long_random_secret_at_least_32_characters
FRONTEND_ORIGINS=https://YOUR_GITHUB_USERNAME.github.io
GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID_HERE.apps.googleusercontent.com
```

For a GitHub project page, `FRONTEND_ORIGINS` still uses only the origin, for example:

```text
https://rahul123.github.io
```

Do not add the repository path after `.github.io`.

If MongoDB Atlas blocks the server connection, allow your backend host's outbound IP. For a quick test people often allow `0.0.0.0/0`, but that should only be used with a strong MongoDB username/password and preferably tightened later.

After deployment, test:

```text
https://YOUR-BACKEND.onrender.com/api/health
```

It should return JSON with `"ok": true`.

## 3. Connect GitHub Pages to the backend

Edit `config.js`:

```js
window.TEAM_SECRET_CONFIG = {
  API_BASE_URL: "https://YOUR-REAL-BACKEND.onrender.com",
  GOOGLE_CLIENT_ID: "YOUR_GOOGLE_CLIENT_ID_HERE.apps.googleusercontent.com"
};
```

`API_BASE_URL` is public and safe to expose. **Never** put `MONGODB_URI`, `ADMIN_PASSWORD`, or `JWT_SECRET` in `config.js` or `index.html`.

Then push these root files to the GitHub Pages repository:

```text
index.html
404.html
config.js
```

The `backend` folder can stay in the same GitHub repository, but it is deployed separately on Render/Railway.

## 4. First admin login

Use the password from backend environment variable `ADMIN_PASSWORD`.

After the first successful login, the backend creates a hashed admin credential in MongoDB. You can then change the password from Admin → Settings.

## 5. Order flow

1. User signs in as guest or Google user.
2. User adds products to cart.
3. User pays your configured UPI ID.
4. User submits UTR.
5. Backend creates a `pending` order in MongoDB.
6. Admin sees the order in Admin → Orders.
7. Admin changes it to `paid` or `delivered` after checking the payment.
8. User opens **My orders** and sees download links automatically.

No email-delivery service is wired in yet. The new flow gives the download link directly inside **My Orders** after approval.

## Important limitation of guest login

Guest login has no email/password verification. A secure random browser token is used to identify that browser. If the user clears browser storage or opens another device, old guest orders will not automatically appear there.

For proper cross-device accounts, use Google Sign-In or add OTP/email login later.

## Next good upgrades

The foundation is ready for:

- payment gateway auto-verification (Cashfree/Razorpay)
- email/Telegram order notifications
- coupon codes
- product images
- search and filters
- order notes / rejection reason
- dashboard analytics
- downloadable invoice
- user support/contact tickets
- admin pagination and search
