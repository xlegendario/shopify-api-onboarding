const express = require("express");
const crypto = require("crypto");

const app = express();

const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;

function verifyHmac(query) {
  const { hmac, signature, ...params } = query;

  const message = Object.keys(params)
    .sort()
    .map((key) => `${key}=${Array.isArray(params[key]) ? params[key].join(",") : params[key]}`)
    .join("&");

  const generated = crypto
    .createHmac("sha256", CLIENT_SECRET)
    .update(message)
    .digest("hex");

  return crypto.timingSafeEqual(
    Buffer.from(generated, "utf8"),
    Buffer.from(hmac, "utf8")
  );
}

app.get("/shopify", (req, res) => {
  const shop = req.query.shop;

  if (!shop) return res.status(400).send("Missing shop");

  const scopes =
    "read_assigned_fulfillment_orders,write_assigned_fulfillment_orders,read_fulfillments,write_fulfillments,write_inventory,read_inventory,write_locations,read_locations,read_merchant_managed_fulfillment_orders,write_merchant_managed_fulfillment_orders,read_orders,read_products,write_products";

  const redirectUri = "https://shopify-api-onboarding.onrender.com/shopify/callback";

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${CLIENT_ID}` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}`;

  res.redirect(installUrl);
});

app.get("/shopify/callback", async (req, res) => {
  try {
    const { shop, code, hmac } = req.query;

    if (!shop || !code || !hmac) {
      return res.status(400).send("Missing shop, code or hmac");
    }

    if (!verifyHmac(req.query)) {
      return res.status(401).send("Invalid HMAC");
    }

    const tokenResponse = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code
      })
    });

    const data = await tokenResponse.json();

    console.log("SHOP:", shop);
    console.log("ACCESS TOKEN:", data.access_token);
    console.log("SCOPES:", data.scope);

    res.send(`
      <h2>Shopify app installed</h2>
      <p>Store: ${shop}</p>
      <p>Token ontvangen. Check Render logs.</p>
    `);
  } catch (error) {
    console.error(error);
    res.status(500).send("Install failed");
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
