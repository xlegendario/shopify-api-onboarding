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

/*
  THIS list is what a store actually grants, not the one in the Partner
  dashboard.

  The dashboard says what the app MAY ask for. This string is what it DOES
  ask for, and Shopify grants exactly what is asked. So adding a scope there
  and reinstalling changes nothing: the install link built below still asks
  for the same thirteen, the store grants thirteen, and the token comes back
  with thirteen. That cost an afternoon of reinstalling and wondering.

  read_publications and write_publications are new. Without them a product
  can be created, priced and stocked and still be visible to nobody,
  because a product made through the API is published to no channel at all.

  Changing this list means every store has to install again to get a token
  that carries it. An existing token keeps the scopes it was born with,
  forever, and goes on working - which is exactly why this is easy to miss.
*/
const SCOPES = [
  "read_assigned_fulfillment_orders",
  "write_assigned_fulfillment_orders",
  "read_fulfillments",
  "write_fulfillments",
  "read_inventory",
  "write_inventory",
  "read_locations",
  "write_locations",
  "read_merchant_managed_fulfillment_orders",
  "write_merchant_managed_fulfillment_orders",
  "read_orders",
  "read_products",
  "write_products",
  "read_publications",
  "write_publications"
];

app.get("/shopify", (req, res) => {
  const shop = req.query.shop;

  if (!shop) return res.status(400).send("Missing shop");

  const scopes = SCOPES.join(",");

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

    /*
      Said out loud, because the failure this catches is silent otherwise.

      Shopify grants what was asked for, so a scope missing here means the
      version that was installed is not the one this code asks for - and the
      token still works for everything else, which is what makes it hard to
      spot.
    */
    const granted = String(data.scope || "").split(",");
    const missing = SCOPES.filter((scope) => !granted.includes(scope));

    if (missing.length) {
      console.warn("LET OP - niet toegekend:", missing.join(", "));
    }

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
