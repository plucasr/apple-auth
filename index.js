// Load environment variables from .env file
require("dotenv").config();

const express = require("express");
const jwt = require("jsonwebtoken"); // Used to generate the Client Secret
const axios = require("axios"); // Used to make the call to Apple

const app = express();

app.use(express.json());
// This is essential for Apple's 'form_post' response
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// Serve your main page
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// This MUST be a POST route and MUST match your redirect_uri exactly
app.post("/api/security/apple/callback", async (req, res) => {
  try {
    const { code } = req.body;
    console.log("Authorization code received from Apple:", code);

    if (!code) {
      console.log("No code received from Apple:", code);
      return res.status(400).send("Error: No authorization code received.");
    }

    // 1. Get secrets from environment variables
    const privateKey = process.env.APPLE_PRIVATE_KEY.replace(/\\n/g, "\n");
    const teamId = process.env.APPLE_TEAM_ID;
    const keyId = process.env.APPLE_KEY_ID;
    const clientId = process.env.APPLE_CLIENT_ID;
    console.log({ privateKey, teamId, keyId, clientId });

    // 2. Generate the Client Secret (the JWT "access pass")
    const now = Math.floor(Date.now() / 1000);
    const clientSecret = jwt.sign(
      {
        iss: teamId, // Issuer (your Team ID)
        iat: now, // Issued At (now)
        exp: now + 86400 * 30, // Expires in 30 days (max 6 months)
        aud: "https://appleid.apple.com", // Audience (Apple)
        sub: clientId, // Subject (your Services ID)
      },
      privateKey,
      {
        algorithm: "ES256", // Apple uses ES256
        keyid: keyId,
      },
    );
    console.log({ clientSecret });
    // 3. Exchange the code for the user's tokens
    const tokenUrl = "https://appleid.apple.com/auth/token";

    // The parameters must be sent as 'form-urlencoded'
    const params = new URLSearchParams();
    params.append("client_id", clientId);
    params.append("client_secret", clientSecret);
    params.append("code", code);
    params.append("grant_type", "authorization_code");
    params.append(
      "redirect_uri",
      "https://coach.cbhexp.com/api/security/apple/callback",
    );

    const response = await axios.post(tokenUrl, params, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });

    // 4. SUCCESS! You have the user's tokens
    const { id_token } = response.data;
    console.log("ID Token received:", id_token);

    // The id_token is another JWT. Decode it to see the user data.
    // Apple only sends 'name' and 'email' the *very first time* the user logs in.
    const userData = jwt.decode(id_token);

    console.log("User Data:", userData);

    // TODO:
    // 1. Find a user in your database with `userData.sub` (the unique Apple ID).
    // 2. If one doesn't exist, create a new user with `userData.email` (if available).
    // 3. Create a login session for that user in your app.

    // Redirect the user to a success page (or send back a session token)
    res.send(`
      <h1>Apple Login Successful!</h1>
      <p>Email: ${userData.email || "Not provided"}</p>
      <p>Apple Unique ID: ${userData.sub}</p>
      <pre>${JSON.stringify(userData, null, 2)}</pre>
    `);
  } catch (error) {
    console.error("Error during Apple authentication:");
    // Log the detailed error from Apple if available
    console.error(error.response ? error.response.data : error.message);
    res.status(500).send("An error occurred during authentication.");
  }
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
