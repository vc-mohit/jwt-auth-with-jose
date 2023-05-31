const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const crypto = require("crypto-js");

app.use(express.json({ limit: "5mb" }));

// Normal JWT
app.post("/signup", (req, res) => {
  const { email } = req.body;
  const token = jwt.sign({ email: email }, "c1feb1c5f02e4759acc0182d83c878dc", { expiresIn: "1d" });
  const enc = crypto.AES.encrypt(token, "c1feb1c5f02e4759acc0182d83c878dc").toString();

  res.send({ message: "user registered successfully", token: token, encryptedToken: enc });
});

app.post("/login", async (req, res) => {
  const jwtToken = req.headers.authorization;
  const data = jwtToken.split(" ")[1];
  const dec = crypto.AES.decrypt(data, "c1feb1c5f02e4759acc0182d83c878dc").toString(crypto.enc.Utf8);
  const verifyJwt = jwt.verify(dec, "c1feb1c5f02e4759acc0182d83c878dc");

  res.send({ message: "User logged in successfully", decryotedToken: dec, token: verifyJwt });
});

app.listen(3000, () => {
  console.log("Server started at port 3000");
});
