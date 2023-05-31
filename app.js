const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const jose = require("jose");

app.use(express.json({ limit: "5mb" }));

const secret = Buffer.from("af659f1faf94fd81ce24e12f7a63915da0e306bef68652e250dcf6f8c1748e84", "hex");

// Sign JWT using Jose
const signJwt = async (payload, subject, secret) => {
  return new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(subject)
    .setIssuedAt()
    .setIssuer("http://localhost:3000/")
    .setAudience("http://localhost:3000/")
    .setExpirationTime("1d")
    .sign(secret);
};

// Verify JWT with Jose
const verifyJwt = async (jwt, secret) => {
  return await jose.jwtVerify(jwt, secret, {
    issuer: "http://localhost:3000/",
    audience: "http://localhost:3000/",
    algorithms: ["HS256"],
  });
};

// Sign Encrypted JWT using Jose
const encryptedJwt = (payload, subject, secret) => {
  return new jose.EncryptJWT(payload)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setSubject(subject)
    .setIssuedAt()
    .setIssuer("http://localhost:3000/")
    .setAudience("http://localhost:3000/")
    .setExpirationTime("1d")
    .encrypt(secret);
};

// Decrypt JWT with Jose
const decryptJwt = async (jwt, secret) => {
  return jose.jwtDecrypt(jwt, secret, {
    issuer: "http://localhost:3000/",
    audience: "http://localhost:3000/",
    contentEncryptionAlgorithms: ["A256GCM"],
    keyManagementAlgorithms: ["dir"],
  });
};

// Normal JWT Signing
app.post("/signup", (req, res) => {
  const { email } = req.body;
  const token = jwt.sign({ email: email }, secret, { expiresIn: "1d" });
  res.send({ message: "user registered successfull", token });
});

// JWT with Jose
app.post("/new-signup", async (req, res) => {
  const { email } = req.body;

  const token = await signJwt({ email }, "test subject", secret);
  res.send({ message: "user registered successfull", token });
});

// Encrypted JWT with Jose
app.post("/enc-signup", async (req, res) => {
  const { email } = req.body;
  const token = await encryptedJwt({ email }, "test subject", secret);
  res.send({ message: "user registered successfull", token });
});

// Normal JWT Verify
app.post("/login", async (req, res) => {
  const { email } = req.body;
  const jwtData = req.headers.authorization;
  const data = jwtData.split(" ")[1];
  const getData = jwt.verify(data, secret);

  res.send({ message: "user logged in successfull", getData });
});

// Verify login with JWT Jose
app.post("/new-login", async (req, res) => {
  const { email } = req.body;
  const jwt = req.headers.authorization;
  const data = jwt.split(" ")[1];
  const getData = await verifyJwt(data, secret);

  res.send({ message: "user logged in successfull", getData });
});

// Encrypted login with JWT jose
app.post("/enc-login", async (req, res) => {
  const { email } = req.body;
  const jwt = req.headers.authorization;
  const data = jwt.split(" ")[1];
  const getData = await decryptJwt(data, secret);

  res.send({ message: "user logged in successfull", getData });
});

app.listen(3000, () => {
  console.log("Server started at port 3000");
});
