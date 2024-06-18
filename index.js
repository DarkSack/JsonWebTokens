import express from "express";
import { PORT, SECRET_JWT_KEY } from "./config.js";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { UserRepository } from "./user-repository.js";
const app = express();
app.set("view engine", "ejs");
app.use(express.json());
app.use(cookieParser());
app.use((req, res, next) => {
  const token = req.cookies.access_cookie;
  req.session = { user: null };
  try {
    const data = jwt.verify(token, SECRET_JWT_KEY);
    req.session.user = data;
  } catch (error) {}
  next();
});
app.get("/", (req, res) => {
  const { user } = req.session;
  res.render("index", user);
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await UserRepository.login({ username, password });
    const token = jwt.sign(
      {
        id: user._id,
        username: user.username,
        password: user.password,
      },
      SECRET_JWT_KEY,
      {
        expiresIn: "1h",
      }
    );
    res
      .cookie("access_cookie", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 100 * 60 * 60,
      })
      .send({ user, token });
  } catch (error) {
    res.status(401).json(error.message);
  }
});
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const id = await UserRepository.create({ username, password });
    res.send({ id });
  } catch (error) {
    //NO ES BUENA IDEA MANDAR EL ERROR.MESSAGE
    res.status(500).send(error.message);
  }
});
app.post("/logout", (req, res) => {
  res.clearCookie("access_cookie").json({ message: "Logout successful" });
});
app.get("/protected", (req, res) => {
  const { user } = req.session;
  if (!user) return res.status(403).send("Access no authorized");
  res.render("protected", { user });
});
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
