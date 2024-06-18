import DBLocal from "db-local";
import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { SALT_ROUNDS } from "./config.js";

const { Schema } = new DBLocal({ path: "./db" });

const Session = Schema("Session", {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
});

const User = Schema("User", {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
});
export class UserRepository {
  static async create({ username, password }) {
    //1. Validacines de username
    validations.username(username);
    validations.password(password);
    //2. Asegurarse que el username no exista
    const user = User.findOne({ username });
    if (user) throw new Error("User alredy exist");

    const id = crypto.randomUUID();
    const hashPassword = bcrypt.hashSync(password, SALT_ROUNDS);
    User.create({
      _id: id,
      username,
      password: hashPassword,
    }).save();
    return id;
  }

  static async login({ username, password }) {
    validations.username(username);
    validations.password(password);
    const user = User.findOne({ username });
    if (!user) throw new Error("User does not exist");

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) throw new Error("Pass invalid");
    const { password: _, ...publicUser } = user;
    return publicUser;
  }
}
class validations {
  static username(username) {
    if (typeof username !== "string")
      throw new Error("Username must be a string");
    if (username.length < 3)
      throw new Error("Username must be at least 3 characters long");
  }
  static password(password) {
    if (typeof password !== "string")
      throw new Error("Password must be a string");
    if (password.length < 3)
      throw new Error("Password must be at least 3 characters long");
  }
}
