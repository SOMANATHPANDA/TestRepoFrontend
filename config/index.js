const dotenv = require("dotenv");
dotenv.config();

const {
  PORT,
  MONGODB_CONNECTION_STRING,
  ACCESS_TOKEN_SECRET,
  REFRESH_TOKEN_SECRET,
} = process.env;

module.exports = {
  PORT,
  MONGODB_CONNECTION_STRING,
  ACCESS_TOKEN_SECRET,
  REFRESH_TOKEN_SECRET,
};
