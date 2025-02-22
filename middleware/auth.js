const JWTService = require("../services/JWTService");
const User = require("../models/user/User");
const UserDTO = require("../dto/user/user");
const auth = async (req, res, next) => {
  try {
    // 1.refresh, access token validation
    const accessToken =
      req.cookies?.accessToken ||
      req.header("Authorization")?.replace("Bearer ", "");
    if (!accessToken) {
      const error = {
        status: 401,
        message: "Unauthorized",
      };
      return next(error);
    }
    let _id;
    try {
      _id = JWTService.verifyAccessToken(accessToken)._id;
    } catch (error) {
      return next(error);
    }
    let user;
    try {
      user = await User.findOne({ _id: _id });
      if (!user) {
        return next({ status: 404, message: "User not found" });
      }
    } catch (error) {
      return next(error);
    }
    const userDto = new UserDTO(user);
    req.user = userDto;
    next();
  } catch (error) {
    return next(error);
  }
};
module.exports = auth;
