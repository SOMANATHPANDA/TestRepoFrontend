const Joi = require("joi");
const bcrypt = require("bcryptjs");
const User = require("../../models/user/User");
const RefreshToken = require("../../models/RefreshToken");
const JWTService = require("../../services/JWTService");
const UserDTO = require("../../dto/user/user");

const UserController = {
  async signUp(req, res, next) {
    const signUpSchema = Joi.object({
      firstName: Joi.string().required(),
      lastName: Joi.string().required(),
      email: Joi.string().email().required(),
      age: Joi.string().required(),
      address: Joi.string().required(),
      password: Joi.string().required(),
      confirmPassword: Joi.string()
        .required()
        .valid(Joi.ref("password"))
        .messages({
          "any.only": "Password and confirm password must match",
        }),
    });

    const { error } = signUpSchema.validate(req.body);
    if (error) {
      return next(error);
    }

    const { firstName, lastName, email, age, address, password } = req.body;

    try {
      const user = await User.findOne({ email });
      if (user) {
        const error = {
          message: "user with same email already exist",
          status: "400",
        };
        return next(error);
      }
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      const newUser = new User({
        firstName,
        lastName,
        email,
        age,
        address,
        password: hashedPassword,
      });

      await newUser.save();

      const accessToken = JWTService.signAccessToken({ _id: newUser._id }, "10d");
      const refreshToken = JWTService.signRefreshToken(
        { _id: newUser._id },
        "20d"
      );
      await RefreshToken.updateOne(
        {
          _id: newUser._id,
        },
        { token: refreshToken },
        { upsert: true }
      );

      res.cookie("accessToken", accessToken, {
        maxAge: 1000 * 60 * 60 * 24 * 10,
        httpOnly: true,
        sameSite: "None",
        secure: true,
      });
      res.cookie("refreshToken", refreshToken, {
        maxAge: 1000 * 60 * 60 * 24 * 20,
        httpOnly: true,
        sameSite: "None",
        secure: true,
      });
      const userDto = new UserDTO(newUser);

      return res.json({ user: userDto, auth: true });
    } catch (error) {
      return next(error);
    }
  },

  async login(req, res, next) {
    const loginSchema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().required(),
    });

    const { error } = loginSchema.validate(req.body);
    if (error) {
      return next(error);
    }

    const { email, password } = req.body;
    try {
      const user = await User.findOne({ email });
      if (!user) {
        const error = {
          status: 400,
          message: "Invalid email try again!",
        };
        return next(error);
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        const error = {
          status: 400,
          message: "Invalid Password",
        };
        return next(error);
      }

      const accessToken = JWTService.signAccessToken({ _id: user._id }, "10d");
      const refreshToken = JWTService.signRefreshToken(
        { _id: user._id },
        "20d"
      );
      await RefreshToken.updateOne(
        {
          _id: user._id,
        },
        { token: refreshToken },
        { upsert: true }
      );

      res.cookie("accessToken", accessToken, {
        maxAge: 1000 * 60 * 60 * 24 * 10,
        httpOnly: true,
        sameSite: "None",
        secure: true,
      });
      res.cookie("refreshToken", refreshToken, {
        maxAge: 1000 * 60 * 60 * 24 * 20,
        httpOnly: true,
        sameSite: "None",
        secure: true,
      });
      const userDto = new UserDTO(user);

      return res.status(200).json({ user: userDto, auth: true });
    } catch (error) {
      return next(error);
    }
  },

  async userDetails(req, res, next) {
    try {
      const user = await User.findOne({ _id: req.user._id });

      const userDto = new UserDTO(user);

      return res.json({ user: userDto });
    } catch (error) {
      return next(error);
    }
  },

  async logout(req, res, next) {
    const { refreshToken } = req.cookies;
    try {
      await RefreshToken.deleteOne({ token: refreshToken });
    } catch (error) {
      return next(error);
    }

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    res.status(200).json({ user: null, auth: false });
  },

  async refresh(req, res, next) {
    // 1.get refreshToken from cookies
    // 2.verify refreshToken
    // 3.generate new tokens
    // update db, return response
    const originalRefreshToken = req.cookies.refreshToken;
    let id;
    try {
      id = JWTService.verifyRefreshToken(originalRefreshToken)._id;
    } catch (e) {
      const error = {
        status: 400,
        message: "Unauthorized",
      };
      return next(error);
    }
    try {
      const match = RefreshToken.findOne({
        _id: id,
        token: originalRefreshToken,
      });
      if (!match) {
        const error = {
          status: 400,
          message: "Unauthorized",
        };
        return next(error);
      }
    } catch (e) {
      return next(error);
    }
    try {
      const accessToken = JWTService.signAccessToken({ _id: id }, "1d");
      const refreshToken = JWTService.signRefreshToken({ _id: id }, "2d");

      await RefreshToken.updateOne({ _id: id }, { token: refreshToken });

      res.cookie("accessToken", accessToken, {
        maxAge: 1000 * 60 * 60 * 24 * 10,
        httpOnly: true,
        sameSite: "None",
        secure: true,
      });
      res.cookie("refreshToken", refreshToken, {
        maxAge: 1000 * 60 * 60 * 24 * 20,
        httpOnly: true,
        sameSite: "None",
        secure: true,
      });
    } catch (e) {
      return next(e);
    }
    const user = await User.findOne({ _id: id });

    const userDto = new UserDTO(user);
    return res.status(200).json({ user: userDto, auth: true });
  },
};
module.exports = UserController;
