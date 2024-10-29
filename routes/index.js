const express = require("express");
const UserController = require("../controller/user/UserController");
const router = express.Router();
const auth = require("../middleware/auth");

router.get("/", (req, res) => {
  res.json({ msg: "working properly" });
});

router.post("/sign-up", UserController.signUp);
router.post("/login", UserController.login);
router.get("/user-details", auth, UserController.userDetails);
router.post("/logout", auth, UserController.logout);
router.get("/refresh", UserController.refresh);

module.exports = router;
