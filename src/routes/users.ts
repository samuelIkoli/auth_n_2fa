import express from "express";
const router = express.Router();
import {
  register,
  login,
  ping,
  getUsers,
  setup_2fa,
  authenticate_otp,
} from "../controllers/users";
import { authenticateToken } from "../utils/middlewares";

router.post("/register", register);
router.post("/login", login);
router.post("/two-fa", setup_2fa);
router.get("/two-fa", setup_2fa);
router.get("/ping", ping);
router.get("/users", getUsers);
router.post("/verify");
router.get("/protected", authenticateToken, (req: any, res: any) => {
  res.status(200).json({
    message:
      "This is a protected route, you are successfully logged in and have view access.",
    user: req.user,
  });
});

module.exports = router;
