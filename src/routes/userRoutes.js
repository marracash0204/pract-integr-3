import { userModel } from "../models/userModel.js";
import { cartManager } from "../service/cartsManager.js";
import { Router } from "express";
import passport from "passport";
import emailService from "../service/emailService.js";
import {
  generateAndStoreTokenService,
  resetPasswordService,
  getUserByTokenService,
  isTokenExpiredService,
} from "../service/authService.js";
import bcrypt from "bcrypt";
import { getUserById } from "../repository/authRepository.js";
import { isUserOrPremium } from "../middlewares/autMiddleware.js";

const cartsManager = new cartManager();
const router = Router();

router.get("/users/premium/:uId", isUserOrPremium, async (req, res) => {
  try {
    const userId = req.params.uId;
    const user = await getUserById(userId);

    return res.render("auth/rol", { user });
  } catch (error) {
    return error;
  }
});

router.post(
  "/signup",
  passport.authenticate("register", { failureRedirect: "/failregister" }),
  async (req, res) => {
    const newUser = req.user;
    const newCart = await cartsManager.createCart();
    newUser.cart = newCart._id;
    await newUser.save();
    req.session.cartId = newCart._id;

    res.redirect("/login");
  }
);

router.post(
  "/login",
  passport.authenticate("login", { failureRedirect: "/login" }),
  async (req, res) => {
    if (!req.user) {
      res.status(400).send();
    }

    req.session.rol =
      req.user.email === "adminCoder@coder.com" ? "admin" : "usuario";
    req.session.user = {
      first_name: req.user.nombre,
      last_name: req.user.apellido,
      email: req.user.email,
      age: req.user.edad,
      cart: req.user.cart,
    };

    req.session.cartId = req.user.cart;
    req.session.isLogged = true;

    res.redirect("/profile");
  }
);

router.post("/auth/recover-request", async (req, res) => {
  const { email } = req.body;
  const user = await userModel.findOne({ email });

  if (!user) {
    return res.render("error", { emailNotFound: true });
  }

  const token = await generateAndStoreTokenService(email);

  if (token) {
    const resetLink = `http://localhost:3001/recover-reset/${token}`;
    const mailOptions = {
      from: "shea.mitchell70@ethereal.email",
      to: user.email,
      subject: "Recuperación de Contraseña",
      html: `Haz clic <a href="${resetLink}">aquí</a> para restablecer tu contraseña. Este enlace expirará en 1 hora.`,
    };

    try {
      await emailService.sendEmail(mailOptions);
      res.render("auth/recoverRequest", {
        success:
          "Se ha enviado un correo con las instrucciones para restablecer tu contraseña.",
      });
    } catch (error) {
      console.error("Error al enviar el correo electrónico:", error);
      res.status(500).render("auth/recoverRequest", {
        error: "Error al enviar el correo de recuperación de contraseña.",
      });
    }
  } else {
    console.log("Error al generar y almacenar token.");
    res.render("auth/recoverRequest", {
      error: "Error al generar el token. Intenta nuevamente.",
    });
  }
});

router.get("/recover-reset/:token", async (req, res) => {
  const { token } = req.params;

  try {
    const isExpired = await isTokenExpiredService(token);

    if (isExpired) {
      return res.render("error", { tokenExpired: true });
    }

    res.render("auth/recoverReset", { token });
  } catch (error) {
    console.error(
      "Error al validar el token de restablecimiento de contraseña:",
      error
    );
    res.status(500).render("auth/recoverReset", {
      error: "Error al validar el token de restablecimiento de contraseña.",
    });
  }
});

router.post("/recover-reset/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword, confirmPassword } = req.body;

  if (newPassword !== confirmPassword) {
    return res.render("error", { notSamePass: true });
  }

  try {
    const user = await getUserByTokenService(token);

    if (!user) {
      return res.render("auth/recoverReset", {
        error:
          "El enlace de restablecimiento de contraseña no es válido o ha expirado. Intenta nuevamente.",
      });
    }

    const isSameAsOldPassword = await bcrypt.compare(
      newPassword,
      user.password
    );
    if (isSameAsOldPassword) {
      return res.render("error", { sameAsOldPassword: true, token });
    }

    const success = await resetPasswordService(token, newPassword);

    if (success) {
      res.render("auth/recoverReset", {
        success:
          "Contraseña restablecida con éxito. Puedes iniciar sesión con tu nueva contraseña.",
      });
    } else {
      res.render("auth/recoverReset", {
        error:
          "El enlace de restablecimiento de contraseña no es válido o ha expirado. Intenta nuevamente.",
      });
    }
  } catch (error) {
    console.error(
      "Error en el proceso de restablecimiento de contraseña:",
      error
    );
    res.status(500).render("auth/recoverReset", {
      error: "Error en el proceso de restablecimiento de contraseña.",
    });
  }
});

export default router;
