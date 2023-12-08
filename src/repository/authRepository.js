import { userModel } from "../models/userModel.js";
import bcrypt from "bcrypt";
import crypto from "crypto";

const generateToken = async () => {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(32, (err, buffer) => {
      if (err) {
        reject(err);
      } else {
        const token = buffer.toString("hex");
        resolve({ token, expiration: Date.now() + 3600000 });
      }
    });
  });
};

const generateAndStoreToken = async (email) => {
  try {
    const { token, expiration } = await generateToken();

    const updatedUser = await userModel.findOneAndUpdate(
      { email },
      { $set: { resetToken: token, resetTokenExpiration: expiration } },
      { new: true }
    );

    if (!updatedUser) {
      console.log(
        `No hay usuarios con el correo ${email} disponibles para actualizar.`
      );
      return null;
    }

    return token;
  } catch (error) {
    console.error(
      "Error al generar token y almacenar en la base de datos:",
      error
    );
    throw error;
  }
};

const resetPassword = async (token, newPassword) => {
  try {
    const user = await userModel.findOne({
      resetToken: token,
      resetTokenExpiration: { $gt: Date.now() },
    });

    if (user) {
      const isSameAsCurrentPassword = await bcrypt.compare(
        newPassword,
        user.password
      );
      if (isSameAsCurrentPassword) {
        console.error(
          "La nueva contraseña no puede ser igual a la contraseña actual."
        );
        return false;
      }
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      user.password = hashedPassword;

      user.resetToken = undefined;
      user.resetTokenExpiration = undefined;

      await user.save();

      return true;
    } else {
      return false;
    }
  } catch (error) {
    console.error("Error al restablecer la contraseña:", error);
    throw error;
  }
};

const getUserByToken = async (token) => {
  try {
    const user = await userModel.findOne({ resetToken: token });

    return user;
  } catch (error) {
    console.error("Error al obtener usuario por token:", error);
    throw error;
  }
};

const isTokenExpired = async (token) => {
  try {
    const user = await userModel.findOne({
      resetToken: token,
      resetTokenExpiration: { $gt: Date.now() },
    });

    return !user;
  } catch (error) {
    console.error("Error al verificar la expiración del token:", error);
    throw error;
  }
};

async function getUserByEmail(email) {
  try {
    return await userModel.findOne({ email: email });
  } catch (error) {
    console.error("Error al obtener email de usuario");
    throw error;
  }
}

export {
  generateToken,
  resetPassword,
  generateAndStoreToken,
  getUserByToken,
  isTokenExpired,
  getUserByEmail,
};
