import {
  generateAndStoreToken,
  generateToken,
  resetPassword,
  getUserByToken,
  isTokenExpired,
  getUserByEmail,
} from "../repository/authRepository.js";

const generateTokenService = async () => {
  try {
    const { token, expiration } = await generateToken();
    return { token, expiration };
  } catch (error) {
    console.error("Error al generar token:", error);
    throw error;
  }
};

const generateAndStoreTokenService = async (email) => {
  try {
    const { token, expiration } = await generateTokenService();
    const storedToken = await generateAndStoreToken(email, token, expiration);
    return storedToken;
  } catch (error) {
    console.error("Error al generar y almacenar token:", error);
    throw error;
  }
};

const resetPasswordService = async (token, newPassword) => {
  try {
    const passwordResetResult = await resetPassword(token, newPassword);
    return passwordResetResult;
  } catch (error) {
    console.error("Error al restablecer la contraseña:", error);
    throw error;
  }
};

const getUserByTokenService = async (token) => {
  try {
    const user = await getUserByToken(token);

    return user;
  } catch (error) {
    console.error("Error en getUserByTokenService:", error);
    throw error;
  }
};

const isTokenExpiredService = async (token) => {
  try {
    const user = isTokenExpired(token);

    return !user;
  } catch (error) {
    console.error("Error al verificar la expiración del token:", error);
    throw error;
  }
};

async function getUserByEmailService(email) {
  try {
    return await getUserByEmail(email);
  } catch (error) {
    console.error("No se pudo obtener email de usuario");
    throw error;
  }
}

export {
  generateTokenService,
  generateAndStoreTokenService,
  resetPasswordService,
  getUserByTokenService,
  isTokenExpiredService,
  getUserByEmailService,
};
