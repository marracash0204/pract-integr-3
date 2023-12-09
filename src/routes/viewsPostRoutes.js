import { Router } from "express";
import { cartManager } from "../service/cartsManager.js";
import { ticketManager } from "../service/ticketManager.js";
import { productsManager } from "../service/productsManager.js";
import {
  isAdminOrPremium,
  isUserOrPremium,
} from "../middlewares/autMiddleware.js";
import emailService from "../service/emailService.js";
import { createError } from "../service/utilities/errorHandler.js";
import logger from "../service/utilities/logger.js";
import { changeUserRole } from "../service/authService.js";
import { getUserById } from "../repository/authRepository.js";

const cartsManager = new cartManager();
const productManager = new productsManager();

const router = Router();

router.post("/addproduct", isAdminOrPremium, async (req, res) => {
  try {
    const { title, description, price, code, stock } = req.body;

    if (!title || !price || !code || !stock) {
      throw createError("EMPTY_FIELDS");
    }

    const product = await productManager.addProduct(
      title,
      description,
      price,
      code,
      stock,
      req.user
    );

    const productId = product.id;
    res.redirect(`/addproduct`);
  } catch (error) {
    logger.error("Error al agregar o modificar un producto:", error);
    res.status(500).send("Error al agregar o modificar un producto");
  }
});

router.post("/add-to-cart/:productId", async (req, res) => {
  try {
    const productId = req.params.productId;
    const cartId = req.session.cartId;
    const user = req.user;

    if (!cartId) {
      const newCart = await cartsManager.createCart();
      req.session.cartId = newCart._id;
    } else {
      const existingCart = await cartsManager.getCartById(cartId);

      if (!existingCart) {
        const newCart = await cartsManager.createCart();
        req.session.cartId = newCart._id;
      }
    }

    const product = await productManager.getProductById(productId);

    if (
      user.rol === "premium" &&
      product.owner._id.toString() === user._id.toString()
    ) {
      return res.render("error", { sameProduct: true });
    }

    const cartAdd = await cartsManager.addProductToCart(
      req.session.cartId,
      productId
    );

    if (cartAdd !== null) {
      return res.redirect("/products");
    } else {
      res.render("error", { error: "El producto no tiene stock disponible." });
    }
  } catch (error) {
    logger.error("Error al agregar producto al carrito:", error);
    return res.status(500).send("Error al agregar producto al carrito");
  }
});

router.post("/api/users/premium/:uid", isUserOrPremium, async (req, res) => {
  try {
    const userId = req.params.uid;
    const newRole = req.body.newRole;

    const user = await getUserById(userId);

    if (!user) {
      return res.status(404).json({ message: "Usuario no encontrado." });
    }

    if (user.rol === newRole) {
      return res
        .status(400)
        .json({ message: "El usuario ya tiene asignado el rol seleccionado." });
    }

    const success = await changeUserRole(userId, newRole);

    if (success) {
      return res
        .status(200)
        .json({ message: "Rol de usuario actualizado con éxito." });
    } else {
      return res
        .status(404)
        .json({ message: "No se pudo actualizar el rol del usuario." });
    }
  } catch (error) {
    console.error("Error al cambiar el rol de usuario:", error);
    res
      .status(500)
      .json({ message: "Error interno al cambiar el rol de usuario." });
  }
});

router.post("/cart/:cid/purchase", async (req, res) => {
  try {
    const cartId = req.params.cid;
    const purchaser = req.user.email;
    const cart = await cartsManager.getCartById(cartId);

    if (!cart || !cart.products || cart.products.length === 0) {
      res.render("error", {
        noProducts: true,
        error:
          "No fue posible hacer su ticket, no hay productos agregados al carrito",
      });
    }

    const ticketResult = await ticketManager.generateTicket(cartId, purchaser);

    if (ticketResult !== null) {
      const purchaserEmail = req.user.email;
      await emailService.sendPurchaseConfirmation(
        purchaserEmail,
        ticketResult.purchaser,
        cart.products
      );

      res.render("ticket", { result: ticketResult, purchaser: purchaser });
    } else {
      res.render("ticket", {
        result: "Compra finalizada pero no se pudo generar el ticket",
      });
    }
  } catch (error) {
    logger.error("Error al finalizar la compra:", error);
    res.status(500).render("error", { error: "Error al finalizar la compra" });
  }
});
router.post("/delete-product/:productId", async (req, res) => {
  try {
    const productId = req.params.productId;
    const cartId = req.session.cartId;

    if (!cartId) {
      throw createError("MISSING_CART_ID");
    }

    try {
      const result = await cartsManager.deleteProductFromCart(
        cartId,
        productId
      );

      if (result && result.noProducts) {
        return res.render("error", { noProductsToDelete: true });
      }

      return res.redirect("/products");
    } catch (error) {
      logger.error("Error al eliminar producto del carrito:", error);

      if (error.message === "Producto no existe en el carrito") {
        console.log("noProductsToDelete es true");
        return res.render("error", { noProductsToDelete: true });
      }

      return res.status(500).send("Error al eliminar producto del carrito");
    }
  } catch (error) {
    logger.error("Error general al eliminar producto del carrito:", error);

    return res.render("error", { noProductsToDelete: true });
  }
});

router.post("/modify-product/:prodId", isAdminOrPremium, async (req, res) => {
  try {
    const productId = req.params.prodId;
    const { title, description, price, code, stock } = req.body;

    const result = await productManager.updateProduct(
      productId,
      title,
      description,
      price,
      code,
      stock
    );

    if (result.success) {
      res.redirect(`/productDetails/${productId}`);
    } else {
      res.status(404).send(result.message);
    }
  } catch (error) {
    logger.error("Error al modificar un producto:", error);
    res.status(500).send("Error al modificar un producto");
  }
});

router.post(
  "/delete-product-stock/:prodId",
  isAdminOrPremium,
  async (req, res) => {
    try {
      const productId = req.params.prodId;
      const product = await productManager.getProductById(productId);
      const user = req.user;

      if (
        user.rol === "admin" ||
        (user.rol === "premium" &&
          product.owner._id.toString() === user._id.toString())
      ) {
        const result = await productManager.deleteProduct(productId);

        if (result.success) {
          res.redirect("/modifyProduct");
        } else {
          res.status(404).send("No se pudo eliminar el producto");
        }
      } else {
        console.log(
          "No tienes permisos. User Role:",
          user.rol,
          "Product Owner Id:",
          product.owner._id.toString(),
          "User Id:",
          user._id.toString()
        );
        return res
          .status(403)
          .send("No tienes permisos para eliminar este producto");
      }
    } catch (error) {
      logger.error("Error al eliminar un producto:", error);
      res.status(500).send("Error al eliminar un producto");
    }
  }
);

router.post("/logout", async (req, res) => {
  try {
    req.logout((err) => {
      if (err) {
        throw createError("SESSION_NOT_CLOSED");
      }

      req.session.destroy((err) => {
        if (err) {
          logger.error("Error al destruir la sesión:", err);
          return res.status(500).send("Error al cerrar sesión");
        }

        res.redirect("/login");
      });
    });
  } catch (error) {
    logger.error("Error al cerrar sesión:", error);
    res.status(500).send("Error al cerrar sesión");
  }
});

export default router;
