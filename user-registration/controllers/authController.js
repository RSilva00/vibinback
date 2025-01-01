const express = require("express");
const { registerUser } = require("../services/authService");
const router = express.Router();

// Ruta para registrar un nuevo usuario
router.post("/register", async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const token = await registerUser(name, email, password);
        res.status(201).json({
            message: "Usuario registrado con éxito",
            token
        });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

module.exports = router;
