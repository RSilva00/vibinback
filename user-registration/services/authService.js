const jwt = require("jsonwebtoken");
const User = require("../models/User");

// Registrar un nuevo usuario
async function registerUser(name, email, password) {
    const userExists = await User.findOne({ email });
    if (userExists) {
        throw new Error("El usuario ya existe");
    }

    const user = new User({
        name,
        email,
        password
    });

    await user.save();
    return generateToken(user._id);
}

// Generar un JWT
function generateToken(userId) {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "30d" });
}

module.exports = { registerUser };
