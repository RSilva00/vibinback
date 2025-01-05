const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fetch = require("node-fetch");
const cors = require("cors");
const dotenv = require("dotenv");
const pLimit = require("p-limit");

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 5000;

mongoose
    .connect(process.env.MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    })
    .then(() => console.log("Conectado a MongoDB"))
    .catch((err) => console.error("Error de conexión a MongoDB:", err));

// Esquema y Modelo de Usuario
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

// Elimina cualquier middleware innecesario
userSchema.pre("save", function (next) {
    console.log("Middleware pre-save ejecutado"); // Depuración
    next();
});

const User = mongoose.model("User", userSchema);

(async () => {
    const password = "admin";
    const hash = await bcrypt.hash(password, 10);
    console.log("Hash generado:", hash);

    const isMatch = await bcrypt.compare(password, hash);
    console.log("¿Coincide la contraseña?", isMatch); // true
})();

// Ruta: Registro de Usuario
app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    // Validar si el usuario ya existe
    const existingUser = await User.findOne({ username });
    if (existingUser) {
        return res.status(400).json({ error: "El usuario ya existe" });
    }

    // Encriptar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Contraseña cifrada:", hashedPassword);

    const user = new User({ username, email, password: hashedPassword });
    try {
        console.log("Antes de guardar:", user);

        await user.save();

        const savedUser = await User.findOne({ username });
        console.log("Después de guardar:", savedUser);
        res.status(201).json({ message: "Usuario registrado con éxito" });
    } catch (err) {
        res.status(500).json({ error: "Error al registrar el usuario" });
        console.log(user);
    }
});

// Ruta: Inicio de Sesión
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    // Buscar al usuario en la base de datos
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    // Validar la contraseña
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log("Contraseña proporcionada:", password);
    console.log("Contraseña almacenada (hash):", user.password);
    console.log("¿Contraseña válida?", isPasswordValid);
    if (!isPasswordValid) {
        return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    // Generar un token JWT
    const token = jwt.sign(
        { id: user._id, username: user.username },
        process.env.JWT_SECRET,
        {
            expiresIn: "1h"
        }
    );

    res.json({ message: "Inicio de sesión exitoso", token });
});

// Ruta: Verificar Token (para rutas protegidas)
const verifyToken = (req, res, next) => {
    const token = req.headers["authorization"];
    if (!token) {
        return res.status(403).json({ error: "Token no proporcionado" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Información del usuario decodificada
        next();
    } catch (err) {
        res.status(401).json({ error: "Token no válido" });
    }
};

// Ruta protegida de ejemplo
app.get("/protected", verifyToken, (req, res) => {
    res.json({ message: "Acceso autorizado", user: req.user });
});

// Endpoint básico
app.get("/api", (req, res) => {
    res.json({ message: "Hola desde el servidor Node.js" });
});

// Configurar el límite de solicitudes
const limit = pLimit(10); // Máximo 10 solicitudes simultáneas (ajustado según tus necesidades)

// Función para realizar solicitudes a la API
const fetchArtistData = async (query) => {
    const response = await fetch(
        `https://api.deezer.com/search/artist?q=${query}`
    );
    if (!response.ok) throw new Error("Error en la API de Deezer");
    return response.json();
};

// Ruta para buscar artistas
app.get("/api/search-artists", async (req, res) => {
    const { query } = req.query;

    // Log de la solicitud entrante
    console.log(`[${new Date().toISOString()}] Solicitud recibida: "${query}"`);

    if (!query) {
        return res
            .status(400)
            .json({ error: "Se requiere un término de búsqueda" });
    }

    try {
        // Agregar la solicitud a la cola con límite
        const data = await limit(() => fetchArtistData(query));
        res.json(data.data.slice(0, 10)); // Limitar a 10 resultados
    } catch (error) {
        console.error("Error al buscar artistas:", error);
        res.status(500).json({ error: "Error al realizar la búsqueda" });
    }
});

const DEEZER_API_URL = "https://api.deezer.com";

// Endpoint para buscar artistas
app.get("/api/search-artists", async (req, res) => {
    const { query } = req.query;
    try {
        const response = await fetch(
            `${DEEZER_API_URL}/search/artist?q=${query}`
        );
        const data = await response.json();
        res.json(data.data); // Enviar los artistas encontrados
    } catch (err) {
        res.status(500).json({ error: "Error al buscar artistas" });
    }
});

// Endpoint para obtener las 10 canciones principales de un artista
app.get("/api/artist-top-tracks/:artistId", async (req, res) => {
    const { artistId } = req.params;
    try {
        const response = await fetch(
            `${DEEZER_API_URL}/artist/${artistId}/top?limit=10`
        );
        const data = await response.json();
        console.log(data);
        res.json(data.data); // Enviar las canciones principales del artista
    } catch (err) {
        res.status(500).json({
            error: "Error al obtener las canciones principales"
        });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
