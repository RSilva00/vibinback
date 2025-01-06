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

// Modelo de Mensaje
const MessageSchema = new mongoose.Schema({
    sender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    }, // ID del remitente
    message: { type: String, required: true }, // Contenido del mensaje
    timestamp: { type: Date, default: Date.now } // Marca de tiempo
});

// Modelo de Chat
const ChatSchema = new mongoose.Schema({
    friend: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    }, // Amigo con el que se está chateando
    messages: [MessageSchema] // Historial de mensajes
});

// Modelo de Usuario
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true }, // Nombre de usuario
    email: { type: String, required: true, unique: true }, // Correo electrónico
    password: { type: String, required: true }, // Contraseña (debería estar cifrada)
    favoriteSongs: [
        {
            type: String
        }
    ],
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }], // Referencias a otros usuarios
    chats: [ChatSchema] // Chats con cada amigo
});

// Elimina cualquier middleware innecesario
UserSchema.pre("save", function (next) {
    console.log("Middleware pre-save ejecutado"); // Depuración
    next();
});

const User = mongoose.model("User", UserSchema);

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

const verifyToken = (req, res, next) => {
    const token = req.headers["authorization"];
    if (!token) {
        return res.status(403).json({ error: "Token no proporcionado" });
    }

    try {
        const decoded = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET); // Asegúrate de separar 'Bearer' y el token
        req.user = decoded; // Guardar la información del usuario decodificada
        next();
    } catch (err) {
        return res.status(401).json({ error: "Token no válido" });
    }
};
// Obtener información del usuario autenticado
app.get("/user", verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id)
            .populate("friends", "username email") // Popula amigos con campos básicos
            .populate("favoriteSongs"); // Popula canciones favoritas

        if (!user) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: "Error al obtener información del usuario"
        });
    }
});
// Mock de datos o conexión con la base de datos (ejemplo básico)
const users = [
    {
        id: 1,
        username: "john_doe",
        email: "john@example.com",
        favorites: [],
        friends: [],
        chats: []
    }
];

// Rutas protegidas

// Obtener información del usuario
app.get("/api/user", verifyToken, (req, res) => {
    const user = users.find((u) => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }
    res.json(user);
});

// Gestionar canciones favoritas
app.post("/api/favorites", verifyToken, async (req, res) => {
    console.log("Me han llamado");
    const { songId } = req.body; // Ahora se espera solo el ID de la canción

    if (!songId) {
        return res.status(400).json({ error: "ID de canción no especificado" });
    }

    try {
        // Buscar el usuario autenticado en la base de datos
        const user = await User.findById(req.user.id); // Usamos el ID del usuario del token

        if (!user) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        // Verificar si el usuario ya tiene la canción en sus favoritos
        if (user.favoriteSongs.includes(songId)) {
            return res
                .status(400)
                .json({ error: "La canción ya está en favoritos" });
        }

        // Añadir la canción a los favoritos del usuario (solo el ID)
        user.favoriteSongs.push(songId);
        await user.save();

        // Responder con un mensaje de éxito
        res.json({
            message: "Canción añadida a favoritos",
            favorites: user.favoriteSongs
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: "Error al añadir la canción a favoritos"
        });
    }
});

app.delete("/api/favorites", verifyToken, (req, res) => {
    const { song } = req.body;
    const user = users.find((u) => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }
    user.favorites = user.favorites.filter((s) => s !== song);
    res.json({
        message: "Canción eliminada de favoritos",
        favorites: user.favorites
    });
});

// Gestionar lista de amigos
app.post("/api/friends", verifyToken, (req, res) => {
    const { friendId } = req.body;
    const user = users.find((u) => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }
    if (user.friends.includes(friendId)) {
        return res
            .status(400)
            .json({ error: "Este amigo ya está en la lista" });
    }
    user.friends.push(friendId);
    res.json({ message: "Amigo añadido", friends: user.friends });
});

app.delete("/api/friends", verifyToken, (req, res) => {
    const { friendId } = req.body;
    const user = users.find((u) => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }
    user.friends = user.friends.filter((f) => f !== friendId);
    res.json({ message: "Amigo eliminado", friends: user.friends });
});

// Manejar chats
app.post("/api/chats", verifyToken, (req, res) => {
    const { friendId, message } = req.body;
    const user = users.find((u) => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }
    const chat = user.chats.find((c) => c.friendId === friendId);
    if (!chat) {
        user.chats.push({
            friendId,
            messages: [{ message, timestamp: Date.now() }]
        });
    } else {
        chat.messages.push({ message, timestamp: Date.now() });
    }
    res.json({ message: "Mensaje enviado", chats: user.chats });
});

app.get("/api/chats/:friendId", verifyToken, (req, res) => {
    const { friendId } = req.params;
    const user = users.find((u) => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }
    const chat = user.chats.find((c) => c.friendId === parseInt(friendId));
    if (!chat) {
        return res.status(404).json({ error: "Chat no encontrado" });
    }
    res.json(chat);
});

// Ruta de autenticación (login)
app.post("/api/login", (req, res) => {
    const { username } = req.body;
    const user = users.find((u) => u.username === username);
    if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado" });
    }
    // Generar un token JWT
    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ token });
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

// Ruta protegida de ejemplo
app.get("/protected", verifyToken, (req, res) => {
    res.json({ message: "Acceso autorizado", user: req.user });
});

// Endpoint básico
app.get("/api", (req, res) => {
    res.json({ message: "Hola desde el servidor Node.js" });
});

// Ruta para obtener las últimas canciones
app.get("/api/latest-tracks", async (req, res) => {
    try {
        // Realizar la solicitud a la API de Deezer
        const response = await fetch(
            "https://api.deezer.com/chart/tracks/tracks"
        );

        // Verificar si la respuesta es exitosa (status 200)
        if (!response.ok) {
            return res
                .status(response.status)
                .json({ error: "Error al obtener las canciones de Deezer" });
        }

        // Convertir la respuesta en formato JSON
        const data = await response.json();

        // Devolver los datos obtenidos de Deezer al cliente
        res.json(data);
    } catch (err) {
        // Si ocurre un error en la solicitud, manejarlo
        res.status(500).json({ error: "Error al obtener las canciones" });
    }
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
