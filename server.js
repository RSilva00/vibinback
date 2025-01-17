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
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    favoriteSongs: [{ type: Number }],
    recentlyPlayed: [
        {
            trackId: { type: Number, required: true }
        }
    ]
});

const verifyToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    console.log("Encabezado Authorization:", authHeader);

    if (!authHeader) {
        return res.status(403).json({ error: "Token no proporcionado" });
    }

    const token = authHeader.split(" ")[1];
    console.log("Token extraído:", token);

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("Token decodificado:", decoded);
        req.user = decoded;
        next();
    } catch (err) {
        console.error("Error al verificar token:", err);
        return res.status(401).json({ error: "Token no válido" });
    }
};

// Añadir una canción al historial de reproducidas recientemente
app.post("/api/recently-played", verifyToken, async (req, res) => {
    const { songId } = req.body;

    console.log("Cuerpo de la solicitud recibido:", req.body);

    // Validar datos de entrada
    if (!songId) {
        return res.status(400).json({ error: "Faltan datos obligatorios" });
    }

    try {
        // Buscar al usuario autenticado
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        // Crear un nuevo objeto para la canción
        const newTrack = {
            trackId: parseInt(songId, 10)
        };

        // Agregar la canción al principio del historial
        user.recentlyPlayed.unshift(newTrack);

        // Limitar el historial a 10 canciones
        if (user.recentlyPlayed.length > 10) {
            user.recentlyPlayed = user.recentlyPlayed.slice(0, 10);
        }

        // Guardar los cambios en la base de datos
        await user.save();

        res.json({
            message: "Canción añadida al historial",
            recentlyPlayed: user.recentlyPlayed
        });
    } catch (err) {
        console.error("Error al añadir canción al historial:", err);
        res.status(500).json({
            error: "Error al añadir la canción al historial"
        });
    }
});

// Obtener el historial de canciones reproducidas recientemente
app.get("/api/recently-played", verifyToken, async (req, res) => {
    try {
        // Buscar al usuario autenticado
        const user = await User.findById(req.user.id).select("recentlyPlayed");

        if (!user) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        res.json(user.recentlyPlayed);
    } catch (err) {
        console.error("Error al obtener el historial de canciones:", err);
        res.status(500).json({
            error: "Error al obtener el historial de canciones"
        });
    }
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

app.get("/api/getFavorites", verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id); // Recuperamos el usuario por su id (extraído del token)

        if (!user) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        res.json({ favorites: user.favoriteSongs }); // Retornamos las canciones favoritas del usuario
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Error al obtener los favoritos" });
    }
});

// Añadir una canción a los favoritos
app.post("/api/favorites", verifyToken, async (req, res) => {
    const { songId } = req.body;

    console.log("Cuerpo de la solicitud recibido:", req.body);

    if (!songId) {
        return res.status(400).json({ error: "ID de canción no especificado" });
    }

    try {
        // Buscar al usuario autenticado
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        // Normalizar el ID de la canción a número para garantizar consistencia
        const songIdNormalized = parseInt(songId, 10);

        // Verificar si la canción ya está en favoritos
        if (user.favoriteSongs.includes(songIdNormalized)) {
            return res
                .status(400)
                .json({ error: "La canción ya está en favoritos" });
        }

        // Agregar la canción a favoritos
        user.favoriteSongs.push(songIdNormalized);
        await user.save();

        res.json({
            message: "Canción añadida a favoritos",
            favorites: user.favoriteSongs
        });
    } catch (err) {
        console.error("Error al añadir canción a favoritos:", err);
        res.status(500).json({
            error: "Error al añadir la canción a favoritos"
        });
    }
});

// Eliminar una canción de los favoritos
app.delete("/api/favorites/:songId", verifyToken, async (req, res) => {
    const { songId } = req.params; // Recibimos el ID de la canción desde la URL

    console.log("ID de la canción a eliminar recibido:", songId);

    if (!songId) {
        return res.status(400).json({ error: "ID de canción no especificado" });
    }

    try {
        // Buscar al usuario autenticado
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        // Normalizar el ID de la canción a número para garantizar consistencia
        const songIdNormalized = parseInt(songId, 10);

        // Verificar si la canción está en favoritos
        if (!user.favoriteSongs.includes(songIdNormalized)) {
            return res
                .status(400)
                .json({ error: "La canción no está en favoritos" });
        }

        // Eliminar la canción de los favoritos
        user.favoriteSongs = user.favoriteSongs.filter(
            (song) => song !== songIdNormalized
        );
        await user.save();

        res.json({
            message: "Canción eliminada de favoritos",
            favorites: user.favoriteSongs
        });
    } catch (err) {
        console.error("Error al eliminar canción de favoritos:", err);
        res.status(500).json({
            error: "Error al eliminar la canción de favoritos"
        });
    }
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

// Función para realizar solicitudes a la API
const fetchArtistData = async (query) => {
    const response = await fetch(
        `https://api.deezer.com/search/artist?q=${query}`
    );
    if (!response.ok) throw new Error("Error en la API de Deezer");
    return response.json();
};

// Endpoint para búsqueda general
app.get("/api/search", async (req, res) => {
    const { query } = req.query;

    if (!query) {
        return res
            .status(400)
            .json({ error: 'El parámetro "query" es requerido.' });
    }

    try {
        console.log("Búsqueda en Deezer para:", query);

        // Realizar las tres solicitudes simultáneamente
        const [artistResponse, albumResponse, trackResponse] =
            await Promise.all([
                fetch(
                    `https://api.deezer.com/search/artist?q=${encodeURIComponent(
                        query
                    )}&limit=4`
                ),
                fetch(
                    `https://api.deezer.com/search/album?q=${encodeURIComponent(
                        query
                    )}&limit=4`
                ),
                fetch(
                    `https://api.deezer.com/search/track?q=${encodeURIComponent(
                        query
                    )}&limit=4`
                )
            ]);

        // Verificar que todas las respuestas sean exitosas
        if (
            ![artistResponse, albumResponse, trackResponse].every(
                (res) => res.ok
            )
        ) {
            throw new Error("Error en una de las solicitudes a Deezer");
        }

        // Parsear las respuestas JSON
        const artistsData = await artistResponse.json();
        const albumsData = await albumResponse.json();
        const tracksData = await trackResponse.json();

        // Transformar los datos
        const artists = artistsData.data.map((item) => ({
            id: item.id,
            name: item.name,
            picture: item.picture_medium,
            type: "artist"
        }));

        const albums = albumsData.data.map((item) => ({
            id: item.id,
            title: item.title,
            cover: item.cover_medium,
            artist: item.artist.name,
            type: "album"
        }));

        const tracks = tracksData.data.map((item) => ({
            id: item.id,
            title: item.title,
            artist: item.artist.name,
            album: item.album.title,
            cover: item.album.cover_medium,
            preview: item.preview,
            type: "track"
        }));

        // Combinar los resultados
        const results = [...artists, ...albums, ...tracks];

        // Responder con los resultados al frontend
        res.json({ results });
    } catch (error) {
        console.error(
            "Error al realizar la búsqueda en Deezer:",
            error.message
        );
        res.status(500).json({
            error: "Hubo un problema al realizar la búsqueda."
        });
    }
});

const limit = pLimit(10); // Máximo 10 solicitudes simultáneas

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

// Endpoint para obtener las 5 canciones principales de un artista
app.get("/api/artist-top-tracks/:artistId", async (req, res) => {
    const { artistId } = req.params;
    try {
        const response = await fetch(
            `${DEEZER_API_URL}/artist/${artistId}/top?limit=5`
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

// Endpoint para obtener detalles de canciones favoritas
app.post("/api/userFavorites", async (req, res) => {
    const { ids } = req.body; // Obtener los IDs desde el cuerpo de la solicitud

    if (!ids || !Array.isArray(ids) || ids.length === 0) {
        return res
            .status(400)
            .json({ error: "No se proporcionaron IDs de canciones" });
    }

    try {
        // Llama a la API de Deezer para cada ID de canción
        const songDetailsPromises = ids.map((id) =>
            fetch(`https://api.deezer.com/track/${id}`)
                .then((response) => {
                    if (!response.ok) {
                        throw new Error(
                            `Error al obtener el track con ID ${id}`
                        );
                    }
                    return response.json(); // Convertir a JSON
                })
                .catch((error) => {
                    console.error(`Error con el ID ${id}:`, error.message);
                    return null; // Manejar errores de forma que no rompan el flujo
                })
        );

        // Espera a que todas las promesas se resuelvan
        const songs = await Promise.all(songDetailsPromises);

        // Filtra resultados nulos (errores en algunas solicitudes)
        const validSongs = songs.filter((song) => song !== null);

        res.json({ favorites: validSongs });
    } catch (error) {
        console.error("Error fetching song details:", error.message);
        res.status(500).json({
            error: "Error al obtener detalles de las canciones"
        });
    }
});

// Endpoint para obtener detalles por ID
app.get("/api/identify/:id", async (req, res) => {
    const { id } = req.params;

    try {
        // Intenta validar el ID como track
        let response = await fetch(`https://api.deezer.com/track/${id}`);
        let data = await response.json();

        if (!data.error) {
            return res.json({ type: "track", data });
        }

        // Intenta validar el ID como artist
        response = await fetch(`https://api.deezer.com/artist/${id}`);
        data = await response.json();

        if (!data.error) {
            return res.json({ type: "artist", data });
        }

        // Intenta validar el ID como album
        response = await fetch(`https://api.deezer.com/album/${id}`);
        data = await response.json();

        if (!data.error) {
            return res.json({ type: "album", data });
        }

        // Si no coincide con ninguno
        return res.status(404).json({ error: "ID no válido o desconocido" });
    } catch (error) {
        console.error("Error al identificar el ID:", error);
        return res.status(500).json({ error: "Error interno del servidor" });
    }
});

// Endpoint para obtener álbumes de un artista
app.get("/api/artist/:id/albums", async (req, res) => {
    const { id } = req.params;

    try {
        const response = await fetch(
            `https://api.deezer.com/artist/${id}/albums`
        );
        const data = await response.json();

        if (!data.error) {
            return res.json(data.data); // Devuelve solo la lista de álbumes
        }

        return res
            .status(404)
            .json({ error: "No se encontraron álbumes para el artista." });
    } catch (error) {
        console.error("Error al obtener álbumes del artista:", error);
        return res.status(500).json({ error: "Error interno del servidor" });
    }
});

// Endpoint para obtener canciones de un álbum
app.get("/api/album/:id/tracks", async (req, res) => {
    const { id } = req.params;

    try {
        const response = await fetch(
            `https://api.deezer.com/album/${id}/tracks`
        );
        const data = await response.json();

        if (!data.error) {
            return res.json(data.data); // Devuelve solo la lista de canciones
        }

        return res
            .status(404)
            .json({ error: "No se encontraron canciones para el álbum." });
    } catch (error) {
        console.error("Error al obtener canciones del álbum:", error);
        return res.status(500).json({ error: "Error interno del servidor" });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
