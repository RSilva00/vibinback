const express = require("express");
const mongoose = require("mongoose");
const fetch = require("node-fetch");
const cors = require("cors");
const dotenv = require("dotenv");
const authRoutes = require("./user-registration/controllers/authController");
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

// Rutas de autenticación
app.use("/api/auth", authRoutes);

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

app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
