const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3001;

// Endpoint básico
app.get("/api", (req, res) => {
    res.json({ message: "Hola desde el servidor Node.js" });
});

app.listen(PORT, () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
