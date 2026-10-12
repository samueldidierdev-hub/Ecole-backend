const express = require('express');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// 0. Route d'accueil
app.get('/', (req, res) => {
  res.send('🚀 Bienvenue sur le backend de l\'application (Service de paiement Nyole actif) !');
});

// 1. Route pour afficher la page de confirmation HTML
app.get('/payment-complete', (req, res) => {
  res.sendFile(path.join(__dirname, 'merci.html'));
});

// 2. Route de création de la session de paiement
app.post('/api/create-payment', async (req, res) => {
  try {
    const { amount, orderId, customerEmail } = req.body;
    const SERVER_URL = process.env.SERVER_URL || 'http://localhost:3000';

    // Appel corrigé vers l'endpoint officiel de l'API Nyole
    const response = await axios.post(
      'https://app.nyole.com/api/v1/checkout/sessions',
      {
        amount: amount || 5000,
        currency: 'CDF',
        customer_email: customerEmail || 'test@example.com',
        order_id: orderId || 'CS-MU8A1B-2C0X1',
        redirect_url: `${SERVER_URL}/payment-complete`,
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.NYOLE_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );

    res.status(200).json({
      success: true,
      paymentUrl: response.data.url, // URL renvoyée par l'API Nyole
      sessionId: response.data.id,   // ID de la session
      orderId: response.data.order_id
    });
  } catch (error) {
    console.error('Erreur Nyole:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      message: 'Impossible de créer la session de paiement',
      error: error.response?.data || error.message,
    });
  }
});

// --- FONCTION : Vérification de la signature du Webhook ---
function verifyNyoleSignature(req) {
  const signature = req.headers['x-nyole-signature'];
  if (!process.env.NYOLE_WEBHOOK_SECRET) return true; 
  if (!signature) return false;

  const payload = JSON.stringify(req.body);
  const hmac = crypto.createHmac('sha256', process.env.NYOLE_WEBHOOK_SECRET);
  const digest = hmac.update(payload).digest('hex');

  return signature === digest;
}

// 3. Route Webhook de réception des notifications de paiement
app.post('/api/webhooks/cartflox', (req, res) => {
  if (!verifyNyoleSignature(req)) {
    console.warn('[SECURITY] Alerte : Tentative de webhook avec une signature invalide !');
    return res.status(400).json({ error: 'Signature invalide' });
  }

  const event = req.body;
  console.log('[WEBHOOK] Événement reçu :', event);

  res.status(200).json({ received: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Serveur démarré et à l'écoute sur le port ${PORT}`);
});