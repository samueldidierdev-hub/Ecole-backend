const express = require('express');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json());

// 0. Route d'accueil pour éviter le message "Cannot GET /" dans le navigateur
app.get('/', (req, res) => {
  res.send('🚀 Bienvenue sur le backend de l\'application École (Service de paiement Nyole actif) !');
});

// 1. Route pour afficher la page de confirmation HTML
app.get('/payment-complete', (req, res) => {
  res.sendFile(path.join(__dirname, 'merci.html'));
});

// 2. Route de création de la session de paiement
app.post('/api/create-payment', async (req, res) => {
  try {
    const { amount, orderId, customerEmail } = req.body;

    // Récupère l'URL de Render ou utilise localhost par défaut
    const SERVER_URL = cle_api.env.SERVER_URL || 'http://localhost:3000';

    const response = await axios.post(
      'https://api.nyole.com/v1/sessions',
      {
        amount: amount,
        currency: 'FC',
        order_id: orderId,
        customer_email: customerEmail,
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
      paymentUrl: response.data.payment_url,
      sessionId: response.data.session_id,
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

// --- FONCTION EXPERT : Vérification de la signature du Webhook ---
function verifyNyoleSignature(req) {
  const signature = req.headers['x-nyole-signature'];
  
  if (!process.env.NYOLE_WEBHOOK_SECRET) return true; 
  if (!signature) return false;

  const payload = JSON.stringify(req.body);
  const hmac = crypto.createHmac('sha256', process.env.NYOLE_WEBHOOK_SECRET);
  const digest = hmac.update(payload).digest('hex');

  return signature === digest;
}

// 3. Route Webhook avec vérification rigoureuse de la signature
app.post('/api/webhooks/nyole', (req, res) => {
  if (!verifyNyoleSignature(req)) {
    console.warn('[SECURITY] Alerte : Tentative de webhook avec une signature invalide !');
    return res.status(400).json({ error: 'Signature invalide' });
  }

  const event = req.body;

  if (event.type === 'payment.success' || event.status === 'success') {
    const orderId = event.order_id || event.data?.order_id;
    const sessionId = event.session_id || event.data?.session_id;

    console.log(`[WEBHOOK] Sécurité validée - Paiement réussi pour la commande : ${orderId} (Session: ${sessionId})`);
  }

  res.status(200).json({ received: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});