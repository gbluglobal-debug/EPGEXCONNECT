/*
  EPGEXX CONNECT - owner-only "add coins" endpoint   POST /admin/grant
  Body: { uid, coins, idem }      Header: Authorization: Bearer <Firebase Auth ID token>

  Put this inside the same Cloud Function that serves your /checkout, /gift, /payout routes
  (the one you set as EXX_API in index.html). Example with Express inside a Firebase function:

      const { adminGrant } = require("./exx-admin-grant");
      app.post("/admin/grant", adminGrant);

  IMPORTANT
  - The check happens HERE, on the server. The page only shows the button.
  - The server must verify a Firebase Auth ID token. Your current custom login cannot be verified,
    so the owner must sign in with Firebase Authentication (email + password) with the owner email.
  - Keep Firestore rules so that wallets/*, wtx/* and grants/* can only be written by the server.
*/
const admin = require("firebase-admin");
if (!admin.apps.length) admin.initializeApp();

/* Only these emails may add coins. Must match OWNER_EMAILS in index.html. */
const OWNER_EMAILS = ["gblu.global@gmail.com"];
const MAX_PER_GRANT = 1000000;

async function adminGrant(req, res) {
  try {
    /* 1. who is calling? */
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : "";
    if (!token) return res.status(401).json({ error: "unauthorized" });
    let user;
    try { user = await admin.auth().verifyIdToken(token); }
    catch (e) { return res.status(401).json({ error: "unauthorized" }); }
    const email = String(user.email || "").toLowerCase();
    if (!user.email_verified || OWNER_EMAILS.indexOf(email) < 0) {
      return res.status(403).json({ error: "forbidden" });
    }

    /* 2. check the request */
    const b = req.body || {};
    const uid = typeof b.uid === "string" ? b.uid.trim() : "";
    const coins = Number(b.coins);
    const idem = typeof b.idem === "string" ? b.idem.trim() : "";
    if (!uid || uid.indexOf("/") >= 0 || uid.length > 128) return res.status(400).json({ error: "bad_uid" });
    if (!Number.isInteger(coins) || coins < 1 || coins > MAX_PER_GRANT) return res.status(400).json({ error: "bad_amount" });
    if (!idem || idem.length > 80 || idem.indexOf("/") >= 0) return res.status(400).json({ error: "bad_idem" });

    /* 3. add the coins once (the same idem never adds twice) and keep a record */
    const db = admin.firestore();
    const FV = admin.firestore.FieldValue;
    const grantRef = db.doc("grants/" + idem);
    const walletRef = db.doc("wallets/" + uid);
    await db.runTransaction(async (tx) => {
      const g = await tx.get(grantRef);
      if (g.exists) return; /* already done */
      tx.set(walletRef, { coins: FV.increment(coins) }, { merge: true });
      tx.set(db.collection("wtx").doc(), { uid, type: "grant", coins, note: "Added by EPGEXX team", ts: Date.now(), by: user.uid });
      tx.set(grantRef, { uid, coins, by: user.uid, email, ts: Date.now() });
    });
    return res.json({ ok: true });
  } catch (e) {
    console.error("adminGrant", e);
    return res.status(500).json({ error: "fail" });
  }
}

module.exports = { adminGrant };
