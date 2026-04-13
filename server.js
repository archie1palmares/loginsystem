import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Supabase Admin Client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ==============================
// SIGN UP
// ==============================
app.post("/signup", async (req, res) => {
  const { email, password, first, last } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const { data, error } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: {
        first_name: first,
        last_name: last,
      },
    });

    if (error) throw error;

    await logEvent("signup", data.user.id, email);

    res.json({ success: true, user: data.user });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ==============================
// LOGIN
// ==============================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) throw error;

    await logEvent("login", data.user.id, email);

    res.json({
      success: true,
      session: data.session,
    });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// ==============================
// FORGOT PASSWORD
// ==============================
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: "http://localhost:5500",
    });

    if (error) throw error;

    res.json({ success: true, message: "Reset email sent" });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ==============================
// AUTH LOGGING
// ==============================
async function logEvent(type, userId, email) {
  await supabase.from("auth_logs").insert({
    event_type: type,
    user_id: userId,
    email,
    created_at: new Date().toISOString(),
  });
}
