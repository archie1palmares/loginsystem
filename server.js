import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// =====================
// SUPABASE (SERVER ONLY)
// =====================
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// =====================
// HELPER: LOG EVENTS
// =====================
async function logAuthEvent(type, userId, email, metadata = {}) {
  try {
    await supabase.from("auth_logs").insert({
      event_type: type,
      user_id: userId || null,
      email,
      metadata,
      user_agent: null,
      created_at: new Date().toISOString(),
    });
  } catch (err) {
    console.log("Log error:", err.message);
  }
}

// =====================
// SIGN UP
// =====================
app.post("/signup", async (req, res) => {
  const { email, password, first_name, last_name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Missing email or password" });
  }

  try {
    const { data, error } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: {
        first_name,
        last_name,
        full_name: `${first_name || ""} ${last_name || ""}`.trim(),
      },
    });

    if (error) throw error;

    await logAuthEvent("signup", data.user.id, email, {
      first_name,
      last_name,
    });

    res.json({
      success: true,
      user: data.user,
    });
  } catch (err) {
    res.status(400).json({
      error: err.message,
    });
  }
});

// =====================
// LOGIN
// =====================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Missing email or password" });
  }

  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) throw error;

    await logAuthEvent("login", data.user.id, email);

    res.json({
      success: true,
      session: data.session,
      user: data.user,
    });
  } catch (err) {
    res.status(401).json({
      error: err.message,
    });
  }
});

// =====================
// FORGOT PASSWORD
// =====================
app.post("/forgot", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email required" });
  }

  try {
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: "http://localhost:5500",
    });

    if (error) throw error;

    res.json({
      success: true,
      message: "Password reset email sent",
    });
  } catch (err) {
    res.status(400).json({
      error: err.message,
    });
  }
});

// =====================
// GOOGLE OAUTH (BACKEND TRIGGER)
// =====================
app.get("/google", async (req, res) => {
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: "google",
    options: {
      redirectTo: "http://localhost:5500",
    },
  });

  if (error) return res.status(400).json({ error: error.message });

  res.json({ url: data.url });
});

// =====================
// START SERVER
// =====================
app.listen(3000, () => {
  console.log("🚀 Backend running on http://localhost:3000");
});
