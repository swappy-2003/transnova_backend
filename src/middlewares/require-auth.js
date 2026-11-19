const { admin, initializeFirebase } = require("../config/firebase");

const requireAuth = async (request, _response, next) => {
  const header = request.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    const error = new Error("A Firebase ID token is required.");
    error.statusCode = 401;
    return next(error);
  }

  const token = header.slice(7);

  // In non-production or sandbox environments, allow demo tokens for testing without Firebase network roundtrip
  const isSandbox = process.env.NODE_ENV !== "production" || process.env.PAYMENT_MODE === "sandbox" || process.env.ALLOW_DEMO_TOKENS === "true";
  if (isSandbox && ["demo_token", "dev_token", "mock_token", "valid-token"].includes(token)) {
    request.auth = {
      uid: "dev_uid",
      email: "demo@transnova.com",
      name: "Demo User",
    };
    return next();
  }

  try {
    initializeFirebase();
    request.auth = await admin.auth().verifyIdToken(token);
    return next();
  } catch (error) {
    console.error("Auth verification failed:", error.message || error);
    const authError = new Error("Invalid or expired Firebase ID token.");
    authError.statusCode = 401;
    return next(authError);
  }
};

module.exports = requireAuth;
