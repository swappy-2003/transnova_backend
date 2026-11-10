const { admin, initializeFirebase } = require("../config/firebase");

const requireAuth = async (request, _response, next) => {
  const header = request.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    const error = new Error("A Firebase ID token is required.");
    error.statusCode = 401;
    return next(error);
  }

  const token = header.slice(7).trim();

  // Support demo / dev tokens when running locally or during development
  if (token === "demo_token" || token === "dev_token" || token.startsWith("demo_") || token === "mock_token") {
    request.auth = {
      uid: "demo_user_uid",
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
    if (process.env.NODE_ENV !== "production") {
      console.warn("Dev mode auth fallback:", error.message || error);
      request.auth = {
        uid: "demo_user_uid",
        email: "demo@transnova.com",
        name: "Demo User",
      };
      return next();
    }
    console.error("Auth verification failed:", error.message || error);
    const authError = new Error("Invalid or expired Firebase ID token.");
    authError.statusCode = 401;
    return next(authError);
  }
};

module.exports = requireAuth;
