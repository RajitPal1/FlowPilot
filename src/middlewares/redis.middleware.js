const Redis = require("ioredis");

const redis = new Redis({
  connectTimeout: 5000, // Timeout after 5 seconds instead of hanging forever
  maxRetriesPerRequest: 1,
});

redis.on("error", (err) => {
  console.error("Redis Connection Error:", err.message);
});

module.exports = redis;