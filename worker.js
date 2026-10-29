
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      return json({
        ok: true,
        service: "AZXCV API",
        database: Boolean(env.DB)
      });
    }

    if (url.pathname.startsWith("/api/")) {
      if (!env.DB) {
        return json({
          ok: false,
          error: "D1 database binding DB is missing"
        }, 500);
      }

      return json({
        ok: false,
        error: "API endpoint not implemented yet"
      }, 501);
    }

    // Serve the existing static website through the configured assets binding.
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("AZXCV Worker is running. Configure static assets.", {
      status: 200,
      headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  }
};
