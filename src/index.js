export default {
    async fetch(request, env, ctx) {
        const corsHeaders = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-Timestamp, X-Signature"
        };

        if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

        // --- DEBUG HELPER ---
        const returnDebugError = (msg, details = {}) => new Response(JSON.stringify({
            status: "error",
            message: msg,
            details: details,
            debug: {
                received_timestamp: request.headers.get("X-Timestamp"),
                received_signature: request.headers.get("X-Signature"),
                server_time: Date.now(),
                secret_exists: !!env.API_SECRET,
                secret_start: env.API_SECRET ? env.API_SECRET.substring(0, 3) : "N/A"
            }
        }), {
            status: 400, // Return 400 so the client knows it failed logic, not a crash
            headers: { "Content-Type": "application/json", ...corsHeaders }
        });

        // 1. GET HEADERS
        const clientTimestamp = request.headers.get("X-Timestamp");
        const clientSignature = request.headers.get("X-Signature");
        const secret = env.API_SECRET;

        // 2. CHECK IF DATA EXISTS
        if (!clientTimestamp || !clientSignature || !secret) {
            return returnDebugError("Missing Headers or Server Secret");
        }

        // 3. CHECK TIME DRIFT (DEBUG: Increased to 10 minutes)
        const serverTime = Date.now();
        const clientTime = parseInt(clientTimestamp, 10);
        const diff = Math.abs(serverTime - clientTime);

        if (isNaN(clientTime) || diff > 600000) {
            return returnDebugError("Time Drift Error", { diff_ms: diff, limit_ms: 600000 });
        }

        // 4. VERIFY SIGNATURE
        const expectedSignature = await generateHash(secret, clientTimestamp);

        if (clientSignature !== expectedSignature) {
            return returnDebugError("Signature Mismatch", {
                expected: expectedSignature,
                received: clientSignature
            });
        }

        // 5. SUCCESS! EXECUTE SQL
        if (request.method !== "POST") return returnDebugError("Method must be POST");

        try {
            const payload = await request.json();

            // Execute Query on D1
            const stmt = env.DB.prepare(payload.sql).bind(...(payload.params || []));
            const result = await stmt.all();

            return Response.json({
                success: true,
                meta: result.meta,
                results: result.results
            }, { headers: corsHeaders });

        } catch (err) {
            return Response.json({
                success: false,
                error: err.message,
                stack: err.stack
            }, { status: 200, headers: corsHeaders });
        }
    }
};

/**
 * SHA-256 Hash Function
 */
async function generateHash(secret, timestamp) {
    const encoder = new TextEncoder();
    const msgBuffer = encoder.encode(secret + timestamp);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    return [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}
