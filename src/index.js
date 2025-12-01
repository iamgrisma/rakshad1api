export default {
  async fetch(request, env, ctx) {
    // --- CORS HEADERS (Required for your HTML Tool) ---
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Timestamp, X-Signature"
    };

    // Handle Browser Pre-flight
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

    // --- CONFIGURATION ---
    // The "Stealth" Fake PHP Error (Camouflage)
    const FAKE_ERROR = `
<br />
<b>Parse error</b>:  syntax error, unexpected '?' in <b>/var/www/html/libs/db_connect.php</b> on line <b>14</b><br />
`;

    // Helper to return Stealth Response (Status 200 + HTML)
    const returnStealth = () => new Response(FAKE_ERROR, { 
      status: 200, 
      headers: { "Content-Type": "text/html", ...corsHeaders } 
    });

    // 1. GET HEADERS
    const clientTimestamp = request.headers.get("X-Timestamp");
    const clientSignature = request.headers.get("X-Signature");
    const secret = env.API_SECRET;

    // 2. CHECK IF DATA EXISTS
    if (!clientTimestamp || !clientSignature || !secret) {
        return returnStealth();
    }

    // 3. CHECK TIME DRIFT (Allow +/- 2 Minutes)
    const serverTime = Date.now();
    const clientTime = parseInt(clientTimestamp, 10);
    const diff = Math.abs(serverTime - clientTime);

    // If time is invalid or drift is > 120 seconds, show Fake Error
    if (isNaN(clientTime) || diff > 120000) { 
        return returnStealth();
    }

    // 4. VERIFY SIGNATURE (The Math Check)
    const expectedSignature = await generateHash(secret, clientTimestamp);

    if (clientSignature !== expectedSignature) {
        return returnStealth(); // Mismatch = Fake Error
    }

    // 5. SUCCESS! EXECUTE SQL
    if (request.method !== "POST") return returnStealth();

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
      // If SQL fails (syntax error), we return JSON so you can fix your query
      return Response.json({
        success: false,
        error: err.message
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
