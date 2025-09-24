// Function to get an access token from Genesys Cloud
async function getAccessToken(env) {
  const url = `https://login.mypurecloud.com/oauth/token?grant_type=client_credentials`;

  const headers = new Headers();
  headers.append("Content-Type", "application/x-www-form-urlencoded");
  headers.append("Authorization", "Basic " + btoa(`${env.GENESYS_CLIENT_ID}:${env.GENESYS_CLIENT_SECRET}`));

  const requestOptions = {
    method: "POST",
    headers: headers,
  };

  try {
    const response = await fetch(url, requestOptions);
    const data = await response.json();
    return data.access_token;
  } catch (error) {
    console.error("Error fetching access token:", error);
    return null;
  }
}

// Function to update a conversation with a custom attribute
async function updateConversationAttribute(conversationId, accessToken) {
  const url = `https://api.mypurecloud.com/api/v2/conversations/chats/${conversationId}`;

  const headers = new Headers();
  headers.append("Content-Type", "application/json");
  headers.append("Authorization", `Bearer ${accessToken}`);

  const body = JSON.stringify({
    "attributes": {
      "genesys-todo": "followup required"
    }
  });

  const requestOptions = {
    method: "PATCH",
    headers: headers,
    body: body,
  };

  try {
    const response = await fetch(url, requestOptions);
    if (!response.ok) {
      console.error("Failed to update conversation:", await response.text());
    }
  } catch (error) {
    console.error("Error updating conversation:", error);
  }
}

// Basic Authentication
function authorize(request, env) {
  const authHeader = request.headers.get('Authorization');

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return false;
  }

  const encoded = authHeader.substring(6);
  const decoded = atob(encoded);
  const [username, password] = decoded.split(':');

  return username === env.BASIC_AUTH_USERNAME && password === env.BASIC_AUTH_PASSWORD;
}

// --- NEW IP WHITELISTING LOGIC ---

// IMPORTANT: Replace these examples with the actual official Genesys Cloud public API IP addresses/CIDRs
const ALLOWED_GENESYS_CLOUD_IPS = [
    // EXAMPLE IPS - YOU MUST REPLACE THESE
    '52.129.96.0/20', 
    '169.150.104.0/21',
    '167.234.48.0/20',
    '136.245.64.0/18'
]; 

// Simple check for whitelisted IPs (NOTE: A real-world solution should use a robust CIDR library)
function isIpAllowed(clientIP, env) {
    // Check against the personal test IP (from Cloudflare environment variable)
    if (clientIP === env.TEST_IP_ADDRESS) {
        return true;
    }
    
    // Check against the Genesys Cloud allowed IPs
    // WARNING: This is a simplified check. For CIDR ranges, a proper check is needed.
    for (const allowedIp of ALLOWED_GENESYS_CLOUD_IPS) {
        if (clientIP === allowedIp) {
            return true;
        }
    }

    return false;
}

// The main Worker fetch handler
export default {
  async fetch(request, env) {
    // 1. We only want to handle POST requests from the webhook
    if (request.method !== 'POST') {
      return new Response("Only POST requests are accepted.", { status: 405 });
    }

    // 2. IP WHITELISTING CHECK
    const clientIP = request.headers.get('cf-connecting-ip');
    
    if (!isIpAllowed(clientIP, env)) {
        console.warn(`Forbidden attempt from IP: ${clientIP}`);
        return new Response('Forbidden: IP Address Not Allowed.', { status: 403 });
    }

    // 3. Authenticate the request
    if (!authorize(request, env)) {
      return new Response('Unauthorized.', { status: 401 });
    }

    // --- CONTINUED LOGIC ---
    try {
      // Get the incoming JSON payload from the Genesys Cloud data action
      const dataActionPayload = await request.json();
      
      // Extract the conversationId and message from the data action payload
      const conversationId = dataActionPayload.eventBody.conversationId;
      const message = dataActionPayload.eventBody.message.body;

      // Define your trigger phrase
      const triggerPhrase = "i'll follow up on that";

      // Check if the message contains the trigger phrase
      if (message && message.toLowerCase().includes(triggerPhrase.toLowerCase())) {
        // Get an access token using your client credentials
        const accessToken = await getAccessToken(env);

        if (accessToken) {
          // Update the conversation with the custom attribute
          await updateConversationAttribute(conversationId, accessToken);
        }
      }

      // Return a successful response to Genesys Cloud
      return new Response("Webhook processed successfully!", { status: 200 });

    } catch (error) {
      console.error("Data action processing error:", error);
      return new Response("Data action processing failed.", { status: 500 });
    }
  },
};