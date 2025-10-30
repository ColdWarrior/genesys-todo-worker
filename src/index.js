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

// -----------------------------------------------------------
// --- CIDR IP WHITELISTING LOGIC ---
// -----------------------------------------------------------

// Genesys Cloud US East CIDR ranges (Includes Media and expanded API/Data Action ranges)
const ALLOWED_GENESYS_CLOUD_IPS = [
    '18.214.48.52',   // <-- TEMPORARY HARDCODE FOR DEBUGGING
    
    // Media/Voice Services (Core/Satellite) - Genesys-owned ranges
    '52.129.96.0/20', 
    '169.150.104.0/21',
    '167.234.48.0/20',
    '136.245.64.0/18',
    
    // AWS us-east-1 (N. Virginia) Public IP Ranges (Required for Data Actions)
    '18.212.0.0/15',
    '52.192.0.0/12', 
    '3.208.0.0/12',
    '3.232.0.0/14',
    '3.250.0.0/15',
    '34.192.0.0/12',
    '52.0.0.0/11',
    '54.80.0.0/12',
    '54.197.0.0/16', 
    '54.204.0.0/16',
    '64.252.176.0/20' 
]; 

// Helper function to convert an IP address string to a number (32-bit integer)
function ipToNum(ip) {
    return ip.split('.').reduce((num, octet) => (num << 8) + parseInt(octet, 10), 0) >>> 0;
}

// Core function to check if a single IP falls within a CIDR range
function checkCidr(ip, cidr) {
    const [range, bits] = cidr.split('/');
    const mask = ~(0xFFFFFFFF >>> parseInt(bits, 10));

    const ipNum = ipToNum(ip);
    const rangeNum = ipToNum(range);
    
    return (ipNum & mask) === (rangeNum & mask);
}

// Main IP check function
function isIpAllowed(clientIP, env) {
    // 1. Check against the personal test IP (from Cloudflare environment variable)
    if (clientIP === env.TEST_IP_ADDRESS) {
        return true;
    }
    
    // 2. Check against the Genesys Cloud allowed IPs (CIDR ranges)
    for (const cidr of ALLOWED_GENESYS_CLOUD_IPS) {
        if (checkCidr(clientIP, cidr)) {
            return true;
        }
    }

    return false;
}

// -----------------------------------------------------------
// --- END CIDR IP WHITELISTING LOGIC ---
// -----------------------------------------------------------

// The main Worker fetch handler
export default {
  async fetch(request, env) {
    // 1. We only want to handle POST requests from the webhook
    if (request.method !== 'POST') {
	  return new Response(JSON.stringify({ message: "Only POST requests are accepted." }), {
		  status: 405,
		  headers: {
			  'Content-Type': 'application/json'
		  }
	  });
    }

    // 2. IP WHITELISTING CHECK (Genesys Cloud CIDR and Test IP)
    const clientIP = request.headers.get('cf-connecting-ip');
    
    if (!isIpAllowed(clientIP, env)) {
        console.warn(`Forbidden attempt from IP: ${clientIP}`);
		return new Response(JSON.stringify({ message: "Forbidden: IP Address Not Allowed." }), {
		  status: 403,
		  headers: {
			  'Content-Type': 'application/json'
		  }
	    });
    }

    // 3. Authenticate the request (Primary Defense)
    if (!authorize(request, env)) {
      // NOTE: We don't check for the TEST_IP_ADDRESS here because 
      // the IP is already allowed above. If the TEST_IP is active 
      // but doesn't have the correct Basic Auth, it fails here 
      // like any other authorized IP.
	  return new Response(JSON.stringify({ message: "Unauthorized." }), {
		  status: 401,
		  headers: {
			  'Content-Type': 'application/json'
		  }
	  });
    }
	
	// --- NEW UTILITY FUNCTION: Workitem Creation (Add this to your Worker) ---
	async function createWorkitem(conversationId, triggerText, accessToken, env) {
		// You must replace these placeholders with the actual IDs from your Genesys Cloud setup
		// (See Step 1 and Step 2 in the previous instructions for obtaining these IDs)
		const workitemTypeId = env.WORKITEM_TYPE_ID; // Use ENV variable for secure ID storage
		const queueId = env.WORKITEM_QUEUE_ID;       // Use ENV variable for secure ID storage
		const statusId = env.WORKITEM_STATUS_ID; 	// Use ENV variable for secure ID storage
		
		const workitemName = `Follow-up needed: Conversation ${conversationId}`; 
		const workitemDescription = `Agent used the phrase: "${triggerText}". Review full transcript for action.`;
	
		// Genesys Cloud API Endpoint for Workitems
		const url = `https://api.mypurecloud.com/api/v2/taskmanagement/workitems`; 

		const headers = new Headers();
		headers.append("Content-Type", "application/json");
		headers.append("Authorization", `Bearer ${accessToken}`);

		const requestOptions = {
			method: "POST",
			headers: headers,
			// Define the body object directly in the request options
			body: JSON.stringify({
				"name": workitemName,
				"description": workitemDescription,
				"typeId": workitemTypeId, 
				"queueId": queueId, 
				"statusId": statusId
			}),
		};

		try {
			const response = await fetch(url, requestOptions);
			
			if (!response.ok) {
				const errorBody = await response.text(); 
				// Log the API error (e.g., 403 Forbidden due to missing permission, or 400 Bad Request)
				console.error(`Failed to create Workitem. Status: ${response.status}. Body: ${errorBody}`);
			} else {
				const data = await response.json();
				console.log(`Successfully created Workitem: ${data.id}`);
			}
		} catch (error) {
			console.error("Error communicating with Workitem API:", error);
		}
	}

    // --- CONTINUED LOGIC ---
    try {
		// [Existing security checks remain here]

        const payload = await request.json();
        const conversationId = payload.eventBody.conversationId;
        const rawTranscript = payload.eventBody.message.body; 
        
        // --- NEW DEBUG LOGS START ---
        console.log(`Processing Conversation ID: ${conversationId}`);
		
		// --- NEW: Array of multiple trigger phrases ---
		const TRIGGER_PHRASES = [
			"follow up",
			"get back to you",
			"noted on",
			"make that update",
			"take note"
		];

        const agentIdentifier = "agent"; 
        let transcriptArray = [];

        try {
            transcriptArray = JSON.parse(rawTranscript);
            console.log(`Successfully parsed transcript with ${transcriptArray.length} messages.`);
        } catch (e) {
            console.error("Parsing Failed. Returning 400.");
            return new Response(JSON.stringify({ message: "Invalid transcript format. Check Data Action mapping." }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        
        let workitemCreatedCount = 0;

        // Loop through the transcript
        for (const message of transcriptArray) {
            
			if (message.device === agentIdentifier && message.text) {
            
				// Convert message text once for efficiency
				const currentMessageText = message.text.toLowerCase();

				// Check if the current message contains ANY of the trigger phrases
				for (const phrase of TRIGGER_PHRASES) {
					
					if (currentMessageText.includes(phrase.toLowerCase())) {
						
						// --- TRIGGER PHRASE MATCH FOUND ---
						console.log("--- TRIGGER PHRASE FOUND. ATTEMPTING TOKEN AND WORKITEM CREATION. ---");
						const accessToken = await getAccessToken(env);
						
						if (accessToken) {
							// Create Workitem for this specific match. 
							// The description can include the exact phrase that triggered it.
							const specificTriggerText = `Phrase: "${phrase}"`; 
							await createWorkitem(conversationId, specificTriggerText, accessToken, env);
							workitemCreatedCount++;
						} else {
							console.error("TOKEN FAILURE: Skipping workitem creation for matches.");
							// Continue loop
						}
					}
				}
			}
 
        }

        // Final result log
        console.log(`Processing complete. Total Workitems created: ${workitemCreatedCount}`);

        // Return a successful response
        return new Response(JSON.stringify({ message: `Transcript processed. Created ${workitemCreatedCount} workitems.` }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });

    } catch (error) {
        console.error("Worker processing error:", error.stack);
        return new Response(JSON.stringify({ message: "Processing failed.", error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
  },
};