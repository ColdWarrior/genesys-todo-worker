export default {
  async fetch(request, env, ctx) {
    // Check if the request method is POST.
    if (request.method === "POST") {
      // This is where your webhook logic would go.
      // For now, let's return a success message.
      return new Response("Webhook received!", { status: 200 });
    }

    // For any other request method (like GET), return a different message.
    return new Response("This endpoint only accepts POST requests.", {
      status: 405,
      headers: {
        'Allow': 'POST'
      }
    });
  },
};