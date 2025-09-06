import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { corsHeaders, handleOptionsRequest } from '../_shared/cors.ts';
serve(async (req)=>{
  // Handle OPTIONS request for CORS preflight
  if (req.method === 'OPTIONS') {
    return handleOptionsRequest();
  }
  try {
    const payload = await req.json();
    const record = payload.record;
    // Get phone number and API key from environment variables
    const PHONE_NUMBER = Deno.env.get('WHATSAPP_PHONE_NUMBER');
    const API_KEY = Deno.env.get('WHATSAPP_API_KEY');
    if (!PHONE_NUMBER || !API_KEY) {
      throw new Error('WhatsApp environment variables are not set.');
    }
    const feedbackMessage = `New Feedback Submitted!\n\n*Type:* ${record.feedback_type}\n*From:* ${record.name} (${record.email})\n*Page:* ${record.page_url}\n*Message:* ${record.message}`;
    const response = await fetch('https://api.callmebot.com/whatsapp.php', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        phone: PHONE_NUMBER,
        text: feedbackMessage,
        apikey: API_KEY
      })
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`CallMeBot API Error: ${errorText}`);
    }
    return new Response(JSON.stringify({
      success: true
    }), {
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json'
      },
      status: 200
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: error.message
    }), {
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json'
      },
      status: 500
    });
  }
});
