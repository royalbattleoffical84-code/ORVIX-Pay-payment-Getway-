ORVIX PAY AI Render integration patch

1) Render/GitHub: Replace the existing backend server.js with render-backend/server.js.
   Keep the existing package.json and famMail.js. Do not change Root Directory,
   Build Command, or Start Command if the current Gmail bridge already deploys.
2) Render Environment: keep ORVIX_IMAP_API_KEY unchanged; set GEMINI_API_KEY
   to your own Google AI Studio key; optionally set GEMINI_MODEL=gemini-2.5-flash.
3) InfinityFree: back up htdocs/ai-chat.php, then replace it with
   infinityfree/ai-chat.php. Keep config.php's ORVIX_IMAP_API_URL and
   ORVIX_IMAP_API_KEY matching the Render service URL and ORVIX_IMAP_API_KEY.
4) Keep the Admin AI model setting blank or set it to gemini-2.5-flash.
5) Test while logged in. Never share API keys or Gmail App Passwords.

This patch adds /v1/ai-chat while preserving the existing Gmail routes and
length-safe Bearer-key authentication. It does not modify payment processing.
