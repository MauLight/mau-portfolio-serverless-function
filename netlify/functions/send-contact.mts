import sanitizeHtml from 'sanitize-html'
import validator from 'validator'
import postmark from 'postmark'

export const handler = async (event, context) => {

    const corsHeaders = {
        "Access-Control-Allow-Origin": "*", // or restrict to a specific domain
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "POST, OPTIONS"
    }

    // Handle CORS preflight request
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers: corsHeaders,
            body: 'OK'
        }
    }

    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, headers: corsHeaders, body: 'Method not allowed' }
    }

    //* This regex will catch potential malicious scripts in the body.
    const maliciousJsRegex = /(<script\b[^>]*>[\s\S]*?<\/script>|javascript\s*:|on\w+\s*=|eval\s*\(|document\.(cookie|write|location)|window\.(location|open)|fetch\s*\(|XMLHttpRequest\s*\()/i
    const { name, email, message } = JSON.parse(event.body || '{}')

    if (!name || !email || !message) {
        return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: 'You must provide name, email and message.' }) }
    }

    if (maliciousJsRegex.test(name) || maliciousJsRegex.test(email) || maliciousJsRegex.test(message)) {
        return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: 'Invalid input detected.' }) }
    }

    if (!validator.isEmail(email)) {
        return { statusCode: 401, headers: corsHeaders, body: JSON.stringify({ error: `${email} is not a valid email address.` }) }
    }

    try {
        const safeName = sanitizeHtml(name.trim())
        const safeEmail = sanitizeHtml(email.trim())
        const safeMessage = sanitizeHtml(message.trim())

        const client = new postmark.ServerClient(process.env.POSTMARK as string)
        const response = await client.sendEmail({
            From: 'mauluz@symetria.lat',
            To: 'mauluz@symetria.lat',
            Subject: 'Mau, you have a new message!',
            HtmlBody: `<div>
        <strong>This one comes from</strong> ${safeName}.
        <br>
        <p>This is their email: ${safeEmail}</p>
        <br>
        <p>And this is their message: ${safeMessage}</p>
        <br>
        <p>If you have any questions, feel free to contact us at <a href="mailto:support@symetria.lat">support@symetria.lat</a></p>
      </div>`,
            TextBody: 'Mau, you have a new message!',
            MessageStream: 'outbound'
        })

        console.log(response)
        return { statusCode: 201, headers: corsHeaders, body: JSON.stringify({ message: 'Email sent successfully.' }) }
    } catch (error) {
        console.error(error)
        return { statusCode: 500, headers: corsHeaders, body: JSON.stringify({ error: 'Error sending email.' }) }
    }
}