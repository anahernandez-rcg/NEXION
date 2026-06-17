module.exports = async function (context, req) {

    const allowedOrigins = [
        'https://white-dune-07516d40f.7.azurestaticapps.net'
    ];

    const origin = (req.headers['origin'] || '');
    const allowOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];

    const corsHeaders = {
        'Access-Control-Allow-Origin': allowOrigin,
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Credentials': 'true',
        'Content-Type': 'application/json'
    };

    if (req.method === 'OPTIONS') {
        context.res = { status: 204, headers: corsHeaders, body: '' };
        return;
    }

    try {
        const tenant = (req.body && req.body.tenant) || process.env['TENANT_ID'];
        const clientId = (req.body && req.body.clientId) || process.env['CLIENT_ID'];
        const clientSecret = process.env['CLIENT_SECRET'];

        if (!clientSecret) {
            context.res = {
                status: 500, headers: corsHeaders,
                body: JSON.stringify({ error: 'CLIENT_SECRET not configured' })
            };
            return;
        }

        const params = new URLSearchParams({
            grant_type: 'client_credentials',
            client_id: clientId,
            client_secret: clientSecret,
            scope: 'https://analysis.windows.net/powerbi/api/.default'
        });

        const response = await fetch(
            `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
            { method: 'POST', body: params }
        );

        const data = await response.json();

        if (!data.access_token) {
            context.res = {
                status: 401, headers: corsHeaders,
                body: JSON.stringify({ error: 'Token failed', details: data })
            };
            return;
        }

        context.res = {
            status: 200, headers: corsHeaders,
            body: JSON.stringify({ access_token: data.access_token })
        };

    } catch (err) {
        context.res = {
            status: 500, headers: corsHeaders,
            body: JSON.stringify({ error: err.message })
        };
    }
};
