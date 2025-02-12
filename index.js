const SECRET_KEY = "tfsg666"; // 替换为你的密钥
const TIME_WINDOW_MS = 5 * 60 * 1000; // 5 分钟的时间窗口

// 生成签名
async function generateSign(key, timestamp) {
    const encoder = new TextEncoder();
    const keyBuffer = encoder.encode(key);
    const timestampBuffer = encoder.encode(timestamp);

    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const signature = await crypto.subtle.sign("HMAC", cryptoKey, timestampBuffer);
    return Array.from(new Uint8Array(signature))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

// 验证签名
async function verifySignature(request) {
    const headers = request.headers;
    const timestamp = headers.get("timestamp");
    const sign = headers.get("sign");

    if (!timestamp || !sign) {
        return new Response("Missing timestamp or sign in headers", { status: 400 });
    }

    // 验证时间戳是否在 5 分钟内
    const currentTime = Date.now();
    const requestTime = parseInt(timestamp, 10);
    if (isNaN(requestTime) || Math.abs(currentTime - requestTime) > TIME_WINDOW_MS) {
        return new Response("Timestamp is invalid or expired", { status: 401 });
    }

    // 重新生成签名并比对
    const expectedSign = await generateSign(SECRET_KEY, timestamp);
    if (sign !== expectedSign) {
        return new Response("Invalid signature", { status: 401 });
    }

    return null; // 验证通过
}

// 主处理逻辑
addEventListener("fetch", event => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const verificationResult = await verifySignature(request);
    if (verificationResult) {
        return verificationResult; // 返回错误响应
    }

    // 验证通过，继续处理请求
    return fetch(request);
}