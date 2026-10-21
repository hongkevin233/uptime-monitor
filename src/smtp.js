// 极简 SMTP 客户端（Cloudflare Workers 版）
// 用 cloudflare:sockets 直连 smtp.qq.com:465（隐式 TLS），AUTH LOGIN + 授权码
// QQ 邮箱 → QQ 邮箱为站内投递，反垃圾待遇最优

import { connect } from "cloudflare:sockets";

const enc = new TextEncoder();

function b64utf8(s) {
  const bytes = enc.encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function mimeSubject(s) {
  // RFC2047 B 编码，兼容中文主题
  return `=?UTF-8?B?${b64utf8(s)}?=`;
}

export async function sendMail({ user, pass, from, to, subject, text }) {
  // 465 隐式 TLS
  const socket = connect(
    { hostname: "smtp.qq.com", port: 465 },
    { secureTransport: "on", allowHalfOpen: false }
  );

  const decoder = new TextDecoder();
  let buf = "";
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();

  async function readReply() {
    // 读一条完整回复（支持 250-xxx 多行，直到 250<空格> 结束）
    for (;;) {
      for (;;) {
        const idx = buf.indexOf("\r\n");
        if (idx < 0) break;
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        if (line.length >= 4 && line[3] === "-") continue; // 多行中间行，继续读
        return line;
      }
      const { value, done } = await reader.read();
      if (done) throw new Error("SMTP connection closed unexpectedly");
      buf += decoder.decode(value, { stream: true });
    }
  }

  async function cmd(line, expect) {
    await writer.write(enc.encode(line + "\r\n"));
    const reply = await readReply();
    if (!reply.startsWith(expect)) {
      throw new Error(`SMTP ${expect} expected, got: ${reply.slice(0, 120)}`);
    }
    return reply;
  }

  try {
    await readReply(); // 220 greeting

    await cmd(`EHLO uptime-monitor`, "250");
    await cmd("AUTH LOGIN", "334");
    await cmd(b64utf8(user), "334");
    await cmd(b64utf8(pass), "235");

    await cmd(`MAIL FROM:<${from}>`, "250");
    await cmd(`RCPT TO:<${to}>`, "250");
    await cmd("DATA", "354");

    const bodyB64 = b64utf8(text).replace(/(.{76})/g, "$1\r\n");
    const msg = [
      `From: "Uptime Monitor" <${from}>`,
      `To: <${to}>`,
      `Subject: ${mimeSubject(subject)}`,
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=UTF-8",
      "Content-Transfer-Encoding: base64",
      "",
      bodyB64,
      ".",
    ].join("\r\n");

    await writer.write(enc.encode(msg + "\r\n"));
    const done = await readReply();
    if (!done.startsWith("250")) {
      throw new Error(`SMTP DATA rejected: ${done.slice(0, 120)}`);
    }
    try { await writer.write(enc.encode("QUIT\r\n")); } catch (_) {}
  } finally {
    try { await reader.cancel(); } catch (_) {}
    try { await socket.close(); } catch (_) {}
  }
}
