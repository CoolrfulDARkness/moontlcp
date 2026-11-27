/**
 * Real OS TCP Socket End-to-End GM/T 0024 TLCP 1.1 Demo (Zero npm dependencies).
 *
 * Uses Node.js built-in `node:net` loopback sockets (`127.0.0.1:0`) coupled
 * directly to the pure-MoonBit Sans-I/O TLCP 1.1 state machine compiled to ESM.
 *
 * Run:
 *   moon build web_api --target js --release
 *   node examples/tlcp-tcp-demo/tlcp_tcp_demo.mjs
 */
import net from "node:net";
import assert from "node:assert/strict";
import {
  tlcp_tcp_init_pair,
  tlcp_tcp_poll_out,
  tlcp_tcp_feed_in,
  tlcp_tcp_send_app,
  tlcp_tcp_close,
} from "../../_build/js/release/build/web_api/web_api.js";

function mustOk(resp, label) {
  if (!resp.startsWith("OK")) {
    throw new Error(`${label} failed: ${resp}`);
  }
  return resp.startsWith("OK:") ? resp.slice(3) : "";
}

function flushToSocket(handle, socket, onWireSent) {
  const hex = mustOk(tlcp_tcp_poll_out(handle), "tlcp_tcp_poll_out");
  if (hex.length > 0) {
    const buf = Buffer.from(hex, "hex");
    onWireSent(buf, hex);
    socket.write(buf);
  }
}

async function runTcpScenario({ suite, mutualAuth, clientMsg, serverReply }) {
  console.log(
    `\n--- Real OS TCP Loopback Scenario: ${suite} (${mutualAuth ? "mTLCP Mutual Auth" : "Server Auth"}) ---`
  );

  const pairStr = mustOk(
    tlcp_tcp_init_pair(suite, mutualAuth),
    "tlcp_tcp_init_pair"
  );
  const [clientIdStr, serverIdStr] = pairStr.split("|");
  const clientHandle = Number.parseInt(clientIdStr, 10);
  const serverHandle = Number.parseInt(serverIdStr, 10);

  let clientWireBytes = 0;
  let serverWireBytes = 0;
  let clientEstablished = false;
  let serverEstablished = false;
  let clientAppSent = false;
  let serverReplySent = false;
  let clientAppWireHex = "";
  let serverAppWireHex = "";
  let serverDecrypted = "";
  let clientDecrypted = "";

  const server = net.createServer();

  try {
    const listenPort = await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        resolve(addr.port);
      });
    });

    await new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err) => {
        if (!settled) {
          settled = true;
          reject(err);
        }
      };
      const done = () => {
        if (!settled) {
          settled = true;
          resolve();
        }
      };

      let clientSock = null;
      let serverSock = null;

      server.on("connection", (sock) => {
        serverSock = sock;
        console.log(
          `  [TCP] Server listening on 127.0.0.1:${listenPort} <- accepted peer ${sock.remoteAddress}:${sock.remotePort}`
        );

        sock.on("data", (chunk) => {
          try {
            const feed = mustOk(
              tlcp_tcp_feed_in(serverHandle, chunk.toString("hex")),
              "server feed_in"
            );
            const [st, appHex] = feed.split("|");
            if (st === "ESTABLISHED" && !serverEstablished) {
              serverEstablished = true;
              console.log(`  [TLCP Server] Handshake ESTABLISHED over OS TCP`);
            }
            flushToSocket(serverHandle, sock, (buf) => {
              serverWireBytes += buf.length;
            });
            if (appHex && appHex.length > 0) {
              serverDecrypted += Buffer.from(appHex, "hex").toString("utf8");
              if (serverDecrypted === clientMsg && !serverReplySent) {
                serverReplySent = true;
                mustOk(
                  tlcp_tcp_send_app(serverHandle, serverReply),
                  "server send_app"
                );
                flushToSocket(serverHandle, sock, (buf, hex) => {
                  serverWireBytes += buf.length;
                  serverAppWireHex = hex;
                });
              }
            }
          } catch (err) {
            fail(err);
          }
        });
        sock.on("error", fail);
      });

      clientSock = net.createConnection({ host: "127.0.0.1", port: listenPort }, () => {
        console.log(
          `  [TCP] Client connected from 127.0.0.1:${clientSock.localPort} -> 127.0.0.1:${listenPort}`
        );
        try {
          // Transmit initial ClientHello queued by tlcp_tcp_init_pair
          flushToSocket(clientHandle, clientSock, (buf) => {
            clientWireBytes += buf.length;
          });
        } catch (err) {
          fail(err);
        }
      });

      clientSock.on("data", (chunk) => {
        try {
          const feed = mustOk(
            tlcp_tcp_feed_in(clientHandle, chunk.toString("hex")),
            "client feed_in"
          );
          const [st, appHex] = feed.split("|");
          if (st === "ESTABLISHED" && !clientEstablished) {
            clientEstablished = true;
            console.log(`  [TLCP Client] Handshake ESTABLISHED over OS TCP`);
          }
          flushToSocket(clientHandle, clientSock, (buf) => {
            clientWireBytes += buf.length;
          });
          if (clientEstablished && !clientAppSent) {
            clientAppSent = true;
            mustOk(
              tlcp_tcp_send_app(clientHandle, clientMsg),
              "client send_app"
            );
            flushToSocket(clientHandle, clientSock, (buf, hex) => {
              clientWireBytes += buf.length;
              clientAppWireHex = hex;
            });
          }
          if (appHex && appHex.length > 0) {
            clientDecrypted += Buffer.from(appHex, "hex").toString("utf8");
            if (clientDecrypted === serverReply) {
              clientSock.end();
              if (serverSock) serverSock.end();
              done();
            }
          }
        } catch (err) {
          fail(err);
        }
      });

      clientSock.on("error", fail);
    });

    assert.equal(clientEstablished, true);
    assert.equal(serverEstablished, true);
    assert.equal(serverDecrypted, clientMsg);
    assert.equal(clientDecrypted, serverReply);
    assert.ok(clientAppWireHex.length > 0);
    assert.ok(serverAppWireHex.length > 0);

    console.log(
      `  [Wire] Total OS TCP bytes: Client->Server=${clientWireBytes}B, Server->Client=${serverWireBytes}B`
    );
    console.log(
      `  [Wire] Client AppData Ciphertext (${clientAppWireHex.length / 2}B): ${clientAppWireHex.slice(0, 80)}...`
    );
    console.log(`  [Server Decrypted] ${serverDecrypted}`);
    console.log(
      `  [Wire] Server AppData Ciphertext (${serverAppWireHex.length / 2}B): ${serverAppWireHex.slice(0, 80)}...`
    );
    console.log(`  [Client Decrypted] ${clientDecrypted}`);
    console.log(`  [PASS] ${suite} real OS TCP socket end-to-end verified!`);
  } finally {
    await new Promise((resolve) => server.close(() => resolve()));
    mustOk(tlcp_tcp_close(clientHandle), "close clientHandle");
    mustOk(tlcp_tcp_close(serverHandle), "close serverHandle");
  }
}

async function main() {
  console.log("=== MoonTLCP Real OS TCP Socket E2E Demo (Node " + process.version + ") ===");
  await runTcpScenario({
    suite: "ECC_SM4_GCM_SM3",
    mutualAuth: false,
    clientMsg: "GET /gm/v1/account HTTP/1.1 | 国密 TLCP 1.1 SM4-GCM 实测报文",
    serverReply: "HTTP/1.1 200 OK | Authenticated & Encrypted via SM4-GCM",
  });
  await runTcpScenario({
    suite: "ECDHE_SM4_CBC_SM3",
    mutualAuth: true,
    clientMsg: "POST /gm/v1/settlement | mTLCP 双向认证 + SM2-KE + CBC-SM3",
    serverReply: "HTTP/1.1 200 OK | mTLCP Dual-Cert Verified & Settled",
  });
  console.log("\n=== ALL REAL OS TCP SOCKET TLCP 1.1 DEMOS PASSED ===");
}

main().catch((err) => {
  console.error("TCP DEMO FAILED:", err);
  process.exit(1);
});
