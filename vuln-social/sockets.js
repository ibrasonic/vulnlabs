// sockets.js — Socket.IO realtime layer.
// VULNS:
//  * cors: { origin: '*' }                                  -> CSWSH
//  * no auth challenge on connect (no session/JWT check)    -> anyone can subscribe
//  * `read_dm` event accepts arbitrary dm_id and returns it -> WS-level IDOR
//  * `broadcast` event accepts any message and emits to all -> abuse
const { Server } = require('socket.io');
const db = require('./lib/db');

function attach(httpServer) {
  const io = new Server(httpServer, {
    cors: { origin: '*', credentials: true }
  });

  io.on('connection', (socket) => {
    console.log('[ws] client connected', socket.id, 'origin=', socket.handshake.headers.origin || '');
    socket.emit('hello', { id: socket.id, banner: 'Pulse realtime ready' });

    // VULN: no auth required to fetch any DM.
    socket.on('read_dm', (payload) => {
      const id = parseInt((payload && payload.id) || '0', 10);
      if (!id) return socket.emit('dm', { error: 'missing id' });
      const dm = db.prepare('SELECT * FROM dms WHERE id = ?').get(id);
      socket.emit('dm', dm || { error: 'not found' });
    });

    // VULN: open broadcast channel.
    socket.on('broadcast', (payload) => {
      io.emit('broadcast', { from: socket.id, ts: Date.now(), msg: payload && payload.msg });
    });

    // VULN: subscribe to a user-id stream with no permission check.
    socket.on('subscribe', (payload) => {
      const uid = parseInt((payload && payload.user_id) || '0', 10);
      if (!uid) return;
      socket.join('user:' + uid);
      socket.emit('subscribed', { user_id: uid });
    });

    socket.on('disconnect', () => console.log('[ws] disconnected', socket.id));
  });

  return io;
}

module.exports = { attach };
