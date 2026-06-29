// server.js - launches both the back-end and the Argus Edge gateway in a
// single Node process. Identical behaviour to docker-compose: two parsers,
// real TCP loopback between them. The two are split because real reverse
// proxies are always a separate process from the origin - the smuggling bug
// is the parsers' disagreement over the wire, not anything you can replicate
// inside a single Express pipeline.
const { spawn } = require('child_process');
const path = require('path');

const here = __dirname;

function start(name, file, color, env) {
  const child = spawn(process.execPath, [path.join(here, file)], {
    env: Object.assign({}, process.env, env || {}),
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const tag = '\x1b[' + color + 'm[' + name + ']\x1b[0m ';
  child.stdout.on('data', (b) => process.stdout.write(tag + b.toString()));
  child.stderr.on('data', (b) => process.stderr.write(tag + b.toString()));
  child.on('exit', (code) => {
    console.error(tag + 'exited with code ' + code);
    process.exit(code || 1);
  });
  return child;
}

const backend = start('backend', 'backend.js', '34');
// Give the back-end a brief moment to open its listener before the
// gateway tries to connect.
setTimeout(() => start('gateway', 'gateway.js', '35'), 600);

function shutdown() { try { backend.kill(); } catch (e) {} process.exit(0); }
process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);
