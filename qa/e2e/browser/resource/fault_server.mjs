import { spawn } from 'node:child_process';

export async function startFaultServer() {
  const binary = process.env.KASPA_PORTAL_FAULT_SERVER_BIN;
  if (!binary) throw new Error('KASPA_PORTAL_FAULT_SERVER_BIN is required');
  const child = spawn(binary, [], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.stdout.setEncoding('utf8');
  const endpoint = await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`fault server startup timeout: ${stderr}`)),
      10_000,
    );
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.stdout.on('data', (chunk) => {
      const match = String(chunk).match(/FAULT_SERVER_URL=(ws:\/\/[^\s]+)/);
      if (match) {
        clearTimeout(timer);
        resolve(match[1]);
      }
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`fault server exited during startup (${code}): ${stderr}`));
    });
  });
  return { child, endpoint };
}

export async function stopFaultServer(child) {
  if (child.exitCode !== null) return;
  child.kill();
  await new Promise((resolve) => {
    const timer = setTimeout(resolve, 2_000);
    child.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
  });
}
