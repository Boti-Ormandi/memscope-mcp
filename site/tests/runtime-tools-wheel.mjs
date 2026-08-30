import { spawnSync } from 'node:child_process'
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { compareRuntimeTools } from './runtime-tools-snapshot.mjs'

const siteRoot = fileURLToPath(new URL('../', import.meta.url))
const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url))
const captureScript = fileURLToPath(new URL('./capture-runtime-tools.py', import.meta.url))
const snapshotPath = join(siteRoot, 'tools.json')
const update = process.argv.slice(2).includes('--update')
const python = process.env.PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3')

function run(command, args, options = {}) {
  const completed = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    windowsHide: true,
    ...options
  })
  if (completed.error) throw completed.error
  if (completed.status !== 0) {
    throw new Error(
      `${basename(command)} ${args.join(' ')} failed (${completed.status})\n${completed.stdout}${completed.stderr}`
    )
  }
  return completed.stdout
}

const workspace = mkdtempSync(join(tmpdir(), 'memscope-site-wheel-'))
try {
  const wheelDirectory = join(workspace, 'dist')
  const environment = join(workspace, 'venv')
  mkdirSync(wheelDirectory)

  run(python, [
    '-m',
    'pip',
    'wheel',
    '--disable-pip-version-check',
    '--no-deps',
    '--wheel-dir',
    wheelDirectory,
    repositoryRoot
  ])

  const wheels = readdirSync(wheelDirectory).filter((name) => /^memscope_mcp-.*\.whl$/.test(name))
  if (wheels.length !== 1) throw new Error(`expected one memscope-mcp wheel, found ${wheels.length}`)
  const wheel = join(wheelDirectory, wheels[0])

  run(python, ['-m', 'venv', environment])
  const environmentPython =
    process.platform === 'win32'
      ? join(environment, 'Scripts', 'python.exe')
      : join(environment, 'bin', 'python')
  run(environmentPython, [
    '-m',
    'pip',
    'install',
    '--disable-pip-version-check',
    wheel
  ])

  const runtimeCapture = JSON.parse(run(environmentPython, [captureScript]))
  const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8'))

  if (update) {
    snapshot.tools = runtimeCapture.tools
    writeFileSync(snapshotPath, `${JSON.stringify(snapshot, null, 2)}\n`, 'utf8')
    process.stdout.write(`Updated site/tools.json from installed ${wheels[0]}.\n`)
  } else {
    const count = compareRuntimeTools(snapshot, runtimeCapture)
    process.stdout.write(
      `Installed ${wheels[0]} matches site/tools.json for ${count} ordered tools.\n`
    )
  }
} finally {
  rmSync(workspace, { recursive: true, force: true })
}
