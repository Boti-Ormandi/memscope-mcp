import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const snapshotPath = new URL('../tools.json', import.meta.url)
const comparedFields = ['name', 'description', 'inputSchema', 'outputSchema']

function toolFields(tool, index, source) {
  assert.equal(typeof tool, 'object', `${source} tool ${index} must be an object`)
  assert.notEqual(tool, null, `${source} tool ${index} must be an object`)
  assert.equal(Array.isArray(tool), false, `${source} tool ${index} must be an object`)
  assert.equal(typeof tool.name, 'string', `${source} tool ${index} must have a name`)
  assert.equal(typeof tool.description, 'string', `${source} tool ${index} must have a description`)
  assert.equal(
    Object.hasOwn(tool, 'inputSchema'),
    true,
    `${source} tool ${index} must have an inputSchema`
  )

  return Object.fromEntries(
    comparedFields
      .filter((field) => Object.hasOwn(tool, field))
      .map((field) => [field, tool[field]])
  )
}

function runtimeTools(payload) {
  if (Array.isArray(payload)) return payload
  assert.equal(typeof payload, 'object', 'runtime capture must be an array or an object with tools')
  assert.notEqual(payload, null, 'runtime capture must be an array or an object with tools')
  assert.equal(Array.isArray(payload.tools), true, 'runtime capture tools must be an array')
  return payload.tools
}

export function compareRuntimeTools(snapshot, runtimeCapture) {
  assert.equal(snapshot?.formatVersion, 1, 'site snapshot formatVersion must be 1')
  assert.equal(Array.isArray(snapshot?.tools), true, 'site snapshot tools must be an array')

  const expected = snapshot.tools.map((tool, index) => toolFields(tool, index, 'site snapshot'))
  const actual = runtimeTools(runtimeCapture).map((tool, index) =>
    toolFields(tool, index, 'runtime capture')
  )
  assert.deepStrictEqual(
    actual,
    expected,
    'installed-wheel list_tools fields differ from site/tools.json'
  )
  return actual.length
}

function invokedDirectly() {
  const entry = process.argv[1]
  return entry !== undefined && import.meta.url === pathToFileURL(resolve(entry)).href
}

if (invokedDirectly()) {
  if (process.argv.length !== 3) {
    process.stderr.write('Usage: node tests/runtime-tools-snapshot.mjs <list-tools.json>\n')
    process.exitCode = 2
  } else {
    try {
      const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8'))
      const capture = JSON.parse(readFileSync(resolve(process.argv[2]), 'utf8'))
      const count = compareRuntimeTools(snapshot, capture)
      process.stdout.write(
        `Installed-wheel list_tools matches site/tools.json for ${count} ordered tools and ${comparedFields.join(', ')}.\n`
      )
    } catch (error) {
      process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`)
      process.exitCode = 1
    }
  }
}
