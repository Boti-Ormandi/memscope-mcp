import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { compareRuntimeTools } from './runtime-tools-snapshot.mjs'

const snapshot = JSON.parse(
  readFileSync(new URL('../tools.json', import.meta.url), 'utf8')
)

function capture() {
  return { tools: structuredClone(snapshot.tools) }
}

test('accepts the exact ordered runtime tool fields', () => {
  assert.equal(compareRuntimeTools(snapshot, capture()), 11)
})

test('detects name, description, schema, presence, and order drift', async (t) => {
  const cases = {
    name(value) {
      value.tools[0].name = 'changed-name'
    },
    description(value) {
      value.tools[0].description += ' changed'
    },
    inputSchema(value) {
      value.tools[0].inputSchema.properties.limit.default = 99
    },
    outputSchema(value) {
      value.tools.find((tool) => Object.hasOwn(tool, 'outputSchema')).outputSchema.title = 'Changed'
    },
    outputSchemaPresence(value) {
      value.tools[0].outputSchema = { type: 'object' }
    },
    order(value) {
      value.tools.reverse()
    }
  }

  for (const [name, mutate] of Object.entries(cases)) {
    await t.test(name, () => {
      const value = capture()
      mutate(value)
      assert.throws(
        () => compareRuntimeTools(snapshot, value),
        /installed-wheel list_tools fields differ/
      )
    })
  }
})
