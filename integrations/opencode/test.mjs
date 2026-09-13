import assert from "node:assert/strict"
import { chmod, copyFile, mkdtemp, mkdir, readFile, symlink, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { pathToFileURL } from "node:url"

const root = await mkdtemp(path.join(os.tmpdir(), "omasafe-opencode-tool-test."))
const trusted = path.join(root, "trusted")
const capture = path.join(root, "runner-argv.txt")
await mkdir(trusted, { mode: 0o700 })

const cli = path.join(trusted, "omasafe-cli")
const runner = path.join(trusted, "run-omasafe.py")
const python = path.join(trusted, "python")
await writeFile(cli, "#!/bin/sh\nexit 0\n", { mode: 0o700 })
await writeFile(runner, "#!/bin/sh\nexit 0\n", { mode: 0o700 })
await writeFile(
  python,
  `#!/bin/sh
printf '%s\\n' "$@" > ${JSON.stringify(capture)}
printf '%s\\n' '{"status":"ok"}'
`,
  { mode: 0o700 },
)
await chmod(cli, 0o700)
await chmod(runner, 0o700)
await chmod(python, 0o700)

// Resolve the installed OpenCode plugin without modifying the user's config.
// The override is useful on hosts that keep OpenCode dependencies elsewhere.
const pluginDir = process.env.OPENCODE_PLUGIN_DIR || "/home/hvo/.config/opencode/node_modules/@opencode-ai/plugin"
await mkdir(path.join(root, "node_modules"), { recursive: true })
await symlink(path.dirname(pluginDir), path.join(root, "node_modules", "@opencode-ai"), "dir")
await copyFile(
  path.resolve("integrations/opencode/.opencode/tools/omasafe_review.ts"),
  path.join(root, "omasafe_review.ts"),
)

process.env.OMASAFE_REVIEW_CLI = cli
process.env.OMASAFE_REVIEW_RUNNER = runner
process.env.OMASAFE_REVIEW_PYTHON = python
process.env.OMASAFE_REVIEW_CWD = trusted

const adapter = (await import(pathToFileURL(path.join(root, "omasafe_review.ts")).href)).default
const context = { directory: trusted }
const revision = "a".repeat(40)
const result = await adapter.execute(
  { selector: "git", value: "https://github.com/example/plugin.git", revision, boundedEvidence: true },
  context,
)
assert.equal(result, '{"status":"ok"}\n')

const argv = (await readFile(capture, "utf8")).trimEnd().split("\n")
assert.deepEqual(argv.slice(-11), [
  "--",
  "scan-plugin",
  "--git",
  "https://github.com/example/plugin.git",
  "--revision",
  revision,
  "--report-profile",
  "review",
  "--format",
  "json",
  "--bounded-evidence",
])

await assert.rejects(
  () => adapter.execute(
    { selector: "git", value: "https://user@example.com/plugin.git", revision },
    context,
  ),
  /credential-free HTTPS URL/,
)
await assert.rejects(
  () => adapter.execute({ selector: "path", value: "/tmp/candidate" }, { directory: root }),
  /trusted launcher directory/,
)

console.log("OpenCode adapter tests: ok")
