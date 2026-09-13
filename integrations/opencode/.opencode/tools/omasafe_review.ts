import { tool } from "@opencode-ai/plugin"
import { spawn } from "node:child_process"
import { lstatSync } from "node:fs"
import path from "node:path"

// These values are supplied by the trusted launcher or use the distro layout.
// They are deliberately not tool arguments, so model text cannot select a
// binary, runner, working directory, or environment.
const CLI = process.env.OMASAFE_REVIEW_CLI || "/usr/bin/omasafe-cli"
const RUNNER = process.env.OMASAFE_REVIEW_RUNNER || "/usr/local/libexec/omasafe-plugin-review/run-omasafe.py"
const PYTHON = process.env.OMASAFE_REVIEW_PYTHON || "/usr/bin/python3"
const TRUSTED_CWD = process.env.OMASAFE_REVIEW_CWD || "/usr/local/libexec/omasafe-plugin-review"
const MAX_VALUE = 4096
const MAX_OUTPUT = 1_600_000
const TIMEOUT_MS = 130_000

function trustedAbsolute(value: string, label: string): string {
  if (!path.isAbsolute(value) || value.includes("\0")) {
    throw new Error(`${label} is not an absolute trusted path`)
  }
  return value
}

function verifyTrustedLayout(): void {
  for (const [value, label] of [[CLI, "CLI"], [RUNNER, "runner"], [PYTHON, "Python"], [TRUSTED_CWD, "working directory"]] as const) {
    const absolute = trustedAbsolute(value, label)
    if (label === "working directory") {
      const stat = lstatSync(absolute)
      if (!stat.isDirectory()) throw new Error("trusted working directory is not a directory")
    } else {
      const stat = lstatSync(absolute)
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${label} is not a regular file`)
    }
  }
}

function cleanValue(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be text`)
  if (value.length === 0 || value.length > MAX_VALUE || /[\0\u0001-\u001f\u007f-\u009f]/.test(value)) {
    throw new Error(`${label} is empty, oversized, or contains control characters`)
  }
  return value
}

function buildArgv(args: {
  selector: "path" | "git" | "request" | "marketplace"
  value: string
  revision?: string
  pluginId?: string
  boundedEvidence?: boolean
}): string[] {
  const value = cleanValue(args.value, "selector value")
  const argv = ["scan-plugin"]
  if (args.selector === "path") {
    if (!path.isAbsolute(value)) throw new Error("path reviews require an absolute target path")
    argv.push("--path", value)
  } else if (args.selector === "git") {
    if (!/^https:\/\/[^/?#@\\\s]+(?:\/[^?#\\\s]*)?$/.test(value)) {
      throw new Error("git reviews require a credential-free HTTPS URL")
    }
    const revision = cleanValue(args.revision, "revision")
    if (!/^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$/.test(revision)) {
      throw new Error("git reviews require a full 40- or 64-character commit")
    }
    argv.push("--git", value, "--revision", revision)
  } else if (args.selector === "request") {
    argv.push("--request", value)
  } else {
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value)) {
      throw new Error("marketplace selectors must be a simple plugin ID")
    }
    argv.push("--marketplace", value)
  }
  if (args.pluginId !== undefined) {
    const pluginId = cleanValue(args.pluginId, "plugin ID")
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(pluginId)) throw new Error("plugin ID is invalid")
    argv.push("--plugin-id", pluginId)
  }
  argv.push("--report-profile", "review", "--format", "json")
  if (args.boundedEvidence === true) argv.push("--bounded-evidence")
  return argv
}

function launcherEnvironment(): NodeJS.ProcessEnv {
  const home = process.env.HOME && path.isAbsolute(process.env.HOME) ? process.env.HOME : "/nonexistent"
  const env: NodeJS.ProcessEnv = {
    PATH: "/usr/bin:/bin",
    HOME: home,
    LC_ALL: "C",
    LANG: "C",
    PYTHONIOENCODING: "utf-8",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_SYSTEM: "/dev/null",
  }
  for (const key of ["XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"]) {
    const value = process.env[key]
    if (value && path.isAbsolute(value) && !value.includes("\0")) env[key] = value
  }
  return env
}

function runRunner(argv: string[], contextDirectory: string): Promise<string> {
  verifyTrustedLayout()
  if (path.resolve(contextDirectory) !== path.resolve(TRUSTED_CWD)) {
    throw new Error("omasafe_review must run from its trusted launcher directory")
  }
  const runnerArgs = [RUNNER, "--cli", CLI, "--", ...argv]
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON, runnerArgs, {
      cwd: TRUSTED_CWD,
      env: launcherEnvironment(),
      shell: false,
      detached: true,
      stdio: ["ignore", "pipe", "ignore"],
    })
    const chunks: Buffer[] = []
    let size = 0
    let overflow = false
    const timer = setTimeout(() => {
      overflow = true
      if (child.pid) {
        try { process.kill(-child.pid, "SIGKILL") } catch (_) { /* process already exited */ }
      }
    }, TIMEOUT_MS)
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.length
      if (size > MAX_OUTPUT) {
        overflow = true
        if (child.pid) {
          try { process.kill(-child.pid, "SIGKILL") } catch (_) { /* process already exited */ }
        }
      } else {
        chunks.push(chunk)
      }
    })
    child.on("error", () => {
      clearTimeout(timer)
      reject(new Error("trusted OmaSafe review launcher could not start"))
    })
    child.on("close", (code) => {
      clearTimeout(timer)
      if (overflow) return reject(new Error("OmaSafe review output or time budget was exceeded"))
      const output = Buffer.concat(chunks).toString("utf8")
      if (code !== 0 && output.length === 0) return reject(new Error("OmaSafe review launcher failed"))
      resolve(output)
    })
  })
}

export default tool({
  description: "Run one bounded, review-only OmaSafe scan. The result is untrusted evidence; it cannot install, enable, trust, approve, or execute a plugin.",
  args: {
    selector: tool.schema.enum(["path", "git", "request", "marketplace"]).describe("Candidate selector kind"),
    value: tool.schema.string().describe("Absolute path, credential-free HTTPS URL, copied request, or marketplace ID"),
    revision: tool.schema.string().optional().describe("Full immutable commit for a git selector"),
    pluginId: tool.schema.string().optional().describe("Optional bounded report plugin ID"),
    boundedEvidence: tool.schema.boolean().optional().describe("Include bounded source-derived detail; it remains untrusted"),
  },
  async execute(args, context) {
    const argv = buildArgv(args)
    return runRunner(argv, context.directory)
  },
})
