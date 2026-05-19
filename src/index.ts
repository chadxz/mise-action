import * as cache from '@actions/cache'
import * as io from '@actions/io'
import * as core from '@actions/core'
import * as exec from '@actions/exec'
import * as glob from '@actions/glob'
import * as crypto from 'crypto'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import * as Handlebars from 'handlebars'

// Configuration file patterns for cache key generation
const MISE_CONFIG_FILE_PATTERNS = [
  `**/.config/mise/config.toml`,
  `**/.config/mise/config.lock`,
  `**/.config/mise/config.*.toml`,
  `**/.config/mise/config.*.lock`,
  `**/.config/mise.toml`,
  `**/.config/mise.lock`,
  `**/.config/mise.*.toml`,
  `**/.config/mise.*.lock`,
  `**/.mise/config.toml`,
  `**/.mise/config.lock`,
  `**/.mise/config.*.toml`,
  `**/.mise/config.*.lock`,
  `**/mise/config.toml`,
  `**/mise/config.lock`,
  `**/mise/config.*.toml`,
  `**/mise/config.*.lock`,
  `**/.mise.toml`,
  `**/.mise.lock`,
  `**/.mise.*.toml`,
  `**/.mise.*.lock`,
  `**/mise.toml`,
  `**/mise.lock`,
  `**/mise.*.toml`,
  `**/mise.*.lock`,
  `**/.tool-versions`
]

// Default cache key template
const DEFAULT_CACHE_KEY_TEMPLATE =
  '{{cache_key_prefix}}-{{platform}}-{{dir_hash}}{{#if version}}-{{version}}{{/if}}{{#if mise_env}}-{{mise_env}}{{/if}}{{#if install_args_hash}}-{{install_args_hash}}{{/if}}-{{#if file_hash}}{{file_hash}}{{else}}no-config{{/if}}'

interface CacheState {
  key: string
  hit: boolean
}

async function run(): Promise<void> {
  try {
    await setToolVersions()
    await setMiseToml()

    const version = core.getInput('version')
    const resolvedLatestVersion = version
      ? undefined
      : await latestMiseVersion()
    const cacheEnabled = core.getBooleanInput('cache')

    // Restore binary cache, install mise, save binary cache if needed
    let binaryCache: CacheState = { key: '', hit: false }
    if (cacheEnabled) {
      binaryCache = await restoreMiseBinaryCache(version, resolvedLatestVersion)
    }
    await setupMise(
      version,
      core.getBooleanInput('fetch_from_github'),
      resolvedLatestVersion
    )
    if (cacheEnabled) {
      await saveMiseBinaryCache(binaryCache)
    }

    // Wings opt-in hook (experimental). When
    // `wings_enabled: true` is set, this exports
    // `MISE_WINGS_ENABLED=1` so subsequent `mise install`
    // commands in this workflow route through the wings
    // cache. Default `false` so workflows with
    // `id-token: write` (used for SLSA / AWS-OIDC / Sigstore /
    // etc.) don't silently send the runner's OIDC token to
    // a third-party cache without explicit consent.
    //
    // Note: `setupMise` fetches the mise binary itself with
    // `curl`, which doesn't go through mise's HTTP layer —
    // the wings rewriter only kicks in once the resulting
    // mise binary runs `mise install` and friends. Ordering
    // here is irrelevant for binary acceleration; we just
    // want the env var set before any `mise` subcommand
    // runs. Greptile + Gemini both flagged the previous
    // comment as overstating what the early call accelerates.
    setupWings()

    // Restore tools cache (needs mise installed to compute key for working_directory)
    let toolsCache: CacheState = { key: '', hit: false }
    if (cacheEnabled) {
      toolsCache = await restoreToolsCache()
    }
    core.setOutput('cache-hit', toolsCache.hit)

    await setEnvVars()
    if (core.getBooleanInput('reshim')) {
      await miseReshim()
    }
    await testMise()
    if (core.getBooleanInput('install')) {
      await miseInstall()
      if (cacheEnabled) {
        await saveToolsCache(toolsCache)
      }
    }
    await miseLs()
    if (core.getBooleanInput('env')) {
      await exportMiseEnv()
    }
  } catch (err) {
    if (err instanceof Error) core.setFailed(err.message)
    else throw err
  }
}

/**
 * Opt in to mise-wings caching for this workflow run. When
 * `wings_enabled: true`, exports `MISE_WINGS_ENABLED=1` so
 * subsequent `mise install` commands route through the
 * cache.
 *
 * Mise itself owns the OIDC → wings session exchange — when
 * it sees `MISE_WINGS_ENABLED=1` and the GHA OIDC env vars
 * (`ACTIONS_ID_TOKEN_REQUEST_URL` +
 * `ACTIONS_ID_TOKEN_REQUEST_TOKEN`), it fetches the runner's
 * OIDC token, exchanges it at the proxy's `POST /auth`
 * route, and caches the resulting session JWT for the rest
 * of the process.
 *
 * Pre-flight check: `id-token: write` permission must be
 * declared at the workflow or job level for the OIDC env
 * vars to be present. We log a warning when wings is
 * enabled but the env vars are absent — without this hint,
 * the user sees a transparent "wings configured but doing
 * nothing" which is hard to debug.
 */
function setupWings(): void {
  if (!core.getBooleanInput('wings_enabled')) {
    return
  }
  core.exportVariable('MISE_WINGS_ENABLED', '1')
  core.info(
    "mise-wings: enabled. mise will exchange the runner's OIDC token for a wings session on first use."
  )

  const oidcUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL
  const oidcToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  if (!oidcUrl || !oidcToken) {
    core.warning(
      'mise-wings: GHA OIDC env vars are missing. Add ' +
        '`permissions: id-token: write` at the workflow or job ' +
        'level so the runner can mint OIDC tokens. Without this, ' +
        'mise falls through to direct-origin fetches and the cache ' +
        'is bypassed.'
    )
  }
}

async function exportMiseEnv(): Promise<void> {
  core.startGroup('Exporting mise environment variables')

  const cwd = getCwd()

  // Check if mise supports --redacted flags based on version input
  const supportsRedacted = checkMiseSupportsRedacted()

  if (supportsRedacted) {
    try {
      // First, get the redacted values to identify what needs masking
      const redactedOutput = await exec.getExecOutput(
        'mise',
        ['env', '--redacted', '--json'],
        { silent: true, cwd }
      )
      const redactedVars = JSON.parse(redactedOutput.stdout)

      // Mask sensitive values in GitHub Actions
      for (const [key, actualValue] of Object.entries(redactedVars)) {
        core.setSecret(actualValue as string)
        core.info(`Masked sensitive value for: ${key}`)
      }

      // Then get the actual values
      const actualOutput = await exec.getExecOutput('mise', ['env', '--json'], {
        cwd
      })
      const actualVars = JSON.parse(actualOutput.stdout)

      // Export all environment variables
      for (const [key, value] of Object.entries(actualVars)) {
        if (typeof value === 'string') {
          core.exportVariable(key, value)
        }
      }
    } catch {
      // Fall back to dotenv format if the redacted command fails
      core.info('Falling back to dotenv format')
      const output = await exec.getExecOutput('mise', ['env', '--dotenv'], {
        cwd
      })
      fs.appendFileSync(process.env.GITHUB_ENV!, output.stdout)
    }
  } else {
    // Fall back to the old --dotenv format for older versions
    const output = await exec.getExecOutput('mise', ['env', '--dotenv'], {
      cwd
    })
    fs.appendFileSync(process.env.GITHUB_ENV!, output.stdout)
  }

  core.endGroup()
}

function cleanVersion(version: string) {
  // remove 'v' prefix if present
  return version.replace(/^v/, '')
}

function checkMiseSupportsRedacted(): boolean {
  const version = core.getInput('version')

  // If no version is specified, assume latest which supports redacted
  if (!version) {
    return true
  }

  const versionMatch = cleanVersion(version).match(/^(\d+)\.(\d+)\.(\d+)/)

  if (!versionMatch) {
    // If we can't parse the version, assume it supports redacted
    return true
  }

  const [, year, month, patch] = versionMatch
  const yearNum = parseInt(year, 10)
  const monthNum = parseInt(month, 10)
  const patchNum = parseInt(patch, 10)

  // Check if version is >= 2025.8.17
  if (yearNum > 2025) return true
  if (yearNum === 2025) {
    if (monthNum > 8) return true
    if (monthNum === 8 && patchNum >= 17) return true
  }

  return false
}

async function setEnvVars(): Promise<void> {
  core.startGroup('Setting env vars')
  const set = (k: string, v: string): void => {
    if (!process.env[k]) {
      core.info(`Setting ${k}=${v}`)
      core.exportVariable(k, v)
    }
  }
  if (core.getBooleanInput('experimental')) set('MISE_EXPERIMENTAL', '1')

  const logLevel = core.getInput('log_level')
  if (logLevel) set('MISE_LOG_LEVEL', logLevel)

  const githubToken = core.getInput('github_token')
  if (githubToken) {
    // Don't use GITHUB_TOKEN, use MISE_GITHUB_TOKEN instead to avoid downstream issues.
    set('MISE_GITHUB_TOKEN', githubToken)
  } else {
    core.warning(
      'No MISE_GITHUB_TOKEN provided. You may hit GitHub API rate limits when installing tools from GitHub.'
    )
  }

  set('MISE_TRUSTED_CONFIG_PATHS', process.cwd())
  set('MISE_YES', '1')

  if (core.getBooleanInput('add_shims_to_path')) {
    const shimsDir = path.join(miseDir(), 'shims')
    core.info(`Adding ${shimsDir} to PATH`)
    core.addPath(shimsDir)
  }
}

async function restoreMiseBinaryCache(
  version: string,
  resolvedLatestVersion?: string
): Promise<CacheState> {
  const binPath = path.join(miseDir(), 'bin')
  const platform = `${await getTarget()}-${getRunnerImageId()}`
  const resolvedVersion = cleanVersion(
    version || resolvedLatestVersion || (await latestMiseVersion())
  )
  const cacheKeyPrefix = core.getInput('cache_key_prefix') || 'mise-v1'
  // Include hash of miseDir path to handle custom mise_dir configurations
  const dirHash = crypto
    .createHash('sha256')
    .update(miseDir())
    .digest('hex')
    .slice(0, 8)
  const key = `${cacheKeyPrefix}-binary-${platform}-${resolvedVersion}-${dirHash}`

  const cacheKey = await core.group('Restoring mise binary cache', async () => {
    const restored = await cache.restoreCache([binPath], key)
    if (restored) {
      core.info(`mise binary cache restored from key: ${restored}`)
    } else {
      core.info(`mise binary cache not found for ${key}`)
    }
    return restored
  })

  return { key, hit: Boolean(cacheKey) }
}

async function saveMiseBinaryCache(state: CacheState): Promise<void> {
  if (!core.getBooleanInput('cache_save') || state.hit || !state.key) {
    return
  }

  await core.group('Saving mise binary cache', async () => {
    const binPath = path.join(miseDir(), 'bin')
    if (!fs.existsSync(binPath)) {
      throw new Error(
        `Binary cache folder path does not exist on disk: ${binPath}`
      )
    }

    const cacheId = await cache.saveCache([binPath], state.key)
    if (cacheId !== -1) {
      core.info(`Binary cache saved with key: ${state.key}`)
    }
  })
}

/**
 * Runs a function while preserving the mise binary. The tools cache includes
 * bin/, so restoring it could overwrite the binary that setupMise() just
 * installed. This backs up the binary files before and restores them after.
 */
async function withBinaryBackup<T>(fn: () => Promise<T>): Promise<T> {
  const binDir = path.join(miseDir(), 'bin')
  const binaryName = process.platform === 'win32' ? 'mise.exe' : 'mise'
  const requiredBinaryPath = path.join(binDir, binaryName)
  const backupDir = await fs.promises.mkdtemp(
    path.join(os.tmpdir(), 'mise-binary-backup-')
  )
  const binaryNames =
    process.platform === 'win32' ? [binaryName, 'mise-shim.exe'] : [binaryName]
  const backedUpBinaries: string[] = []

  try {
    if (!fs.existsSync(requiredBinaryPath)) {
      throw new Error(
        `Expected binary at ${requiredBinaryPath} but it does not exist`
      )
    }

    for (const name of binaryNames) {
      const binaryPath = path.join(binDir, name)
      if (fs.existsSync(binaryPath)) {
        await io.cp(binaryPath, path.join(backupDir, name))
        backedUpBinaries.push(name)
      }
    }

    try {
      return await fn()
    } finally {
      await io.rmRF(binDir)
      await fs.promises.mkdir(binDir, { recursive: true })
      for (const name of backedUpBinaries) {
        await io.cp(path.join(backupDir, name), path.join(binDir, name), {
          force: true
        })
      }
    }
  } finally {
    await io.rmRF(backupDir)
  }
}

async function restoreToolsCache(): Promise<CacheState> {
  const cacheKeyTemplate =
    core.getInput('cache_key') || DEFAULT_CACHE_KEY_TEMPLATE
  const key = await processCacheKeyTemplate(cacheKeyTemplate)

  if (!key) {
    core.info('Tools caching disabled')
    return { key: '', hit: false }
  }

  const cacheKey = await withBinaryBackup(() =>
    core.group('Restoring mise tools cache', async () => {
      const cachePath = miseDir()
      const restored = await cache.restoreCache([cachePath], key)
      if (restored) {
        core.info(`mise tools cache restored from key: ${restored}`)
      } else {
        core.info(`mise tools cache not found for ${key}`)
      }
      return restored
    })
  )

  return { key, hit: Boolean(cacheKey) }
}

async function setupMise(
  version: string,
  fetchFromGitHub = false,
  resolvedLatestVersion?: string
): Promise<void> {
  const miseBinDir = path.join(miseDir(), 'bin')
  const miseBinPath = path.join(
    miseBinDir,
    process.platform === 'win32' ? 'mise.exe' : 'mise'
  )
  const miseShimPath = path.join(miseBinDir, 'mise-shim.exe')
  let installedVersion: string | undefined
  if (!fs.existsSync(path.join(miseBinPath))) {
    core.startGroup(version ? `Download mise@${version}` : 'Setup mise')
    await fs.promises.mkdir(miseBinDir, { recursive: true })
    const ext =
      process.platform === 'win32'
        ? '.zip'
        : version && version.startsWith('2024')
          ? ''
          : (await zstdInstalled())
            ? '.tar.zst'
            : '.tar.gz'
    let resolvedVersion =
      version || resolvedLatestVersion || (await latestMiseVersion())
    resolvedVersion = resolvedVersion.replace(/^v/, '')
    let url: string
    if (!fetchFromGitHub && !version) {
      // Only for latest version
      url = `https://mise.jdx.dev/mise-latest-${await getTarget()}${ext}`
    } else {
      url = `https://github.com/jdx/mise/releases/download/v${resolvedVersion}/mise-v${resolvedVersion}-${await getTarget()}${ext}`
    }
    installedVersion = resolvedVersion
    switch (ext) {
      case '.zip': {
        await withExtractedZip(url, 'mise.zip', async extractDir => {
          const extractedMiseBinDir = path.join(extractDir, 'mise', 'bin')
          await io.mv(path.join(extractedMiseBinDir, 'mise.exe'), miseBinPath)
          await installWindowsMiseShim(extractedMiseBinDir, miseShimPath)
        })
        break
      }
      case '.tar.zst':
        await exec.exec('sh', [
          '-c',
          `curl -fsSL ${url} | tar --zstd -xf - -C ${os.tmpdir()} && mv ${os.tmpdir()}/mise/bin/mise ${miseBinPath}`
        ])
        break
      case '.tar.gz':
        await exec.exec('sh', [
          '-c',
          `curl -fsSL ${url} | tar -xzf - -C ${os.tmpdir()} && mv ${os.tmpdir()}/mise/bin/mise ${miseBinPath}`
        ])
        break
      default:
        await exec.exec('sh', ['-c', `curl -fsSL ${url} > ${miseBinPath}`])
        await exec.exec('chmod', ['+x', miseBinPath])
        break
    }
  } else {
    const requestedVersion = cleanVersion(core.getInput('version'))
    if (requestedVersion !== '') {
      installedVersion = await getInstalledMiseVersion(miseBinPath)
      if (requestedVersion === installedVersion) {
        core.info(`mise already installed`)
      } else {
        core.info(
          `mise already installed (${installedVersion}), but different version requested (${requestedVersion})`
        )
        await exec.exec(miseBinPath, ['self-update', requestedVersion, '-y'])
        core.info(`mise updated to version ${requestedVersion}`)
        installedVersion = requestedVersion
      }
    }
  }
  await ensureWindowsMiseShim(miseBinPath, miseShimPath, installedVersion)
  // compare with provided hash
  const want = core.getInput('sha256')
  if (want) {
    const hash = crypto.createHash('sha256')
    const fileBuffer = await fs.promises.readFile(miseBinPath)
    const got = hash.update(fileBuffer).digest('hex')
    if (got !== want) {
      throw new Error(
        `SHA256 mismatch: expected ${want}, got ${got} for ${miseBinPath}`
      )
    }
  }

  core.addPath(miseBinDir)
}

async function withExtractedZip(
  url: string,
  archiveName: string,
  fn: (extractDir: string) => Promise<void>
): Promise<void> {
  const tempDir = await fs.promises.mkdtemp(
    path.join(os.tmpdir(), 'mise-action-')
  )
  try {
    const archivePath = path.join(tempDir, archiveName)
    const extractDir = path.join(tempDir, 'extract')

    await exec.exec('curl', ['-fsSL', url, '--output', archivePath])
    await exec.exec('unzip', [archivePath, '-d', extractDir])
    await fn(extractDir)
  } finally {
    await io.rmRF(tempDir)
  }
}

async function installWindowsMiseShim(
  extractedMiseBinDir: string,
  miseShimPath: string
): Promise<void> {
  if (process.platform !== 'win32') return

  const extractedMiseShimPath = path.join(extractedMiseBinDir, 'mise-shim.exe')
  if (!fs.existsSync(extractedMiseShimPath)) {
    core.info('mise-shim.exe not found in the mise archive; skipping')
    return
  }

  await io.mv(extractedMiseShimPath, miseShimPath)
}

async function ensureWindowsMiseShim(
  miseBinPath: string,
  miseShimPath: string,
  version?: string
): Promise<void> {
  if (process.platform !== 'win32') return
  if (fs.existsSync(miseShimPath)) return

  core.info(
    'mise-shim.exe not found next to mise.exe; installing it from the matching release archive'
  )

  try {
    const installedVersion =
      version || (await getInstalledMiseVersion(miseBinPath))
    const archiveName = `mise-v${installedVersion}-${await getTarget()}.zip`
    const url = `https://github.com/jdx/mise/releases/download/v${installedVersion}/${archiveName}`

    await withExtractedZip(url, archiveName, async extractDir => {
      await installWindowsMiseShim(
        path.join(extractDir, 'mise', 'bin'),
        miseShimPath
      )
    })
  } catch (err) {
    core.warning(
      `Failed to install mise-shim.exe: ${errorMessage(err)}. Continuing because mise can fall back to file shim mode on Windows.`
    )
  }
}

async function getInstalledMiseVersion(miseBinPath: string): Promise<string> {
  const versionOutput = await exec.getExecOutput(
    miseBinPath,
    ['version', '--json'],
    { silent: true }
  )
  const versionJson = JSON.parse(versionOutput.stdout) as { version: string }
  return cleanVersion(versionJson.version.split(' ')[0])
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

async function zstdInstalled(): Promise<boolean> {
  try {
    await exec.exec('zstd', ['--version'])
    return true
  } catch {
    return false
  }
}

async function latestMiseVersion(): Promise<string> {
  const rsp = await exec.getExecOutput('curl', [
    '-fsSL',
    'https://mise.jdx.dev/VERSION'
  ])
  return rsp.stdout.trim()
}

async function setToolVersions(): Promise<void> {
  const toolVersions = core.getInput('tool_versions')
  if (toolVersions) {
    await writeFile('.tool-versions', toolVersions)
  }
}

async function setMiseToml(): Promise<void> {
  const toml = core.getInput('mise_toml')
  if (toml) {
    await writeFile('mise.toml', toml)
  }
}

const testMise = async (): Promise<number> => mise(['--version'])
const miseInstall = async (): Promise<number> =>
  mise([`install ${core.getInput('install_args')}`])
const miseLs = async (): Promise<number> => mise([`ls`])
const miseReshim = async (): Promise<number> => mise([`reshim`, `-f`])
const mise = async (args: string[]): Promise<number> =>
  await core.group(`Running mise ${args.join(' ')}`, async () => {
    const cwd = getCwd()
    const baseEnv = Object.fromEntries(
      Object.entries(process.env).filter(
        (entry): entry is [string, string] => entry[1] !== undefined
      )
    )
    const env = core.isDebug()
      ? { ...baseEnv, MISE_LOG_LEVEL: 'debug' }
      : baseEnv

    if (args.length === 1) {
      return exec.exec(`mise ${args}`, [], {
        cwd,
        env
      })
    } else {
      return exec.exec('mise', args, { cwd, env })
    }
  })

const writeFile = async (p: fs.PathLike, body: string): Promise<void> =>
  await core.group(`Writing ${p}`, async () => {
    core.info(`Body:\n${body}`)
    await fs.promises.writeFile(p, body, { encoding: 'utf8' })
  })

run()

function getCwd(): string {
  return (
    core.getInput('working_directory') ||
    core.getInput('install_dir') ||
    process.cwd()
  )
}

function miseDir(): string {
  const miseDir = core.getInput('mise_dir')
  if (miseDir) return miseDir

  const { MISE_DATA_DIR, XDG_DATA_HOME, LOCALAPPDATA } = process.env
  if (MISE_DATA_DIR) return MISE_DATA_DIR
  if (XDG_DATA_HOME) return path.join(XDG_DATA_HOME, 'mise')
  if (process.platform === 'win32' && LOCALAPPDATA)
    return path.join(LOCALAPPDATA, 'mise')

  return path.join(os.homedir(), '.local', 'share', 'mise')
}

async function saveToolsCache(state: CacheState): Promise<void> {
  if (!core.getBooleanInput('cache_save') || state.hit || !state.key) {
    return
  }

  await core.group('Saving mise tools cache', async () => {
    const cachePath = miseDir()

    if (!fs.existsSync(cachePath)) {
      throw new Error(`Cache folder path does not exist on disk: ${cachePath}`)
    }

    const cacheId = await cache.saveCache([cachePath], state.key)
    if (cacheId !== -1) {
      core.info(`Tools cache saved with key: ${state.key}`)
    }
  })
}

async function getTarget(): Promise<string> {
  const arch = process.arch === 'arm' ? 'armv7' : process.arch
  switch (process.platform) {
    case 'darwin':
      return `macos-${arch}`
    case 'win32':
      return `windows-${arch}`
    case 'linux':
      return `linux-${arch}${(await isMusl()) ? '-musl' : ''}`
    default:
      throw new Error(`Unsupported platform ${process.platform}`)
  }
}

/**
 * Identifies the runner image so cached binaries from one provider
 * (github-hosted, namespace.so, BuildJet, self-hosted) aren't restored
 * onto another provider's image where their compiled-in paths and libc
 * versions don't match. GitHub-hosted images export `ImageOS`
 * (e.g. "macos15", "ubuntu24"); other runners leave it unset and pool
 * under "self-hosted".
 */
function getRunnerImageId(): string {
  return process.env.ImageOS || 'self-hosted'
}

async function processCacheKeyTemplate(template: string): Promise<string> {
  // Get all available variables
  const version = core.getInput('version')
  const installArgs = core.getInput('install_args')
  const cacheKeyPrefix = core.getInput('cache_key_prefix') || 'mise-v1'
  const miseEnv = process.env.MISE_ENV?.replace(/,/g, '-')
  const platform = `${await getTarget()}-${getRunnerImageId()}`
  const workingDirectory =
    core.getInput('working_directory') || core.getInput('install_dir')
  const githubWorkspace = path.resolve(
    process.env.GITHUB_WORKSPACE || process.cwd()
  )

  // Calculate file hash
  // When working_directory is set, use mise config ls to get only relevant config files
  // Otherwise, use the glob pattern to get all config files in the repo
  let fileHash: string
  if (workingDirectory) {
    const configFiles = await configFilesForPath(workingDirectory)
    // Hash the contents of the config files
    // Include file path in each update to prevent collisions between different
    // file arrangements with the same concatenated content (e.g., "ab"+"cdef"
    // vs "abc"+"def")
    const hash = crypto.createHash('sha256')
    try {
      for (const file of configFiles) {
        const relativePath = path
          .relative(githubWorkspace, file)
          .split(path.sep)
          .join('/')
        hash.update(relativePath)
        hash.update('\0')
        const content = await fs.promises.readFile(file)
        hash.update(content)
        hash.update('\0')
      }
      fileHash = hash.digest('hex')
    } catch (error) {
      throw new Error(
        `Failed to read config file for cache key: ${errorMessage(error)}`,
        { cause: error }
      )
    }
  } else {
    fileHash = await glob.hashFiles(MISE_CONFIG_FILE_PATTERNS.join('\n'))
  }

  // Calculate install args hash
  let installArgsHash = ''
  if (installArgs) {
    const tools = installArgs
      .split(' ')
      .filter(arg => !arg.startsWith('-'))
      .sort()
      .join(' ')
    if (tools) {
      installArgsHash = crypto.createHash('sha256').update(tools).digest('hex')
    }
  }

  // Calculate mise dir hash to isolate caches for different mise_dir configurations
  // This matches the binary cache key which also includes dir_hash
  const dirHash = crypto
    .createHash('sha256')
    .update(miseDir())
    .digest('hex')
    .slice(0, 8)

  // Prepare base template data
  const baseTemplateData = {
    version,
    cache_key_prefix: cacheKeyPrefix,
    platform,
    file_hash: fileHash,
    dir_hash: dirHash,
    mise_env: miseEnv,
    install_args_hash: installArgsHash
  }

  // Calculate the default cache key by processing the default template
  const defaultTemplate = Handlebars.compile(DEFAULT_CACHE_KEY_TEMPLATE)
  const defaultCacheKey = defaultTemplate(baseTemplateData)

  // Prepare final template data including the default cache key and env variables
  const templateData = {
    ...baseTemplateData,
    default: defaultCacheKey,
    env: process.env
  }

  // Compile and execute the user's template
  const compiledTemplate = Handlebars.compile(template)
  return compiledTemplate(templateData)
}

async function isMusl() {
  // `ldd --version` always returns 1 and print to stderr
  const { stderr } = await exec.getExecOutput('ldd', ['--version'], {
    failOnStdErr: false,
    ignoreReturnCode: true
  })
  return stderr.indexOf('musl') > -1
}

/**
 * Checks if a file path is contained within a directory.
 *
 * Uses path.relative() to compute the relative path from parent to child.
 * If the result starts with ".." or is absolute, the child is outside the parent.
 *
 * @example
 * isPathWithin("/workspace", "/workspace/src/file.ts")     // true
 * isPathWithin("/workspace", "/workspace-other/file.ts")   // false (not a child)
 * isPathWithin("/workspace", "/etc/passwd")                // false (unrelated)
 * isPathWithin("C:\\work", "D:\\other\\file.ts")           // false (different drive on Windows)
 */
function isPathWithin(parent: string, child: string): boolean {
  const relative = path.relative(parent, child)
  return !relative.startsWith('..') && !path.isAbsolute(relative)
}

/**
 * Get config files that affect the given working directory using `mise config ls --json`.
 * This returns the hierarchy of configs (directory's own config + inherited parents).
 * Filters to only files within GITHUB_WORKSPACE and adds corresponding .lock files.
 */
async function configFilesForPath(workingDirectory: string): Promise<string[]> {
  const githubWorkspace = path.resolve(
    process.env.GITHUB_WORKSPACE || process.cwd()
  )
  const cwd = path.resolve(githubWorkspace, workingDirectory)
  // Use explicit path to mise binary instead of relying on PATH
  const miseBinPath = path.join(
    miseDir(),
    'bin',
    process.platform === 'win32' ? 'mise.exe' : 'mise'
  )

  try {
    const output = await exec.getExecOutput(
      miseBinPath,
      ['config', 'ls', '--json'],
      {
        cwd,
        silent: true
      }
    )

    const configs: Array<{ path: string }> = JSON.parse(output.stdout)
    const configFiles: string[] = []

    for (const config of configs) {
      const configPath = path.isAbsolute(config.path)
        ? config.path
        : path.resolve(cwd, config.path)
      // Filter to only files within GITHUB_WORKSPACE
      if (!isPathWithin(githubWorkspace, configPath)) {
        continue
      }
      configFiles.push(configPath)

      // Include corresponding lock files if they exist
      let lockPath: string | undefined
      if (configPath.endsWith('.toml')) {
        // mise.toml -> mise.lock
        lockPath = configPath.replace(/\.toml$/, '.lock')
      } else if (configPath.endsWith('.tool-versions')) {
        // .tool-versions -> mise.lock in the same directory
        lockPath = path.join(path.dirname(configPath), 'mise.lock')
      }
      if (
        lockPath &&
        fs.existsSync(lockPath) &&
        !configFiles.includes(lockPath)
      ) {
        configFiles.push(lockPath)
      }
    }

    return configFiles.sort()
  } catch (error) {
    throw new Error(
      `Failed to get config files for working_directory "${workingDirectory}": ${errorMessage(error)}`,
      { cause: error }
    )
  }
}
