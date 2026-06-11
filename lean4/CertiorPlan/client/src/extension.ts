/**
 * Certior Plan DAP - VS Code Extension
 *
 * Fork of ImpLab's `client/src/extension.ts` adapted for verified
 * agent plan debugging. Key differences:
 *
 * - Debug type: `certior-plan-dap` (was `lean-toy-dap`)
 * - Binary: `certior-dap` (was `toydap`)
 * - PlanInfo replaces ProgramInfo
 * - Additional launch config: `compliancePolicy`, `capabilityTokens`
 * - Custom commands: certificates, flowGraph, complianceExport
 *
 * Copyright (c) 2026 Certior. All rights reserved.
 * Architecture adapted from ImpLab (Lean FRO, Apache 2.0).
 */

import * as vscode from 'vscode'
import * as fs from 'node:fs'
import * as path from 'node:path'

// ─────────────────────────────────────────────────────────────────────
//  Debug Adapter Factory
// ─────────────────────────────────────────────────────────────────────

class CertiorDebugAdapterFactory
  implements vscode.DebugAdapterDescriptorFactory
{
  constructor(private readonly output: vscode.OutputChannel) {}

  createDebugAdapterDescriptor(
    session: vscode.DebugSession,
  ): vscode.ProviderResult<vscode.DebugAdapterDescriptor> {
    const command = this.resolveDapCommand(session)
    const args = this.resolveDapArgs(session)
    this.output.appendLine(
      `[certior-dap] launching ${command}${args.length > 0 ? ` ${args.join(' ')}` : ''}`,
    )
    return new vscode.DebugAdapterExecutable(command, args)
  }

  /**
   * Resolve the path to the certior-dap binary.
   *
   * Resolution order:
   * 1. Explicit `certiorDapPath` in launch config
   * 2. `.lake/build/bin/certior-dap` in workspace
   * 3. `certior-dap` in PATH
   */
  private resolveDapCommand(session: vscode.DebugSession): string {
    const configured = session.configuration?.certiorDapPath
    if (typeof configured === 'string' && configured.trim().length > 0) {
      return configured.trim()
    }

    const workspaceFolders = vscode.workspace.workspaceFolders ?? []
    for (const folder of workspaceFolders) {
      const candidate = path.join(
        folder.uri.fsPath,
        '.lake',
        'build',
        'bin',
        'certior-dap',
      )
      if (fs.existsSync(candidate)) {
        return candidate
      }
    }

    return 'certior-dap'
  }

  private resolveDapArgs(session: vscode.DebugSession): string[] {
    const raw = session.configuration?.certiorDapArgs
    if (!Array.isArray(raw)) {
      return []
    }
    return raw.map((value: unknown) => String(value))
  }
}

// ─────────────────────────────────────────────────────────────────────
//  Debug Configuration Provider
// ─────────────────────────────────────────────────────────────────────

class CertiorDebugConfigurationProvider
  implements vscode.DebugConfigurationProvider
{
  constructor(private readonly output: vscode.OutputChannel) {}

  private tryLoadJson(filePath: string): unknown | undefined {
    if (!fs.existsSync(filePath)) {
      return undefined
    }
    const raw = fs.readFileSync(filePath, 'utf8')
    return JSON.parse(raw)
  }

  /**
   * Walk up from the source file to find the project root
   * (directory containing lakefile.lean or lakefile.toml).
   */
  private resolveProjectRootFromSource(
    sourcePath: string,
  ): string | undefined {
    let dir = path.dirname(sourcePath)
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const hasLakefile =
        fs.existsSync(path.join(dir, 'lakefile.lean')) ||
        fs.existsSync(path.join(dir, 'lakefile.toml'))
      if (hasLakefile) {
        return dir
      }
      const parent = path.dirname(dir)
      if (parent === dir) {
        return undefined
      }
      dir = parent
    }
  }

  /**
   * Generate candidate paths for auto-discovered planInfo JSON.
   */
  private resolveGeneratedPlanInfoPaths(
    folder: vscode.WorkspaceFolder | undefined,
    config: vscode.DebugConfiguration,
  ): string[] {
    const paths: string[] = []
    const pushUnique = (p: string | undefined) => {
      if (p && !paths.includes(p)) {
        paths.push(p)
      }
    }

    const workspaceRoot =
      folder?.uri.fsPath ??
      vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
    const source =
      typeof config.source === 'string' ? config.source : undefined
    const sourcePath = source ? path.resolve(source) : undefined
    const sourceProjectRoot = sourcePath
      ? this.resolveProjectRootFromSource(sourcePath)
      : undefined

    // Also try explicit planInfoPath
    if (typeof config.planInfoPath === 'string') {
      pushUnique(path.resolve(config.planInfoPath))
    }

    pushUnique(
      sourceProjectRoot
        ? path.join(
            sourceProjectRoot,
            '.dap',
            'planInfo.generated.json',
          )
        : undefined,
    )
    pushUnique(
      workspaceRoot
        ? path.join(
            workspaceRoot,
            '.dap',
            'planInfo.generated.json',
          )
        : undefined,
    )

    return paths
  }

  resolveDebugConfiguration(
    folder: vscode.WorkspaceFolder | undefined,
    config: vscode.DebugConfiguration,
  ): vscode.ProviderResult<vscode.DebugConfiguration> {
    if (!config.type) {
      config.type = 'certior-plan-dap'
    }
    if (!config.request) {
      config.request = 'launch'
    }
    if (!config.name) {
      config.name = 'Certior Plan DAP'
    }
    if (!config.source) {
      const active = vscode.window.activeTextEditor?.document.uri
      if (active?.scheme === 'file') {
        config.source = active.fsPath
      }
    }
    if (!config.planInfo) {
      for (const generatedPath of this.resolveGeneratedPlanInfoPaths(
        folder,
        config,
      )) {
        try {
          const loaded = this.tryLoadJson(generatedPath)
          if (loaded !== undefined) {
            config.planInfo = loaded
            this.output.appendLine(
              `[certior-dap] planInfo loaded from ${generatedPath}`,
            )
            break
          }
        } catch {
          vscode.window.showErrorMessage(
            `certior-plan-dap: invalid JSON in ${generatedPath}`,
          )
          return null
        }
      }
    }
    if (!config.planInfo) {
      vscode.window.showErrorMessage(
        "Certior Plan DAP launch requires 'planInfo'. " +
          "Run `lake exe plan-export --decl basic --out .dap/planInfo.generated.json` " +
          'or set launch.planInfo in your debug configuration.',
      )
      return null
    }
    return config
  }
}

// ─────────────────────────────────────────────────────────────────────
//  Custom Commands
// ─────────────────────────────────────────────────────────────────────

/**
 * Send a custom DAP request and display results.
 */
async function sendCustomRequest(
  command: string,
  title: string,
): Promise<void> {
  const session = vscode.debug.activeDebugSession
  if (!session || session.type !== 'certior-plan-dap') {
    vscode.window.showWarningMessage(
      'No active Certior Plan debug session.',
    )
    return
  }
  try {
    const response = await session.customRequest(command)
    const content = JSON.stringify(response, null, 2)
    const doc = await vscode.workspace.openTextDocument({
      content,
      language: 'json',
    })
    await vscode.window.showTextDocument(doc, {
      viewColumn: vscode.ViewColumn.Beside,
      preview: true,
    })
  } catch (err) {
    vscode.window.showErrorMessage(
      `${title} failed: ${String(err)}`,
    )
  }
}

// ─────────────────────────────────────────────────────────────────────
//  Extension Lifecycle
// ─────────────────────────────────────────────────────────────────────

export function activate(
  context: vscode.ExtensionContext,
): void {
  const output = vscode.window.createOutputChannel(
    'Certior Plan DAP',
  )

  const configProvider = new CertiorDebugConfigurationProvider(output)
  const adapterFactory = new CertiorDebugAdapterFactory(output)

  context.subscriptions.push(
    output,

    // Core DAP registration
    vscode.debug.registerDebugConfigurationProvider(
      'certior-plan-dap',
      configProvider,
    ),
    vscode.debug.registerDebugAdapterDescriptorFactory(
      'certior-plan-dap',
      adapterFactory,
    ),

    // Start debugging command
    vscode.commands.registerCommand(
      'certiorPlan.startDebugging',
      async () => {
        const active =
          vscode.window.activeTextEditor?.document.uri
        const source =
          active?.scheme === 'file' ? active.fsPath : undefined
        await vscode.debug.startDebugging(undefined, {
          name: 'Certior Plan DAP',
          type: 'certior-plan-dap',
          request: 'launch',
          source,
          stopOnEntry: true,
        })
      },
    ),

    // Custom Certior commands
    vscode.commands.registerCommand(
      'certiorPlan.showCertificates',
      () => sendCustomRequest('certificates', 'Certificates'),
    ),
    vscode.commands.registerCommand(
      'certiorPlan.showFlowGraph',
      () => sendCustomRequest('flowGraph', 'Flow Graph'),
    ),
    vscode.commands.registerCommand(
      'certiorPlan.exportCompliance',
      () =>
        sendCustomRequest('complianceExport', 'Compliance Export'),
    ),
  )
}

export function deactivate(): void {}
