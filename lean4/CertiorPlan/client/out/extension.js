"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const fs = __importStar(require("node:fs"));
const path = __importStar(require("node:path"));
// ─────────────────────────────────────────────────────────────────────
//  Debug Adapter Factory
// ─────────────────────────────────────────────────────────────────────
class CertiorDebugAdapterFactory {
    constructor(output) {
        this.output = output;
    }
    createDebugAdapterDescriptor(session) {
        const command = this.resolveDapCommand(session);
        const args = this.resolveDapArgs(session);
        this.output.appendLine(`[certior-dap] launching ${command}${args.length > 0 ? ` ${args.join(' ')}` : ''}`);
        return new vscode.DebugAdapterExecutable(command, args);
    }
    /**
     * Resolve the path to the certior-dap binary.
     *
     * Resolution order:
     * 1. Explicit `certiorDapPath` in launch config
     * 2. `.lake/build/bin/certior-dap` in workspace
     * 3. `certior-dap` in PATH
     */
    resolveDapCommand(session) {
        const configured = session.configuration?.certiorDapPath;
        if (typeof configured === 'string' && configured.trim().length > 0) {
            return configured.trim();
        }
        const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
        for (const folder of workspaceFolders) {
            const candidate = path.join(folder.uri.fsPath, '.lake', 'build', 'bin', 'certior-dap');
            if (fs.existsSync(candidate)) {
                return candidate;
            }
        }
        return 'certior-dap';
    }
    resolveDapArgs(session) {
        const raw = session.configuration?.certiorDapArgs;
        if (!Array.isArray(raw)) {
            return [];
        }
        return raw.map((value) => String(value));
    }
}
// ─────────────────────────────────────────────────────────────────────
//  Debug Configuration Provider
// ─────────────────────────────────────────────────────────────────────
class CertiorDebugConfigurationProvider {
    constructor(output) {
        this.output = output;
    }
    tryLoadJson(filePath) {
        if (!fs.existsSync(filePath)) {
            return undefined;
        }
        const raw = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(raw);
    }
    /**
     * Walk up from the source file to find the project root
     * (directory containing lakefile.lean or lakefile.toml).
     */
    resolveProjectRootFromSource(sourcePath) {
        let dir = path.dirname(sourcePath);
        // eslint-disable-next-line no-constant-condition
        while (true) {
            const hasLakefile = fs.existsSync(path.join(dir, 'lakefile.lean')) ||
                fs.existsSync(path.join(dir, 'lakefile.toml'));
            if (hasLakefile) {
                return dir;
            }
            const parent = path.dirname(dir);
            if (parent === dir) {
                return undefined;
            }
            dir = parent;
        }
    }
    /**
     * Generate candidate paths for auto-discovered planInfo JSON.
     */
    resolveGeneratedPlanInfoPaths(folder, config) {
        const paths = [];
        const pushUnique = (p) => {
            if (p && !paths.includes(p)) {
                paths.push(p);
            }
        };
        const workspaceRoot = folder?.uri.fsPath ??
            vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        const source = typeof config.source === 'string' ? config.source : undefined;
        const sourcePath = source ? path.resolve(source) : undefined;
        const sourceProjectRoot = sourcePath
            ? this.resolveProjectRootFromSource(sourcePath)
            : undefined;
        // Also try explicit planInfoPath
        if (typeof config.planInfoPath === 'string') {
            pushUnique(path.resolve(config.planInfoPath));
        }
        pushUnique(sourceProjectRoot
            ? path.join(sourceProjectRoot, '.dap', 'planInfo.generated.json')
            : undefined);
        pushUnique(workspaceRoot
            ? path.join(workspaceRoot, '.dap', 'planInfo.generated.json')
            : undefined);
        return paths;
    }
    resolveDebugConfiguration(folder, config) {
        if (!config.type) {
            config.type = 'certior-plan-dap';
        }
        if (!config.request) {
            config.request = 'launch';
        }
        if (!config.name) {
            config.name = 'Certior Plan DAP';
        }
        if (!config.source) {
            const active = vscode.window.activeTextEditor?.document.uri;
            if (active?.scheme === 'file') {
                config.source = active.fsPath;
            }
        }
        if (!config.planInfo) {
            for (const generatedPath of this.resolveGeneratedPlanInfoPaths(folder, config)) {
                try {
                    const loaded = this.tryLoadJson(generatedPath);
                    if (loaded !== undefined) {
                        config.planInfo = loaded;
                        this.output.appendLine(`[certior-dap] planInfo loaded from ${generatedPath}`);
                        break;
                    }
                }
                catch {
                    vscode.window.showErrorMessage(`certior-plan-dap: invalid JSON in ${generatedPath}`);
                    return null;
                }
            }
        }
        if (!config.planInfo) {
            vscode.window.showErrorMessage("Certior Plan DAP launch requires 'planInfo'. " +
                "Run `lake exe plan-export --decl basic --out .dap/planInfo.generated.json` " +
                'or set launch.planInfo in your debug configuration.');
            return null;
        }
        return config;
    }
}
// ─────────────────────────────────────────────────────────────────────
//  Custom Commands
// ─────────────────────────────────────────────────────────────────────
/**
 * Send a custom DAP request and display results.
 */
async function sendCustomRequest(command, title) {
    const session = vscode.debug.activeDebugSession;
    if (!session || session.type !== 'certior-plan-dap') {
        vscode.window.showWarningMessage('No active Certior Plan debug session.');
        return;
    }
    try {
        const response = await session.customRequest(command);
        const content = JSON.stringify(response, null, 2);
        const doc = await vscode.workspace.openTextDocument({
            content,
            language: 'json',
        });
        await vscode.window.showTextDocument(doc, {
            viewColumn: vscode.ViewColumn.Beside,
            preview: true,
        });
    }
    catch (err) {
        vscode.window.showErrorMessage(`${title} failed: ${String(err)}`);
    }
}
// ─────────────────────────────────────────────────────────────────────
//  Extension Lifecycle
// ─────────────────────────────────────────────────────────────────────
function activate(context) {
    const output = vscode.window.createOutputChannel('Certior Plan DAP');
    const configProvider = new CertiorDebugConfigurationProvider(output);
    const adapterFactory = new CertiorDebugAdapterFactory(output);
    context.subscriptions.push(output, 
    // Core DAP registration
    vscode.debug.registerDebugConfigurationProvider('certior-plan-dap', configProvider), vscode.debug.registerDebugAdapterDescriptorFactory('certior-plan-dap', adapterFactory), 
    // Start debugging command
    vscode.commands.registerCommand('certiorPlan.startDebugging', async () => {
        const active = vscode.window.activeTextEditor?.document.uri;
        const source = active?.scheme === 'file' ? active.fsPath : undefined;
        await vscode.debug.startDebugging(undefined, {
            name: 'Certior Plan DAP',
            type: 'certior-plan-dap',
            request: 'launch',
            source,
            stopOnEntry: true,
        });
    }), 
    // Custom Certior commands
    vscode.commands.registerCommand('certiorPlan.showCertificates', () => sendCustomRequest('certificates', 'Certificates')), vscode.commands.registerCommand('certiorPlan.showFlowGraph', () => sendCustomRequest('flowGraph', 'Flow Graph')), vscode.commands.registerCommand('certiorPlan.exportCompliance', () => sendCustomRequest('complianceExport', 'Compliance Export')));
}
function deactivate() { }
//# sourceMappingURL=extension.js.map