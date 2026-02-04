// Minimal OpenClaw plugin SDK typings for this plugin's integration.
export type PluginLogger = {
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string) => void;
};

export type PluginCommandContext = {
  senderId?: string;
  channel: string;
  isAuthorizedSender: boolean;
  args?: string;
  commandBody: string;
  config: Record<string, unknown>;
};

export type ReplyPayload = {
  text?: string;
};

export type PluginCommandResult = ReplyPayload;

export type OpenClawPluginCommandDefinition = {
  name: string;
  description: string;
  acceptsArgs?: boolean;
  requireAuth?: boolean;
  handler: (ctx: PluginCommandContext) => PluginCommandResult | Promise<PluginCommandResult>;
};

export type CommanderCommand = {
  command: (name: string) => CommanderCommand;
  description: (text: string) => CommanderCommand;
  argument: (syntax: string, description?: string) => CommanderCommand;
  option: (flags: string, description?: string) => CommanderCommand;
  action: (handler: (...args: unknown[]) => void) => CommanderCommand;
};

export type CommanderProgram = CommanderCommand;

export type OpenClawPluginCliContext = {
  program: CommanderProgram;
  config: Record<string, unknown>;
  workspaceDir?: string;
  logger: PluginLogger;
};

export type PluginHookBeforeToolCallEvent = {
  toolName: string;
  params: Record<string, unknown>;
};

export type PluginHookToolContext = {
  agentId?: string;
  sessionKey?: string;
  toolName: string;
};

export type PluginHookBeforeToolCallResult = {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
};

export type PluginHookToolResultPersistEvent = {
  toolName?: string;
  toolCallId?: string;
  message: unknown;
  isSynthetic?: boolean;
};

export type PluginHookToolResultPersistContext = {
  agentId?: string;
  sessionKey?: string;
  toolName?: string;
  toolCallId?: string;
};

export type PluginHookToolResultPersistResult = {
  message?: unknown;
};

export type OpenClawPluginApi = {
  id: string;
  name: string;
  config: Record<string, unknown>;
  pluginConfig?: Record<string, unknown>;
  logger: PluginLogger;
  resolvePath: (input: string) => string;
  registerCommand: (command: OpenClawPluginCommandDefinition) => void;
  registerCli: (registrar: (ctx: OpenClawPluginCliContext) => void, opts?: { commands?: string[] }) => void;
  on: {
    (
      hookName: "before_tool_call",
      handler: (
        event: PluginHookBeforeToolCallEvent,
        ctx: PluginHookToolContext
      ) => PluginHookBeforeToolCallResult | void | Promise<PluginHookBeforeToolCallResult | void>
    ): void;
    (
      hookName: "tool_result_persist",
      handler: (
        event: PluginHookToolResultPersistEvent,
        ctx: PluginHookToolResultPersistContext
      ) => PluginHookToolResultPersistResult | void
    ): void;
  };
};
