declare module '@jrcdev/boros-code-sdk' {
  export type SDKMessage = any;
  export type SDKAssistantMessage = any;
  export type SDKSystemMessage = any;
  export type SDKUserMessage = any;
  export type ContentBlock = any;
  export type TextBlock = any;
  export type ToolUseBlock = any;
  export function query(opts: any): AsyncIterable<any> & { close(): Promise<void>; endInput(): void; setPermissionMode(mode: string): Promise<void> };
  export function isSDKAssistantMessage(x: any): boolean;
  export function isSDKSystemMessage(x: any): boolean;
  export function isSDKResultMessage(x: any): boolean;
}
