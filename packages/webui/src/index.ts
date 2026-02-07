/**
 * @license
 * Copyright 2025 Qwen Team
 * SPDX-License-Identifier: Apache-2.0
 */

// eslint-disable-next-line import/no-internal-modules
import './styles/variables.css';
// eslint-disable-next-line import/no-internal-modules
import './styles/timeline.css';
// eslint-disable-next-line import/no-internal-modules
import './styles/components.css';

// Shared UI Components Export
// Export all shared components from this package

// Context
export {
  PlatformContext,
  PlatformProvider,
  usePlatform,
} from './context/PlatformContext.js';
export type {
  PlatformContextValue,
  PlatformProviderProps,
  PlatformType,
} from './context/PlatformContext.js';

// Layout components
export { default as Container } from './components/layout/Container.js';
export { default as Header } from './components/layout/Header.js';
export { default as Sidebar } from './components/layout/Sidebar.js';
export { default as Main } from './components/layout/Main.js';
export { default as Footer } from './components/layout/Footer.js';
export { FileLink } from './components/layout/FileLink.js';
export type { FileLinkProps } from './components/layout/FileLink.js';
export { ChatHeader } from './components/layout/ChatHeader.js';
export type { ChatHeaderProps } from './components/layout/ChatHeader.js';
export { ContextIndicator } from './components/layout/ContextIndicator.js';
export type {
  ContextIndicatorProps,
  ContextUsage,
} from './components/layout/ContextIndicator.js';
export { CompletionMenu } from './components/layout/CompletionMenu.js';
export type { CompletionMenuProps } from './components/layout/CompletionMenu.js';
export { SessionSelector } from './components/layout/SessionSelector.js';
export type { SessionSelectorProps } from './components/layout/SessionSelector.js';
export { EmptyState } from './components/layout/EmptyState.js';
export type { EmptyStateProps } from './components/layout/EmptyState.js';
export { InputForm, getEditModeIcon } from './components/layout/InputForm.js';
export type {
  InputFormProps,
  EditModeInfo,
  EditModeIconType,
} from './components/layout/InputForm.js';
export { Onboarding } from './components/layout/Onboarding.js';
export type { OnboardingProps } from './components/layout/Onboarding.js';

// Message components
export { default as Message } from './components/messages/Message.js';
export { default as MessageInput } from './components/messages/MessageInput.js';
export { default as MessageList } from './components/messages/MessageList.js';
export { WaitingMessage } from './components/messages/Waiting/WaitingMessage.js';
export { InterruptedMessage } from './components/messages/Waiting/InterruptedMessage.js';
export { MarkdownRenderer } from './components/messages/MarkdownRenderer/MarkdownRenderer.js';
export type { MarkdownRendererProps } from './components/messages/MarkdownRenderer/MarkdownRenderer.js';
export { MessageContent } from './components/messages/MessageContent.js';
export type { MessageContentProps } from './components/messages/MessageContent.js';
export { UserMessage } from './components/messages/UserMessage.js';
export type {
  UserMessageProps,
  FileContext,
} from './components/messages/UserMessage.js';
export { ThinkingMessage } from './components/messages/ThinkingMessage.js';
export type { ThinkingMessageProps } from './components/messages/ThinkingMessage.js';
export { AssistantMessage } from './components/messages/Assistant/AssistantMessage.js';
export type {
  AssistantMessageProps,
  AssistantMessageStatus,
} from './components/messages/Assistant/AssistantMessage.js';
export {
  CollapsibleFileContent,
  parseContentWithFileReferences,
} from './components/messages/CollapsibleFileContent.js';
export type {
  CollapsibleFileContentProps,
  ContentSegment,
} from './components/messages/CollapsibleFileContent.js';

// ChatViewer - standalone chat display component
export {
  ChatViewer,
  default as ChatViewerDefault,
} from './components/ChatViewer/index.js';
export type {
  ChatViewerProps,
  ChatViewerHandle,
  ChatMessageData,
  ClaudeContentItem,
  MessagePart,
  ToolCallData as ChatViewerToolCallData,
} from './components/ChatViewer/index.js';

// UI Elements
export { default as Button } from './components/ui/Button.js';
export { default as Input } from './components/ui/Input.js';
export { Tooltip } from './components/ui/Tooltip.js';
export type { TooltipProps } from './components/ui/Tooltip.js';

// Permission components
export { PermissionDrawer } from './components/PermissionDrawer.js';
export type {
  PermissionDrawerProps,
  PermissionOption,
  PermissionToolCall,
} from './components/PermissionDrawer.js';

// ToolCall shared components
export {
  ToolCallContainer,
  ToolCallCard,
  ToolCallRow,
  StatusIndicator,
  CodeBlock,
  LocationsList,
  handleCopyToClipboard,
  CopyButton,
  // Utility functions
  extractCommandOutput,
  formatValue,
  safeTitle,
  shouldShowToolCall,
  groupContent,
  hasToolCallOutput,
  mapToolStatusToContainerStatus,
  // Business ToolCall components
  ThinkToolCall,
  SaveMemoryToolCall,
  GenericToolCall,
  EditToolCall,
  WriteToolCall,
  SearchToolCall,
  UpdatedPlanToolCall,
  ShellToolCall,
  ReadToolCall,
  WebFetchToolCall,
  CheckboxDisplay,
} from './components/toolcalls/index.js';
export type {
  ToolCallContainerProps,
  ToolCallContent,
  ToolCallData,
  BaseToolCallProps,
  GroupedContent,
  ContainerStatus,
  PlanEntryStatus,
  CheckboxDisplayProps,
} from './components/toolcalls/index.js';

// Icons
export { default as Icon } from './components/icons/Icon.js';
export { default as CloseIcon } from './components/icons/CloseIcon.js';
export { default as SendIcon } from './components/icons/SendIcon.js';

// File Icons
export {
  FileIcon,
  FileListIcon,
  SaveDocumentIcon,
  FolderIcon,
} from './components/icons/FileIcons.js';

// Status Icons
export {
  PlanCompletedIcon,
  PlanInProgressIcon,
  PlanPendingIcon,
  WarningTriangleIcon,
  UserIcon,
  SymbolIcon,
  SelectionIcon,
} from './components/icons/StatusIcons.js';

// Navigation Icons
export {
  ChevronDownIcon,
  PlusIcon,
  PlusSmallIcon,
  ArrowUpIcon,
  CloseIcon as CloseXIcon,
  CloseSmallIcon,
  SearchIcon,
  RefreshIcon,
} from './components/icons/NavigationIcons.js';

// Edit Icons
export {
  EditPencilIcon,
  AutoEditIcon,
  PlanModeIcon,
  CodeBracketsIcon,
  HideContextIcon,
  SlashCommandIcon,
  LinkIcon,
  OpenDiffIcon,
  UndoIcon,
} from './components/icons/EditIcons.js';

// Special Icons
export { ThinkingIcon, TerminalIcon } from './components/icons/SpecialIcons.js';

// Action Icons
export { StopIcon } from './components/icons/StopIcon.js';

// Hooks
export { useTheme } from './hooks/useTheme.js';
export { useLocalStorage } from './hooks/useLocalStorage.js';

// Types
export type { Theme } from './types/theme.js';
export type { MessageProps } from './types/messages.js';
export type { ChatMessage, MessageRole, PlanEntry } from './types/chat.js';
// ToolCallStatus and ToolCallLocation are now exported from './components/toolcalls'
export type { ToolCallContentItem, ToolCallUpdate } from './types/toolCall.js';
// Re-export ToolCallStatus and ToolCallLocation for backward compatibility
export type { ToolCallStatus, ToolCallLocation } from './components/toolcalls/index.js';
export type { CompletionItem, CompletionItemType } from './types/completion.js';

// Utils
export { groupSessionsByDate, getTimeAgo } from './utils/sessionGrouping.js';
export type { SessionGroup } from './utils/sessionGrouping.js';

// Adapters - for normalizing different data formats
export {
  adaptJSONLMessages,
  adaptACPMessages,
  filterEmptyMessages,
  isToolCallData,
  isMessageData,
} from './adapters/index.js';
export type {
  UnifiedMessage,
  UnifiedMessageType,
  JSONLMessage,
  ACPMessage,
  ACPMessageData,
} from './adapters/index.js';

// VSCode Webview utilities
export { default as WebviewContainer } from './components/WebviewContainer.js';
