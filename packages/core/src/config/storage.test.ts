/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';
import { Storage } from './storage.js';

describe('Storage – getGlobalSettingsPath', () => {
  it('returns path to ~/.boros/settings.json', () => {
    const expected = path.join(os.homedir(), '.boros', 'settings.json');
    expect(Storage.getGlobalSettingsPath()).toBe(expected);
  });
});

describe('Storage – additional helpers', () => {
  const projectRoot = '/tmp/project';
  const storage = new Storage(projectRoot);

  it('getWorkspaceSettingsPath returns project/.boros/settings.json', () => {
    const expected = path.join(projectRoot, '.boros', 'settings.json');
    expect(storage.getWorkspaceSettingsPath()).toBe(expected);
  });

  it('getUserCommandsDir returns ~/.boros/commands', () => {
    const expected = path.join(os.homedir(), '.boros', 'commands');
    expect(Storage.getUserCommandsDir()).toBe(expected);
  });

  it('getProjectCommandsDir returns project/.boros/commands', () => {
    const expected = path.join(projectRoot, '.boros', 'commands');
    expect(storage.getProjectCommandsDir()).toBe(expected);
  });

  it('getMcpOAuthTokensPath returns ~/.boros/mcp-oauth-tokens.json', () => {
    const expected = path.join(os.homedir(), '.boros', 'mcp-oauth-tokens.json');
    expect(Storage.getMcpOAuthTokensPath()).toBe(expected);
  });
});
