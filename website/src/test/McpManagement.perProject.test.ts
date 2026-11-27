import { describe, expect, it } from 'vitest'

import { ApiError, type McpManagedServer } from '../api/client'
import {
  autoShareCandidates,
  detailsWhyKey,
  rowState,
  stateLabelKey,
  stubErrorKey,
} from '../pages/settings/mcpManagementModel'

function server(over: Partial<McpManagedServer> = {}): McpManagedServer {
  return {
    name: 'files',
    stub: false,
    can_stub: true,
    in_allowlist: false,
    entry_poolable: false,
    agents: ['a'],
    transport: 'stdio',
    denylisted: false,
    ...over,
  } as McpManagedServer
}

describe('a per-project server', () => {
  it('reads shared in project while sharing is on, whatever the Share mark says', () => {
    for (const stub of [false, true]) {
      const s = server({ per_project: true, stub, in_allowlist: stub })
      expect(rowState(s, true)).toBe('project')
      expect(stateLabelKey(rowState(s, true))).toBe('pages.mcpManagement.state_project')
      expect(detailsWhyKey(s, 'project')).toBe('pages.mcpManagement.why_project')
    }
  })

  it('reads direct with sharing off, and says it shares once sharing is on', () => {
    const s = server({ per_project: true })
    expect(rowState(s, false)).toBe('direct')
    expect(detailsWhyKey(s, 'direct')).toBe('pages.mcpManagement.why_project_off')
  })

  it("reads direct under Don't share, and says each chat launches its own", () => {
    const s = server({ per_project: true, declined: true })
    expect(rowState(s, true)).toBe('direct')
    expect(detailsWhyKey(s, 'direct')).toBe('pages.mcpManagement.why_dont_share')
  })

  it('is never a Share candidate, since it needs no mark', () => {
    expect(autoShareCandidates([server({ per_project: true }), server({ name: 'free' })]).map(s => s.name)).toEqual([
      'free',
    ])
  })

  it('names its own refusal of the Share press', () => {
    const err = new ApiError(409, 'shared per project', '{"code":"per_project"}')
    expect(stubErrorKey(err)).toBe('pages.mcpManagement.stub_error_per_project')
  })
})
