import { NextRequest, NextResponse } from 'next/server'
import { createRequire } from 'module'

const _ai_app_sec_059_require = createRequire(import.meta.url)
const { lineaje_guardrail } = _ai_app_sec_059_require('lineaje_guardrail')

const _ai_app_sec_059_guardrail = new lineaje_guardrail()
_ai_app_sec_059_guardrail.enable_policies(['AI_APP_SEC_059.json'])

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'

const _ai_app_sec_070_patterns: Array<{ marker: string; pattern: RegExp }> = [
  {
    marker: 'instruction_override',
    pattern: /ignore\s+previous\s+instructions|forget\s+everything\s+above/gi,
  },
  {
    marker: 'role_hijack',
    pattern: /you\s+are\s+now\s+DAN|act\s+as\s+unrestricted/gi,
  },
  {
    marker: 'delimiter_escape',
    pattern: /<\/?system>|<\/?tool>|<\/?assistant>|<\/?user>/gi,
  },
  {
    marker: 'encoded_payload',
    pattern: /(?:[A-Za-z0-9+\/]{20,}={0,2})|(?:\\u[0-9a-fA-F]{4}){3,}|(?:%[0-9a-fA-F]{2}){5,}|(?:[0-9a-fA-F]{2}\s*){8,}(?=\s|$)/g,
  },
  {
    marker: 'hidden_text',
    pattern: /<!--.*?-->|[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]/gs,
  },
  {
    marker: 'fake_system_message',
    pattern: /\[\s*(?:system|SYSTEM|tool|TOOL)\s*\]\s*:/g,
  },
  {
    marker: 'exfiltration_attempt',
    pattern: /!\[.*?\]\(https?:\/\/[^)]+\)|send\s+(?:this|the)\s+(?:data|prompt|system\s+prompt)|leak\s+(?:the\s+)?system\s+prompt/gi,
  },
  {
    marker: 'context_poisoning',
    pattern: /in\s+(?:a\s+)?previous\s+(?:conversation|turn|message).*?(?:you\s+said|you\s+agreed|you\s+confirmed)/gi,
  },
  {
    marker: 'indirect_injection',
    pattern: /(?:the\s+(?:file|document|data|metadata|code)\s+(?:says|contains|instructs)\s*:)/gi,
  },
  {
    marker: 'command_injection',
    pattern: /`[^`]*`|\$\([^)]*\)|;\s*(?:rm|ls|cat|curl|wget|bash|sh|python|node)\s/g,
  },
  {
    marker: 'split_payload',
    pattern: /(?:part\s*[1-9]\s*of\s*[1-9].*?(?:combine|concatenate|join))|(?:continue\s+from\s+(?:previous|last)\s+(?:message|part))/gi,
  },
  {
    marker: 'jailbreak_attempt',
    pattern: /\bDAN\b|developer\s+mode|fictional\s+(?:framing|scenario|universe)\s+(?:where|in\s+which)\s+(?:you|AI|the\s+model)\s+(?:can|must|should|will)/gi,
  },
]

function _ai_app_sec_070_sanitize(text: string): string {
  let sanitized = text
  for (const { marker, pattern } of _ai_app_sec_070_patterns) {
    sanitized = sanitized.replace(pattern, `<prompt_injection_removed: ${marker}>`)
  }
  return sanitized
}

function _ai_app_sec_070_sanitize_body(body: Record<string, unknown>): Record<string, unknown> {
  const sanitized: Record<string, unknown> = { ...body }
  // Sanitize common message fields
  for (const field of ['message', 'content', 'query', 'prompt', 'text', 'input']) {
    if (typeof sanitized[field] === 'string') {
      sanitized[field] = _ai_app_sec_070_sanitize(sanitized[field] as string)
    }
  }
  // Sanitize messages array (e.g. OpenAI-style chat history)
  if (Array.isArray(sanitized['messages'])) {
    sanitized['messages'] = (sanitized['messages'] as Array<Record<string, unknown>>).map(
      (msg) => {
        if (typeof msg['content'] === 'string') {
          return { ...msg, content: _ai_app_sec_070_sanitize(msg['content'] as string) }
        }
        return msg
      }
    )
  }
  return sanitized
}

export async function POST(request: NextRequest) {
  try {
    let body = await request.json()

    try {
      body = _ai_app_sec_059_guardrail.evaluate(body)
    } catch (guardErr: any) {
      if (guardErr?.name === 'GuardrailBlockedError' || guardErr?.constructor?.name === 'GuardrailBlockedError') {
        return NextResponse.json(
          {
            detail: 'Request blocked by security policy',
            policy_error: {
              type: 'AI_APP_SEC_059',
              message: 'Prompt contains disallowed command execution content',
            },
          },
          { status: 403 }
        )
      }
      throw guardErr
    }

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    })

    const data = await response.json()

    if (!response.ok) {
      return NextResponse.json(data, { status: response.status })
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error('Backend proxy error:', error)
    return NextResponse.json(
      {
        detail: 'Failed to connect to backend service',
        policy_error: {
          type: 'general',
          message: 'Backend service unavailable',
        },
      },
      { status: 503 }
    )
  }
}
