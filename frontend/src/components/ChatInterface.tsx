'use client'

import { useState, useRef, useEffect } from 'react'
import { v4 as uuidv4 } from 'uuid'
import { MessageList } from './MessageList'
import { FileUpload } from './FileUpload'
import { WorkflowStage } from './SkillWorkflowProgress'
import {
  buildSkillWorkflowStages,
  extractDocumentNumber,
  isLoanDocumentWorkflow,
  runWorkflowStages,
} from '../lib/skillWorkflow'
import { ArrowUp, Loader2, Paperclip, Plus } from 'lucide-react'

export interface SkillInvocationInfo {
  id: string
  name: string
  version: string
  description: string
  status: string
}

export interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: Date
  attachments?: FileAttachment[]
  error?: PolicyError
  kind?: 'text' | 'skill_workflow'
  workflowStages?: WorkflowStage[]
  workflowComplete?: boolean
  skillInvocation?: SkillInvocationInfo
}

export interface FileAttachment {
  id: string
  name: string
  type: string
  size: number
  content?: string
}

export interface PolicyError {
  type: 'pii' | 'threat' | 'auth' | 'general'
  message: string
  details?: Record<string, unknown>
}

export function ChatInterface() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [pendingFiles, setPendingFiles] = useState<File[]>([])
  const [showFileUpload, setShowFileUpload] = useState(false)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus()
    }
  }, [])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isLoading, showFileUpload])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!input.trim() && pendingFiles.length === 0) return

    const messageText = input
    const attachments: FileAttachment[] = []
    for (const file of pendingFiles) {
      const content = await readFileContent(file)
      attachments.push({
        id: uuidv4(),
        name: file.name,
        type: file.type,
        size: file.size,
        content,
      })
    }

    const userMessage: Message = {
      id: uuidv4(),
      role: 'user',
      content: messageText || `Uploaded ${pendingFiles.length} file(s)`,
      timestamp: new Date(),
      attachments: attachments.length > 0 ? attachments : undefined,
    }

    setMessages(prev => [...prev, userMessage])
    setInput('')
    setPendingFiles([])
    setShowFileUpload(false)
    setIsLoading(true)

    const skillWorkflow = isLoanDocumentWorkflow(messageText)
    const workflowMessageId = uuidv4()

    if (skillWorkflow) {
      const documentNumber = extractDocumentNumber(messageText)
      const initialStages = buildSkillWorkflowStages(documentNumber)

      setMessages(prev => [
        ...prev,
        {
          id: workflowMessageId,
          role: 'assistant',
          content: '',
          timestamp: new Date(),
          kind: 'skill_workflow',
          workflowStages: initialStages,
          workflowComplete: false,
          skillInvocation: {
            id: 'loan-document-helper',
            name: 'loan-document-helper',
            version: '0.1.0',
            description: 'Summarize loan documents and prepare borrower follow-up steps.',
            status: 'loading',
          },
        },
      ])
    }

    try {
      const apiPromise = fetch('/api/backend/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: messageText,
          attachments,
          conversation_id: uuidv4(),
        }),
      }).then(async (response) => ({
        response,
        data: await response.json(),
      }))

      if (skillWorkflow) {
        const initialStages = buildSkillWorkflowStages(extractDocumentNumber(messageText))

        const [, apiResult] = await Promise.all([
          runWorkflowStages(initialStages, (nextStages) => {
            setMessages(prev =>
              prev.map(message =>
                message.id === workflowMessageId
                  ? { ...message, workflowStages: nextStages }
                  : message,
              ),
            )
          }).then((completedStages) => {
            setMessages(prev =>
              prev.map(message =>
                message.id === workflowMessageId
                  ? {
                      ...message,
                      workflowStages: completedStages,
                      workflowComplete: true,
                      skillInvocation: message.skillInvocation
                        ? { ...message.skillInvocation, status: 'loaded' }
                        : message.skillInvocation,
                    }
                  : message,
              ),
            )
          }),
          apiPromise,
        ])

        const { response, data } = apiResult

        if (!response.ok) {
          const errorMessage: Message = {
            id: uuidv4(),
            role: 'assistant',
            content: data.detail || 'An error occurred',
            timestamp: new Date(),
            error: data.policy_error ? {
              type: data.policy_error.type,
              message: data.policy_error.message,
              details: data.policy_error.details,
            } : undefined,
          }
          setMessages(prev => [...prev, errorMessage])
        } else {
          if (data.skill_invocation) {
            setMessages(prev =>
              prev.map(message =>
                message.id === workflowMessageId
                  ? {
                      ...message,
                      skillInvocation: data.skill_invocation,
                    }
                  : message,
              ),
            )
          }

          setMessages(prev => [
            ...prev,
            {
              id: uuidv4(),
              role: 'assistant',
              content: data.response,
              timestamp: new Date(),
              error: data.policy_warning ? {
                type: data.policy_warning.type,
                message: data.policy_warning.message,
                details: data.policy_warning.details,
              } : undefined,
            },
          ])
        }
      } else {
        const { response, data } = await apiPromise

        if (!response.ok) {
          const errorMessage: Message = {
            id: uuidv4(),
            role: 'assistant',
            content: data.detail || 'An error occurred',
            timestamp: new Date(),
            error: data.policy_error ? {
              type: data.policy_error.type,
              message: data.policy_error.message,
              details: data.policy_error.details,
            } : undefined,
          }
          setMessages(prev => [...prev, errorMessage])
        } else {
          const assistantMessage: Message = {
            id: uuidv4(),
            role: 'assistant',
            content: data.response,
            timestamp: new Date(),
            error: data.policy_warning ? {
              type: data.policy_warning.type,
              message: data.policy_warning.message,
              details: data.policy_warning.details,
            } : undefined,
          }
          setMessages(prev => [...prev, assistantMessage])
        }
      }
    } catch (error) {
      const errorMessage: Message = {
        id: uuidv4(),
        role: 'assistant',
        content: 'Failed to connect to the backend. Please ensure the server is running.',
        timestamp: new Date(),
        error: {
          type: 'general',
          message: 'Connection error',
        },
      }
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  const readFileContent = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      const shouldEncodeAsBase64 =
        file.type.startsWith('image/') ||
        file.type === 'application/pdf' ||
        file.type === 'application/msword' ||
        file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

      reader.onload = () => {
        const result = reader.result as string
        if (shouldEncodeAsBase64) {
          resolve(result.split(',')[1])
        } else {
          resolve(result)
        }
      }
      reader.onerror = reject

      if (shouldEncodeAsBase64) {
        reader.readAsDataURL(file)
      } else {
        reader.readAsText(file)
      }
    })
  }

  const handleFileSelect = (files: File[]) => {
    setPendingFiles(prev => [...prev, ...files])
  }

  const removePendingFile = (index: number) => {
    setPendingFiles(prev => prev.filter((_, i) => i !== index))
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  const starterPrompts = [
    {
      label: 'View borrower details',
      action: () => {
        setInput('Show me the loan status for Alice Morgan and include the full borrower details')
        inputRef.current?.focus()
      },
    },
    {
      label: 'Review support document',
      action: () => {
        setInput("Review this uploaded support document and summarize it's contents")
        inputRef.current?.focus()
      },
    },
    {
      label: 'Process loan document',
      action: () => {
        setInput('Process my loan document, document number 1523')
        inputRef.current?.focus()
      },
    },
    {
      label: 'Review closing image',
      action: () => {
        setInput('Can you review this closing image?')
        setShowFileUpload(true)
        inputRef.current?.focus()
      },
    },
    {
      // Unapproved LLM  →  Rate Check Agent (DeepSeek, not on the approved list)
      label: 'Check current rates',
      action: () => {
        setInput("What are today's average interest rates for a 30-year fixed mortgage?")
        inputRef.current?.focus()
      },
    },
  ]

  return (
    <div className="mx-auto flex h-screen w-full max-w-5xl flex-col px-4 pb-4 pt-4 sm:px-6">
      <div className="glass-panel flex min-h-0 flex-1 flex-col overflow-hidden rounded-[24px]">
        <div className="accent-band h-1.5 w-full" />
        <header className="soft-divider flex items-center justify-between border-b px-5 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br from-blue-600 to-sky-400 shadow-[0_8px_20px_rgba(37,99,235,0.25)]">
              <div className="h-3 w-3 rounded-full bg-white/95" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-slate-50">Acme Loan Processor</h1>
            </div>
          </div>
          <div className="hidden text-sm text-slate-400 sm:block">Loan assistant</div>
        </header>

        <div className="chat-scrollbar flex-1 overflow-y-auto px-4 py-5 sm:px-6">
          {messages.length === 0 ? (
            <div className="fade-in-up flex h-full items-start justify-center pt-10 sm:pt-14">
              <div className="w-full max-w-3xl">
                <p className="text-2xl font-semibold tracking-tight text-slate-50">
                  Hi, how can I help you today?
                </p>
                <p className="mt-2 text-sm text-slate-400">
                  Ask about a loan, review a support document, or review a closing image.
                </p>
                <div className="mt-6 flex flex-wrap gap-3">
                  {starterPrompts.map((prompt) => (
                    <button
                      key={prompt.label}
                      type="button"
                      onClick={prompt.action}
                      className="rounded-full border border-slate-700 bg-slate-900/90 px-4 py-2 text-sm text-slate-200 transition hover:border-sky-500/40 hover:bg-slate-800 hover:text-sky-200"
                    >
                      {prompt.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <>
              <MessageList messages={messages} />
              <div ref={messagesEndRef} />
            </>
          )}
        </div>

        {showFileUpload && (
          <div className="soft-divider border-t px-4 py-4 sm:px-6">
            <FileUpload onFilesSelected={handleFileSelect} />
          </div>
        )}

        {pendingFiles.length > 0 && (
          <div className="soft-divider border-t px-4 py-3 sm:px-6">
            <div className="flex flex-wrap gap-2">
              {pendingFiles.map((file, index) => (
                <div
                  key={`${file.name}-${index}`}
                  className="flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200"
                >
                  <span className="max-w-[220px] truncate">{file.name}</span>
                  <button
                    onClick={() => removePendingFile(index)}
                    className="text-slate-500 transition-colors hover:text-rose-400"
                    aria-label={`Remove ${file.name}`}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="soft-divider border-t px-4 py-4 sm:px-6">
          <form onSubmit={handleSubmit} className="mx-auto max-w-4xl">
            <div className="rounded-[22px] border border-slate-700 bg-slate-950/90 px-3 py-2 shadow-[0_12px_32px_rgba(2,6,23,0.35)]">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setShowFileUpload(!showFileUpload)}
                  className="inline-flex h-9 shrink-0 items-center gap-2 rounded-xl bg-slate-900 px-3 text-xs text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-100"
                  aria-label={showFileUpload ? 'Hide document upload' : 'Show document upload'}
                >
                  {showFileUpload ? <Paperclip className="h-[16px] w-[16px]" /> : <Plus className="h-[16px] w-[16px]" />}
                  <span>{showFileUpload ? 'Hide upload' : 'Attach document'}</span>
                </button>

                <div className="flex min-h-[40px] flex-1 min-w-0 items-center">
                  <textarea
                    ref={inputRef}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask about a loan, review a support document, or review a closing image..."
                    className="max-h-40 w-full resize-none bg-transparent px-1 py-0 text-[15px] leading-[24px] text-slate-100 outline-none placeholder:text-slate-500"
                    rows={1}
                    disabled={isLoading}
                  />
                </div>

                <button
                  type="submit"
                  disabled={isLoading || (!input.trim() && pendingFiles.length === 0)}
                  className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-[16px] bg-gradient-to-br from-blue-600 to-sky-500 text-white transition hover:from-blue-700 hover:to-sky-600 disabled:cursor-not-allowed disabled:bg-slate-800 disabled:text-slate-500"
                  aria-label="Send message"
                >
                  {isLoading ? (
                    <Loader2 className="h-[18px] w-[18px] animate-spin" />
                  ) : (
                    <ArrowUp className="h-[18px] w-[18px]" />
                  )}
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}
