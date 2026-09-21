export const CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN = 'refresh_token'
export const CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY = 'access_token_only'
export const CHATGPT_REGISTRATION_MODE_STORAGE_KEY = 'chatgpt-registration-mode'

export type ChatGPTRegistrationMode =
  | typeof CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN
  | typeof CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY

export const DEFAULT_CHATGPT_REGISTRATION_MODE: ChatGPTRegistrationMode =
  CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN

export function normalizeChatGPTRegistrationMode(
  value: unknown,
): ChatGPTRegistrationMode {
  if (value === CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY) {
    return CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY
  }
  return DEFAULT_CHATGPT_REGISTRATION_MODE
}

export function loadChatGPTRegistrationMode(): ChatGPTRegistrationMode {
  if (typeof window === 'undefined') {
    return DEFAULT_CHATGPT_REGISTRATION_MODE
  }

  return normalizeChatGPTRegistrationMode(
    window.localStorage.getItem(CHATGPT_REGISTRATION_MODE_STORAGE_KEY),
  )
}

export function saveChatGPTRegistrationMode(
  mode: ChatGPTRegistrationMode,
): void {
  if (typeof window === 'undefined') return
  window.localStorage.setItem(CHATGPT_REGISTRATION_MODE_STORAGE_KEY, mode)
}
