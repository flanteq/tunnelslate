// Count Unicode code points, matching utf8.RuneCountInString on the server.
export const passwordLength = (value: string) => Array.from(value).length
export const validNewPassword = (value: string) => {
  const length = passwordLength(value)
  return length >= 12 && length <= 72
}
// HTML maxlength counts UTF-16 units; each code point can occupy two units.
// The character limit itself is checked by validNewPassword on submit.
export const passwordInputMaxLength = 144
