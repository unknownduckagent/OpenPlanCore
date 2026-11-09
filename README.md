# OpenPlanCore

An independent MIT-licensed Swift package for user-authorized Sign in with ChatGPT and eligible ChatGPT-plan Responses API requests on Apple devices.

## Boundary

This package has **no host application data access**. It receives only user-approved message text, optional image bytes, a model identifier, and a host-supplied application name. It does not supply application-specific instructions, rules, integrations, or UI.

## Integration contract

- Platforms: iOS 16+, macOS 13+; no server or API key.
- Public OAuth client registration; browser authorization with `state`, `nonce`, and PKCE S256.
- A one-time HTTP callback bound to `127.0.0.1` and `/auth/callback`.
- Signed ID-token validation against OpenAI's JWKS and account-scoped Keychain storage.
- Model names retrieved with the connected user's access token; streamed Responses API requests use `store: false` and `stream: true`.
- Authenticated user controls every request; caller must explicitly approve content transmission.
- The client is **disabled by default** until its host application has independently established permission to offer ChatGPT-plan access. Publishing this library by itself does not establish such permission.
- R110 request limits: 12 MB aggregate source content and 18 MB maximum JSON body, applied before base64 construction; oversized requests fail closed.
- R110 networking: token-bearing requests use a redirect-blocking ephemeral session (including HTTP 307/308), with exact HTTPS response URL checks.
- R110 SSE: incoming bytes are framed with a 1 MB maximum line and an 8 MB total event-stream ceiling *before* decoding a whole line.
- R110 image handling: Apple ImageIO decodes pixels and re-encodes image data without copying original EXIF/GPS/XMP metadata; images are downsampled to a maximum of 1,280 pixels. WebP input is converted to PNG if ImageIO can decode it. Unrecognized/corrupt images fail closed. Image transfer is unsupported on non-Apple platforms.
- R110 OAuth callback: malformed same-state callbacks are rejected without terminating the one-use loopback listener.

### Apple integration example

```swift
import OpenPlanCore

// Choose a unique Keychain service belonging to your host app.
let client = try PlanChatGPTClient(keychainService: "org.example.myapp.openplan", enabledForHostApp: false)

// When the host is authorized to provide the feature, construct an enabled
// instance and show a user-triggered Continue with ChatGPT action. On iOS:
// let account = try await client.connect(agentName: "My App") { url in
//     UIApplication.shared.open(url)
// }
// let models = try await client.availableModels()
// let message = try PlanMessage(role: .user, text: "Explain this image", images: [image])
// let result = try await client.complete(model: models[0].slug,
//     messages: [message], userApprovedSendingContent: true)
```

The host must supply localized UI, a reliable browser opener, explicit consent and any usage-limit messaging. Do not display the library's English errors directly in a localized interface. Never insert private host instructions or application-specific configuration into this public repository.

## Testing

From this directory run `swift test`. Apple framework code additionally requires a Mac/iPhone build and a signed-in manual test. R110 additionally has Apple-only tests for URL redirect policy and stripping GPS metadata, which require macOS Swift Package Manager to run. This standalone hardening version is **not represented as device-verified or integrated into an existing application** by its portable tests.

## License and eligibility

MIT license (see `LICENSE`). Read the current [Sign in with ChatGPT terms](https://openai.com/policies/sign-in-with-chatgpt-terms/) and [open-source client documentation](https://developers.openai.com/siwc/token-sharing-open-source). Embedding this package into a proprietary, publicly distributed application does not itself confirm that application's eligibility. No real client identifier, tokens, credentials or user data are included.
