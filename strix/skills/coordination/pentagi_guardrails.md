---
name: pentagi_guardrails
description: PentAGI loop containment, execution monitoring, and prompt caching optimization guidelines
---

# PentAGI Guardrails and Execution Monitoring

Inspired by PentAGI's guardrail architecture, this protocol implements loop containment, execution redundancy controls, and prompt context caching optimization to maximize safety and efficiency.

## 1. Loop Containment Engine (Self-Monitoring)

To prevent infinite loops, redundant command execution, and tool-call stagnation:

*   **Rule of 3 (Tool-Call Redundancy)**: Monitor your own tool calls. If you execute the *same security tool* (e.g., repeating the same playwritgh click, browser input, or bash command) **3 times consecutively** without making demonstrable progress:
    *   Stop immediately.
    *   Initiate a `think` turn.
    *   Force yourself to analyze the failure: *Why is this tool failing? Are parameters incorrect? Is a firewall blocking?*
    *   Change your parameters, payloads, or tools entirely.
*   **Rule of 5 (Mentor Escalation)**: If you fail to resolve a roadblock or task after **5 consecutive attempts**:
    *   Stop executing automated commands.
    *   If you are a Child agent, immediately report the roadblock to your Parent agent using `agent_finish` or `send_message_to_agent` to ask for re-orientation.
    *   If you are the Root agent, either re-route the task to a different sub-target or prompt the user for manual guidance.
*   **Rule of Time-Bound Verification (Verification Cap)**: When conducting targeted vulnerability verification tasks (like validating an injection or testing for a specific endpoint response), budget a maximum of 5 to 10 minutes. If verification cannot be accomplished in that time frame, abort, document the current status/roadblock, and report back to the parent agent. Do not let simple verification tasks run indefinitely.

## 2. Context & Token Optimization

To prevent prompt bloat and keep context windows compact:

*   **Summarize history**: When passing historical context to child agents (`inherit_context=True`), summarize long tool outputs (like extensive HTML dumps or port logs) to include only the relevant lines (endpoints, CVEs).
*   **Avoid redundant reading**: Do not view the same large file multiple times. Keep the important structures in your notes or todo state.
*   **Prompt Cache Alignment**: Write responses in a consistent, structured manner to allow the underlying LLM to utilize prompt caching effectively, reducing time-to-first-token and lowering costs.
