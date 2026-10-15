# DiskFree: 200-item improvement program

This is a staged engineering checklist, not a claim that every item is already
shipped. **Checked items are implemented in code; unchecked items are backlog.**
The list is intentionally concrete so each change can be reviewed and tested.
Phase 1 focuses on API boundaries, scan resource limits, and updater correctness.

## API safety and input limits

1. [x] Reject client-supplied `system` messages in chat history.
2. [x] Limit client-provided chat history to 12 turns.
3. [x] Limit combined chat message/history content to 32,000 characters.
4. [x] Omit rejected request values from validation-error responses.
5. [x] Compare UI bearer tokens with a constant-time digest function.
6. [ ] Set a request-body byte ceiling before JSON parsing.
7. [x] Limit scan-root string length and reject NUL/control characters.
8. [x] Normalize and deduplicate scan roots before starting work.
9. [x] Bound individual plan, journal, operation, and scan IDs at schema level.
10. [x] Put a total character budget on cleanup-instruction payloads.
11. [ ] Bound provider-check response time separately from inference time.
12. [ ] Redact credentials embedded in provider error URLs.
13. [ ] Return a stable machine-readable error code for every API failure.
14. [ ] Add request IDs to API responses and structured logs.
15. [ ] Add explicit cache-control headers to sensitive API responses.
16. [ ] Make CORS preflight behavior explicit for token-protected deployments.
17. [ ] Reject unsupported content types with a concise 415 response.
18. [ ] Add per-route response-size limits for large finding results.
19. [x] Validate and deduplicate scan category names before creating a job.
20. [ ] Add API compatibility tests for every public request schema.

## Scan admission and lifecycle

21. [x] Cap queued/running scans at two by default.
22. [x] Return HTTP 429 with `Retry-After` when scan capacity is full.
23. [ ] Show which roots belong to each active scan in the scan-list endpoint.
24. [ ] Make the scan concurrency cap configurable.
25. [ ] Add a queue instead of rejecting scans when capacity is full.
26. [ ] Report queued position and estimated wait time.
27. [ ] Prevent retention eviction from removing jobs with active API readers.
28. [ ] Add explicit job-state transition validation.
29. [ ] Add a bounded shutdown wait for active scanner threads.
30. [ ] Surface thread-start failures as structured failed jobs.
31. [ ] Record cancellation request and completion timestamps separately.
32. [ ] Distinguish cancelled-before-start from cancelled-mid-scan.
33. [ ] Add a stale-job cleanup interval independent of new scans.
34. [ ] Expose job age and retention-expiry estimates.
35. [ ] Add a scan progress heartbeat for slow filesystem calls.
36. [ ] Make progress snapshots immutable and thread-safe.
37. [ ] Add tests for concurrent start/cancel/clear races.
38. [ ] Add per-root progress so multi-root scans are understandable.
39. [ ] Report filesystem permission failures by root without leaking extra paths.
40. [ ] Add limits for simultaneous duplicate-hash operations.

## Updater correctness and portability

41. [x] Keep `--check` strictly read-only and skip all pip commands.
42. [x] Report a failed dependency probe as unknown/failure, not “all installed.”
43. [x] Preserve partial stdout/stderr when a subprocess times out.
44. [ ] Add regression tests for pip-install timeout and cancellation.
45. [ ] Make dependency checks use the selected interpreter after branch updates.
46. [ ] Detect an interrupted/partial virtualenv and offer a safe repair path.
47. [ ] Verify the checkout branch before any fetch/merge operation.
48. [ ] Report fetch failures separately from “branch has no upstream.”
49. [ ] Make git credential prompts disabled for every updater git call.
50. [ ] Sanitize secrets from git and pip subprocess output.
51. [ ] Report when the configured Python path is a directory or non-executable.
52. [ ] Check interpreter architecture against the current platform.
53. [ ] Validate `python.env` keys and report ignored/unknown entries.
54. [ ] Test CRLF, UTF-8 BOM, and whitespace in `python.env` on all platforms.
55. [ ] Handle symlinked project roots consistently across launchers.
56. [ ] Add a dry-run summary of exact source and dependency actions.
57. [ ] Include elapsed time for each updater step.
58. [ ] Add an offline update mode that skips fetches but checks local packaging.
59. [ ] Verify scripts from paths containing spaces and Unicode.
60. [ ] Add signed-release or checksum verification before package installation.

## AI and provider trust

61. [ ] Enforce that every model-referenced ID belongs to the current scan payload.
62. [ ] Show omitted finding counts prominently before tailored selection.
63. [ ] Tell the model to request a relevant scan when requested types are absent.
64. [ ] Distinguish “no match found” from “model returned no recommendations.”
65. [ ] Prevent fallback advice from being presented as instruction-aware advice.
66. [ ] Record provider/model actually used when Auto falls through providers.
67. [ ] Validate provider-returned model IDs against discovered models.
68. [ ] Add a maximum response-token budget to provider requests.
69. [ ] Add retry/backoff only for safe idempotent model requests.
70. [ ] Limit simultaneous inference requests per provider.
71. [ ] Cancel inference when the client disconnects from an SSE stream.
72. [ ] Add a maximum duration for streamed model responses.
73. [ ] Redact API keys from provider diagnostics and logs.
74. [ ] Add prompt-injection tests for hostile paths, names, and metadata.
75. [ ] Show the exact scan timestamp used by tailored advice.
76. [ ] Prevent stale advice from being applied after a newer scan completes.
77. [ ] Keep per-model selection history local and clearable.
78. [ ] Add structured-output compatibility checks for each supported model host.
79. [ ] Show a clear warning when a provider is online but has no text model.
80. [ ] Add offline golden tests for deterministic rule-engine output.

## Clean plan and quarantine safety

81. [ ] Revalidate the scan job status immediately before plan creation.
82. [ ] Show changed-file size/mtime between scan and plan as a refusal reason.
83. [ ] Add device/inode checks to reduce path-replacement races.
84. [ ] Ensure a plan fingerprint includes every field shown to the user.
85. [ ] Cap plan item count after expanding aggregate findings.
86. [ ] Add explicit “all selected items refused” presentation.
87. [ ] Record why each item was refused in both plan and journal.
88. [ ] Verify the destination filesystem before quarantine moves.
89. [ ] Make cross-device quarantine fallback behavior explicit in the plan.
90. [ ] Add a configurable quarantine size ceiling.
91. [ ] Warn before quarantine may exceed available free space.
92. [ ] Add a retention policy for old quarantine entries.
93. [ ] Make restore collision behavior selectable: skip, rename, or ask.
94. [ ] Verify restored content hashes when a journal hash is available.
95. [ ] Add recovery for interrupted multi-file clean operations.
96. [ ] Make journal writes atomic across power loss.
97. [ ] Add journal schema migrations with backup-before-upgrade.
98. [ ] Add a dry-run preview for restore and purge operations.
99. [ ] Require a typed confirmation for permanent purge batches.
100. [ ] Add tests for symlink swaps between planning and execution.

## Scanner accuracy and performance

101. [ ] Add a configurable maximum traversal wall-clock budget.
102. [ ] Add an explicit skipped-directory summary and reason codes.
103. [ ] Report hard-linked byte totals without double counting reclaimable space.
104. [ ] Avoid hashing files that changed while duplicate scanning was in progress.
105. [ ] Add a configurable duplicate hashing concurrency limit.
106. [ ] Reuse stable file metadata when multiple rules inspect the same path.
107. [ ] Add a path-length guard with a visible warning rather than silent loss.
108. [ ] Add filesystem case-sensitivity tests for rule matching.
109. [ ] Test Unicode-normalized path names on macOS filesystems.
110. [ ] Make sparse-file reclaimable-size estimates explicit.
111. [ ] Distinguish logical size from allocated disk blocks in the UI.
112. [ ] Add an option to skip network-mounted volumes.
113. [ ] Add a scan-time estimate based on previous local runs.
114. [ ] Avoid repeated mount-table reads during one scan.
115. [ ] Bound in-memory directory-total collection for huge trees.
116. [ ] Add scan warnings for inaccessible roots before traversal begins.
117. [ ] Make scanner traversal ordering deterministic across platforms.
118. [ ] Add tests for junctions and reparse points on Windows.
119. [ ] Add tests for bind mounts and mount-boundary behavior on Linux.
120. [ ] Add a benchmark fixture for million-entry directory trees.

## WebUI accessibility and responsive behavior

121. [ ] Add automated keyboard-only navigation coverage for every view.
122. [ ] Keep focus inside modal dialogs and restore it to the opener.
123. [ ] Announce scan progress changes without excessive screen-reader chatter.
124. [ ] Add visible focus rings to every interactive element.
125. [ ] Ensure contrast ratios meet WCAG AA for text and status pills.
126. [ ] Add accessible names to every icon-only action.
127. [ ] Keep table headers associated with sortable/filterable controls.
128. [ ] Add reduced-motion behavior for all transitions, not only chat chips.
129. [ ] Support browser zoom to 200% without horizontal overflow.
130. [ ] Add a high-contrast mode respecting system preferences.
131. [ ] Add an explicit empty-state action to every list/table view.
132. [ ] Announce validation errors next to the related form control.
133. [ ] Move focus to page headings after route navigation.
134. [ ] Mark active navigation with `aria-current`.
135. [ ] Ensure touch targets meet the 44-by-44 CSS pixel guideline.
136. [ ] Add tablet-width snapshots for the topbar and sidebar.
137. [ ] Test long paths and model names for safe wrapping.
138. [ ] Ensure dropdowns remain usable with native keyboard controls.
139. [ ] Add descriptive labels for progress meters and charts.
140. [ ] Add a non-color signal for every risk/action state.

## WebUI workflow and data clarity

141. [ ] Add a scan comparison view for two completed scans.
142. [ ] Add saved scan presets with user-editable labels.
143. [ ] Add a “rescan this folder” action from an unmatched chat request.
144. [ ] Show scan scope and exclusions beside every finding list.
145. [ ] Add explicit sorting direction labels and indicators.
146. [ ] Persist safe, non-sensitive filter preferences across reloads.
147. [ ] Add undo affordances immediately after a successful clean.
148. [ ] Show per-item expected reclaimable bytes in the confirmation screen.
149. [ ] Add a plan-expiry countdown and one-click refresh action.
150. [ ] Keep manual selections separate from AI-staged selections in the UI.
151. [ ] Show whether a result came from rules, model advice, or user selection.
152. [ ] Add a compact table density preference.
153. [ ] Add a copy-path button with accessible success feedback.
154. [ ] Add search-result count and visible pagination controls.
155. [ ] Add a clear-all-filters action that preserves scan scope.
156. [ ] Show hidden/filtered selected-item counts before planning.
157. [ ] Add a user-facing scan settings summary before pressing Start.
158. [ ] Add an exportable, redacted scan summary for support.
159. [ ] Add a local-only feedback form for false-positive rule IDs.
160. [ ] Add first-run guidance that explains scan, review, plan, and approval.

## Runtime reliability and observability

161. [ ] Add structured JSON logs with secret/path redaction.
162. [ ] Add a readiness endpoint distinct from liveness.
163. [ ] Report worker/thread counts and scan queue state in diagnostics.
164. [ ] Add per-endpoint latency and error counters without file paths.
165. [ ] Add a safe diagnostics download excluding scan data and credentials.
166. [ ] Detect low-memory conditions before starting deep scans.
167. [ ] Add configurable limits for in-memory scan result retention.
168. [ ] Add graceful handling for process termination during file moves.
169. [ ] Add retryable status guidance for transient filesystem errors.
170. [ ] Add startup validation for writable data and quarantine directories.

## Tests, packaging, and developer experience

171. [ ] Add a CI matrix for Linux, Windows, and macOS.
172. [ ] Run the test suite on Python 3.11, 3.12, and 3.13 in CI.
173. [ ] Add coverage reporting with an agreed minimum threshold.
174. [ ] Add property-based tests for path-policy edge cases.
175. [ ] Add fuzz tests for API request schemas and cleanup plans.
176. [ ] Add browser-level tests for the clean confirmation flow.
177. [ ] Add JavaScript unit tests for model-choice parsing and selection invalidation.
178. [ ] Add reproducible test fixtures for permission-denied behavior.
179. [ ] Add package-install smoke tests from a built wheel.
180. [ ] Verify packaged WebUI assets and updater scripts in release artifacts.
181. [ ] Add a pre-commit configuration matching Ruff and whitespace checks.
182. [ ] Add a static check that every public API route has a contract test.
183. [ ] Add a static check that every cleanup rule declares risk and actionability.
184. [ ] Add a lint rule preventing unsafe shell invocation in the cleaner.
185. [ ] Add a test proving no production path invokes permanent deletion by default.
186. [ ] Add a test proving AI output cannot select IDs absent from the scan.
187. [ ] Add a test proving dangerous text never becomes an executable action.
188. [ ] Add deterministic time-control helpers for expiry and retention tests.
189. [ ] Add a documented command for the complete local quality gate.
190. [ ] Add a changelog fragment per user-visible improvement batch.

## Documentation and support

191. [ ] Document scan concurrency and how to change its limit.
192. [ ] Document what “reclaimable bytes” means on sparse/compressed filesystems.
193. [ ] Add troubleshooting steps for each updater failure code.
194. [ ] Add a privacy inventory of every data field sent to local model hosts.
195. [ ] Document chat selection limits and behavior when findings are omitted.
196. [ ] Add a support bundle policy explaining exactly what is excluded.
197. [ ] Document safe quarantine migration between disks.
198. [ ] Add an operator guide for reverse-proxy and token-protected deployments.
199. [ ] Document platform-specific permission limitations in one matrix.
200. [ ] Publish release notes grouped by safety, usability, and performance.
