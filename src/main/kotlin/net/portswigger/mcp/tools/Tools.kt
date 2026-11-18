package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.ScanTask
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.utilities.DigestAlgorithm
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.encodeHistoryItem
import net.portswigger.mcp.schema.limitText
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.ActionApprovalSecurity
import net.portswigger.mcp.security.ActionType
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import net.portswigger.mcp.security.isUrlInScope
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

internal fun String.toHttpMode(): HttpMode = when (uppercase()) {
    "AUTO" -> HttpMode.AUTO
    "HTTP_1" -> HttpMode.HTTP_1
    "HTTP_2" -> HttpMode.HTTP_2
    "HTTP_2_IGNORE_ALPN" -> HttpMode.HTTP_2_IGNORE_ALPN
    else -> throw IllegalArgumentException("Unknown httpMode '$this'. Expected one of AUTO, HTTP_1, HTTP_2, HTTP_2_IGNORE_ALPN")
}

/**
 * Sends a request, layering optional per-call overrides on top of Montoya's defaults.
 * Uses the plain overloads when nothing extra was requested, so behaviour matches the
 * extension's original tools.
 */
private fun Http.sendWithOptions(
    request: HttpRequest,
    httpMode: HttpMode? = null,
    redirectionMode: String? = null,
    responseTimeoutMillis: Long? = null
): HttpRequestResponse? {
    val needsRequestOptions = redirectionMode != null || (responseTimeoutMillis != null && responseTimeoutMillis > 0)

    return when {
        needsRequestOptions -> {
            val options = RequestOptions.requestOptions()
            if (httpMode != null) options.withHttpMode(httpMode)
            when (redirectionMode?.uppercase()) {
                "ALWAYS" -> options.withRedirectionMode(RedirectionMode.ALWAYS)
                "NEVER" -> options.withRedirectionMode(RedirectionMode.NEVER)
                "SAME_HOST" -> options.withRedirectionMode(RedirectionMode.SAME_HOST)
                "IN_SCOPE" -> options.withRedirectionMode(RedirectionMode.IN_SCOPE)
            }
            if (responseTimeoutMillis != null && responseTimeoutMillis > 0) {
                options.withResponseTimeout(responseTimeoutMillis)
            }
            sendRequest(request, options)
        }

        httpMode != null -> sendRequest(request, httpMode)

        else -> sendRequest(request)
    }
}

/**
 * Serialises a request/response, applying an optional character cap so a large response body
 * cannot blow up the client's context window. `maxResponseLength <= 0` means unlimited.
 */
private fun formatResponse(response: HttpRequestResponse?, maxResponseLength: Int): String {
    if (response == null) return "<no response>"
    val text = response.toString()
    return if (maxResponseLength > 0) limitText(text, maxResponseLength) else text
}

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    return (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: return normalizePrelude(content)
    return normalizePrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")   // Literal \r\n escape sequences → LF
    .replace("\\n", "\n")      // Remaining literal \n → LF
    .replace("\\r", "")        // Remaining literal \r → remove
    .replace("\r", "")          // Actual CR → remove
    .replace("\n", "\r\n")      // All LF → proper CRLF

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        val scopeUrl = "http${if (usesHttps) "s" else ""}://$targetHostname:$targetPort/"
        if (!isUrlInScope(scopeUrl, config, api)) {
            api.logging().logToOutput("MCP HTTP request out of scope: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied: target is out of scope"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = normalizeHttpContent(content)

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        currentCoroutineContext().ensureActive()
        val response = api.http().sendWithOptions(
            request,
            httpMode = httpMode?.toHttpMode(),
            redirectionMode = redirectionMode,
            responseTimeoutMillis = responseTimeoutMillis
        )

        formatResponse(response, maxResponseLength)
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        val scopeUrl = "http${if (usesHttps) "s" else ""}://$targetHostname:$targetPort/"
        if (!isUrlInScope(scopeUrl, config, api)) {
            api.logging().logToOutput("MCP HTTP request out of scope: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied: target is out of scope"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        currentCoroutineContext().ensureActive()
        val response = api.http().sendWithOptions(
            request,
            httpMode = HttpMode.HTTP_2,
            redirectionMode = redirectionMode,
            responseTimeoutMillis = responseTimeoutMillis
        )

        formatResponse(response, maxResponseLength)
    }

    mcpUnitTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }

        registerScannerControlTools(api, config)
    }

    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetOrganizerItems>("Displays items within the Organizer tab") {
        val allowed = checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        api.organizer().items().asSequence().map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetOrganizerItemsRegex>("Displays items matching a specified regex within the Organizer tab") {
        val allowed = checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.organizer().items { it.contains(compiledRegex) }.asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        val allowed = ActionApprovalSecurity.checkActionPermission(
            ActionType.TASK_ENGINE, if (running) "resume task execution" else "pause task execution", config
        )
        if (!allowed) return@mcpTool "Set task execution engine state denied by Burp Suite"

        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        val allowed = ActionApprovalSecurity.checkActionPermission(
            ActionType.INTERCEPT, if (intercepting) "enable intercept" else "disable intercept", config
        )
        if (!allowed) return@mcpTool "Set proxy intercept state denied by Burp Suite"

        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }

    registerScopeTools(api, config)
    registerSiteMapTools(api, config)
    registerHandoffTools(api, config)
    registerExtraUtilityTools(api, config)
}

private fun Server.registerScannerControlTools(api: MontoyaApi, config: McpConfig) {
    val scanTasks = java.util.concurrent.ConcurrentHashMap<String, ScanTask>()
    val scanTaskCounter = java.util.concurrent.atomic.AtomicInteger(0)

    fun registerTask(task: ScanTask): String {
        val id = "scan-${scanTaskCounter.incrementAndGet()}"
        scanTasks[id] = task
        return id
    }

    mcpTool<StartAudit>(
        "Starts an active/passive audit of one or more URLs using Burp Scanner (Professional only). " +
        "Returns a task ID that can be polled with get_scan_task_status. Requires approval."
    ) {
        val allowed = ActionApprovalSecurity.checkActionPermission(ActionType.SCANNER, "start audit of ${urls.size} URL(s)", config)
        if (!allowed) return@mcpTool "Start audit denied by Burp Suite"

        val outOfScope = urls.filterNot { isUrlInScope(it, config, api) }
        if (outOfScope.isNotEmpty()) {
            return@mcpTool "Start audit denied: out of scope URLs ${outOfScope.joinToString(", ")}"
        }

        val audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS))
        urls.forEach { audit.addRequest(HttpRequest.httpRequestFromUrl(it)) }

        val id = registerTask(audit)
        "Started audit $id for ${urls.size} URL(s). Poll with get_scan_task_status."
    }

    mcpTool<StartCrawl>(
        "Starts a crawl of one or more seed URLs using Burp Scanner (Professional only). " +
        "Returns a task ID that can be polled with get_scan_task_status. Requires approval."
    ) {
        val allowed = ActionApprovalSecurity.checkActionPermission(ActionType.SCANNER, "start crawl of ${urls.size} URL(s)", config)
        if (!allowed) return@mcpTool "Start crawl denied by Burp Suite"

        val crawl = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(*urls.toTypedArray()))
        val id = registerTask(crawl)
        "Started crawl $id for ${urls.size} seed URL(s). Poll with get_scan_task_status."
    }

    mcpTool<GetScanTaskStatus>("Reports the status of a scanner task started via start_audit or start_crawl") {
        val task = scanTasks[taskId] ?: return@mcpTool "No such scan task: $taskId"
        buildString {
            appendLine("Task: $taskId")
            appendLine("Status: ${task.statusMessage()}")
            appendLine("Requests: ${task.requestCount()}")
            appendLine("Errors: ${task.errorCount()}")
            if (task is Audit) {
                appendLine("Insertion points: ${task.insertionPointCount()}")
                appendLine("Issues found: ${task.issues().size}")
            }
        }
    }

    mcpTool<DeleteScanTask>("Deletes a scanner task started via start_audit or start_crawl. Requires approval.") {
        val task = scanTasks[taskId] ?: return@mcpTool "No such scan task: $taskId"

        val allowed = ActionApprovalSecurity.checkActionPermission(ActionType.SCANNER, "delete scan task $taskId", config)
        if (!allowed) return@mcpTool "Delete scan task denied by Burp Suite"

        task.delete()
        scanTasks.remove(taskId)
        "Deleted scan task $taskId"
    }
}

private fun Server.registerScopeTools(api: MontoyaApi, config: McpConfig) {
    mcpTool<IsInScope>("Checks whether a URL is within Burp's target scope. Returns 'true' or 'false'.") {
        api.scope().isInScope(url).toString()
    }

    mcpTool<IncludeInScope>("Adds a URL to Burp's target scope. This changes the user's scope configuration and requires approval.") {
        val allowed = ActionApprovalSecurity.checkActionPermission(ActionType.SCOPE, "include $url in scope", config)
        if (!allowed) return@mcpTool "Include in scope denied by Burp Suite"

        api.scope().includeInScope(url)
        "Added to scope: $url"
    }

    mcpTool<ExcludeFromScope>("Removes a URL from Burp's target scope. This changes the user's scope configuration and requires approval.") {
        val allowed = ActionApprovalSecurity.checkActionPermission(ActionType.SCOPE, "exclude $url from scope", config)
        if (!allowed) return@mcpTool "Exclude from scope denied by Burp Suite"

        api.scope().excludeFromScope(url)
        "Removed from scope: $url"
    }
}

private fun Server.registerSiteMapTools(api: MontoyaApi, config: McpConfig) {
    mcpPaginatedTool<GetSiteMap>("Displays request/response pairs within Burp's site map") {
        val allowed = checkDataAccessOrDeny(DataAccessType.SITEMAP, config, api, "site map")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Site map access denied by Burp Suite")
        }

        api.siteMap().requestResponses().asSequence().map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetSiteMapRegex>("Displays site map entries matching a specified regex") {
        val allowed = checkDataAccessOrDeny(DataAccessType.SITEMAP, config, api, "site map")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Site map access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.siteMap().requestResponses().asSequence()
            .filter { it.contains(compiledRegex) }
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpUnitTool<AddToSiteMap>("Adds a request/response pair to Burp's site map") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.siteMap().add(HttpRequestResponse.httpRequestResponse(request, null))
    }
}

private fun Server.registerHandoffTools(api: MontoyaApi, config: McpConfig) {
    mcpUnitTool<SendToDecoder>("Sends a value to Burp's Decoder tool for manual inspection") {
        api.decoder().sendToDecoder(ByteArray.byteArray(content))
    }

    mcpUnitTool<SendToComparer>("Sends one or more values to Burp's Comparer tool for manual diffing") {
        api.comparer().sendToComparer(*items.map { ByteArray.byteArray(it) }.toTypedArray())
    }

    mcpTool<SendToOrganizer>("Sends a raw HTTP/1.1 request to the Organizer for later review. Requires approval.") {
        val allowed = ActionApprovalSecurity.checkActionPermission(
            ActionType.ORGANIZER, "send request to Organizer for $targetHostname:$targetPort", config
        )
        if (!allowed) return@mcpTool "Send to Organizer denied by Burp Suite"

        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.organizer().sendToOrganizer(request)

        "Request sent to Organizer"
    }
}

private fun Server.registerExtraUtilityTools(api: MontoyaApi, config: McpConfig) {
    mcpTool<HtmlEncode>("HTML-encodes the input string") {
        api.utilities().htmlUtils().encode(content)
    }

    mcpTool<HtmlDecode>("HTML-decodes the input string") {
        api.utilities().htmlUtils().decode(content)
    }

    mcpTool<AsciiToHex>("Converts an ASCII string to its hexadecimal representation") {
        api.utilities().stringUtils().convertAsciiToHexString(content)
    }

    mcpTool<HexToAscii>("Converts a hexadecimal string to ASCII") {
        api.utilities().stringUtils().convertHexStringToAscii(content)
    }

    mcpTool<GenerateHash>("Generates a cryptographic hash of the input using the specified algorithm (e.g. SHA_256, MD5)") {
        val algorithm = try {
            DigestAlgorithm.valueOf(algorithm.uppercase())
        } catch (_: IllegalArgumentException) {
            return@mcpTool "Unknown algorithm '$algorithm'. Example values: MD5, SHA_1, SHA_256, SHA_512."
        }
        api.utilities().cryptoUtils().generateDigest(ByteArray.byteArray(content), algorithm).toString()
    }

    mcpTool<ReadJsonPath>("Reads a value from a JSON document using Burp's JSON path syntax") {
        api.utilities().jsonUtils().read(json, path) ?: "<no value>"
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
    val httpMode: String? = null,
    val redirectionMode: String? = null,
    val responseTimeoutMillis: Long? = null,
    val maxResponseLength: Int = 0
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
    val redirectionMode: String? = null,
    val responseTimeoutMillis: Long? = null,
    val maxResponseLength: Int = 0
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItems(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItemsRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class StartAudit(val urls: List<String>)

@Serializable
data class StartCrawl(val urls: List<String>)

@Serializable
data class GetScanTaskStatus(val taskId: String)

@Serializable
data class DeleteScanTask(val taskId: String)

@Serializable
data class IsInScope(val url: String)

@Serializable
data class IncludeInScope(val url: String)

@Serializable
data class ExcludeFromScope(val url: String)

@Serializable
data class GetSiteMap(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetSiteMapRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class AddToSiteMap(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToDecoder(val content: String)

@Serializable
data class SendToComparer(val items: List<String>)

@Serializable
data class SendToOrganizer(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class HtmlEncode(val content: String)

@Serializable
data class HtmlDecode(val content: String)

@Serializable
data class AsciiToHex(val content: String)

@Serializable
data class HexToAscii(val content: String)

@Serializable
data class GenerateHash(val content: String, val algorithm: String)

@Serializable
data class ReadJsonPath(val json: String, val path: String)

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)
