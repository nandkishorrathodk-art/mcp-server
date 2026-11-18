package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig

/**
 * Actions that mutate Burp state or start long-running work (scanner, scope, intercept,
 * task engine, config). These are gated behind their own approval so that a client cannot
 * silently kick off a scan or rewrite scope without the user noticing.
 */
enum class ActionType {
    SCANNER,
    SCOPE,
    INTERCEPT,
    TASK_ENGINE,
    ORGANIZER,
    SITEMAP,
    CONFIG
}

interface ActionApprovalHandler {
    suspend fun requestActionApproval(actionType: ActionType, detail: String, config: McpConfig): Boolean
}

class SwingActionApprovalHandler : ActionApprovalHandler {
    override suspend fun requestActionApproval(
        actionType: ActionType, detail: String, config: McpConfig
    ): Boolean {
        val message = buildString {
            appendLine("An MCP client is requesting to perform a Burp action:")
            appendLine()
            appendLine("Action: ${actionType.name.lowercase().replace('_', ' ')}")
            appendLine("Detail: $detail")
            appendLine()
            appendLine("Choose how you would like to respond:")
        }

        val result = Dialogs.requestOption(findBurpFrame(), message, arrayOf("Allow Once", "Deny"))

        return result == 0
    }
}

object ActionApprovalSecurity {

    var approvalHandler: ActionApprovalHandler = SwingActionApprovalHandler()

    suspend fun checkActionPermission(
        actionType: ActionType, detail: String, config: McpConfig
    ): Boolean {
        if (!config.requireActionApproval) {
            return true
        }
        return approvalHandler.requestActionApproval(actionType, detail, config)
    }
}

/**
 * Enforces the optional "only send requests to in-scope targets" setting. Returns true when
 * the request may proceed. A disabled setting always allows.
 *
 * [url] is evaluated lazily so callers that would have to build the URL from a request (or
 * from pseudo-headers) do not pay for it when the setting is off.
 */
fun isUrlInScope(url: () -> String, config: McpConfig, api: MontoyaApi): Boolean {
    if (!config.enforceScope) return true
    return try {
        api.scope().isInScope(url())
    } catch (e: Exception) {
        // Fail closed: a URL we cannot resolve or a scope lookup that errors must not silently allow.
        api.logging().logToError("Scope check failed: ${e.message}")
        false
    }
}
