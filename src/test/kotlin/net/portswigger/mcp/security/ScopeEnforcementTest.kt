package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.scope.Scope
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ScopeEnforcementTest {

    private fun configWith(enforceScope: Boolean): McpConfig {
        val storage = mutableMapOf<String, Any>(
            "enabled" to true,
            "configEditingTooling" to false,
            "requireHttpRequestApproval" to false,
            "enforceScope" to enforceScope,
            "host" to "127.0.0.1",
            "_autoApproveTargets" to "",
            "port" to 9876
        )
        val persisted = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers { storage[firstArg()] as? Boolean ?: false }
            every { getString(any()) } answers { storage[firstArg()] as? String ?: "" }
            every { getInteger(any()) } answers { storage[firstArg()] as? Int ?: 0 }
            every { setBoolean(any(), any()) } returns Unit
            every { setString(any(), any()) } returns Unit
            every { setInteger(any(), any()) } returns Unit
        }
        val logging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
            every { logToOutput(any<String>()) } returns Unit
        }
        return McpConfig(persisted, logging)
    }

    @Test
    fun `disabled enforcement allows any url without consulting scope`() {
        val api = mockk<MontoyaApi>(relaxed = true)
        val config = configWith(enforceScope = false)

        val allowed = isUrlInScope({ "https://example.com/" }, config, api)

        assertTrue(allowed)
        verify(exactly = 0) { api.scope() }
    }

    @Test
    fun `enabled enforcement allows in-scope url`() {
        val scope = mockk<Scope>()
        val api = mockk<MontoyaApi>(relaxed = true).apply {
            every { scope() } returns scope
        }
        val config = configWith(enforceScope = true)
        every { scope.isInScope("https://example.com/api") } returns true

        assertTrue(isUrlInScope({ "https://example.com/api" }, config, api))
        verify(exactly = 1) { scope.isInScope("https://example.com/api") }
    }

    @Test
    fun `enabled enforcement denies out-of-scope url`() {
        val scope = mockk<Scope>()
        val api = mockk<MontoyaApi>(relaxed = true).apply {
            every { scope() } returns scope
        }
        val config = configWith(enforceScope = true)
        every { scope.isInScope("https://evil.example/") } returns false

        assertFalse(isUrlInScope({ "https://evil.example/" }, config, api))
    }

    @Test
    fun `scope failures fail closed`() {
        val scope = mockk<Scope>()
        val api = mockk<MontoyaApi>(relaxed = true).apply {
            every { scope() } returns scope
        }
        val config = configWith(enforceScope = true)
        every { scope.isInScope(any()) } throws IllegalStateException("scope unavailable")

        assertFalse(isUrlInScope({ "https://example.com/" }, config, api))
    }

    @Test
    fun `url lambda is not evaluated when enforcement is disabled`() {
        val api = mockk<MontoyaApi>(relaxed = true)
        val config = configWith(enforceScope = false)
        var evaluated = false

        isUrlInScope({ evaluated = true; "https://example.com/" }, config, api)

        assertFalse(evaluated)
    }
}
