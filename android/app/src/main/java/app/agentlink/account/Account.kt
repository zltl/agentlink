package app.agentlink.account

import android.net.Uri
import app.agentlink.bridge.ClientSession

/** No built-in relay. Callers pass a URL or keep one already saved. */
const val DEFAULT_RELAY = ""

data class UserAccount(
    val server: String,
    val fingerprint: String,
    val user: String,
    val role: String,
    val deviceId: String,
    val accessToken: String,
    val accessExpiresUnix: Long,
    val refreshToken: String,
    /** Unix seconds. `0` means the stored session predates this field; still try to refresh. */
    val refreshExpiresUnix: Long = 0,
)

data class NodeRow(
    val id: String,
    val name: String,
    val owner: String,
    val relation: String,
    val access: String,
    val online: Boolean,
)

data class DeviceRow(
    val id: String,
    val name: String,
    val revoked: Boolean,
)

data class EnrollLink(
    val server: String,
    val fingerprint: String,
    val token: String,
    val name: String,
)

interface SessionStore {
    fun load(): UserAccount?
    fun save(account: UserAccount)
    fun clear()
}

interface AccountApi {
    fun login(
        server: String,
        fingerprint: String,
        username: String,
        password: String,
        totp: String,
        deviceName: String,
    ): UserAccount

    fun refresh(account: UserAccount): UserAccount
    fun logout(account: UserAccount)
    fun listNodes(account: UserAccount): List<NodeRow>
    fun listDevices(account: UserAccount): List<DeviceRow>

    /**
     * Hex Ed25519 public key this device signs with. It is the grantee id of
     * any signed grant issued for this phone. Empty when the caller has no
     * device key (test doubles).
     */
    fun devicePublicHex(): String = ""

    /** Enroll this phone under the logged-in user. No pairing token. */
    fun enrollAsNode(account: UserAccount, name: String)
    fun connect(account: UserAccount): ClientSession
}

fun parseEnroll(uri: Uri?): EnrollLink? {
    if (uri == null || uri.scheme != "agentlink" || uri.host != "enroll") return null
    val token = uri.getQueryParameter("token").orEmpty()
    if (token.isEmpty()) return null
    val relay = uri.getQueryParameter("relay").orEmpty().ifBlank { DEFAULT_RELAY }
    return EnrollLink(
        server = relay,
        fingerprint = uri.getQueryParameter("fingerprint").orEmpty(),
        token = token,
        name = uri.getQueryParameter("name").orEmpty().ifBlank { "phone" },
    )
}
