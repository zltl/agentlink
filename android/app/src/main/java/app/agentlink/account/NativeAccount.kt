package app.agentlink.account

import android.content.Context
import app.agentlink.bridge.ClientSession
import app.agentlink.bridge.GrantRow
import app.agentlink.bridge.LinkFailure
import app.agentlink.bridge.NativeClient
import app.agentlink.bridge.NodePinRow
import uniffi.agentlink_ffi.LinkException
import uniffi.agentlink_ffi.MobileClient
import uniffi.agentlink_ffi.loginAccount
import uniffi.agentlink_ffi.refreshAccount
import java.io.File

class NativeAccount(context: Context) : AccountApi {
    private val appContext = context.applicationContext
    private val signer = KeystoreSigner(appContext, DEVICE_KEY_ALIAS)
    private val nodeDir = File(appContext.noBackupFilesDir, "node").apply { mkdirs() }
    private val clientLock = Any()
    private var cachedKey: Triple<String, String, String>? = null
    private var cachedClient: MobileClient? = null

    override fun login(
        server: String,
        fingerprint: String,
        username: String,
        password: String,
        totp: String,
        deviceName: String,
    ): UserAccount {
        val issued = call { loginAccount(server, fingerprint, username, password, totp, deviceName, signer) }
        return UserAccount(
            server = server.trim(),
            fingerprint = fingerprint.trim(),
            user = issued.user,
            role = issued.role,
            deviceId = issued.deviceId,
            accessToken = issued.accessToken,
            accessExpiresUnix = issued.accessExpiresUnix,
            refreshToken = issued.refreshToken,
            refreshExpiresUnix = issued.refreshExpiresUnix,
        )
    }

    override fun refresh(account: UserAccount): UserAccount {
        val issued = call { refreshAccount(account.server, account.fingerprint, account.refreshToken, signer) }
        return account.copy(
            user = issued.user,
            role = issued.role,
            deviceId = issued.deviceId,
            accessToken = issued.accessToken,
            accessExpiresUnix = issued.accessExpiresUnix,
            refreshToken = issued.refreshToken,
            refreshExpiresUnix = issued.refreshExpiresUnix,
        )
    }

    override fun logout(account: UserAccount) {
        try {
            use(account) { call { it.logout(account.refreshToken) } }
        } finally {
            closeCached()
        }
    }

    override fun listNodes(account: UserAccount): List<NodeRow> = use(account) { client ->
        call { client.listMachines() }.map { machine ->
            NodeRow(
                id = machine.id,
                name = machine.name,
                owner = machine.owner,
                relation = machine.relation,
                access = machine.access,
                online = machine.online,
            )
        }
    }

    override fun listDevices(account: UserAccount): List<DeviceRow> = use(account) { client ->
        call { client.listDevices() }.map { device ->
            DeviceRow(id = device.id, name = device.name, revoked = device.revoked)
        }
    }

    override fun revokeDevice(account: UserAccount, deviceId: String) {
        use(account) { call { it.revokeDevice(deviceId) } }
    }

    override fun listNodePins(account: UserAccount): List<NodePinRow> = use(account) { client ->
        call { client.listNodePins() }.map { NodePinRow(name = it.name, nodeId = it.nodeId) }
    }

    override fun clearNodePin(account: UserAccount, name: String): Boolean = use(account) { client ->
        call { client.clearNodePin(name) }
    }

    override fun listGrants(account: UserAccount): List<GrantRow> = use(account) { client ->
        call { client.listGrants() }.map {
            GrantRow(
                nodeId = it.nodeId,
                granteeId = it.granteeId,
                issuerId = it.issuerId,
                jti = it.jti,
                nbfUnix = it.nbfUnix,
                expUnix = it.expUnix,
                preset = it.preset,
            )
        }
    }

    override fun importGrant(account: UserAccount, grantJson: String): GrantRow = use(account) { client ->
        val g = call { client.importGrant(grantJson) }
        GrantRow(
            nodeId = g.nodeId,
            granteeId = g.granteeId,
            issuerId = g.issuerId,
            jti = g.jti,
            nbfUnix = g.nbfUnix,
            expUnix = g.expUnix,
            preset = g.preset,
        )
    }

    override fun deleteGrant(account: UserAccount, nodeId: String): Boolean = use(account) { client ->
        call { client.deleteGrant(nodeId) }
    }

    override fun devicePublicHex(): String = signer.publicHex()

    override fun enrollAsNode(account: UserAccount, name: String) {
        use(account) { call { it.enrollSelf(name, nodeDir.absolutePath) } }
    }

    override fun connect(account: UserAccount): ClientSession = NativeClient(open(account))

    private fun <T> use(account: UserAccount, block: (MobileClient) -> T): T {
        val key = Triple(account.server.trim(), account.fingerprint.trim(), account.deviceId)
        val client = synchronized(clientLock) {
            val existing = cachedClient
            if (existing != null && cachedKey == key) {
                runCatching { existing.updateAccessToken(account.accessToken) }
                existing
            } else {
                runCatching { existing?.close() }
                val created = open(account)
                cachedKey = key
                cachedClient = created
                created
            }
        }
        return block(client)
    }

    private fun closeCached() {
        synchronized(clientLock) {
            runCatching { cachedClient?.close() }
            cachedClient = null
            cachedKey = null
        }
    }

    private fun open(account: UserAccount): MobileClient = call {
        MobileClient.connectUser(
            account.server,
            account.fingerprint,
            account.accessToken,
            signer,
            appContext.filesDir.absolutePath,
        )
    }

    private inline fun <T> call(block: () -> T): T {
        try {
            return block()
        } catch (err: LinkException.Fail) {
            throw LinkFailure(err.detail)
        }
    }
}
