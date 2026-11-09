package app.agentlink.account

import android.content.Context
import app.agentlink.bridge.ClientSession
import app.agentlink.bridge.NativeClient
import uniffi.agentlink_ffi.MobileClient
import uniffi.agentlink_ffi.loginAccount
import uniffi.agentlink_ffi.refreshAccount
import java.io.File

class NativeAccount(context: Context) : AccountApi {
    private val appContext = context.applicationContext
    private val signer = KeystoreSigner(appContext, DEVICE_KEY_ALIAS)
    private val nodeDir = File(appContext.noBackupFilesDir, "node").apply { mkdirs() }

    override fun login(
        server: String,
        fingerprint: String,
        username: String,
        password: String,
        totp: String,
        deviceName: String,
    ): UserAccount {
        val issued = loginAccount(server, fingerprint, username, password, totp, deviceName, signer)
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
        val issued = refreshAccount(account.server, account.fingerprint, account.refreshToken, signer)
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
        use(account) { it.logout(account.refreshToken) }
    }

    override fun listNodes(account: UserAccount): List<NodeRow> = use(account) { client ->
        client.listMachines().map { machine ->
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
        client.listDevices().map { device ->
            DeviceRow(id = device.id, name = device.name, revoked = device.revoked)
        }
    }

    override fun devicePublicHex(): String = signer.publicHex()

    override fun enrollAsNode(account: UserAccount, name: String) {
        use(account) { it.enrollSelf(name, nodeDir.absolutePath) }
    }

    override fun connect(account: UserAccount): ClientSession = NativeClient(open(account))

    private fun <T> use(account: UserAccount, block: (MobileClient) -> T): T {
        val client = open(account)
        return try {
            block(client)
        } finally {
            client.close()
        }
    }

    private fun open(account: UserAccount): MobileClient = MobileClient.connectUser(
        account.server,
        account.fingerprint,
        account.accessToken,
        signer,
        appContext.filesDir.absolutePath,
    )
}
