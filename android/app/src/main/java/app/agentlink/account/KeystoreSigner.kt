package app.agentlink.account

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import uniffi.agentlink_ffi.KeySigner
import uniffi.agentlink_ffi.publicHexEd25519
import uniffi.agentlink_ffi.signEd25519
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

/** Alias of the login device key in the Android Keystore. */
internal const val DEVICE_KEY_ALIAS = "agentlink.device"

/**
 * Ed25519 operations on a raw 32-byte seed. Production uses the native
 * library; tests supply a JVM implementation because Robolectric cannot load
 * the Android native library.
 */
internal interface SoftwareEd25519 {
    fun publicHex(seed: ByteArray): String
    fun sign(seed: ByteArray, message: ByteArray): String
}

private object NativeSoftwareEd25519 : SoftwareEd25519 {
    override fun publicHex(seed: ByteArray): String = publicHexEd25519(seed)
    override fun sign(seed: ByteArray, message: ByteArray): String = signEd25519(seed, message)
}

/**
 * Login device key.
 *
 * The relay expects an Ed25519 signature. Many Android Keystore
 * implementations, including API 33 and later, throw
 * `NoSuchAlgorithmException: no such algorithm: Ed25519 for provider
 * AndroidKeyStore`. The 32-byte seed is generated in software and sealed with
 * a Keystore AES-256-GCM key, which is what those devices do support (and
 * what StrongBox supports). The ciphertext is stored under
 * [Context.getNoBackupFilesDir] so it is not backed up without the
 * non-exportable wrap key. Signing uses the same Ed25519 implementation as
 * the relay.
 *
 * A phone that already has an Ed25519 key in the Keystore keeps signing with
 * it, so that device id does not change.
 */
class KeystoreSigner internal constructor(
    context: Context,
    private val alias: String,
    private val software: SoftwareEd25519,
) : KeySigner {
    constructor(context: Context, alias: String) : this(context, alias, NativeSoftwareEd25519)

    private val appContext = context.applicationContext
    private val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override fun publicHex(): String = synchronized(this) {
        hardwarePrivateKey()?.let { return hardwarePublic() }
        withSeed { software.publicHex(it) }
    }

    override fun sign(message: ByteArray): String = synchronized(this) {
        hardwarePrivateKey()?.let { return hardwareSign(it, message) }
        withSeed { software.sign(it, message) }
    }

    private fun withSeed(block: (ByteArray) -> String): String {
        val seed = unwrapSeed()
        return try {
            block(seed)
        } finally {
            seed.fill(0)
        }
    }

    private fun hardwarePrivateKey(): PrivateKey? {
        return try {
            if (!store.containsAlias(alias)) return null
            val key = store.getKey(alias, null) as? PrivateKey ?: return null
            val certificateAlgorithm = store.getCertificate(alias)?.publicKey?.algorithm
            if (isEd25519(key.algorithm) || isEd25519(certificateAlgorithm)) key else null
        } catch (_: GeneralSecurityException) {
            null
        }
    }

    private fun hardwarePublic(): String {
        val encoded = store.getCertificate(alias)?.publicKey?.encoded
            ?: throw IllegalStateException("keystore device key has no public key")
        if (encoded.size < 32) throw IllegalStateException("keystore public key is too short")
        return encoded.copyOfRange(encoded.size - 32, encoded.size).toHex()
    }

    private fun hardwareSign(privateKey: PrivateKey, message: ByteArray): String {
        val signature = Signature.getInstance("Ed25519")
        signature.initSign(privateKey)
        signature.update(message)
        return signature.sign().toHex()
    }

    private fun unwrapSeed(): ByteArray {
        ensureWrapKey()
        val file = seedFile()
        if (!file.exists()) {
            val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
            writeSeed(file, seed)
            return seed
        }
        val blob = file.readBytes()
        val (seed, migrated) = open(blob)
        if (migrated) {
            runCatching { writeSeed(file, seed) }
        }
        return seed
    }

    private fun ensureWrapKey() {
        if (store.containsAlias(alias)) return
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false)
                .build(),
        )
        generator.generateKey()
    }

    private fun writeSeed(file: File, seed: ByteArray) {
        val sealed = seal(seed)
        val tmp = File(file.parentFile, "${file.name}.tmp")
        if (tmp.exists()) tmp.delete()
        tmp.writeBytes(sealed)
        if (!tmp.renameTo(file)) {
            file.writeBytes(sealed)
            tmp.delete()
        }
    }

    private fun aadBytes(): ByteArray = "agentlink.seed.v1:$alias".toByteArray(Charsets.UTF_8)

    private fun seal(seed: ByteArray): ByteArray {
        val key = store.getKey(alias, null)
            ?: throw GeneralSecurityException("wrap key missing for $alias")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aadBytes())
        val iv = cipher.iv
        val body = cipher.doFinal(seed)
        return byteArrayOf(iv.size.toByte()) + iv + body
    }

    private fun open(blob: ByteArray): Pair<ByteArray, Boolean> {
        if (blob.size < 1 + MIN_GCM_IV_BYTES + GCM_TAG_BYTES) {
            throw GeneralSecurityException("wrapped device key blob is truncated")
        }
        val ivLen = blob[0].toInt() and 0xff
        if (ivLen !in MIN_GCM_IV_BYTES..MAX_GCM_IV_BYTES || 1 + ivLen + GCM_TAG_BYTES > blob.size) {
            throw GeneralSecurityException("wrapped device key has invalid IV length $ivLen")
        }
        val iv = blob.copyOfRange(1, 1 + ivLen)
        val body = blob.copyOfRange(1 + ivLen, blob.size)
        val key = store.getKey(alias, null)
            ?: throw GeneralSecurityException("wrap key missing for $alias")
        val (plain, migrated) = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher.updateAAD(aadBytes())
            cipher.doFinal(body) to false
        } catch (_: AEADBadTagException) {
            // Legacy blobs written before AAD binding had no AAD; decrypt once and migrate.
            val legacy = Cipher.getInstance("AES/GCM/NoPadding")
            legacy.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            legacy.doFinal(body) to true
        }
        if (plain.size != 32) {
            plain.fill(0)
            throw GeneralSecurityException("wrapped device key has invalid seed length ${plain.size}")
        }
        return plain to migrated
    }

    private fun seedFile(): File {
        val dir = File(appContext.noBackupFilesDir, "keys").apply { mkdirs() }
        return File(dir, "$alias.seed")
    }

    companion object {
        private const val MIN_GCM_IV_BYTES = 12
        private const val MAX_GCM_IV_BYTES = 16
        private const val GCM_TAG_BYTES = 16
    }
}

private fun isEd25519(algorithm: String?): Boolean {
    val name = algorithm?.trim().orEmpty()
    return name.equals("Ed25519", ignoreCase = true) || name.equals("EdDSA", ignoreCase = true)
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
