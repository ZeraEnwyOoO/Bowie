package org.bowie

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.net.InetAddress
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.util.concurrent.Executors

class BowieVpnService : VpnService() {
    private val worker = Executors.newSingleThreadExecutor()
    @Volatile private var nativeHandle: Long = 0
    @Volatile private var nativeOperation = false
    @Volatile private var stopRequested = false
    @Volatile private var configuredBootstrapPort = 0
    @Volatile private var configuredClientMode = false
    @Volatile private var clientFullTunnelActive = false
    private var sessionConfig: Intent? = null
    private var vpnFd: ParcelFileDescriptor? = null

    external fun nativeStart(
        tunFd: Int,
        bootstrapHost: String,
        bootstrapPort: Int,
        stunHost: String,
        stunPort: Int,
        turnHost: String,
        turnPort: Int,
        turnUsername: String,
        turnPassword: String,
        signalRelayHost: String,
        signalRelayPort: Int,
        signalMeteredApiKey: String,
        signalMeteredChannel: String,
        identitySeed: ByteArray
    ): Long
    external fun nativePeerId(handle: Long): ByteArray?
    external fun nativeConnectedPeerId(handle: Long): ByteArray?
    external fun nativeSignalPort(handle: Long): Int
    external fun nativeDisconnect(handle: Long): Int
    external fun nativeRevokeGrant(handle: Long, grantId: ByteArray): Int
    external fun nativeIssueGrant(handle: Long, subject: ByteArray, ttlMs: Long, maxEgressBytes: Long): ByteArray?
    external fun nativeSetGrant(handle: Long, grantWire: ByteArray): Int
    external fun nativeAccept(handle: Long, expectedPeer: ByteArray): Int
    external fun nativeAnnounceRoom(handle: Long, room: String): Int
    external fun nativeAcceptDiscovered(handle: Long): Int
    external fun nativeConnect(handle: Long, expectedPeer: ByteArray, host: String, port: Int): Int
    external fun nativeConnectDht(handle: Long, expectedPeer: ByteArray): Int
    external fun nativeConnectRoom(handle: Long, room: String): Int
    external fun nativeConnectRelay(handle: Long, expectedPeer: ByteArray): Int
    external fun nativeReplaceTunFd(handle: Long, tunFd: Int): Int
    external fun nativeStop(handle: Long)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) return START_NOT_STICKY
        if (intent.action == ACTION_STOP) {
            stopBowieSession()
            return START_NOT_STICKY
        }
        if (intent.action == ACTION_REVOKE_GRANT) {
            worker.execute { revokeOwnerGrant(intent) }
            return START_NOT_STICKY
        }
        startForeground(1, notification())
        if (intent.action == ACTION_CONNECT) worker.execute { connectBowie(intent) }
        else if (intent.action == ACTION_ISSUE_GRANT) worker.execute { issueOwnerGrant(intent) }
        else worker.execute { startBowie(intent) }
        return START_NOT_STICKY
    }

    private fun isNumericIpv4(value: String): Boolean {
        val parts = value.split('.')
        return parts.size == 4 && parts.all {
            it.isNotEmpty() && it.length <= 3 && it.all { digit -> digit in '0'..'9' } &&
                it.toIntOrNull()?.let { octet -> octet in 0..255 } == true
        }
    }

    private fun stopBowieSession() {
        logEvent("INFO", "VPN_STOP_REQUESTED")
        val handle = synchronized(this) {
            stopRequested = true
            if (nativeOperation) 0L else nativeHandle.also { nativeHandle = 0L }
        }
        if (handle != 0L) nativeStop(handle)
        vpnFd?.close()
        vpnFd = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        status("STOPPED")
        stopSelf()
    }

    private fun startBowie(intent: Intent) {
        logEvent("INFO", "VPN_START_REQUESTED")
        if (!beginStartOperation()) {
            val existingHandle = synchronized(this) { nativeHandle }
            if (existingHandle != 0L) {
                val requestedClientMode = intent.getBooleanExtra("client_mode", false)
                if (requestedClientMode != configuredClientMode) {
                    status("ERROR VPN is already prepared in another routing mode; stop it before switching")
                    return
                }
                val ownId = nativePeerId(existingHandle)?.toHex()
                if (ownId != null) {
                    status("READY peer=$ownId signal_port=${nativeSignalPort(existingHandle)}")
                    return
                }
            }
            status("ERROR VPN startup is already in progress, or the service is stopping")
            return
        }
        try {
            val localAddress = intent.getStringExtra("overlay_ip") ?: error("overlay_ip missing")
            val prefix = intent.getIntExtra("prefix", 24)
            require(prefix in 1..32)
            val clientMode = intent.getBooleanExtra("client_mode", false)
            val detachedFd = establishVpnInterface(intent, fullTunnel = false)
            val identitySeed = loadOrCreateIdentitySeed()
            val handle = try { nativeStart(detachedFd,
                intent.getStringExtra("bootstrap_host") ?: "",
                intent.getIntExtra("bootstrap_port", 0),
                intent.getStringExtra("stun_host") ?: "",
                intent.getIntExtra("stun_port", 0),
                intent.getStringExtra("turn_host") ?: "",
                intent.getIntExtra("turn_port", 0),
                intent.getStringExtra("turn_username") ?: "",
                intent.getStringExtra("turn_password") ?: "",
                intent.getStringExtra("signal_relay_host") ?: "",
                intent.getIntExtra("signal_relay_port", 0),
                intent.getStringExtra("signal_metered_api_key") ?: "",
                intent.getStringExtra("signal_metered_channel") ?: "", identitySeed)
            } finally {
                identitySeed.fill(0)
            }
            if (handle == 0L) error("Bowie engine start returned no handle")
            for (grantHex in PeerStore.revokedIds(this)) {
                val grantId = grantHex.hexGrantIdToBytes()
                val revokeRc = nativeRevokeGrant(handle, grantId)
                grantId.fill(0)
                if (revokeRc != 0) {
                    nativeStop(handle)
                    error("Could not restore a saved grant revocation ($revokeRc)")
                }
            }
            logEvent("INFO", "NATIVE_ENGINE_STARTED")
            configuredBootstrapPort = intent.getIntExtra("bootstrap_port", 0)
            configuredClientMode = clientMode
            clientFullTunnelActive = false
            sessionConfig = Intent(intent)
            val stopping = synchronized(this) {
                nativeHandle = handle
                stopRequested
            }
            if (stopping) return
            val ownId = nativePeerId(handle)?.toHex() ?: error("could not read peer ID")
            val signalPort = nativeSignalPort(handle)
            status("READY peer=$ownId signal_port=$signalPort")
        } catch (t: Throwable) {
            logEvent("ERROR", "VPN_SESSION_FAILED", JSONObject()
                .put("error", t.message ?: t.javaClass.simpleName)
                .put("stack", Log.getStackTraceString(t)))
            status("ERROR ${t.message ?: t.javaClass.simpleName}")
            stopSelf()
        } finally {
            finishOperation()
        }
    }

    private fun establishVpnInterface(intent: Intent, fullTunnel: Boolean): Int {
        val localAddress = intent.getStringExtra("overlay_ip") ?: error("overlay_ip missing")
        val prefix = intent.getIntExtra("prefix", 24)
        require(prefix in 1..32)
        val clientMode = intent.getBooleanExtra("client_mode", false)
        val builder = Builder().setSession("Bowie").setMtu(1500)
            .addAddress(localAddress, prefix)
            .addRoute(networkAddress(localAddress, prefix), prefix)
        // Keep Bowie's transport sockets on the physical underlay.
        builder.addDisallowedApplication(packageName)
        if (fullTunnel && clientMode) {
            val dns = intent.getStringExtra("dns_server") ?: error("DNS resolver missing")
            require(isNumericIpv4(dns)) { "DNS resolver must be a numeric IPv4 address" }
            builder.addRoute(InetAddress.getByName("0.0.0.0"), 0)
                .addRoute(InetAddress.getByName("::"), 0)
                .addDnsServer(InetAddress.getByName(dns))
        }
        logEvent("INFO", "VPN_INTERFACE_ESTABLISHING", JSONObject()
            .put("overlay_ip", localAddress).put("prefix", prefix)
            .put("client_mode", clientMode).put("full_tunnel", fullTunnel)
            .put("dns_server", if (fullTunnel && clientMode) intent.getStringExtra("dns_server") else ""))
        val established = builder.establish() ?: error("VPN permission was not granted")
        val detachedFd = established.detachFd()
        logEvent("INFO", "VPN_INTERFACE_ESTABLISHED", JSONObject().put("full_tunnel", fullTunnel))
        return detachedFd
    }

    private fun identityKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "org.bowie.identity.wrap.v1"
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .build())
        return generator.generateKey()
    }

    private fun loadOrCreateIdentitySeed(): ByteArray {
        val file = AtomicFile(File(filesDir, "identity-v1.bin"))
        val secret = identityKey()
        if (file.baseFile.exists()) {
            val blob = file.readFully()
            require(blob.size == 12 + 32 + 16) { "stored Bowie identity has an invalid size" }
            val nonce = blob.copyOfRange(0, 12)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, nonce))
            return cipher.doFinal(blob, 12, blob.size - 12).also {
                require(it.size == 32) { "stored Bowie identity seed has an invalid size" }
            }
        }
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secret)
            val nonce = cipher.iv
            val encrypted = cipher.doFinal(seed)
            val stream = file.startWrite()
            try {
                stream.write(nonce)
                stream.write(encrypted)
                file.finishWrite(stream)
            } catch (t: Throwable) {
                file.failWrite(stream)
                throw t
            }
            return seed
        } catch (t: Throwable) {
            seed.fill(0)
            throw t
        }
    }

    private fun connectBowie(intent: Intent) {
        val handle = beginConnectionOperation()
        if (handle == 0L) {
            status("ERROR start the VPN first")
            return
        }
        try {
            performPeerConnection(handle, intent)
            if (configuredClientMode && !clientFullTunnelActive) {
                status("PEER CONNECTED · enabling full tunnel")
                val config = sessionConfig ?: error("VPN configuration is missing")
                val replacementFd = establishVpnInterface(config, fullTunnel = true)
                val replaceRc = nativeReplaceTunFd(handle, replacementFd)
                if (replaceRc != 0) {
                    logEvent("ERROR", "FULL_TUNNEL_ROUTE_ACTIVATION_FAILED",
                        JSONObject().put("result", replaceRc))
                    synchronized(this) { stopRequested = true }
                    stopSelf()
                    error("Could not activate full-tunnel routing ($replaceRc); VPN stopped to restore normal network access")
                }
                clientFullTunnelActive = true
                logEvent("INFO", "FULL_TUNNEL_ROUTE_ACTIVE")
            }
            val connectedPeer = nativeConnectedPeerId(handle)?.toHex().orEmpty()
            status("CONNECTED peer=$connectedPeer overlay=${intent.getStringExtra("overlay_ip")}")
        } catch (t: Throwable) {
            logEvent("ERROR", "PEER_OPERATION_EXCEPTION", JSONObject()
                .put("error", t.message ?: t.javaClass.simpleName)
                .put("stack", Log.getStackTraceString(t)))
            status("ERROR ${t.message ?: t.javaClass.simpleName}")
        } finally {
            finishOperation()
        }
    }

    private fun performPeerConnection(handle: Long, intent: Intent) {
        try {
            val mode = intent.getStringExtra("mode") ?: "connect"
            val peerId = if (mode == "room_connect" || mode == "room_wait") {
                ByteArray(20)
            } else {
                (intent.getStringExtra("peer_id") ?: "").hexToBytes()
            }
            val requestedClientMode = mode != "listen" && mode != "room_wait"
            if (requestedClientMode != configuredClientMode) {
                error("VPN routing mode does not match this peer role; stop and prepare the VPN again")
            }
            if (mode != "listen" && mode != "room_wait") {
                val grantWire = intent.getByteArrayExtra("owner_grant")
                    ?: error("owner grant missing")
                val grantRc = nativeSetGrant(handle, grantWire)
                if (grantRc != 0) error("Owner grant rejected ($grantRc)")
            }
            logEvent("INFO", "PEER_OPERATION_BEGIN", JSONObject()
                .put("mode", mode).put("use_dht", intent.getBooleanExtra("use_dht", false))
                .put("use_signal_relay", intent.getBooleanExtra("use_signal_relay", false))
                .put("peer_id", intent.getStringExtra("peer_id") ?: ""))
            if ((intent.getBooleanExtra("use_dht", false) ||
                    mode == "room_wait" || mode == "room_connect") &&
                configuredBootstrapPort !in 1..65535) {
                error("Configure a bootstrap host and port before preparing the VPN")
            }
            val rc = if (mode == "room_wait") {
                val room = intent.getStringExtra("room") ?: error("room missing")
                val announceRc = nativeAnnounceRoom(handle, room)
                if (announceRc != 0) error("Could not announce DHT room ($announceRc)")
                status("ROOM READY; waiting for a granted guest")
                nativeAcceptDiscovered(handle)
            } else if (mode == "room_connect") {
                val room = intent.getStringExtra("room") ?: error("room missing")
                nativeConnectRoom(handle, room)
            } else if (mode == "listen") {
                nativeAccept(handle, peerId)
            } else if (intent.getBooleanExtra("use_dht", false)) {
                nativeConnectDht(handle, peerId)
            } else if (intent.getBooleanExtra("use_signal_relay", false)) {
                nativeConnectRelay(handle, peerId)
            } else {
                nativeConnect(handle, peerId,
                    intent.getStringExtra("host") ?: error("host missing"),
                    intent.getIntExtra("port", 0))
            }
            logEvent(if (rc == 0) "INFO" else "ERROR", "PEER_OPERATION_END",
                JSONObject().put("result", rc))
            if (rc != 0) error("Bowie connection failed ($rc)")
        } catch (t: Throwable) {
            throw t
        }
    }

    private fun issueOwnerGrant(intent: Intent) {
        val handle = beginConnectionOperation()
        if (handle == 0L) {
            status("ERROR prepare the router VPN before issuing a grant")
            return
        }
        try {
            val subject = (intent.getStringExtra("subject_peer_id") ?: "").hexToBytes()
            val ttlMs = intent.getLongExtra("grant_ttl_ms", 30L * 24L * 60L * 60L * 1000L)
            require(ttlMs in 60_000L..(30L * 24L * 60L * 60L * 1000L)) {
                "grant lifetime must be between one minute and 30 days"
            }
            val dataLimitBytes = intent.getLongExtra("grant_data_limit_bytes", 0L)
            require(dataLimitBytes >= 0L) { "data limit cannot be negative" }
            val grant = nativeIssueGrant(handle, subject, ttlMs, dataLimitBytes)
                ?: error("could not sign the owner grant")
            require(grant.size == 160) { "native grant has an invalid size" }
            sendBroadcast(Intent(ACTION_GRANT_READY).setPackage(packageName)
                .putExtra("grant_wire", grant)
                .putExtra("subject_peer_id", intent.getStringExtra("subject_peer_id") ?: "")
                .putExtra("peer_name", intent.getStringExtra("peer_name") ?: "Peer"))
            status("OWNER GRANT READY with selected expiry")
            grant.fill(0)
        } catch (t: Throwable) {
            status("ERROR ${t.message ?: "could not issue owner grant"}")
        } finally {
            finishOperation()
        }
    }

    private fun revokeOwnerGrant(intent: Intent) {
        val grantHex = intent.getStringExtra("grant_id") ?: run {
            status("ERROR missing grant ID")
            return
        }
        try {
            val grantId = grantHex.hexGrantIdToBytes()
            val handle = synchronized(this) { nativeHandle }
            var disconnectedActivePeer = false
            if (handle != 0L) {
                val expectedPeer = intent.getStringExtra("peer_id")?.lowercase().orEmpty()
                val activePeer = nativeConnectedPeerId(handle)?.toHex().orEmpty()
                if (expectedPeer.isNotEmpty() && activePeer == expectedPeer) {
                    val disconnectRc = nativeDisconnect(handle)
                    if (disconnectRc != 0 && disconnectRc != -160) {
                        grantId.fill(0)
                        error("Could not stop the revoked peer session ($disconnectRc)")
                    }
                    disconnectedActivePeer = true
                }
                val revokeRc = nativeRevokeGrant(handle, grantId)
                if (revokeRc != 0) {
                    grantId.fill(0)
                    error("Could not revoke the owner grant ($revokeRc)")
                }
            }
            grantId.fill(0)
            status(if (disconnectedActivePeer) "DISCONNECTED grant revoked" else "GRANT_REVOKED")
        } catch (t: Throwable) {
            status("ERROR ${t.message ?: "could not revoke grant"}")
        }
    }

    private fun beginStartOperation(): Boolean = synchronized(this) {
        if (stopRequested || nativeHandle != 0L) return@synchronized false
        nativeOperation = true
        true
    }

    private fun beginConnectionOperation(): Long = synchronized(this) {
        if (stopRequested || nativeHandle == 0L) return@synchronized 0L
        nativeOperation = true
        nativeHandle
    }

    private fun finishOperation() {
        val handle = synchronized(this) {
            nativeOperation = false
            if (stopRequested) nativeHandle.also { nativeHandle = 0L } else 0L
        }
        if (handle != 0L) nativeStop(handle)
    }

    private fun networkAddress(address: String, prefix: Int): String {
        val bytes = InetAddress.getByName(address).address
        require(bytes.size == 4) { "Only IPv4 overlay addresses are supported" }
        var value = 0L
        for (b in bytes) value = (value shl 8) or (b.toLong() and 0xff)
        val mask = (0xffffffffL shl (32 - prefix)) and 0xffffffffL
        value = value and mask
        return listOf(24, 16, 8, 0).joinToString(".") { shift -> ((value shr shift) and 0xff).toString() }
    }

    private fun notification(): Notification {
        val channelId = "bowie-vpn"
        if (Build.VERSION.SDK_INT >= 26) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(NotificationChannel(channelId, "Bowie VPN", NotificationManager.IMPORTANCE_LOW))
        }
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, channelId) else Notification.Builder(this)
        return builder.setContentTitle("Bowie tunnel")
            .setContentText("Bowie is establishing a peer connection")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .build()
    }

    private fun status(message: String) {
        logEvent("INFO", "SERVICE_STATUS", JSONObject().put("status", message))
        sendBroadcast(Intent(ACTION_STATUS).setPackage(packageName).putExtra("status", message))
    }

    private fun logEvent(level: String, event: String, details: JSONObject = JSONObject()) {
        val record = JSONObject()
            .put("ts", System.currentTimeMillis() / 1000L)
            .put("level", level)
            .put("module", "AndroidService")
            .put("event", event)
            .put("details", details)
        val priority = when (level) {
            "ERROR" -> Log.ERROR
            "WARN" -> Log.WARN
            "DEBUG" -> Log.DEBUG
            else -> Log.INFO
        }
        Log.println(priority, "BowieJSON", record.toString())
    }

    override fun onDestroy() {
        val handle = synchronized(this) {
            stopRequested = true
            if (nativeOperation) 0L else nativeHandle.also { nativeHandle = 0L }
        }
        if (handle != 0L) nativeStop(handle)
        vpnFd?.close()
        worker.shutdownNow()
        stopForeground(STOP_FOREGROUND_REMOVE)
        status("STOPPED")
        super.onDestroy()
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    private fun String.hexToBytes(): ByteArray {
        require(length == 40 && all { it.digitToIntOrNull(16) != null }) { "peer_id must be 40 hex characters" }
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
    private fun String.hexGrantIdToBytes(): ByteArray {
        require(length == 32 && all { it.digitToIntOrNull(16) != null }) { "grant_id must be 32 hex characters" }
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    companion object {
        const val ACTION_STATUS = "org.bowie.STATUS"
        const val ACTION_CONNECT = "org.bowie.CONNECT"
        const val ACTION_ISSUE_GRANT = "org.bowie.ISSUE_GRANT"
        const val ACTION_REVOKE_GRANT = "org.bowie.REVOKE_GRANT"
        const val ACTION_GRANT_READY = "org.bowie.GRANT_READY"
        const val ACTION_STOP = "org.bowie.STOP"
        init { System.loadLibrary("bowie") }
    }
}
