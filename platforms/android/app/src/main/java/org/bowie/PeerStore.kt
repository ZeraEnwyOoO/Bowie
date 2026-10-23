package org.bowie

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject

internal data class BowiePeer(
    val kind: String,
    val name: String,
    val peerId: String,
    val grantWire: String = "",
    val grantId: String = "",
    val revoked: Boolean = false
)

/** App-private peer and local revocation storage. */
internal object PeerStore {
    private const val PREFS = "bowie_peer_store"
    private const val PEERS = "peers"
    private const val REVOKED = "revoked_grant_ids"
    private const val ACTIVE_PEER = "active_peer_id"

    @Synchronized
    fun peers(context: Context): List<BowiePeer> {
        val raw = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(PEERS, "[]") ?: "[]"
        return try {
            val array = JSONArray(raw)
            (0 until array.length()).mapNotNull { index ->
                val item = array.optJSONObject(index) ?: return@mapNotNull null
                val kind = item.optString("kind")
                val peerId = item.optString("peerId").lowercase()
                if ((kind != "connector" && kind != "shared") || !peerId.isPeerId()) return@mapNotNull null
                BowiePeer(kind, item.optString("name", "Peer"), peerId,
                    item.optString("grantWire"), item.optString("grantId"),
                    item.optBoolean("revoked", false))
            }
        } catch (_: Exception) { emptyList() }
    }

    @Synchronized
    fun upsert(context: Context, peer: BowiePeer) {
        val peers = peers(context).filterNot { it.kind == peer.kind && it.peerId == peer.peerId }.toMutableList()
        peers += peer
        writePeers(context, peers)
    }

    @Synchronized
    fun remove(context: Context, kind: String, peerId: String) {
        writePeers(context, peers(context).filterNot { it.kind == kind && it.peerId == peerId })
    }

    @Synchronized
    fun setRevoked(context: Context, grantId: String) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val ids = (prefs.getStringSet(REVOKED, emptySet()) ?: emptySet()).toMutableSet()
        ids += grantId.lowercase()
        prefs.edit().putStringSet(REVOKED, ids).commit()
    }

    fun revokedIds(context: Context): Set<String> =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getStringSet(REVOKED, emptySet())?.toSet() ?: emptySet()

    fun setActivePeer(context: Context, peerId: String?) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(ACTIVE_PEER, peerId.orEmpty().lowercase()).commit()
    }

    fun activePeer(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(ACTIVE_PEER, "").orEmpty()

    fun encodeGrant(wire: ByteArray): String = Base64.encodeToString(wire, Base64.NO_WRAP)
    fun decodeGrant(encoded: String): ByteArray? = try {
        Base64.decode(encoded, Base64.NO_WRAP).takeIf { it.size == 160 }
    } catch (_: IllegalArgumentException) { null }

    private fun writePeers(context: Context, peers: List<BowiePeer>) {
        val array = JSONArray()
        peers.forEach { peer ->
            array.put(JSONObject().put("kind", peer.kind).put("name", peer.name)
                .put("peerId", peer.peerId).put("grantWire", peer.grantWire)
                .put("grantId", peer.grantId).put("revoked", peer.revoked))
        }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(PEERS, array.toString()).commit()
    }

    private fun String.isPeerId(): Boolean = length == 40 && all { it.digitToIntOrNull(16) != null }
}
