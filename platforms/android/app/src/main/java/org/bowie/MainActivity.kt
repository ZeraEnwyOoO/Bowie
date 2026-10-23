package org.bowie

import android.app.Activity
import android.app.AlertDialog
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ClipboardManager
import android.content.ClipData
import android.content.res.ColorStateList
import android.content.pm.ApplicationInfo
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.ColorDrawable
import android.view.View
import android.view.ViewGroup
import android.text.InputType
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.Spinner
import android.widget.ArrayAdapter
import android.widget.ScrollView
import android.widget.TextView
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.textfield.TextInputLayout

class MainActivity : Activity() {
    private lateinit var mode: RadioGroup
    private lateinit var overlay: EditText
    private lateinit var prefix: EditText
    private lateinit var dnsServer: EditText
    private lateinit var peerId: EditText
    private lateinit var grantPeerId: EditText
    private lateinit var grantPeerName: EditText
    private lateinit var grantLifetime: Spinner
    private lateinit var grantDataLimit: Spinner
    private lateinit var grantStatus: TextView
    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var bootstrapHost: EditText
    private lateinit var bootstrapPort: EditText
    private lateinit var stunHost: EditText
    private lateinit var stunPort: EditText
    private lateinit var turnHost: EditText
    private lateinit var turnPort: EditText
    private lateinit var turnUsername: EditText
    private lateinit var turnPassword: EditText
    private lateinit var signalRelayHost: EditText
    private lateinit var signalRelayPort: EditText
    private lateinit var meteredApiKey: EditText
    private lateinit var meteredChannel: EditText
    private lateinit var roomInput: EditText
    private lateinit var roomButton: Button
    private lateinit var grantImportPanel: LinearLayout
    private lateinit var ownerAccessPanel: LinearLayout
    private lateinit var grantImportCard: MaterialCardView
    private lateinit var ownerAccessCard: MaterialCardView
    private lateinit var useDht: CheckBox
    private lateinit var status: TextView
    private lateinit var localPeerId: TextView
    private lateinit var logConsole: TextView
    private lateinit var logScrollView: ScrollView
    private var pendingTestConnect = false
    private var ownerGrantWire: ByteArray? = null
    private var pendingOwnerGrant: ByteArray? = null
    private var pendingConnector: Pair<String, String>? = null
    private var peerListBody: LinearLayout? = null
    private var peerListDialog: AlertDialog? = null
    private lateinit var roleSourceButton: MaterialButton
    private lateinit var roleGuestButton: MaterialButton

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == BowieVpnService.ACTION_GRANT_READY) {
                val grant = intent.getByteArrayExtra("grant_wire")
                if (grant == null || grant.size != 160) {
                    status.text = "Owner grant generation failed."
                } else {
                    pendingOwnerGrant?.fill(0)
                    pendingOwnerGrant = grant
                    val subject = intent.getStringExtra("subject_peer_id") ?:
                        grant.copyOfRange(0, 20).joinToString("") { "%02x".format(it) }
                    val name = intent.getStringExtra("peer_name")?.takeIf { it.isNotBlank() } ?: "Shared peer"
                    val grantId = grant.copyOfRange(52, 68).joinToString("") { "%02x".format(it) }
                    PeerStore.upsert(this@MainActivity, BowiePeer(
                        "shared", name, subject.lowercase(), grantId = grantId))
                    refreshPeerList()
                    val picker = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                        addCategory(Intent.CATEGORY_OPENABLE)
                        type = "application/octet-stream"
                        putExtra(Intent.EXTRA_TITLE, "bowie-${subject.take(10)}.grant")
                    }
                    startActivityForResult(picker, REQUEST_SAVE_OWNER_GRANT)
                }
                return
            }
            val message = intent?.getStringExtra("status") ?: ""
            status.text = when {
                message.startsWith("READY peer=") -> "Bowie is prepared and ready."
                message.startsWith("CONNECTED peer=") -> "Connected. Your tunnel is running."
                message.startsWith("ERROR") -> "Could not complete that action. Open Activity for details."
                message.startsWith("DISCONNECTED") -> "Peer disconnected."
                message == "STOPPED" -> "Bowie is stopped. Your normal connection is restored."
                else -> message
            }
            when {
                message.startsWith("CONNECTED peer=") -> {
                    val id = message.removePrefix("CONNECTED peer=").substringBefore(' ').lowercase()
                    PeerStore.setActivePeer(this@MainActivity, id.takeIf { it.length == 40 })
                }
                message == "STOPPED" || message.startsWith("DISCONNECTED") || message.startsWith("ERROR") ->
                    PeerStore.setActivePeer(this@MainActivity, null)
            }
            if (message.isNotEmpty()) appendLog("SERVICE", message)
            refreshPeerList()
            if (message.startsWith("READY peer=")) {
                val id = message.removePrefix("READY peer=").substringBefore(' ')
                localPeerId.text = "DEVICE CODE  $id"
                if (pendingTestConnect) {
                    pendingTestConnect = false
                    connectPeer()
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildDashboard()
        val filter = IntentFilter(BowieVpnService.ACTION_STATUS).apply {
            addAction(BowieVpnService.ACTION_GRANT_READY)
        }
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(receiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(receiver, filter)
        }
        configureAutomatedTest(intent)
    }

    private fun buildDashboard() {
        initializeAdvancedFields()
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.BLACK) }
        val topBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(10), dp(16), dp(10))
            background = panelBackground(Color.BLACK, Color.rgb(39,39,42))
            addView(TextView(context).apply {
                text = "⌁  BOWIE"; textSize = 13f; typeface = Typeface.MONOSPACE
                setTextColor(Color.WHITE)
            }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(TextView(context).apply {
                text = if (BowieFlavor.GUEST_ONLY) "GUEST CLIENT" else "PRIVATE CONNECTION"
                textSize = 9f; typeface = Typeface.MONOSPACE
                setTextColor(Color.rgb(161, 161, 170))
            }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        }
        root.addView(topBar, LinearLayout.LayoutParams(-1, dp(52)))
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(16), dp(10), dp(16), dp(12)) }
        val scroll = ScrollView(this).apply { isFillViewport = true; addView(content) }
        root.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        content.addView(TextView(this).apply {
            text = "Bowie"
            textSize = 21f; typeface = Typeface.DEFAULT_BOLD; setTextColor(Color.WHITE)
            setPadding(0, dp(4), 0, dp(2))
        }, matchWrap())
        content.addView(TextView(this).apply {
            text = if (BowieFlavor.GUEST_ONLY)
                "Connect to the Linux source that issued your Bowie grant."
            else "Connect through a trusted Bowie peer, or share your connection."
            textSize = 12f; setTextColor(Color.rgb(161, 161, 170)); setPadding(0, 0, 0, dp(10))
        }, matchWrap())

        mode = RadioGroup(this).apply {
            orientation = RadioGroup.HORIZONTAL
            addView(RadioButton(context).apply { id = 1; text = "Share"; visibility = ViewGroup.GONE })
            addView(RadioButton(context).apply { id = 2; text = "Connect"; visibility = ViewGroup.GONE })
            check(2)
        }
        val roleRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; setPadding(dp(4), dp(4), dp(4), dp(4))
            background = panelBackground(Color.rgb(9,9,11), Color.rgb(39,39,42))
        }
        roleSourceButton = MaterialButton(this).apply {
            text = "Share"; isAllCaps = false
            setOnClickListener { mode.check(1); updateRolePanels(1); updateRoleStyle() }
        }
        roleGuestButton = MaterialButton(this).apply {
            text = if (BowieFlavor.GUEST_ONLY) "GUEST CLIENT" else "Connect"
            isAllCaps = false
            setOnClickListener { mode.check(2); updateRolePanels(2); updateRoleStyle() }
        }
        if (BowieFlavor.GUEST_ONLY) roleSourceButton.visibility = View.GONE
        roleRow.addView(roleSourceButton, LinearLayout.LayoutParams(0, dp(46), 1f))
        roleRow.addView(roleGuestButton, LinearLayout.LayoutParams(
            if (BowieFlavor.GUEST_ONLY) ViewGroup.LayoutParams.MATCH_PARENT else 0,
            dp(46), if (BowieFlavor.GUEST_ONLY) 0f else 1f))
        content.addView(roleRow, matchWrap()); content.addView(mode, LinearLayout.LayoutParams(0,0))
        mode.setOnCheckedChangeListener { _, id -> if (::ownerAccessPanel.isInitialized) updateRolePanels(id); updateRoleStyle() }

        status = TextView(this).apply { text = "Ready when you are"; textSize = 13f; setTextColor(Color.rgb(228,228,231)); setPadding(dp(12),dp(8),dp(12),dp(4)) }
        val master = card()
        master.addView(TextView(this).apply { text = "CONNECTION"; textSize = 10f; typeface = Typeface.MONOSPACE; setTextColor(Color.GRAY) }, matchWrap())
        master.addView(status, matchWrap())
        localPeerId = TextView(this).apply {
            text = "DEVICE CODE  — prepare first"; textSize = 10f; typeface = Typeface.MONOSPACE
            setTextColor(Color.LTGRAY); setTextIsSelectable(true); setPadding(0,dp(4),0,0)
            contentDescription = "Your device code. Tap to copy after preparing Bowie."
            setOnClickListener {
                val id = localPeerId.text.toString().removePrefix("DEVICE CODE  ")
                if (id.length == 40) {
                    (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager)
                        .setPrimaryClip(ClipData.newPlainText("Bowie device code", id))
                    status.text = "Device code copied. Share it with your trusted peer."
                } else status.text = "Prepare Bowie to create your device code."
            }
        }
        master.addView(localPeerId, matchWrap())
        content.addView(materialCard(master), cardParams())

        content.addView(MaterialButton(this).apply {
            text = if (BowieFlavor.GUEST_ONLY) "SOURCES & GRANTS" else "YOUR PEERS"
            isAllCaps = false
            setOnClickListener { showPeerList() }
        }, buttonParams())
        if (BowieFlavor.GUEST_ONLY) content.addView(TextView(this).apply {
            text = "Prepare first and share your device code with the Linux owner. Then add their peer ID and import the .grant file they issue to you."
            textSize = 11f; setTextColor(Color.rgb(161, 161, 170))
            setPadding(dp(4), 0, dp(4), dp(4))
        }, matchWrap())

        grantImportPanel = card()
        grantStatus = TextView(this).apply { text = "No owner grant selected"; textSize = 11f; typeface = Typeface.MONOSPACE; setTextColor(Color.LTGRAY) }
        grantImportPanel.addView(TextView(this).apply { text = "SOURCE AUTHORIZATION"; textSize = 11f; typeface = Typeface.MONOSPACE; setTextColor(Color.WHITE) }, matchWrap())
        grantImportPanel.addView(MaterialButton(this).apply {
            text = "Choose Owner Grant File (.grant)"; isAllCaps = false
            setOnClickListener { val picker = Intent(Intent.ACTION_OPEN_DOCUMENT).apply { addCategory(Intent.CATEGORY_OPENABLE); type = "*/*" }; startActivityForResult(picker, REQUEST_OWNER_GRANT) }
        }, buttonParams())
        grantImportPanel.addView(grantStatus, matchWrap())
        grantImportCard = materialCard(grantImportPanel)
        // Role-specific forms stay out of the everyday dashboard. Peer List owns these actions.

        ownerAccessPanel = card()
        ownerAccessPanel.addView(TextView(this).apply { text = "OWNER ACCESS"; textSize = 11f; typeface = Typeface.MONOSPACE; setTextColor(Color.WHITE) }, matchWrap())
        grantPeerName = field("Guest name", "")
        ownerAccessPanel.addView(inputLayout("Guest name", grantPeerName), matchWrap())
        ownerAccessPanel.addView(TextView(this).apply {
            text = "Grant access for"
            textSize = 12f; setTextColor(Color.LTGRAY); setPadding(0, dp(8), 0, dp(2))
        }, matchWrap())
        grantLifetime = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item,
                listOf("1 hour", "6 hours", "24 hours", "7 days", "30 days"))
            setSelection(4)
        }
        ownerAccessPanel.addView(grantLifetime, matchWrap())
        ownerAccessPanel.addView(TextView(this).apply {
            text = "Per-grant source data limit"
            textSize = 12f; setTextColor(Color.LTGRAY); setPadding(0, dp(8), 0, dp(2))
        }, matchWrap())
        grantDataLimit = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item,
                listOf("100 MB", "500 MB", "1 GB", "5 GB", "No data limit"))
            setSelection(0)
        }
        ownerAccessPanel.addView(grantDataLimit, matchWrap())
        ownerAccessPanel.addView(TextView(this).apply {
            text = "BYOT TURN: relay traffic uses the TURN account configured in Settings and may be billed by that provider. The grant cap counts source gateway packet bytes; TURN provider billing can include protocol overhead. Reaching the cap disconnects the peer."
            textSize = 11f; setTextColor(Color.rgb(245, 190, 120)); setPadding(0, dp(6), 0, dp(4))
        }, matchWrap())
        grantPeerId = field("Guest peer ID (40 hex)", "")
        ownerAccessPanel.addView(inputLayout("Guest peer ID", grantPeerId), matchWrap())
        ownerAccessPanel.addView(MaterialButton(this).apply {
            text = "Issue Owner Grant"; isAllCaps = false
            setOnClickListener {
                val subject = grantPeerId.text.toString().trim()
                if (subject.length != 40 || subject.any { it.digitToIntOrNull(16) == null }) status.text = "Enter the guest peer ID."
                else if (localPeerId.text.toString().contains("prepare first")) status.text = "Prepare Bowie first to create your device code."
                else {
                    val ttlMs = when (grantLifetime.selectedItemPosition) {
                        0 -> 60L * 60L * 1000L
                        1 -> 6L * 60L * 60L * 1000L
                        2 -> 24L * 60L * 60L * 1000L
                        3 -> 7L * 24L * 60L * 60L * 1000L
                        else -> 30L * 24L * 60L * 60L * 1000L
                    }
                    val dataLimitBytes = when (grantDataLimit.selectedItemPosition) {
                        0 -> 100_000_000L
                        1 -> 500_000_000L
                        2 -> 1_000_000_000L
                        3 -> 5_000_000_000L
                        else -> 0L
                    }
                    startService(Intent(this@MainActivity, BowieVpnService::class.java)
                        .setAction(BowieVpnService.ACTION_ISSUE_GRANT)
                        .putExtra("subject_peer_id", subject)
                        .putExtra("grant_ttl_ms", ttlMs)
                        .putExtra("grant_data_limit_bytes", dataLimitBytes)
                        .putExtra("peer_name", grantPeerName.text.toString().trim().ifBlank { "Shared peer" }))
                    status.text = "Signing peer-specific grant…"
                }
            }
        }, buttonParams())
        ownerAccessCard = materialCard(ownerAccessPanel)
        updateRolePanels(mode.checkedRadioButtonId)

        roomInput = field("Shared room name", getSharedPreferences(SETTINGS_PREFS, MODE_PRIVATE)
            .getString("room", "bowie-test-room") ?: "bowie-test-room")
        val roomCard = card()
        roomCard.addView(TextView(this).apply { text = "DHT ROOM"; textSize = 11f; typeface = Typeface.MONOSPACE; setTextColor(Color.WHITE) }, matchWrap())
        roomCard.addView(inputLayout("Room name", roomInput), matchWrap())
        roomCard.addView(MaterialButton(this).apply {
            text = "DISCOVER / ANNOUNCE ROOM"; isAllCaps = false
            setOnClickListener { startRoomFlow() }
        }, buttonParams())
        // Room discovery is an advanced flow and stays reachable from Advanced Settings.

        content.addView(MaterialButton(this).apply {
            text = "PREPARE BOWIE"; isAllCaps = false; textSize = 14f
            setOnClickListener { requestVpn() }
        }, buttonParams())
        roomButton = MaterialButton(this).apply {
            text = "START TUNNEL"; isAllCaps = false; textSize = 14f
            setOnClickListener {
                if (mode.checkedRadioButtonId == 1) startRoomFlow() else showPeerList()
            }
        }
        content.addView(roomButton, buttonParams())
        if (BowieFlavor.GUEST_ONLY) content.addView(MaterialButton(this).apply {
            text = "JOIN DHT ROOM"; isAllCaps = false
            setOnClickListener { startRoomFlow() }
        }, buttonParams())
        content.addView(MaterialButton(this).apply { text = "STOP"; isAllCaps = false; setOnClickListener { startService(Intent(this@MainActivity, BowieVpnService::class.java).setAction(BowieVpnService.ACTION_STOP)) } }, buttonParams())

        val utilityRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        utilityRow.addView(MaterialButton(this).apply { text = "Activity"; isAllCaps = false; setOnClickListener { showActivityLog() } }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        utilityRow.addView(MaterialButton(this).apply { text = "Settings"; isAllCaps = false; setOnClickListener { showAdvancedSettings() } }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        content.addView(utilityRow, buttonParams())
        logConsole = TextView(this).apply { text = "[ENGINE] Bowie is ready."; textSize = 10f; typeface = Typeface.MONOSPACE; setTextColor(Color.rgb(190,190,196)); setTextIsSelectable(true); setPadding(dp(10),dp(10),dp(10),dp(10)); background = panelBackground(Color.BLACK, Color.rgb(39,39,42)) }
        logScrollView = ScrollView(this).apply { addView(logConsole) }

        mode.setOnCheckedChangeListener { _, id ->
            roomButton.text = if (id == 1) "START SHARING" else "START TUNNEL"
            updateRolePanels(id); updateRoleStyle()
        }
        updateRolePanels(mode.checkedRadioButtonId); updateRoleStyle()
        setContentView(root)
    }

    private fun card() = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(12),dp(10),dp(12),dp(10)); background = panelBackground(Color.rgb(18,18,21), Color.rgb(39,39,42)) }
    private fun materialCard(body: View) = MaterialCardView(this).apply {
        radius = dp(12).toFloat(); cardElevation = 0f; strokeWidth = dp(1)
        strokeColor = Color.rgb(39,39,42); setCardBackgroundColor(Color.rgb(18,18,21)); addView(body)
    }
    private fun cardParams() = LinearLayout.LayoutParams(-1, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(8) }
    private fun inputLayout(label: String, input: EditText) = TextInputLayout(this).apply {
        val strokeColors = ColorStateList(
            arrayOf(intArrayOf(android.R.attr.state_focused), intArrayOf()),
            intArrayOf(Color.WHITE, Color.rgb(82, 82, 91)))
        hint = label
        setDefaultHintTextColor(ColorStateList.valueOf(Color.rgb(190, 190, 196)))
        boxBackgroundMode = TextInputLayout.BOX_BACKGROUND_OUTLINE
        setBoxBackgroundColor(Color.rgb(24, 24, 27))
        setBoxCornerRadii(dp(8).toFloat(),dp(8).toFloat(),dp(8).toFloat(),dp(8).toFloat())
        setBoxStrokeColorStateList(strokeColors)
        addView(input, LinearLayout.LayoutParams(-1, dp(48)))
    }
    private fun updateRoleStyle() {
        if (!::roleSourceButton.isInitialized) return
        val source = mode.checkedRadioButtonId == 1
        roleSourceButton.backgroundTintList = android.content.res.ColorStateList.valueOf(if (source) Color.WHITE else Color.rgb(39,39,42))
        roleSourceButton.setTextColor(if (source) Color.BLACK else Color.LTGRAY)
        roleGuestButton.backgroundTintList = android.content.res.ColorStateList.valueOf(if (!source) Color.WHITE else Color.rgb(39,39,42))
        roleGuestButton.setTextColor(if (!source) Color.BLACK else Color.LTGRAY)
    }

    private fun showAdvancedSettings() {
        val panel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(6), dp(12), dp(12))
        }
        var currentGroup: LinearLayout? = null
        fun settingRow(vararg values: Pair<String, EditText>) {
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            values.forEachIndexed { index, (label, edit) ->
                (edit.parent as? ViewGroup)?.removeView(edit)
                edit.hint = null
                val input = inputLayout(label, edit)
                val params = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                if (index > 0) params.marginStart = dp(8)
                row.addView(input, params)
            }
            (currentGroup ?: panel).addView(row, matchWrap())
        }
        fun section(title: String, caption: String, content: () -> Unit) {
            val card = card().apply {
                addView(TextView(this@MainActivity).apply {
                    text = title; textSize = 12f; typeface = Typeface.MONOSPACE
                    setTextColor(Color.WHITE); setPadding(0, 0, 0, dp(2))
                }, matchWrap())
                addView(TextView(this@MainActivity).apply {
                    text = caption; textSize = 10f; setTextColor(Color.rgb(161, 161, 170))
                    setPadding(0, 0, 0, dp(8))
                }, matchWrap())
            }
            val groupBody = card
            currentGroup = groupBody
            content()
            currentGroup = null
            panel.addView(materialCard(groupBody), cardParams())
        }
        if (!::overlay.isInitialized) initializeAdvancedFields()

        section("CONNECTION", "Peer identity and signaling path") {
            (useDht.parent as? ViewGroup)?.removeView(useDht)
            useDht.text = "Find peer by DHT when no signal relay is set"
            useDht.textSize = 11f
            (currentGroup ?: panel).addView(useDht, matchWrap())
            settingRow("Expected peer ID" to peerId)
            settingRow("Direct peer IPv4" to host, "Signal UDP port" to port)
            settingRow("DHT room name" to roomInput)
            settingRow("DHT bootstrap host" to bootstrapHost, "UDP port" to bootstrapPort)
            settingRow("Signal relay host" to signalRelayHost, "UDP port" to signalRelayPort)
            settingRow("Metered API Key" to meteredApiKey)
            settingRow("Metered Channel" to meteredChannel)
        }
        section("TUNNEL", "Applied when preparing the VPN; full routing starts after connection") {
            settingRow("Overlay IPv4" to overlay, "Prefix" to prefix)
            settingRow("Guest DNS resolver" to dnsServer)
        }
        section("NAT TRAVERSAL · BYOT", "Bring your own STUN/TURN provider. TURN relay traffic is billed by that provider and consumes its quota; configure only a provider/account you control.") {
            settingRow("STUN host" to stunHost, "UDP port" to stunPort)
            settingRow("TURN host" to turnHost, "UDP port" to turnPort)
            settingRow("TURN username" to turnUsername, "TURN password" to turnPassword)
        }

        val scroll = ScrollView(this).apply { isFillViewport = false; addView(panel) }
        val dialog = android.app.AlertDialog.Builder(this)
            .setTitle(if (BowieFlavor.GUEST_ONLY) "Guest Connection Settings" else "Connection & VPN Settings")
            .setView(scroll)
            .setPositiveButton("Done", null)
            .create()
        dialog.show()
        dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE)?.setOnClickListener {
            saveConnectionSettings()
            dialog.dismiss()
        }
        dialog.window?.setBackgroundDrawable(ColorDrawable(Color.rgb(9, 9, 11)))
        dialog.window?.setLayout((resources.displayMetrics.widthPixels * 0.94f).toInt(),
            (resources.displayMetrics.heightPixels * 0.82f).toInt())
        dialog.findViewById<TextView>(android.R.id.title)?.setTextColor(Color.WHITE)
        dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE)?.setTextColor(Color.WHITE)
    }

    private fun showActivityLog() {
        val log = TextView(this).apply {
            text = logConsole.text
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.rgb(212, 212, 216))
            setTextIsSelectable(true)
            setPadding(dp(12), dp(12), dp(12), dp(12))
            background = panelBackground(Color.BLACK, Color.rgb(39, 39, 42))
        }
        val scroll = ScrollView(this).apply { addView(log) }
        AlertDialog.Builder(this).setTitle("Activity").setView(scroll)
            .setPositiveButton("DONE", null).show().apply {
                window?.setBackgroundDrawable(ColorDrawable(Color.rgb(9, 9, 11)))
                findViewById<TextView>(android.R.id.title)?.setTextColor(Color.WHITE)
                getButton(AlertDialog.BUTTON_POSITIVE)?.setTextColor(Color.WHITE)
            }
    }

    private fun initializeAdvancedFields() {
        if (::overlay.isInitialized) return
        val prefs = getSharedPreferences(SETTINGS_PREFS, MODE_PRIVATE)
        fun saved(key: String, default: String = "") = prefs.getString(key, default) ?: default
        overlay = field("Overlay IPv4", saved("overlay", "10.77.0.2")); prefix = field("Overlay prefix", saved("prefix", "24")); dnsServer = field("DNS resolver IPv4", saved("dns", "1.1.1.1"))
        peerId = field("Expected peer ID (40 hex)", saved("peer_id")); host = field("Peer IPv4", saved("host")); port = field("Peer signal port", saved("port"))
        bootstrapHost = field("DHT bootstrap host", saved("bootstrap_host")); bootstrapPort = field("DHT bootstrap UDP port", saved("bootstrap_port"))
        stunHost = field("STUN host", saved("stun_host")); stunPort = field("STUN UDP port", saved("stun_port"))
        turnHost = field("TURN host", saved("turn_host")); turnPort = field("TURN UDP port", saved("turn_port")); turnUsername = field("TURN username", saved("turn_username")); turnPassword = field("TURN password", saved("turn_password")).apply { inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD }
        signalRelayHost = field("Signal Relay host", saved("signal_relay_host")); signalRelayPort = field("Signal Relay UDP port", saved("signal_relay_port"))
        meteredApiKey = field("Metered API Key (publishable)", saved("metered_api_key"))
        meteredChannel = field("Metered Channel", saved("metered_channel"))
        useDht = CheckBox(this).apply { text = "Use DHT peer lookup"; isChecked = true; setTextColor(Color.WHITE) }
    }

    private fun saveConnectionSettings() {
        if (!::overlay.isInitialized || !::roomInput.isInitialized) return
        getSharedPreferences(SETTINGS_PREFS, MODE_PRIVATE).edit()
            .putString("overlay", overlay.text.toString())
            .putString("prefix", prefix.text.toString())
            .putString("dns", dnsServer.text.toString())
            .putString("peer_id", peerId.text.toString())
            .putString("host", host.text.toString())
            .putString("port", port.text.toString())
            .putString("bootstrap_host", bootstrapHost.text.toString())
            .putString("bootstrap_port", bootstrapPort.text.toString())
            .putString("stun_host", stunHost.text.toString())
            .putString("stun_port", stunPort.text.toString())
            .putString("turn_host", turnHost.text.toString())
            .putString("turn_port", turnPort.text.toString())
            .putString("turn_username", turnUsername.text.toString())
            .putString("turn_password", turnPassword.text.toString())
            .putString("signal_relay_host", signalRelayHost.text.toString())
            .putString("signal_relay_port", signalRelayPort.text.toString())
            .putString("metered_api_key", meteredApiKey.text.toString())
            .putString("metered_channel", meteredChannel.text.toString())
            .putString("room", roomInput.text.toString())
            .apply()
    }

    private fun configureAutomatedTest(intent: Intent?) {
        if (BowieFlavor.GUEST_ONLY) return
        if (applicationInfo.flags.and(ApplicationInfo.FLAG_DEBUGGABLE) == 0) return
        if (intent?.action == ACTION_TEST_STOP) {
            startService(Intent(this, BowieVpnService::class.java)
                .setAction(BowieVpnService.ACTION_STOP))
            return
        }
        val testAction = intent?.action
        if (testAction != ACTION_TEST_PREPARE && testAction != ACTION_TEST_CONNECT) return
        val remotePeer = intent.getStringExtra("peer_id") ?: return
        val remoteHost = intent.getStringExtra("host") ?: return
        val remotePort = intent.getIntExtra("port", 0)
        if (remotePeer.length != 40 || remotePort !in 1..65535) return

        mode.check(2)
        overlay.setText(intent.getStringExtra("overlay_ip") ?: "10.77.0.2")
        prefix.setText("24")
        dnsServer.setText(intent.getStringExtra("dns_server") ?: "1.1.1.1")
        peerId.setText(remotePeer)
        ownerGrantWire?.fill(0)
        ownerGrantWire = intent.getStringExtra("owner_grant")?.hexToBytesOrNull()
        grantStatus.text = if (ownerGrantWire?.size == 160) {
            "Owner grant loaded for test"
        } else {
            "No owner grant selected"
        }
        host.setText(remoteHost)
        port.setText(remotePort.toString())
        intent.getStringExtra("relay_host")?.let { relayHost ->
            signalRelayHost.setText(relayHost)
            signalRelayPort.setText(intent.getIntExtra("relay_port", 0).toString())
        }
        intent.getStringExtra("metered_api_key")?.let { meteredApiKey.setText(it) }
        intent.getStringExtra("metered_channel")?.let { meteredChannel.setText(it) }
        intent.getStringExtra("stun_host")?.let { stunHost.setText(it) }
        if (intent.hasExtra("stun_port")) stunPort.setText(intent.getIntExtra("stun_port", 0).takeIf { it > 0 }?.toString() ?: "")
        intent.getStringExtra("turn_host")?.let { turnHost.setText(it) }
        if (intent.hasExtra("turn_port")) turnPort.setText(intent.getIntExtra("turn_port", 0).takeIf { it > 0 }?.toString() ?: "")
        intent.getStringExtra("turn_username")?.let { turnUsername.setText(it) }
        intent.getStringExtra("turn_password")?.let { turnPassword.setText(it) }
        if (testAction == ACTION_TEST_PREPARE) {
            pendingTestConnect = false
            requestVpn()
        } else {
            connectPeer()
        }
    }

    private fun field(label: String, initial: String): EditText = EditText(this).apply {
        hint = label
        setText(initial)
        isSingleLine = true
        textSize = 14f
        typeface = Typeface.MONOSPACE
        setTextColor(Color.rgb(244, 244, 245))
        setHintTextColor(Color.rgb(113, 113, 122))
        setPadding(dp(12), dp(5), dp(12), dp(5))
        background = panelBackground(Color.rgb(24, 24, 27), Color.rgb(39, 39, 42))
    }

    private fun sectionTitle(value: String) = TextView(this).apply {
        text = value
        textSize = 12f
        typeface = Typeface.create("monospace", Typeface.BOLD)
        setTextColor(Color.rgb(245, 245, 245))
        setPadding(0, dp(18), 0, dp(4))
    }

    private fun fieldLabel(value: String) = TextView(this).apply {
        text = value
        textSize = 10f
        letterSpacing = 0.1f
        typeface = Typeface.MONOSPACE
        setTextColor(Color.rgb(161, 161, 170))
        setPadding(dp(2), dp(7), 0, 0)
    }

    private fun panelBackground(fill: Int, stroke: Int) = GradientDrawable().apply {
        setColor(fill)
        setStroke(dp(1), stroke)
        cornerRadius = dp(8).toFloat()
    }

    private fun buttonParams() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
        topMargin = dp(6)
        bottomMargin = dp(2)
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun matchWrap() = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)

    private fun requestVpn() {
        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent != null) startActivityForResult(permissionIntent, REQUEST_VPN)
        else startSession()
    }

    @Deprecated("Activity result API compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_OWNER_GRANT) {
            if (resultCode == RESULT_OK) loadOwnerGrant(data)
            else pendingConnector = null
        } else if (requestCode == REQUEST_SAVE_OWNER_GRANT) {
            saveOwnerGrant(data, resultCode)
        } else if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            startSession()
        } else if (requestCode == REQUEST_VPN) {
            status.text = "VPN permission is required."
        }
    }

    private fun startSession() {
        val clientMode = mode.checkedRadioButtonId == 2
        val dnsText = dnsServer.text.toString().trim()
        if (clientMode && !isNumericIpv4(dnsText)) {
            status.text = "CONNECT mode needs a numeric IPv4 DNS resolver."
            return
        }
        val bootstrapHostText = bootstrapHost.text.toString().trim()
        val parsedBootstrapPort = bootstrapPort.text.toString().toIntOrNull() ?: 0
        if ((bootstrapHostText.isEmpty() && parsedBootstrapPort != 0) ||
            (bootstrapHostText.isNotEmpty() && parsedBootstrapPort !in 1..65535)) {
            status.text = "Enter both a bootstrap host and UDP port, or leave both blank."
            return
        }
        val turnHostText = turnHost.text.toString().trim()
        val parsedTurnPort = turnPort.text.toString().toIntOrNull() ?: 0
        val turnUserText = turnUsername.text.toString()
        val turnPasswordText = turnPassword.text.toString()
        if ((turnHostText.isEmpty() && parsedTurnPort != 0) ||
            (turnHostText.isNotEmpty() && parsedTurnPort !in 1..65535)) {
            status.text = "Enter both a TURN host and port, or leave both blank."
            return
        }
        if (turnHostText.isEmpty() && (turnUserText.isNotEmpty() || turnPasswordText.isNotEmpty())) {
            status.text = "Enter a TURN host before adding credentials."
            return
        }
        if (turnUserText.isEmpty() != turnPasswordText.isEmpty()) {
            status.text = "Enter both TURN username and password, or leave both blank."
            return
        }
        val stunHostText = stunHost.text.toString().trim()
        val parsedStunPort = stunPort.text.toString().toIntOrNull() ?: 0
        if ((stunHostText.isEmpty() && parsedStunPort != 0) ||
            (stunHostText.isNotEmpty() && parsedStunPort !in 1..65535)) {
            status.text = "Enter both a STUN host and port, or leave both blank."
            return
        }
        val relayHostText = signalRelayHost.text.toString().trim()
        val parsedRelayPort = signalRelayPort.text.toString().toIntOrNull() ?: 0
        if ((relayHostText.isEmpty() && parsedRelayPort != 0) ||
            (relayHostText.isNotEmpty() && parsedRelayPort !in 1..65535)) {
            status.text = "Enter both a signal relay host and UDP port, or leave both blank."
            return
        }
        val meteredApiKeyText = meteredApiKey.text.toString().trim()
        val meteredChannelText = meteredChannel.text.toString().trim()
        if (meteredApiKeyText.isEmpty() != meteredChannelText.isEmpty()) {
            status.text = "Enter both the Metered API key and channel, or leave both blank."
            return
        }
        if (meteredApiKeyText.isNotEmpty() && relayHostText.isNotEmpty()) {
            status.text = "Use either Metered messaging or the UDP signal relay, not both."
            return
        }
        val intent = Intent(this, BowieVpnService::class.java)
            .putExtra("overlay_ip", overlay.text.toString().trim())
            .putExtra("prefix", prefix.text.toString().toIntOrNull() ?: 24)
            .putExtra("client_mode", clientMode)
            .putExtra("dns_server", dnsText)
            .putExtra("bootstrap_host", bootstrapHostText)
            .putExtra("bootstrap_port", parsedBootstrapPort)
            .putExtra("stun_host", stunHostText)
            .putExtra("stun_port", parsedStunPort)
            .putExtra("turn_host", turnHostText)
            .putExtra("turn_port", parsedTurnPort)
            .putExtra("turn_username", turnUserText)
            .putExtra("turn_password", turnPasswordText)
            .putExtra("signal_relay_host", relayHostText)
            .putExtra("signal_relay_port", parsedRelayPort)
            .putExtra("signal_metered_api_key", meteredApiKeyText)
            .putExtra("signal_metered_channel", meteredChannelText)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
        status.text = "Starting VPN and Bowie engine…"
    }

    private fun isNumericIpv4(value: String): Boolean {
        val parts = value.split('.')
        return parts.size == 4 && parts.all {
            it.isNotEmpty() && it.length <= 3 && it.all { digit -> digit in '0'..'9' } &&
                it.toIntOrNull()?.let { octet -> octet in 0..255 } == true
        }
    }

    private fun connectPeer() {
        val peer = peerId.text.toString().trim()
        if (peer.length != 40 || peer.any { it.digitToIntOrNull(16) == null }) {
            status.text = "Enter the expected peer ID (40 hexadecimal characters)."
            return
        }
        val listening = mode.checkedRadioButtonId == 1
        val relayHost = signalRelayHost.text.toString().trim()
        val useMetered = meteredApiKey.text.toString().trim().isNotEmpty() &&
            meteredChannel.text.toString().trim().isNotEmpty()
        // An explicit peer plus relay uses the relay for this signaling offer.
        val useDhtForPeer = !listening && relayHost.isEmpty() && !useMetered && useDht.isChecked
        var grantBytes = ownerGrantWire
        if (!listening && (grantBytes == null || grantBytes.size != 160)) {
            val selectedOwner = peerId.text.toString().trim().lowercase()
            val savedSources = PeerStore.peers(this).filter { it.kind == "connector" }
            val savedSource = savedSources.firstOrNull { it.peerId == selectedOwner }
                ?: savedSources.singleOrNull()
            grantBytes = savedSource?.let { PeerStore.decodeGrant(it.grantWire) }
            if (grantBytes != null) {
                ownerGrantWire?.fill(0)
                ownerGrantWire = grantBytes
            }
        }
        if (!listening && (grantBytes == null || grantBytes.size != 160)) {
            status.text = "Choose the owner-issued .grant file before connecting."
            return
        }
        if (useDhtForPeer) {
            val bootstrap = bootstrapHost.text.toString().trim()
            val bootstrapUdpPort = bootstrapPort.text.toString().toIntOrNull()
            if (bootstrap.isEmpty() || bootstrapUdpPort == null || bootstrapUdpPort !in 1..65535) {
                status.text = "DHT lookup needs a bootstrap host and UDP port."
                return
            }
        } else if (!listening && relayHost.isEmpty() && !useMetered) {
            val parsedPort = port.text.toString().toIntOrNull()
            if (parsedPort == null || parsedPort !in 1..65535) {
                status.text = "Enter the listener signal port (1–65535)."
                return
            }
        }
        val intent = Intent(this, BowieVpnService::class.java)
            .setAction(BowieVpnService.ACTION_CONNECT)
            .putExtra("mode", if (listening) "listen" else "connect")
            .putExtra("use_dht", useDhtForPeer)
            .putExtra("use_signal_relay", !listening && (relayHost.isNotEmpty() || useMetered))
            .putExtra("overlay_ip", overlay.text.toString().trim())
            .putExtra("peer_id", peer)
            .putExtra("owner_grant", grantBytes ?: ByteArray(0))
            .putExtra("host", host.text.toString().trim())
            .putExtra("port", port.text.toString().toIntOrNull() ?: 0)
        startService(intent)
        appendLog("CONNECT", if (listening) "Waiting for peer $peer" else
            "Connecting to $peer via ${if (useMetered) "Metered" else if (relayHost.isNotEmpty()) "signal relay" else if (useDhtForPeer) "DHT" else "direct UDP"}")
        status.text = "Connecting…"
    }

    private fun startRoomFlow() {
        val room = roomInput.text.toString().trim()
        if (room.isEmpty() || room.length >= 256) {
            status.text = "Enter a room name between 1 and 255 characters."
            return
        }
        val bootstrap = bootstrapHost.text.toString().trim()
        val bootstrapUdpPort = bootstrapPort.text.toString().toIntOrNull()
        if (bootstrap.isEmpty() || bootstrapUdpPort == null || bootstrapUdpPort !in 1..65535) {
            status.text = "DHT room flow needs a bootstrap host and UDP port."
            return
        }
        if (localPeerId.text.toString().contains("prepare first")) {
            status.text = "Prepare the VPN before announcing or joining a room."
            return
        }
        val client = mode.checkedRadioButtonId == 2
        var grantBytes = ownerGrantWire
        if (client && (grantBytes == null || grantBytes.size != 160)) {
            val selectedOwner = peerId.text.toString().trim().lowercase()
            val savedSources = PeerStore.peers(this).filter { it.kind == "connector" }
            val savedSource = savedSources.firstOrNull { it.peerId == selectedOwner }
                ?: savedSources.singleOrNull()
            grantBytes = savedSource?.let { PeerStore.decodeGrant(it.grantWire) }
            if (grantBytes != null) {
                ownerGrantWire?.fill(0)
                ownerGrantWire = grantBytes
            }
        }
        if (client && (grantBytes == null || grantBytes.size != 160)) {
            status.text = "Choose the source owner's .grant file before connecting."
            return
        }
        if (client && !isNumericIpv4(dnsServer.text.toString().trim())) {
            status.text = "Guest client mode needs a numeric IPv4 DNS resolver."
            return
        }
        val flow = if (client) "room_connect" else "room_wait"
        val intent = Intent(this, BowieVpnService::class.java)
            .setAction(BowieVpnService.ACTION_CONNECT)
            .putExtra("mode", flow)
            .putExtra("use_dht", true)
            .putExtra("room", room)
            .putExtra("owner_grant", grantBytes ?: ByteArray(0))
            .putExtra("peer_id", "")
        startService(intent)
        status.text = if (client) "Searching DHT room and connecting…" else "Announcing room; waiting for a granted guest…"
        appendLog("DHT", if (client) "Searching room: $room" else "Announcing room and waiting: $room")
    }

    private fun showPeerList() {
        val shell = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(12))
            setBackgroundColor(Color.rgb(9, 9, 11))
        }
        val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        actions.addView(MaterialButton(this).apply {
            text = if (BowieFlavor.GUEST_ONLY) "ADD LINUX SOURCE" else "ADD CONNECTOR"
            isAllCaps = false
            setOnClickListener { showAddConnectorDialog() }
        }, LinearLayout.LayoutParams(if (BowieFlavor.GUEST_ONLY) -1 else 0, dp(48), if (BowieFlavor.GUEST_ONLY) 0f else 1f))
        if (!BowieFlavor.GUEST_ONLY) actions.addView(MaterialButton(this).apply {
            text = "SHARE ACCESS"; isAllCaps = false
            setOnClickListener { showAddSharedPeerDialog() }
        }, LinearLayout.LayoutParams(0, dp(48), 1f))
        shell.addView(actions, matchWrap())
        val scroll = ScrollView(this)
        val body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        scroll.addView(body)
        shell.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        peerListBody = body
        peerListDialog = AlertDialog.Builder(this)
            .setTitle(if (BowieFlavor.GUEST_ONLY) "SOURCES & GRANTS" else "PEERS")
            .setView(shell)
            .setNegativeButton("DONE", null)
            .create()
        peerListDialog?.setOnDismissListener { peerListBody = null; peerListDialog = null }
        peerListDialog?.show()
        peerListDialog?.window?.setBackgroundDrawable(ColorDrawable(Color.rgb(9, 9, 11)))
        peerListDialog?.window?.setLayout((resources.displayMetrics.widthPixels * 0.96f).toInt(),
            (resources.displayMetrics.heightPixels * 0.88f).toInt())
        refreshPeerList()
    }

    private fun refreshPeerList() {
        val body = peerListBody ?: return
        if (peerListDialog?.isShowing != true) return
        body.removeAllViews()
        val peers = PeerStore.peers(this)
        val activePeer = PeerStore.activePeer(this)
        addPeerSection(body,
            if (BowieFlavor.GUEST_ONLY) "LINUX SOURCES" else "CONNECTORS",
            if (BowieFlavor.GUEST_ONLY) "Sources you are authorized to connect to" else "Owners you can connect to",
            peers.filter { it.kind == "connector" }, activePeer)
        if (!BowieFlavor.GUEST_ONLY) addPeerSection(body, "SHARED", "Guests you have granted access",
            peers.filter { it.kind == "shared" }, activePeer)
    }

    private fun addPeerSection(parent: LinearLayout, title: String, subtitle: String,
                               peers: List<BowiePeer>, activePeer: String) {
        parent.addView(TextView(this).apply {
            text = "$title  ·  ${peers.size}\n$subtitle"
            textSize = 12f; typeface = Typeface.MONOSPACE; setTextColor(Color.WHITE)
            setPadding(dp(2), dp(16), dp(2), dp(6))
        }, matchWrap())
        if (peers.isEmpty()) {
            parent.addView(TextView(this).apply {
                text = "No peers saved"; textSize = 12f; setTextColor(Color.rgb(161, 161, 170))
                setPadding(dp(10), dp(10), dp(10), dp(10))
            }, matchWrap())
            return
        }
        peers.forEach { peer ->
            val row = card()
            val connected = peer.peerId == activePeer
            val state = when {
                peer.kind == "shared" && peer.revoked -> "ACCESS REVOKED"
                connected -> "CONNECTED"
                peer.kind == "shared" -> "GRANT ACTIVE · DISCONNECTED"
                else -> "DISCONNECTED"
            }
            val stateColor = when {
                peer.revoked -> Color.rgb(239, 68, 68)
                connected -> Color.rgb(74, 222, 128)
                peer.kind == "shared" -> Color.rgb(228, 228, 231)
                else -> Color.rgb(239, 68, 68)
            }
            row.addView(TextView(this).apply {
                text = peer.name.ifBlank { "Bowie peer" }; textSize = 15f
                typeface = Typeface.DEFAULT_BOLD; setTextColor(Color.WHITE)
            }, matchWrap())
            row.addView(TextView(this).apply {
                text = state; textSize = 10f; typeface = Typeface.MONOSPACE
                setTextColor(stateColor); setPadding(0, dp(3), 0, dp(3))
            }, matchWrap())
            row.addView(TextView(this).apply {
                text = "${peer.peerId.take(12)}…${peer.peerId.takeLast(6)}"
                textSize = 10f; typeface = Typeface.MONOSPACE; setTextColor(Color.rgb(161, 161, 170))
            }, matchWrap())
            val buttons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            if (peer.kind == "connector") {
                buttons.addView(MaterialButton(this).apply {
                    text = if (connected) "DISCONNECT" else "CONNECT"; isAllCaps = false
                    setOnClickListener {
                        if (connected) startService(Intent(this@MainActivity, BowieVpnService::class.java)
                            .setAction(BowieVpnService.ACTION_STOP))
                        else connectSavedPeer(peer)
                    }
                }, LinearLayout.LayoutParams(0, dp(44), 1f))
            } else if (!peer.revoked) {
                buttons.addView(MaterialButton(this).apply {
                    text = "REVOKE ACCESS"; isAllCaps = false
                    setOnClickListener { confirmRevoke(peer) }
                }, LinearLayout.LayoutParams(0, dp(44), 1f))
            }
            buttons.addView(MaterialButton(this).apply {
                text = "REMOVE"; isAllCaps = false
                setOnClickListener {
                    PeerStore.remove(this@MainActivity, peer.kind, peer.peerId)
                    refreshPeerList()
                }
            }, LinearLayout.LayoutParams(0, dp(44), 1f))
            row.addView(buttons, matchWrap())
            parent.addView(materialCard(row), cardParams())
        }
    }

    private fun showAddConnectorDialog() {
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(8), dp(12), 0)
        }
        val name = field("Name", "")
        val id = field(if (BowieFlavor.GUEST_ONLY) "Linux source peer ID (40 hex)" else "Owner peer ID (40 hex)", "")
        form.addView(inputLayout("Name", name), matchWrap())
        form.addView(inputLayout(if (BowieFlavor.GUEST_ONLY) "Linux source peer ID" else "Owner peer ID", id), matchWrap())
        val dialog = AlertDialog.Builder(this).setTitle(if (BowieFlavor.GUEST_ONLY) "Add Linux source" else "Add connector")
            .setView(form).setNegativeButton("CANCEL", null)
            .setPositiveButton("CHOOSE GRANT", null).create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val peerIdText = id.text.toString().trim().lowercase()
                if (!peerIdText.isPeerId()) {
                    id.error = "Enter the owner's 40-character peer ID"; return@setOnClickListener
                }
                pendingConnector = (name.text.toString().trim().ifBlank { "Owner ${peerIdText.take(6)}" }) to peerIdText
                dialog.dismiss()
                startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE); type = "*/*"
                }, REQUEST_OWNER_GRANT)
            }
        }
        dialog.show()
    }

    private fun showAddSharedPeerDialog() {
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(8), dp(12), 0)
        }
        val name = field("Name", "")
        val id = field("Guest peer ID (40 hex)", "")
        form.addView(inputLayout("Name", name), matchWrap())
        form.addView(inputLayout("Guest peer ID", id), matchWrap())
        val dialog = AlertDialog.Builder(this).setTitle("Share access")
            .setView(form).setNegativeButton("CANCEL", null)
            .setPositiveButton("ISSUE GRANT", null).create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val peer = id.text.toString().trim().lowercase()
                if (!peer.isPeerId()) {
                    id.error = "Enter the guest's 40-character peer ID"; return@setOnClickListener
                }
                dialog.dismiss()
                startService(Intent(this, BowieVpnService::class.java)
                    .setAction(BowieVpnService.ACTION_ISSUE_GRANT)
                    .putExtra("subject_peer_id", peer)
                    .putExtra("peer_name", name.text.toString().trim().ifBlank { "Guest ${peer.take(6)}" }))
                status.text = "Preparing an owner grant…"
            }
        }
        dialog.show()
    }

    private fun connectSavedPeer(peer: BowiePeer) {
        val grant = PeerStore.decodeGrant(peer.grantWire)
        if (grant == null) {
            status.text = "This connector has no saved owner grant. Add it again with its .grant file."
            return
        }
        ownerGrantWire?.fill(0)
        ownerGrantWire = grant
        peerId.setText(peer.peerId)
        mode.check(2)
        if (meteredApiKey.text.isNullOrBlank() && signalRelayHost.text.isNullOrBlank() &&
            useDht.isChecked && (bootstrapHost.text.isNullOrBlank() || bootstrapPort.text.isNullOrBlank())) {
            status.text = "Set up DHT bootstrap in Advanced Settings before connecting."
            showAdvancedSettings()
            return
        }
        connectPeer()
    }

    private fun confirmRevoke(peer: BowiePeer) {
        if (peer.grantId.length != 32) {
            status.text = "This saved grant has no revocation ID. Remove and reissue it."
            return
        }
        AlertDialog.Builder(this).setTitle("Revoke access?")
            .setMessage("${peer.name} will no longer be able to connect with this grant. An active session with this peer will be ended.")
            .setNegativeButton("CANCEL", null)
            .setPositiveButton("REVOKE") { _, _ ->
                PeerStore.setRevoked(this, peer.grantId)
                PeerStore.upsert(this, peer.copy(revoked = true))
                startService(Intent(this, BowieVpnService::class.java)
                    .setAction(BowieVpnService.ACTION_REVOKE_GRANT)
                    .putExtra("grant_id", peer.grantId)
                    .putExtra("peer_id", peer.peerId))
                refreshPeerList()
            }.show()
    }

    private fun String.isPeerId(): Boolean = length == 40 && all { it.digitToIntOrNull(16) != null }

    private fun appendLog(source: String, message: String) {
        if (!::logConsole.isInitialized) return
        val current = logConsole.text.toString().lineSequence().toList().takeLast(7).joinToString("\n")
        logConsole.text = "$current\n[$source] $message".trim()
        peerListDialog?.let { if (it.isShowing) refreshPeerList() }
        if (::logScrollView.isInitialized) logScrollView.post { logScrollView.fullScroll(ViewGroup.FOCUS_DOWN) }
    }

    private fun updateRolePanels(checkedId: Int) {
        val isSource = checkedId == 1
        grantImportCard.visibility = ViewGroup.GONE
        ownerAccessCard.visibility = if (!BowieFlavor.GUEST_ONLY && isSource) ViewGroup.VISIBLE else ViewGroup.GONE
    }

    override fun onDestroy() {
        unregisterReceiver(receiver)
        ownerGrantWire?.fill(0)
        ownerGrantWire = null
        pendingOwnerGrant?.fill(0)
        pendingOwnerGrant = null
        super.onDestroy()
    }

    override fun onPause() {
        saveConnectionSettings()
        super.onPause()
    }

    private fun loadOwnerGrant(data: Intent?) {
        val uri = data?.data ?: return
        try {
            val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: throw IllegalArgumentException("Could not read selected file")
            require(bytes.size == 160) { "Grant file must be exactly 160 bytes" }
            val pending = pendingConnector
            if (pending != null) {
                val subject = bytes.copyOfRange(0, 20).joinToString("") { "%02x".format(it) }
                val localId = localPeerId.text.toString().removePrefix("DEVICE CODE  ")
                require(localId.length == 40 && subject.equals(localId, ignoreCase = true)) {
                    "This grant was issued to a different Bowie device"
                }
                PeerStore.upsert(this, BowiePeer("connector", pending.first, pending.second,
                    grantWire = PeerStore.encodeGrant(bytes)))
                pendingConnector = null
                refreshPeerList()
                status.text = "${pending.first} saved to Connectors."
            }
            ownerGrantWire?.fill(0)
            ownerGrantWire = bytes
            grantStatus.text = "Owner grant loaded (${bytes.size} bytes)"
            grantStatus.setTextColor(Color.rgb(245, 245, 245))
        } catch (error: Exception) {
            pendingConnector = null
            ownerGrantWire?.fill(0)
            ownerGrantWire = null
            grantStatus.text = "Could not load grant: ${error.message ?: "invalid file"}"
            grantStatus.setTextColor(Color.rgb(233, 165, 154))
        }
    }

    private fun saveOwnerGrant(data: Intent?, resultCode: Int) {
        val grant = pendingOwnerGrant
        val uri = data?.data
        try {
            if (resultCode != RESULT_OK || uri == null || grant == null) return
            contentResolver.openOutputStream(uri)?.use { it.write(grant) }
                ?: throw IllegalArgumentException("Could not save grant file")
            status.text = "Owner grant saved. Send the .grant file to that peer through a trusted channel."
        } catch (error: Exception) {
            status.text = "Could not save owner grant: ${error.message ?: "file error"}"
        } finally {
            pendingOwnerGrant?.fill(0)
            pendingOwnerGrant = null
        }
    }

    private fun String.hexToBytesOrNull(): ByteArray? {
        if (length % 2 != 0 || any { it.digitToIntOrNull(16) == null }) return null
        return ByteArray(length / 2) { index ->
            substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    companion object {
        private const val REQUEST_VPN = 31
        private const val REQUEST_OWNER_GRANT = 32
        private const val REQUEST_SAVE_OWNER_GRANT = 33
        private const val SETTINGS_PREFS = "connection_settings"
        const val ACTION_TEST_PREPARE = "org.bowie.TEST_PREPARE"
        const val ACTION_TEST_CONNECT = "org.bowie.TEST_CONNECT"
        const val ACTION_TEST_STOP = "org.bowie.TEST_STOP"
    }
}
