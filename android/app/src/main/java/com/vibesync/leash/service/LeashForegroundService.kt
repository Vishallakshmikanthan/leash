package com.vibesync.leash.service

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.vibesync.leash.MainActivity

class LeashForegroundService : Service() {

    companion object {
        const val CHANNEL_SAFETY = "leash_channel_safety"
        const val CHANNEL_APPROVALS = "leash_channel_approvals"
        const val CHANNEL_ALERTS = "leash_channel_alerts"

        const val NOTIFICATION_SERVICE_ID = 1001
        const val NOTIFICATION_APPROVAL_BASE_ID = 2000
        const val NOTIFICATION_ALERT_ID = 3001

        const val ACTION_APPROVE = "com.vibesync.leash.ACTION_APPROVE"
        const val ACTION_DENY = "com.vibesync.leash.ACTION_DENY"
        const val EXTRA_ACTION_ID = "extra_action_id"

        var onNotificationDecision: ((actionId: String, approve: Boolean) -> Unit)? = null

        fun startService(context: Context) {
            val intent = Intent(context, LeashForegroundService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun showApprovalNotification(
            context: Context,
            actionId: String,
            command: String,
            severity: String,
            agent: String
        ) {
            val manager = context.getSystemService(NotificationManager::class.java)

            val openAppIntent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra(EXTRA_ACTION_ID, actionId)
            }
            val openPending = PendingIntent.getActivity(
                context, actionId.hashCode(), openAppIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )

            // Direct Approve action
            val approveIntent = Intent(context, LeashForegroundService::class.java).apply {
                action = ACTION_APPROVE
                putExtra(EXTRA_ACTION_ID, actionId)
            }
            val approvePending = PendingIntent.getService(
                context, (actionId + "_app").hashCode(), approveIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )

            // Direct Deny action
            val denyIntent = Intent(context, LeashForegroundService::class.java).apply {
                action = ACTION_DENY
                putExtra(EXTRA_ACTION_ID, actionId)
            }
            val denyPending = PendingIntent.getService(
                context, (actionId + "_deny").hashCode(), denyIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )

            val notif = NotificationCompat.Builder(context, CHANNEL_APPROVALS)
                .setContentTitle("Leash [$severity]: $agent")
                .setContentText(command)
                .setStyle(NotificationCompat.BigTextStyle().bigText("Agent '$agent' attempts:\n$command\nRequires your approval."))
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentIntent(openPending)
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setAutoCancel(true)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Deny", denyPending)
                .addAction(android.R.drawable.ic_input_add, "Approve", approvePending)
                .build()

            val notifId = NOTIFICATION_APPROVAL_BASE_ID + (actionId.hashCode() % 500)
            manager.notify(notifId, notif)
        }

        fun cancelApprovalNotification(context: Context, actionId: String) {
            val manager = context.getSystemService(NotificationManager::class.java)
            val notifId = NOTIFICATION_APPROVAL_BASE_ID + (actionId.hashCode() % 500)
            manager.cancel(notifId)
        }

        fun showAgentStatusNotification(
            context: Context,
            status: String,
            agent: String,
            message: String
        ) {
            val manager = context.getSystemService(NotificationManager::class.java)
            val openAppIntent = Intent(context, MainActivity::class.java)
            val openPending = PendingIntent.getActivity(
                context, status.hashCode(), openAppIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )

            val title = when (status.lowercase()) {
                "done" -> "✅ Agent Completed: $agent"
                "stuck" -> "⚠️ Agent Stuck / Looping: $agent"
                "idle" -> "⏳ Agent Waiting for Input: $agent"
                else -> "ℹ️ Agent Status: $agent"
            }

            val notif = NotificationCompat.Builder(context, CHANNEL_ALERTS)
                .setContentTitle(title)
                .setContentText(message)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentIntent(openPending)
                .setAutoCancel(true)
                .build()

            manager.notify(NOTIFICATION_ALERT_ID, notif)
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent != null) {
            val action = intent.action
            val actionId = intent.getStringExtra(EXTRA_ACTION_ID)
            if (actionId != null) {
                if (action == ACTION_APPROVE) {
                    onNotificationDecision?.invoke(actionId, true)
                    cancelApprovalNotification(this, actionId)
                } else if (action == ACTION_DENY) {
                    onNotificationDecision?.invoke(actionId, false)
                    cancelApprovalNotification(this, actionId)
                }
            }
        }

        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, notificationIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_SAFETY)
            .setContentTitle("Leash Safety Guard Active")
            .setContentText("Private on-device agent guard ready")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()

        startForeground(NOTIFICATION_SERVICE_ID, notification)
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)

            val safetyChannel = NotificationChannel(
                CHANNEL_SAFETY,
                "Leash Background Safety Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps connection open with laptop daemon"
            }

            val approvalsChannel = NotificationChannel(
                CHANNEL_APPROVALS,
                "Leash Action Approvals",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Prompts for approving or denying risky coding agent actions"
                enableVibration(true)
            }

            val alertsChannel = NotificationChannel(
                CHANNEL_ALERTS,
                "Leash Agent Lifecycle Alerts",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Alerts for Done, Stuck, or Idle agent states"
            }

            manager.createNotificationChannel(safetyChannel)
            manager.createNotificationChannel(approvalsChannel)
            manager.createNotificationChannel(alertsChannel)
        }
    }
}
