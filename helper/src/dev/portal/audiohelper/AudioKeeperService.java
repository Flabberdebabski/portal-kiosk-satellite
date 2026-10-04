package dev.portal.audiohelper;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.SystemClock;
import android.util.Log;

public final class AudioKeeperService extends Service {
    private static final long CHECK_INTERVAL_MS = 15000;
    private static final long BACKUP_ALARM_MS = 5 * 60 * 1000;
    private HandlerThread thread;
    private Handler handler;
    private PortalAudio audio;

    private final Runnable check = new Runnable() {
        @Override public void run() {
            boolean ok = audio.apply();
            handler.postDelayed(this, ok ? CHECK_INTERVAL_MS : 1000);
        }
    };

    static void start(Context context) {
        try {
            context.startService(new Intent(context, AudioKeeperService.class));
        } catch (Throwable t) {
            Log.e(PortalAudio.TAG, "start service failed", t);
        }
        scheduleBackup(context);
    }

    private static void scheduleBackup(Context context) {
        AlarmManager alarms = (AlarmManager) context.getSystemService(
                Context.ALARM_SERVICE);
        Intent intent = new Intent("dev.portal.audiohelper.APPLY");
        intent.setPackage(context.getPackageName());
        PendingIntent pending = PendingIntent.getBroadcast(context, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT);
        alarms.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP,
                SystemClock.elapsedRealtime() + BACKUP_ALARM_MS, pending);
    }

    @Override public void onCreate() {
        super.onCreate();
        audio = new PortalAudio();
        thread = new HandlerThread("portal-audio-keeper");
        thread.start();
        handler = new Handler(thread.getLooper());
        Log.i(PortalAudio.TAG, "watchdog started");
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        handler.removeCallbacks(check);
        handler.post(check);
        scheduleBackup(this);
        return START_STICKY;
    }

    @Override public void onDestroy() {
        handler.removeCallbacksAndMessages(null);
        thread.quitSafely();
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent intent) {
        return null;
    }
}
