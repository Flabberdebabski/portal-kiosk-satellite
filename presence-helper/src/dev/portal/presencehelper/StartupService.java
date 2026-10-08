package dev.portal.presencehelper;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.os.SystemClock;
import android.util.Log;

public final class StartupService extends Service {
    private static final String TAG = "PortalPresence";
    private static final long INITIAL_DELAY_MS = 15_000L;
    private volatile boolean workerRunning;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (!workerRunning) {
            workerRunning = true;
            new Thread(() -> activateOnce(startId),
                    "portal-presence-startup").start();
        }
        return START_STICKY;
    }

    private void activateOnce(int startId) {
        try {
            SystemClock.sleep(INITIAL_DELAY_MS);
            int fps = getSharedPreferences("config", Context.MODE_PRIVATE)
                    .getInt("fps", -1);
            if (fps < 0 || fps > 10) {
                Log.e(TAG, "helper has no valid presence configuration");
                return;
            }
            activate(fps);
        } catch (Throwable error) {
            Log.e(TAG, "presence pipeline activation failed", error);
        } finally {
            workerRunning = false;
            stopSelf();
        }
    }

    private boolean activate(int fps) {
        try {
            String command = "am start --user 0 -n "
                    + "com.facebook.portal.aiservice/"
                    + "com.facebook.alohaapp.app.MainActivity >/dev/null"
                    + "; sleep 3; am start --user 0 -a android.intent.action.MAIN"
                    + " -c android.intent.category.HOME >/dev/null; sleep 1";
            String output;
            try (AdbClient client = new AdbClient(getFilesDir())) {
                client.connect();
                output = client.shell(command);
            }
            if (output.contains("Error:")) {
                throw new IllegalStateException(output.trim());
            }
            Log.i(TAG, "presence pipeline activation complete fps="
                    + (fps == 0 ? "unchanged" : fps));
            return true;
        } catch (Throwable error) {
            Log.w(TAG, "presence pipeline activation failed fps=" + fps, error);
            return false;
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
