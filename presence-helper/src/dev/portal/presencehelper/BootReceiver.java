package dev.portal.presencehelper;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public final class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "PortalPresence";
    private static final String ACTION_CONFIG =
            "dev.portal.presencehelper.CONFIG";

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (ACTION_CONFIG.equals(action)) {
            int fps = intent.getIntExtra("fps", 0);
            if (fps < 0 || fps > 10) {
                Log.e(TAG, "refusing invalid presence startup FPS=" + fps);
                return;
            }
            context.getSharedPreferences("config", Context.MODE_PRIVATE)
                    .edit().putInt("fps", fps).apply();
            Log.i(TAG, "configured presence startup fps="
                    + (fps == 0 ? "unchanged" : fps));
            context.startService(new Intent(context, StartupService.class));
            return;
        }
        Log.i(TAG, "startup requested action=" + action);
        context.startService(new Intent(context, StartupService.class));
    }
}
