package dev.portal.shizukuhelper;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public final class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "PortalShizuku";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i(TAG, "startup requested action=" + intent.getAction());
        context.startService(new Intent(context, StartupService.class));
    }
}
