package dev.portal.audiohelper;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public final class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        Log.i(PortalAudio.TAG, "received " + intent.getAction());
        AudioKeeperService.start(context);
    }
}
