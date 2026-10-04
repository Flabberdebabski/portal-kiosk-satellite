package dev.portal.shizukuhelper;

import android.app.Service;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.IBinder;
import android.util.Log;

import java.io.File;

public final class StartupService extends Service {
    private static final String TAG = "PortalShizuku";
    private static final String SHIZUKU_PACKAGE = "moe.shizuku.privileged.api";
    private volatile boolean workerRunning;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (!workerRunning) {
            workerRunning = true;
            new Thread(() -> startShizuku(startId), "portal-shizuku-start").start();
        }
        return START_STICKY;
    }

    private void startShizuku(int startId) {
        try {
            for (int attempt = 1; attempt <= 120; attempt++) {
                try {
                    File privateKey = new File(getFilesDir(), "adbkey");
                    File publicKey = new File(getFilesDir(), "adbkey.pub");
                    if (!privateKey.isFile() || !publicKey.isFile()) {
                        throw new IllegalStateException("provisioned ADB key is missing");
                    }
                    ApplicationInfo info = getPackageManager().getApplicationInfo(
                            SHIZUKU_PACKAGE, 0);
                    String starter = quote(info.nativeLibraryDir + "/libshizuku.so");
                    String apk = quote(info.sourceDir);
                    String command = "if pidof shizuku_server >/dev/null 2>&1; then "
                            + "echo PORTAL_SHIZUKU_ALREADY_RUNNING; else "
                            + starter + " --apk=" + apk + "; fi; "
                            + "sleep 1; pidof shizuku_server >/dev/null 2>&1 "
                            + "&& echo PORTAL_SHIZUKU_OK";
                    try (AdbClient client = new AdbClient(getFilesDir())) {
                        client.connect();
                        String output = client.shell(command);
                        if (output.contains("PORTAL_SHIZUKU_OK")) {
                            Log.i(TAG, "Shizuku started through loopback ADB attempt=" + attempt);
                            return;
                        }
                        Log.w(TAG, "starter returned without a running server attempt=" + attempt
                                + " output=" + output.trim());
                    }
                } catch (Exception error) {
                    if (attempt == 1 || attempt % 10 == 0) {
                        Log.w(TAG, "startup attempt=" + attempt + " failed", error);
                    }
                }
                Thread.sleep(3000);
            }
            Log.e(TAG, "Shizuku did not start after 120 attempts");
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        } finally {
            workerRunning = false;
            stopSelf(startId);
        }
    }

    private static String quote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
