import android.content.ComponentName;
import android.content.pm.PackageManager;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.IBinder;
import android.system.Os;
import android.util.Base64;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/** Applies a validated component-state TSV through PackageManager as root. */
public final class PortalComponentCtl {
    private static final String PREFS_DB =
            "/data/user/0/com.facebook.portal.aiservice/databases/prefs_db";
    private static final String FPS_BACKUP =
            "/data/local/tmp/portal-presence-backup/analysis-fps-before-v1.tsv";
    private static final String FPS_INSTALLED =
            "/data/local/tmp/portal-presence-backup/fps-cap-v1";
    private static final String FPS_RESTORED =
            "/data/local/tmp/portal-presence-backup/fps-restored-v1";
    private static final String ENABLE_KEY =
            "/settings/aloha/enable_analysis_throttle";
    private static final String FPS_KEY =
            "/settings/aloha/analysis_throttle_fps";
    private static final String[] PRESENCE_PROFILE_KEYS = new String[] {
            "/settings/aloha/enable_cv_background_detector_v2",
            "/settings/aloha/enable_hardware_cropping",
            "/settings/aloha/enable_liveness_metric",
            "/settings/aloha/enable_color_based_reid",
            "/settings/aloha/enable_face_rec_based_reid_v3",
    };

    private static Object packageService() throws Exception {
        Class<?> serviceManager = Class.forName("android.os.ServiceManager");
        Method getService = serviceManager.getDeclaredMethod(
                "getService", String.class);
        IBinder binder = (IBinder) getService.invoke(null, "package");
        if (binder == null) {
            throw new IllegalStateException("package service is absent");
        }
        Class<?> stub = Class.forName("android.content.pm.IPackageManager$Stub");
        Method asInterface = stub.getDeclaredMethod("asInterface", IBinder.class);
        return asInterface.invoke(null, binder);
    }

    private static int stateFor(String action) {
        switch (action) {
            case "default":
                return PackageManager.COMPONENT_ENABLED_STATE_DEFAULT;
            case "enable":
                return PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
            case "disable":
                return PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
            default:
                throw new IllegalArgumentException("unknown action: " + action);
        }
    }

    private static void makeShellReadable(String path) throws Exception {
        Os.chmod(path, 0644);
        Os.chown(path, 2000, 2000);
    }

    private static void writeMarker(String path, String value) throws Exception {
        try (FileWriter writer = new FileWriter(path, false)) {
            writer.write(value);
            writer.write('\n');
        }
        makeShellReadable(path);
    }

    private static String encode(String value) {
        return Base64.encodeToString(
                value.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
    }

    private static String decode(String value) {
        return new String(Base64.decode(value, Base64.NO_WRAP),
                StandardCharsets.UTF_8);
    }

    private static void backupPreferenceRows(SQLiteDatabase database)
            throws Exception {
        File backup = new File(FPS_BACKUP);
        File parent = backup.getParentFile();
        if (!parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create presence backup directory");
        }
        Set<String> saved = new HashSet<>();
        if (backup.isFile()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(backup))) {
                if (!"# portal-presence-analysis-fps-backup-v1".equals(
                        reader.readLine())) {
                    throw new IllegalArgumentException("unrecognized FPS backup");
                }
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] fields = line.split("\\t", -1);
                    if (fields.length >= 2) saved.add(fields[0]);
                }
            }
        }
        try (BufferedWriter writer = new BufferedWriter(
                new FileWriter(backup, backup.isFile()))) {
            if (saved.isEmpty()) {
                writer.write("# portal-presence-analysis-fps-backup-v1\n");
            }
            String[] keys = new String[2 + PRESENCE_PROFILE_KEYS.length];
            keys[0] = ENABLE_KEY;
            keys[1] = FPS_KEY;
            System.arraycopy(PRESENCE_PROFILE_KEYS, 0, keys, 2,
                    PRESENCE_PROFILE_KEYS.length);
            for (String key : keys) {
                if (saved.contains(key)) continue;
                try (Cursor cursor = database.query(
                        "preferences", new String[] {"type", "value"},
                        "key = ?", new String[] {key}, null, null, null)) {
                    if (!cursor.moveToFirst()) {
                        writer.write(key + "\tabsent\n");
                    } else {
                        int type = cursor.getInt(0);
                        String value = cursor.getString(1);
                        writer.write(key + "\t" + type + "\t"
                                + encode(value == null ? "" : value) + "\n");
                    }
                }
            }
        }
        makeShellReadable(FPS_BACKUP);
    }

    private static void putPreference(
            SQLiteDatabase database, String key, int type, Object value) {
        ContentValues values = new ContentValues();
        values.put("key", key);
        values.put("type", type);
        if (value instanceof Integer) {
            values.put("value", (Integer) value);
        } else if (value instanceof Long) {
            values.put("value", (Long) value);
        } else if (value instanceof Float) {
            values.put("value", (Float) value);
        } else if (value instanceof Double) {
            values.put("value", (Double) value);
        } else {
            values.put("value", String.valueOf(value));
        }
        database.replaceOrThrow("preferences", null, values);
    }

    private static void setPresenceFps(int fps) throws Exception {
        SQLiteDatabase database = SQLiteDatabase.openDatabase(
                PREFS_DB, null, SQLiteDatabase.OPEN_READWRITE);
        try {
            backupPreferenceRows(database);
            database.beginTransaction();
            try {
                putPreference(database, ENABLE_KEY, 2, 1);
                putPreference(database, FPS_KEY, 6, (double) fps);
                for (String key : PRESENCE_PROFILE_KEYS) {
                    putPreference(database, key, 2, 0);
                }
                database.setTransactionSuccessful();
            } finally {
                database.endTransaction();
            }
        } finally {
            database.close();
        }
        new File(FPS_RESTORED).delete();
        writeMarker(FPS_INSTALLED, Integer.toString(fps));
        System.out.println("PORTAL_PRESENCE_FPS action=set fps=" + fps + " ok=1");
    }

    private static void restorePresenceFps() throws Exception {
        File backup = new File(FPS_BACKUP);
        if (!backup.isFile()) {
            new File(FPS_INSTALLED).delete();
            writeMarker(FPS_RESTORED, "no prior FPS preferences were saved");
            System.out.println("PORTAL_PRESENCE_FPS action=restore backup=absent ok=1");
            return;
        }
        SQLiteDatabase database = SQLiteDatabase.openDatabase(
                PREFS_DB, null, SQLiteDatabase.OPEN_READWRITE);
        database.beginTransaction();
        try (BufferedReader reader = new BufferedReader(new FileReader(backup))) {
            if (!"# portal-presence-analysis-fps-backup-v1".equals(
                    reader.readLine())) {
                throw new IllegalArgumentException("unrecognized FPS backup");
            }
            String line;
            while ((line = reader.readLine()) != null) {
                String[] fields = line.split("\\t", -1);
                if (fields.length == 2 && "absent".equals(fields[1])) {
                    database.delete("preferences", "key = ?",
                            new String[] {fields[0]});
                    continue;
                }
                if (fields.length != 3) {
                    throw new IllegalArgumentException("invalid FPS backup line");
                }
                int type = Integer.parseInt(fields[1]);
                String value = decode(fields[2]);
                Object typed = type == 2 || type == 3 ? Integer.valueOf(value)
                        : type == 4 ? Long.valueOf(value)
                        : type == 5 ? Float.valueOf(value)
                        : type == 6 ? Double.valueOf(value) : value;
                putPreference(database, fields[0], type, typed);
            }
            database.setTransactionSuccessful();
        } finally {
            database.endTransaction();
            database.close();
        }
        new File(FPS_INSTALLED).delete();
        writeMarker(FPS_RESTORED, "Portal presence analysis FPS restored");
        System.out.println("PORTAL_PRESENCE_FPS action=restore ok=1");
    }

    public static void main(String[] args) {
        if (args.length < 1 || args.length > 2) {
            System.err.println(
                    "usage: PortalComponentCtl ACTIONS_TSV [none|set:FPS|restore]");
            System.exit(64);
        }
        int changed = 0;
        try {
            Object service = packageService();
            Method setter = Class.forName(
                    "android.content.pm.IPackageManager").getMethod(
                    "setComponentEnabledSetting", ComponentName.class,
                    int.class, int.class, int.class);
            try (BufferedReader reader = new BufferedReader(
                    new FileReader(args[0]))) {
                String header = reader.readLine();
                if (!"# portal-debloat-component-actions-v1".equals(header)) {
                    throw new IllegalArgumentException("unrecognized action file");
                }
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.isEmpty()) {
                        continue;
                    }
                    String[] fields = line.split("\\t", -1);
                    if (fields.length != 2) {
                        throw new IllegalArgumentException("invalid action line");
                    }
                    ComponentName component = ComponentName.unflattenFromString(
                            fields[1]);
                    if (component == null || !fields[1].equals(
                            component.flattenToString())) {
                        throw new IllegalArgumentException(
                                "invalid component: " + fields[1]);
                    }
                    int state = stateFor(fields[0]);
                    try {
                        setter.invoke(service, component, state,
                                PackageManager.DONT_KILL_APP, 0);
                    } catch (InvocationTargetException e) {
                        throw new IllegalStateException(
                                "failed component: " + fields[1], e.getCause());
                    }
                    changed++;
                }
            }
            String presenceAction = args.length == 2 ? args[1] : "none";
            if (presenceAction.startsWith("set:")) {
                int fps = Integer.parseInt(presenceAction.substring(4));
                if (fps < 1 || fps > 10) {
                    throw new IllegalArgumentException("invalid FPS cap");
                }
                setPresenceFps(fps);
            } else if ("restore".equals(presenceAction)) {
                restorePresenceFps();
            } else if (!"none".equals(presenceAction)) {
                throw new IllegalArgumentException(
                        "unknown presence action: " + presenceAction);
            }
            System.out.println("PORTAL_COMPONENT_CTL_OK changed=" + changed);
        } catch (Throwable t) {
            System.err.println("PORTAL_COMPONENT_CTL_ERROR changed=" + changed
                    + " error=" + t);
            t.printStackTrace(System.err);
            System.exit(1);
        }
    }
}
