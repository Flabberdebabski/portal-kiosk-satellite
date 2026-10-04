package dev.portal.audiohelper;

import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.util.Log;

import java.lang.reflect.Method;

final class PortalAudio {
    static final String TAG = "PortalAudioHelper";
    private static final String MANAGER_NAME =
            "com.facebook.IAudioServiceManager";
    private static final String MANAGER_DESCRIPTOR =
            "com.facebook.alohasdk.IAudioServiceManager";
    private static final String AUDIO_DESCRIPTOR =
            "com.facebook.alohasdk.IAudioService";
    private static final String CONNECTION_DESCRIPTOR =
            "com.facebook.alohasdk.IAudioServiceConnection";
    private static final int MANAGER_GET_AUDIO_SERVICE = 3;
    private static final int AUDIO_GET_PROCESSING_PARAM = 3;
    private static final int AUDIO_SET_PROCESSING_PARAM = 4;

    private static final int AEC_ENABLE = 3001;
    private static final int NS_MODE = 4001;

    private static final class Connection extends Binder implements IInterface {
        Connection() {
            attachInterface(this, CONNECTION_DESCRIPTOR);
        }

        @Override public IBinder asBinder() {
            return this;
        }

        @Override protected boolean onTransact(int code, Parcel data,
                Parcel reply, int flags) {
            if (code == INTERFACE_TRANSACTION) {
                if (reply != null) reply.writeString(CONNECTION_DESCRIPTOR);
                return true;
            }
            if (code == 1) {
                data.enforceInterface(CONNECTION_DESCRIPTOR);
                data.readStrongBinder();
                return true;
            }
            try {
                return super.onTransact(code, data, reply, flags);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    private final Connection connection = new Connection();
    private IBinder audio;

    private static IBinder getService(String name) throws Exception {
        Class<?> serviceManager = Class.forName("android.os.ServiceManager");
        Method getService = serviceManager.getDeclaredMethod(
                "getService", String.class);
        return (IBinder) getService.invoke(null, name);
    }

    private synchronized IBinder connect() throws Exception {
        if (audio != null && audio.isBinderAlive()) return audio;
        IBinder manager = getService(MANAGER_NAME);
        if (manager == null) throw new IllegalStateException(
                "audio manager service is absent");
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(MANAGER_DESCRIPTOR);
            data.writeStrongBinder(connection);
            if (!manager.transact(MANAGER_GET_AUDIO_SERVICE, data, reply, 0)) {
                throw new IllegalStateException("manager transaction rejected");
            }
            reply.readException();
            audio = reply.readStrongBinder();
            if (audio == null) throw new IllegalStateException(
                    "manager returned null audio service");
            return audio;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static float getParam(IBinder service, int id) throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(AUDIO_DESCRIPTOR);
            data.writeInt(id);
            if (!service.transact(AUDIO_GET_PROCESSING_PARAM, data, reply, 0)) {
                throw new IllegalStateException("get transaction rejected");
            }
            reply.readException();
            return reply.readFloat();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static void setParam(IBinder service, int id, float value)
            throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(AUDIO_DESCRIPTOR);
            data.writeInt(id);
            data.writeFloat(value);
            if (!service.transact(AUDIO_SET_PROCESSING_PARAM, data, reply, 0)) {
                throw new IllegalStateException("set transaction rejected");
            }
            reply.readException();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static boolean ensureZero(IBinder service, int id)
            throws Exception {
        float before = getParam(service, id);
        if (Float.compare(before, 0.0f) != 0) setParam(service, id, 0.0f);
        float after = getParam(service, id);
        boolean ok = Float.compare(after, 0.0f) == 0;
        Log.i(TAG, "param=" + id + " before=" + before +
                " after=" + after + " ok=" + ok);
        return ok;
    }

    synchronized boolean apply() {
        try {
            IBinder service = connect();
            boolean aec = ensureZero(service, AEC_ENABLE);
            boolean ns = ensureZero(service, NS_MODE);
            if (!aec || !ns) throw new IllegalStateException(
                    "DSP readback mismatch aec=" + aec + " ns=" + ns);
            return true;
        } catch (Throwable t) {
            audio = null;
            Log.e(TAG, "apply failed", t);
            return false;
        }
    }
}
