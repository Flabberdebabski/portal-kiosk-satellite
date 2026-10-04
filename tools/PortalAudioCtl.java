import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;

import java.lang.reflect.Method;

/** Direct Binder client for the Portal audio-processing service. */
public final class PortalAudioCtl {
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

    private static final class Connection extends Binder implements IInterface {
        Connection() {
            attachInterface(this, CONNECTION_DESCRIPTOR);
        }

        @Override
        public IBinder asBinder() {
            return this;
        }

        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply,
                                     int flags) {
            if (code == INTERFACE_TRANSACTION) {
                if (reply != null) {
                    reply.writeString(CONNECTION_DESCRIPTOR);
                }
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

    private static IBinder getService(String name) throws Exception {
        Class<?> serviceManager = Class.forName("android.os.ServiceManager");
        Method getService = serviceManager.getDeclaredMethod(
                "getService", String.class);
        return (IBinder) getService.invoke(null, name);
    }

    private static IBinder getAudioService(IBinder manager) throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(MANAGER_DESCRIPTOR);
            data.writeStrongBinder(new Connection());
            if (!manager.transact(MANAGER_GET_AUDIO_SERVICE, data, reply, 0)) {
                throw new IllegalStateException("manager transaction rejected");
            }
            reply.readException();
            IBinder audio = reply.readStrongBinder();
            if (audio == null) {
                throw new IllegalStateException("manager returned null audio service");
            }
            return audio;
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static float getParam(IBinder audio, int id) throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(AUDIO_DESCRIPTOR);
            data.writeInt(id);
            if (!audio.transact(AUDIO_GET_PROCESSING_PARAM, data, reply, 0)) {
                throw new IllegalStateException("get transaction rejected");
            }
            reply.readException();
            return reply.readFloat();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static void setParam(IBinder audio, int id, float value)
            throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(AUDIO_DESCRIPTOR);
            data.writeInt(id);
            data.writeFloat(value);
            if (!audio.transact(AUDIO_SET_PROCESSING_PARAM, data, reply, 0)) {
                throw new IllegalStateException("set transaction rejected");
            }
            reply.readException();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    public static void main(String[] args) {
        String[] requested = args.length == 0
                ? new String[] {"3001", "0"} : args;
        if ((requested.length & 1) != 0) {
            System.err.println("usage: PortalAudioCtl [id value]...");
            System.exit(64);
        }
        try {
            IBinder manager = getService(MANAGER_NAME);
            if (manager == null) {
                throw new IllegalStateException("audio manager service is absent");
            }
            IBinder audio = getAudioService(manager);
            boolean allMatch = true;
            for (int i = 0; i < requested.length; i += 2) {
                int id = Integer.decode(requested[i]);
                float value = Float.parseFloat(requested[i + 1]);
                float before = getParam(audio, id);
                setParam(audio, id, value);
                float after = getParam(audio, id);
                boolean match = Float.compare(after, value) == 0;
                allMatch &= match;
                System.out.println("PORTAL_AUDIO_CTL_OK id=" + id
                        + " before=" + before + " requested=" + value
                        + " after=" + after + " match=" + match);
            }
            if (!allMatch) {
                System.exit(2);
            }
        } catch (Throwable t) {
            System.err.println("PORTAL_AUDIO_CTL_ERROR " + t);
            Throwable cause = t.getCause();
            if (cause != null) {
                System.err.println("caused by: " + cause);
            }
            t.printStackTrace(System.err);
            System.exit(1);
        }
    }
}
