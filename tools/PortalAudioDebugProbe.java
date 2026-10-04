import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;

import java.lang.reflect.Method;

/** Enumerates the accessible Meta audio-debug Binder manager interface. */
public final class PortalAudioDebugProbe {
    private static final String NAME =
            "com.facebook.alohasdk.audio.IAudioDebugServiceManager";

    private static IBinder getService() throws Exception {
        Class<?> manager = Class.forName("android.os.ServiceManager");
        Method method = manager.getDeclaredMethod("getService", String.class);
        return (IBinder) method.invoke(null, NAME);
    }

    private static final class Connection extends Binder implements IInterface {
        private static final String DESCRIPTOR =
                "com.facebook.alohasdk.audio.IAudioDebugServiceConnection";
        Connection() { attachInterface(this, DESCRIPTOR); }
        @Override public IBinder asBinder() { return this; }
        @Override protected boolean onTransact(int code, Parcel data,
                Parcel reply, int flags) {
            System.out.println("DEBUG_PROBE callback code=" + code +
                    " size=" + data.dataAvail());
            if (code == INTERFACE_TRANSACTION) {
                if (reply != null) reply.writeString(DESCRIPTOR);
                return true;
            }
            try {
                data.enforceInterface(DESCRIPTOR);
                if (data.dataAvail() > 0) {
                    IBinder result = data.readStrongBinder();
                    System.out.println("DEBUG_PROBE callback result=" + result +
                            " descriptor=" + (result == null ? "null" :
                            result.getInterfaceDescriptor()));
                }
                if (reply != null) reply.writeNoException();
                return true;
            } catch (Throwable t) {
                System.out.println("DEBUG_PROBE callback error=" + t);
                return false;
            }
        }
    }

    private static void probeConnection(IBinder manager, String descriptor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(descriptor);
            data.writeStrongBinder(new Connection());
            boolean accepted = manager.transact(1, data, reply, 0);
            System.out.println("DEBUG_PROBE connection accepted=" + accepted +
                    " reply=" + reply.dataAvail());
            reply.readException();
            if (reply.dataAvail() > 0) {
                IBinder result = reply.readStrongBinder();
                System.out.println("DEBUG_PROBE connection result=" + result +
                        " descriptor=" + (result == null ? "null" :
                        result.getInterfaceDescriptor()));
            }
        } catch (Throwable t) {
            System.out.println("DEBUG_PROBE connection error=" + t);
            t.printStackTrace(System.out);
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static void probe(IBinder manager, String descriptor, int code,
            boolean binderArgument) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(descriptor);
            if (binderArgument) data.writeStrongBinder(new Binder());
            boolean accepted = manager.transact(code, data, reply, 0);
            if (!accepted) {
                System.out.println("DEBUG_PROBE code=" + code +
                        " binder=" + binderArgument + " rejected");
                return;
            }
            reply.readException();
            System.out.println("DEBUG_PROBE code=" + code +
                    " binder=" + binderArgument + " accepted size=" +
                    reply.dataAvail());
            if (reply.dataAvail() > 0) {
                int position = reply.dataPosition();
                try {
                    IBinder result = reply.readStrongBinder();
                    System.out.println("DEBUG_PROBE result=" + result +
                            " descriptor=" + (result == null ? "null" :
                            result.getInterfaceDescriptor()));
                } catch (Throwable t) {
                    reply.setDataPosition(position);
                    System.out.println("DEBUG_PROBE unread=" +
                            reply.dataAvail() + " error=" + t);
                }
            }
        } catch (Throwable t) {
            System.out.println("DEBUG_PROBE code=" + code +
                    " binder=" + binderArgument + " error=" + t);
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    public static void main(String[] args) throws Exception {
        IBinder manager = getService();
        if (manager == null) throw new IllegalStateException("service absent");
        String descriptor = manager.getInterfaceDescriptor();
        System.out.println("DEBUG_PROBE manager=" + manager +
                " descriptor=" + descriptor);
        probeConnection(manager, descriptor);
        if (args.length == 0 || !manager.isBinderAlive()) return;
        for (int code = 1; code <= 12; code++) {
            probe(manager, descriptor, code, false);
            probe(manager, descriptor, code, true);
        }
    }
}
