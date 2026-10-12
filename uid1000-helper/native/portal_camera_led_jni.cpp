#include <jni.h>
#include <stdio.h>

int portal_watchdog_main(int argc, char **argv);

extern "C" JNIEXPORT void JNICALL
Java_PortalUid1000Bootstrap_run(JNIEnv *, jclass, jint configuration) {
  char fps[4]{};
  char program[] = "portal-camera-led-watch";
  char camera[] = "--camera";
  char fps_option[] = "--fps";
  char *arguments[6] = {program, nullptr, nullptr, nullptr, nullptr, nullptr};
  int count = 1;
  if ((configuration & 0x100) != 0) {
    arguments[count++] = camera;
  }
  int requested_fps = configuration & 0xff;
  if (requested_fps >= 1 && requested_fps <= 10) {
    snprintf(fps, sizeof(fps), "%d", requested_fps);
    arguments[count++] = fps_option;
    arguments[count++] = fps;
  }
  arguments[count] = nullptr;
  (void)portal_watchdog_main(count, arguments);
}
