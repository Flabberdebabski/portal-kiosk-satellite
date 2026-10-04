#define _GNU_SOURCE

#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>
#include <android/log.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TAG "PortalAudioPersist"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define AUDIO_MANAGER_NAME "com.facebook.IAudioServiceManager"
#define AUDIO_MANAGER_DESCRIPTOR "com.facebook.alohasdk.IAudioServiceManager"
#define AUDIO_SERVICE_DESCRIPTOR "com.facebook.alohasdk.IAudioService"
#define AUDIO_CONNECTION_DESCRIPTOR \
  "com.facebook.alohasdk.IAudioServiceConnection"

#define MANAGER_GET_AUDIO_SERVICE 3
#define AUDIO_GET_PROCESSING_PARAM 3
#define AUDIO_SET_PROCESSING_PARAM 4
#define AEC_ENABLE 3001
#define NS_MODE 4001

static AIBinder_Class *manager_class;
static AIBinder_Class *audio_class;
static AIBinder_Class *connection_class;
static pthread_once_t binder_once = PTHREAD_ONCE_INIT;
static int binder_ready;
typedef AIBinder *(*get_service_fn)(const char *instance);
static get_service_fn get_service;

static void *binder_on_create(void *args) { return args; }
static void binder_on_destroy(void *user_data) { (void)user_data; }

static binder_status_t remote_on_transact(AIBinder *binder,
    transaction_code_t code, const AParcel *in, AParcel *out) {
  (void)binder;
  (void)code;
  (void)in;
  (void)out;
  return STATUS_UNKNOWN_TRANSACTION;
}

static binder_status_t connection_on_transact(AIBinder *binder,
    transaction_code_t code, const AParcel *in, AParcel *out) {
  (void)binder;
  (void)out;
  if (code != 1) return STATUS_UNKNOWN_TRANSACTION;
  AIBinder *service = NULL;
  binder_status_t status = AParcel_readStrongBinder(in, &service);
  if (service) AIBinder_decStrong(service);
  return status;
}

static void binder_init_once(void) {
  void *binder_ndk = dlopen("libbinder_ndk.so", RTLD_NOW | RTLD_LOCAL);
  if (binder_ndk)
    get_service = (get_service_fn)dlsym(binder_ndk,
        "AServiceManager_getService");
  manager_class = AIBinder_Class_define(AUDIO_MANAGER_DESCRIPTOR,
      binder_on_create, binder_on_destroy, remote_on_transact);
  audio_class = AIBinder_Class_define(AUDIO_SERVICE_DESCRIPTOR,
      binder_on_create, binder_on_destroy, remote_on_transact);
  connection_class = AIBinder_Class_define(AUDIO_CONNECTION_DESCRIPTOR,
      binder_on_create, binder_on_destroy, connection_on_transact);
  binder_ready = get_service && manager_class && audio_class &&
      connection_class;
}

static int read_reply_status(const AParcel *reply) {
  AStatus *status = NULL;
  binder_status_t result = AParcel_readStatusHeader(reply, &status);
  int ok = result == STATUS_OK && status && AStatus_isOk(status);
  if (status) AStatus_delete(status);
  return ok;
}

static AIBinder *get_audio_service(void) {
  pthread_once(&binder_once, binder_init_once);
  if (!binder_ready) return NULL;

  AIBinder *manager = get_service(AUDIO_MANAGER_NAME);
  if (!manager || !AIBinder_associateClass(manager, manager_class)) {
    if (manager) AIBinder_decStrong(manager);
    return NULL;
  }

  AIBinder *connection = AIBinder_new(connection_class, NULL);
  AParcel *request = NULL;
  AParcel *reply = NULL;
  binder_status_t status = connection
      ? AIBinder_prepareTransaction(manager, &request) : STATUS_NO_MEMORY;
  if (status == STATUS_OK)
    status = AParcel_writeStrongBinder(request, connection);
  if (status == STATUS_OK) {
    status = AIBinder_transact(manager, MANAGER_GET_AUDIO_SERVICE,
        &request, &reply, 0);
    request = NULL;
  }

  AIBinder *audio = NULL;
  if (status == STATUS_OK && reply && read_reply_status(reply))
    status = AParcel_readStrongBinder(reply, &audio);
  if (status != STATUS_OK || !audio ||
      !AIBinder_associateClass(audio, audio_class)) {
    if (audio) AIBinder_decStrong(audio);
    audio = NULL;
  }
  if (request) AParcel_delete(request);
  if (reply) AParcel_delete(reply);
  if (connection) AIBinder_decStrong(connection);
  AIBinder_decStrong(manager);
  return audio;
}

static int get_param(AIBinder *audio, int32_t id, float *value) {
  AParcel *request = NULL;
  AParcel *reply = NULL;
  binder_status_t status = AIBinder_prepareTransaction(audio, &request);
  if (status == STATUS_OK) status = AParcel_writeInt32(request, id);
  if (status == STATUS_OK) {
    status = AIBinder_transact(audio, AUDIO_GET_PROCESSING_PARAM,
        &request, &reply, 0);
    request = NULL;
  }
  int ok = status == STATUS_OK && reply && read_reply_status(reply) &&
      AParcel_readFloat(reply, value) == STATUS_OK;
  if (request) AParcel_delete(request);
  if (reply) AParcel_delete(reply);
  return ok;
}

static int set_param(AIBinder *audio, int32_t id, float value) {
  AParcel *request = NULL;
  AParcel *reply = NULL;
  binder_status_t status = AIBinder_prepareTransaction(audio, &request);
  if (status == STATUS_OK) status = AParcel_writeInt32(request, id);
  if (status == STATUS_OK) status = AParcel_writeFloat(request, value);
  if (status == STATUS_OK) {
    status = AIBinder_transact(audio, AUDIO_SET_PROCESSING_PARAM,
        &request, &reply, 0);
    request = NULL;
  }
  int ok = status == STATUS_OK && reply && read_reply_status(reply);
  if (request) AParcel_delete(request);
  if (reply) AParcel_delete(reply);
  return ok;
}

static int ensure_zero(AIBinder *audio, int32_t id, int *changed) {
  float before = 0.0f;
  float after = 0.0f;
  int before_ok = get_param(audio, id, &before);
  int needs_set = !before_ok || before != 0.0f;
  int set_ok = !needs_set || set_param(audio, id, 0.0f);
  int after_ok = get_param(audio, id, &after);
  int ok = set_ok && after_ok && after == 0.0f;
  if (changed) *changed |= needs_set && ok;
  if (needs_set || !ok) {
    int priority = ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR;
    __android_log_print(priority, TAG,
        "param=%d before=%s%g after=%s%g set=%d ok=%d", id,
        before_ok ? "" : "unavailable/", before,
        after_ok ? "" : "unavailable/", after, set_ok, ok);
  }
  return ok;
}

static int apply_audio_settings(int *changed) {
  if (changed) *changed = 0;
  AIBinder *audio = get_audio_service();
  if (!audio) return 0;
  int aec_ok = ensure_zero(audio, AEC_ENABLE, changed);
  int ns_ok = ensure_zero(audio, NS_MODE, changed);
  AIBinder_decStrong(audio);
  return aec_ok && ns_ok;
}

static void *watchdog_main(void *unused) {
  (void)unused;
  /* Let the application and the audio manager finish their boot paths. */
  sleep(2);
  unsigned int failures = 0;
  unsigned int healthy_checks = 0;
  int announced_healthy = 0;
  for (;;) {
    int changed = 0;
    int ok = apply_audio_settings(&changed);
    if (ok) {
      if (failures) LOGI("audio processing restored after %u failures", failures);
      if (!announced_healthy) {
        LOGI("audio processing verified aec=0 ns=0");
        announced_healthy = 1;
      }
      failures = 0;
      /* Meta rewrites NS during late boot. Check once a second for 30 clean
       * passes after startup or a correction, then use a low-overhead
       * five-second steady-state interval. */
      healthy_checks = changed ? 0 : healthy_checks + 1;
      sleep(healthy_checks < 30 ? 1 : 5);
    } else {
      failures++;
      if (failures == 1 || failures % 30 == 0)
        LOGE("audio processing apply failed count=%u", failures);
      healthy_checks = 0;
      sleep(2);
    }
  }
  return NULL;
}

__attribute__((constructor)) static void portal_audio_start(void) {
  pthread_t thread;
  int error = pthread_create(&thread, NULL, watchdog_main, NULL);
  if (error == 0) {
    pthread_detach(thread);
    LOGI("persistent audio watchdog started");
  } else {
    LOGE("watchdog pthread_create failed error=%d", error);
  }
}
