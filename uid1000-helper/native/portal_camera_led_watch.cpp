#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

constexpr char kTag[] = "PortalCameraLed";
constexpr char kClientLibrary[] =
    "/system/lib64/privacystate_client1.0.so";
constexpr char kConstructor[] =
    "_ZN8facebook5aloha18PrivacyStateClientC1EN6vendor8facebook8hardware"
    "12privacystate4V1_09ComponentEjb";
constexpr char kDestructor[] =
    "_ZN8facebook5aloha18PrivacyStateClientD1Ev";
constexpr char kConnect[] =
    "_ZN8facebook5aloha18PrivacyStateClient11connectIntfEv";
constexpr char kDisconnect[] =
    "_ZN8facebook5aloha18PrivacyStateClient14disconnectIntfEv";
constexpr char kClear[] =
    "_ZN8facebook5aloha18PrivacyStateClient8clearLedEv";
constexpr char kGet[] =
    "_ZN8facebook5aloha18PrivacyStateClient6getLedEv";

using Constructor = void (*)(void *, uint8_t, uint32_t, bool);
using Destructor = void (*)(void *);
using ConnectMethod = int (*)(void *);
using BoolMethod = bool (*)(void *);
using VoidMethod = void (*)(void *);

volatile sig_atomic_t running = 1;
volatile sig_atomic_t stop_signal = 0;

using LogVPrint = int (*)(int, const char *, const char *, va_list);
LogVPrint real_log_vprint = nullptr;

int quiet_privacy_log(int priority, const char *tag, const char *format, ...) {
  if (tag != nullptr && strcmp(tag, "PrivacyStateClient") == 0) return 0;
  if (real_log_vprint == nullptr) return 0;
  va_list arguments;
  va_start(arguments, format);
  int result = real_log_vprint(priority, tag, format, arguments);
  va_end(arguments);
  return result;
}

uintptr_t loaded_address(uintptr_t base, uintptr_t value) {
  return value >= base ? value : base + value;
}

int silence_privacy_client_logs(dl_phdr_info *info, size_t, void *) {
  if (info->dlpi_name == nullptr ||
      strstr(info->dlpi_name, "privacystate_client1.0.so") == nullptr) {
    return 0;
  }

  const ElfW(Dyn) *dynamic = nullptr;
  for (ElfW(Half) index = 0; index < info->dlpi_phnum; ++index) {
    if (info->dlpi_phdr[index].p_type == PT_DYNAMIC) {
      dynamic = reinterpret_cast<const ElfW(Dyn) *>(
          info->dlpi_addr + info->dlpi_phdr[index].p_vaddr);
      break;
    }
  }
  if (dynamic == nullptr) return 1;

  const ElfW(Rela) *relocations = nullptr;
  size_t relocation_size = 0;
  const ElfW(Sym) *symbols = nullptr;
  const char *strings = nullptr;
  for (const ElfW(Dyn) *entry = dynamic; entry->d_tag != DT_NULL; ++entry) {
    switch (entry->d_tag) {
      case DT_JMPREL:
        relocations = reinterpret_cast<const ElfW(Rela) *>(loaded_address(
            info->dlpi_addr, static_cast<uintptr_t>(entry->d_un.d_ptr)));
        break;
      case DT_PLTRELSZ:
        relocation_size = static_cast<size_t>(entry->d_un.d_val);
        break;
      case DT_SYMTAB:
        symbols = reinterpret_cast<const ElfW(Sym) *>(loaded_address(
            info->dlpi_addr, static_cast<uintptr_t>(entry->d_un.d_ptr)));
        break;
      case DT_STRTAB:
        strings = reinterpret_cast<const char *>(loaded_address(
            info->dlpi_addr, static_cast<uintptr_t>(entry->d_un.d_ptr)));
        break;
    }
  }
  if (relocations == nullptr || relocation_size == 0 || symbols == nullptr ||
      strings == nullptr) {
    return 1;
  }

  const long page_size = sysconf(_SC_PAGESIZE);
  const size_t count = relocation_size / sizeof(ElfW(Rela));
  for (size_t index = 0; index < count; ++index) {
    const ElfW(Rela) &relocation = relocations[index];
    size_t symbol_index = ELF64_R_SYM(relocation.r_info);
    const char *name = strings + symbols[symbol_index].st_name;
    if (strcmp(name, "__android_log_print") != 0) continue;
    auto *slot = reinterpret_cast<void **>(
        info->dlpi_addr + relocation.r_offset);
    uintptr_t page = reinterpret_cast<uintptr_t>(slot) &
        ~static_cast<uintptr_t>(page_size - 1);
    if (mprotect(reinterpret_cast<void *>(page), static_cast<size_t>(page_size),
                 PROT_READ | PROT_WRITE) != 0) {
      return 1;
    }
    *slot = reinterpret_cast<void *>(&quiet_privacy_log);
    (void)mprotect(reinterpret_cast<void *>(page),
                   static_cast<size_t>(page_size), PROT_READ);
    return 1;
  }
  return 1;
}

void stop(int signal_number) {
  stop_signal = signal_number;
  running = 0;
}

void *symbol(void *library, const char *name) {
  dlerror();
  void *result = dlsym(library, name);
  const char *error = dlerror();
  if (error != nullptr) {
    __android_log_print(ANDROID_LOG_ERROR, kTag,
                        "missing symbol %s: %s", name, error);
    return nullptr;
  }
  return result;
}

int claim_singleton() {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  constexpr char name[] = "portal.camera.led.watch";
  static_assert(sizeof(name) < sizeof(address.sun_path));
  memcpy(address.sun_path + 1, name, sizeof(name) - 1);
  socklen_t length = static_cast<socklen_t>(
      sizeof(address.sun_family) + 1 + sizeof(name) - 1);
  if (bind(fd, reinterpret_cast<sockaddr *>(&address), length) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

}  // namespace

int main() {
  prctl(PR_SET_NAME, "portal-led-watch", 0, 0, 0);
  int singleton = claim_singleton();
  if (singleton < 0) {
    __android_log_print(ANDROID_LOG_INFO, kTag,
                        "watchdog already running or socket unavailable: %s",
                        strerror(errno));
    return 0;
  }

  signal(SIGTERM, stop);
  signal(SIGINT, stop);

  void *library = dlopen(kClientLibrary, RTLD_NOW | RTLD_LOCAL);
  if (library == nullptr) {
    __android_log_print(ANDROID_LOG_ERROR, kTag, "dlopen failed: %s",
                        dlerror());
    return 1;
  }
  real_log_vprint = reinterpret_cast<LogVPrint>(
      dlsym(RTLD_DEFAULT, "__android_log_vprint"));
  dl_iterate_phdr(silence_privacy_client_logs, nullptr);
  auto constructor = reinterpret_cast<Constructor>(symbol(library, kConstructor));
  auto destructor = reinterpret_cast<Destructor>(symbol(library, kDestructor));
  auto connect = reinterpret_cast<ConnectMethod>(symbol(library, kConnect));
  auto disconnect = reinterpret_cast<VoidMethod>(symbol(library, kDisconnect));
  auto clear = reinterpret_cast<BoolMethod>(symbol(library, kClear));
  auto get = reinterpret_cast<BoolMethod>(symbol(library, kGet));
  if (constructor == nullptr || destructor == nullptr || connect == nullptr ||
      disconnect == nullptr || clear == nullptr || get == nullptr) {
    dlclose(library);
    return 1;
  }

  alignas(16) unsigned char client[0x100]{};
  constructor(client, 0, 0, true);
  bool connected = connect(client) == 0;
  __android_log_print(ANDROID_LOG_INFO, kTag,
                      "watchdog started uid=%d", getuid());
  if (connected) {
    __android_log_print(ANDROID_LOG_INFO, kTag,
                        "watchdog connected uid=%d", getuid());
  }

  unsigned failures = 0;
  unsigned reconnect_ticks = 0;
  unsigned heartbeat_ticks = 0;
  while (running) {
    if (!connected) {
      if (++reconnect_ticks >= 20) {
        reconnect_ticks = 0;
        connected = connect(client) == 0;
        if (connected) {
          failures = 0;
          __android_log_print(ANDROID_LOG_INFO, kTag,
                              "watchdog connected uid=%d", getuid());
        }
      }
    } else {
      bool should_clear = get(client) || ++heartbeat_ticks >= 240;
      if (should_clear) {
        heartbeat_ticks = 0;
        if (clear(client)) {
          failures = 0;
        } else if (++failures >= 20) {
          __android_log_print(ANDROID_LOG_WARN, kTag,
                              "clearLed failed; reconnecting");
          disconnect(client);
          connected = false;
          failures = 0;
          reconnect_ticks = 0;
        }
      }
    }
    usleep(250000);
  }

  if (connected) disconnect(client);
  __android_log_print(ANDROID_LOG_INFO, kTag,
                      "watchdog exiting signal=%d", stop_signal);
  destructor(client);
  dlclose(library);
  close(singleton);
  return 0;
}
