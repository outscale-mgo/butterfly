/* Copyright 2015 Outscale SAS
 *
 * This file is part of Butterfly.
 *
 * Butterfly is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation.
 *
 * Butterfly is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Butterfly.  If not, see <http://www.gnu.org/licenses/>.
 */
extern "C" {
#include <unistd.h>
#include <syslog.h>
#include <execinfo.h>
#include <glib.h>

#include <amqp.h>
#include <amqp_tcp_socket.h>

#include <packetgraph/packetgraph.h>
}
#include <iostream>
#include <ctime>
#include <thread>
#include <fstream>
#include <string>
#include <sstream>
#include <memory>
#include "api/server/app.h"
#include "api/server/graph.h"
#include "api/server/simpleini/SimpleIni.hpp"
#include "api/version.h"
#include "api/common/crypto.h"

namespace app {
Stats::Stats() {
    start_date = time(nullptr);
    request_counter = 0;
}

Config::Config() {
    api_endpoint = "tcp://0.0.0.0:9999";
    log_level = "error";
    graph_core_id = 0;
    packet_trace = false;
    dpdk_args = DPDK_DEFAULT_ARGS;
    tid = 0;
    nic_mtu = "";
    dpdk_port = 0;
    no_offload = 0;
}

void no_logger(int, const char *, va_list) {
    return;
}

void (*logger)(int, const char *, va_list) = no_logger;

void print_log(int l, const char *format, va_list av) {
    vdprintf(2, format, av);
    dprintf(2, "\n");
}

bool Config::parse_cmd(int argc, char **argv) {
    int ret = true;
    int silentlog = false;
    int dpdkhelp = false;
    int showversion = false;

    auto gfree = [](gchar *p) { g_free(p); };
    std::unique_ptr<gchar, decltype(gfree)> config_path_cmd(nullptr, gfree);
    std::unique_ptr<gchar, decltype(gfree)> external_ip_cmd(nullptr, gfree);
    std::unique_ptr<gchar, decltype(gfree)> api_endpoint_cmd(nullptr, gfree);
    std::unique_ptr<gchar, decltype(gfree)> log_level_cmd(nullptr, gfree);
    std::unique_ptr<gchar, decltype(gfree)> socket_folder_cmd(nullptr, gfree);
    std::unique_ptr<gchar, decltype(gfree)> graph_core_id_cmd(nullptr, gfree);
    std::unique_ptr<gchar, decltype(gfree)> dpdk_args_cmd(nullptr, gfree);
    std::unique_ptr<gchar, decltype(gfree)> nic_mtu_cmd(nullptr, gfree);
    std::unique_ptr<gchar, decltype(gfree)> dpdk_port_cmd(nullptr, gfree);
    std::unique_ptr<gchar, decltype(gfree)> key_path_cmd(nullptr, gfree);

    static GOptionEntry entries[] = {
        {"config", 'c', 0, G_OPTION_ARG_FILENAME, &config_path_cmd,
         "Path to configuration file", "FILE"},
        {"ip", 'i', 0, G_OPTION_ARG_STRING, &external_ip_cmd,
         "IP address to use on VXLAN endpoint", "IP_ADDRESS"},
        {"endpoint", 'e', 0, G_OPTION_ARG_STRING, &api_endpoint_cmd,
         "API endpoint to bind (default is 'tcp://0.0.0.0:9999')",
         "API_ENDPOINT"},
        {"log-level", 'l', 0, G_OPTION_ARG_STRING, &log_level_cmd,
         "Log level to use. LOG_LEVEL can be 'none', 'error' (default), " \
         "'warning', 'info' or 'debug'", "LOG_LEVEL"},
        {"version", 'V', 0, G_OPTION_ARG_NONE, &showversion,
         "Show butterflyd version and exit", nullptr},
        {"socket-dir", 's', 0, G_OPTION_ARG_FILENAME, &socket_folder_cmd,
         "Create network sockets in specified directory", "DIR"},
        {"graph-cpu-core", 'u', 0, G_OPTION_ARG_STRING, &graph_core_id_cmd,
         "Choose your CPU core where to run packet processing (default=0)",
         "ID"},
        {"packet-trace", 't', 0, G_OPTION_ARG_NONE, &config.packet_trace,
         "Trace packets going through Butterfly", nullptr},
        {"no-syslog", 0, 0, G_OPTION_ARG_NONE, &silentlog,
         "use printf instead of syslog for login", nullptr},
        {"dpdk-help", 0, 0, G_OPTION_ARG_NONE, &dpdkhelp,
         "print DPDK help", nullptr},
        {"dpdk-args", 0, 0, G_OPTION_ARG_STRING, &dpdk_args_cmd,
         "set dpdk arguments (default='" DPDK_DEFAULT_ARGS "'", nullptr},
        {"nic-mtu", 'm', 0, G_OPTION_ARG_STRING, &nic_mtu_cmd,
         "set MTU your physical NIC, may fail if not supported. Parameter can"
         " be set to 'max' and butterfly will try to find the maximal MTU.",
         "MTU"},
        {"no-offload", 0, 0, G_OPTION_ARG_NONE, &config.no_offload,
         "block all offloadind features", nullptr},
        {"dpdk-port", 0, 0, G_OPTION_ARG_STRING, &dpdk_port_cmd,
         "choose which dpdk port to use (default=0)", "PORT"},
        {"key", 'k', 0, G_OPTION_ARG_STRING, &key_path_cmd,
         "path to encryption key (raw randomized 32B)", "PATH"},
        { nullptr }
    };
    std::shared_ptr<GOptionContext> context(g_option_context_new(""),
                                            g_option_context_free);

    g_option_context_set_summary(context.get(),
            "butterflyd [OPTIONS]");
    g_option_context_set_description(context.get(), "example:\n"
            "butterflyd --dpdk-args \"-c0xF -n1 --socket-mem 64\" "
            "-i 43.0.0.1 -e tcp://127.0.0.1:8765 -s /tmp");
    g_option_context_add_main_entries(context.get(), entries, nullptr);

    GError *error = nullptr;

    if (!g_option_context_parse(context.get(), &argc, &argv, &error)) {
        if (error != nullptr)
            std::cout << error->message << std::endl;
        return false;
    }

    if (dpdkhelp) {
        dpdk_args = "--help";
        app::graph.Start(dpdk_args);
        app::graph.Stop();
        return false;
    }

    // Ask for version number ?
    if (showversion) {
        std::cout << VERSION_INFO << std::endl;
        return false;
    }

    if (silentlog)
        logger = print_log;
    else
        logger = vsyslog;

    // Get back gchar to config in std::string
    if (config_path_cmd != nullptr)
        config_path = std::string(&*config_path_cmd);
    if (external_ip_cmd != nullptr)
        external_ip = std::string(&*external_ip_cmd);
    if (api_endpoint_cmd != nullptr)
        api_endpoint = std::string(&*api_endpoint_cmd);
    if (log_level_cmd != nullptr)
        log_level = std::string(&*log_level_cmd);
    if (socket_folder_cmd != nullptr)
        socket_folder = std::string(&*socket_folder_cmd);
    if (graph_core_id_cmd != nullptr)
        graph_core_id = std::atoi(&*graph_core_id_cmd);
    if (dpdk_args_cmd != nullptr)
        dpdk_args = std::string(&*dpdk_args_cmd);
    if (nic_mtu_cmd != nullptr)
        nic_mtu = std::string(&*nic_mtu_cmd);
    if (dpdk_port_cmd != nullptr)
        nic_mtu = std::atoi(&*dpdk_port_cmd);
    if (key_path_cmd != nullptr)
        encryption_key_path = std::string(&*key_path_cmd);

    // Load from configuration file if provided
    if (config_path.length() > 0 && !LoadConfigFile(config_path)) {
        std::cerr << "Failed to open configuration file" << std::endl;
        app::log.Error("Failed to open configuration file");
        return false;
    }

    // Load encryption key from file if provided
    if (encryption_key_path.length()) {
        if (Crypto::KeyFromPath(encryption_key_path, &encryption_key)) {
            std::cerr << "Encryption key loaded" << std::endl;
            app::log.Debug("Encryption key loaded");
        } else {
            std::cerr << "Cannot load encryption key" << std::endl;
            app::log.Error("Failed to open encryption key");
            return false;
        }
    } else {
        std::cerr << "No encryption configured" << std::endl;
        app::log.Warning("No encryption configured");
    }

    if (!ret) {
        std::cerr << "wrong usage, butterflyd use -h" << std::endl;
    }
    return ret;
}

bool Config::MissingMandatory() {
    bool ret = false;
    if (external_ip.length() == 0) {
        std::cerr << "IP to use is not set" << std::endl;
        app::log.Error("IP to use is not set");
        ret = true;
    }
    if (socket_folder.length() == 0) {
        std::cerr << "socket folder is not set" << std::endl;
        app::log.Error("socket folder is not set");
        ret = true;
    }

    if (ret)
        app::log.Error("missing mandatory configuration items");
    return ret;
}

Log::Log() {
    // Set default log level
    SetLogLevel("error");

    // Openlog
    Open();
}

Log::~Log() {
    closelog();
}

void Log::Open() {
    openlog("butterfly", LOG_CONS | LOG_PID | LOG_NDELAY | LOG_PERROR,
            LOG_LOCAL0);
}

bool Log::SetLogLevel(std::string level) {
    if (level == "none") {
        setlogmask(0);
    } else if (level == "error") {
        setlogmask(LOG_UPTO(LOG_ERR));
    } else if (level == "warning") {
        setlogmask(LOG_UPTO(LOG_WARNING));
    } else if (level == "info") {
        setlogmask(LOG_UPTO(LOG_INFO));
    } else if (level == "debug") {
        setlogmask(LOG_UPTO(LOG_DEBUG));
    } else {
        Error("Log::SetLogLevel: non existing log level");
        return false;
    }
    return true;
}

#define DEBUG_INTERNAL(TYPE, last_args) do {                            \
        va_list ap;                                                     \
                                                                        \
        va_start(ap, last_args);                                        \
        logger(LOG_##TYPE,                                              \
               (std::string("<"#TYPE"> ") + message).c_str(), ap);      \
        va_end(ap);                                                     \
    } while (0)

void Log::Debug(const char *message, ...) {
    DEBUG_INTERNAL(DEBUG, message);
}

void Log::Info(const char *message, ...) {
    DEBUG_INTERNAL(INFO, message);
}

void Log::Warning(const char *message, ...) {
    DEBUG_INTERNAL(WARNING, message);
}

void Log::Error(const char *message, ...) {
    DEBUG_INTERNAL(ERR, message);
}

void Log::Debug(const std::string msg, ...) {
    const char *message = msg.c_str();
    DEBUG_INTERNAL(DEBUG, msg);
}

void Log::Info(const std::string msg, ...) {
    const char *message = msg.c_str();
    DEBUG_INTERNAL(INFO, msg);
}

void Log::Warning(const std::string msg, ...) {
    const char *message = msg.c_str();
    DEBUG_INTERNAL(WARNING, msg);
}

void Log::Error(const std::string msg, ...) {
    const char *message = msg.c_str();
    DEBUG_INTERNAL(ERR, msg);
}

#undef DEBUG_INTERNAL

bool LoadConfigFile(std::string config_path) {
    CSimpleIniA ini;
    ini.SetUnicode();
    if (ini.LoadFile(config_path.c_str()) != SI_OK)
        return false;
    const char *v;

    v = ini.GetValue("general", "log-level", "_");
    if (std::string(v) != "_") {
        config.log_level = v;
        log.SetLogLevel(config.log_level);
        std::string m = "LoadConfig: get log-level from config: " +
            config.log_level;
        log.Debug(m);
    }

    v = ini.GetValue("general", "ip", "_");
    if (std::string(v) != "_") {
        config.external_ip = v;
        std::string m = "LoadConfig: get ip from config: " +
            config.external_ip;
        log.Debug(m);
    }

    v = ini.GetValue("general", "endpoint", "_");
    if (std::string(v) != "_") {
        config.api_endpoint = v;
        std::string m = "LoadConfig: get endpoint from config: " +
            config.api_endpoint;
        log.Debug(m);
    }

    v = ini.GetValue("general", "socket-dir", "_");
    if (std::string(v) != "_") {
        config.socket_folder = v;
        std::string m = "LoadConfig: get socket-dir from config: " +
            config.socket_folder;
        log.Debug(m);
    }

    v = ini.GetValue("general", "graph-core-id", "_");
    if (std::string(v) != "_") {
        config.graph_core_id = std::stoi(v);
        std::string m = "LoadConfig: get graph-core-id from config: ";

        m += config.graph_core_id;
        log.Debug(m);
    }

    v = ini.GetValue("general", "dpdk-args", "_");
    if (std::string(v) != "_") {
        config.dpdk_args = v;
        std::string m = "LoadConfig: get dpdk-args from config: " +
            config.dpdk_args;
        log.Debug(m);
    }

    v = ini.GetValue("general", "nic-mtu", "_");
    if (std::string(v) != "_") {
        config.nic_mtu = v;
        std::string m = "LoadConfig: get nic_mtu from config: " +
            config.nic_mtu;
        log.Debug(m);
    }

    v = ini.GetValue("general", "dpdk-port", "_");
    if (std::string(v) != "_") {
        config.dpdk_port = std::stoi(v);
        std::string m = "LoadConfig: get dpdk-port from config: ";

        m += config.dpdk_port;
        log.Debug(m);
    }

    v = ini.GetValue("security", "encryption_key_path", "_");
    if (std::string(v) != "_") {
        config.encryption_key_path = v;
        log.Debug("LoadConfig: get encryption key path from config");
    }

    return true;
}

void SegvHandler(int sig) {
  void *array[32];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, 32);

  // print out all the frames to stderr
  fprintf(stderr, "Server Error: segmentation fault");
  backtrace_symbols_fd(array, size, STDERR_FILENO);
  exit(139);
}

void SignalRegister() {
    signal(SIGINT, SignalHandler);
    signal(SIGQUIT, SignalHandler);
    signal(SIGSTOP, SignalHandler);
    signal(SIGTERM, SignalHandler);
    signal(SIGSEGV, SegvHandler);
}

void SignalHandler(int signum) {
    std::string m = "got signal " + std::to_string(signum);
    app::log.Info(m);
    app::request_exit = true;
}

std::string GraphDot(struct pg_brick *brick) {
    char *buf = pg_brick_dot(brick);
    if (!buf) {
        LOG_ERROR_("can't generate dot");
        return std::string("");
    }
    std::string ret(buf);
    free(buf);
    return ret;
}

bool PgStart(std::string dpdk_args) {
    pg_npf_nworkers = 0;
    log.Debug(dpdk_args);
    return pg_start_str(dpdk_args.c_str()) >= 0;
}

// Global instances in app namespace
bool request_exit(false);
Config config;
Stats stats;
Model model;
Log log;
Graph graph;
struct pg_error *pg_error;

}  // namespace app

#define BASH(STR) if (system(("/bin/bash -c \"" + (STR) + "\"").c_str()))

static const char *SrcCgroup() {
    if (!access("/sys/fs/cgroup/cpu/cpu.shares", R_OK)) {
        return "/sys/fs/cgroup/cpu";
    } else if (!access("/sys/fs/cgroup/cpu.shares", R_OK)) {
        return "/sys/fs/cgroup";
    }
    return NULL;
}

static int InitCgroup(int multiplier) {
    const char *cgroupPath = SrcCgroup();

    if (!cgroupPath)
        return -1;
    std::string create_dir("mkdir " + std::string(cgroupPath) + "/butterfly");

    BASH(create_dir) {
        LOG_WARNING_("can't create butterfly cgroup, fail cmd '%s'",
                     create_dir.c_str());
    }
    BASH("echo $(( `cat " + std::string(cgroupPath) + "/cpu.shares` * " +
         std::to_string(multiplier) + " )) > " +
         cgroupPath + "/butterfly/cpu.shares") {
        LOG_WARNING_("can't set cgroup priority");
    }

    // new cgroup use a diferent directory for cpushare and cpu
    // if not, we need to initilize some files
    BASH(std::string("! cat ") + cgroupPath + "/cpuset.mems >> /dev/null") {
            BASH("echo `cat " + std::string(cgroupPath) + "/cpuset.mems` > " +
                 cgroupPath + "/butterfly/cpuset.mems") {
                    LOG_WARNING_("can't set cgroup cpuset.mems");
            }
            BASH("echo `cat " + std::string(cgroupPath) + "/cpuset.cpus` > " +
                 cgroupPath + "/butterfly/cpuset.cpus") {
                    LOG_WARNING_("can't set cgroup cpuset.cpus");
            }
    }
    return 0;
}

void app::SetCgroup() {
    if (!SrcCgroup() || !app::config.tid)
        return;
    std::string setStr;
    std::string unsetOtherStr;
    std::ostringstream oss;

    oss << app::config.tid;
    setStr = "echo " + oss.str() + " > " + SrcCgroup() + "/butterfly/tasks";
    unsetOtherStr = "grep -v " + oss.str() + " " + SrcCgroup() +
                    "/butterfly/tasks | while read ligne; do echo $ligne > " +
                    SrcCgroup() + "/tasks ; done";

    BASH(setStr) {
        LOG_WARNING_("can't set cgroup pid");
    }
    BASH(unsetOtherStr) {
        LOG_WARNING_("can't properly set cgroup pid");
    }
}

void app::DestroyCgroup() {
    if (!SrcCgroup())
        return;
    BASH("cat " + std::string(SrcCgroup()) +
         "/butterfly/tasks | while read ligne; do echo $ligne > " +
         SrcCgroup() + "/bin/bash /tasks ; done") {
        LOG_WARNING_("can't unset task from butterfly cgroup");
    }
    BASH("rmdir " + std::string(SrcCgroup()) + "/butterfly") {
        LOG_WARNING_("can't destroy cgroup");
    }
}

#undef BASH


int chk_on_amqp_error(amqp_rpc_reply_t x, char const *context) {
    switch (x.reply_type) {
	case AMQP_RESPONSE_NORMAL:
            return 0;

	case AMQP_RESPONSE_NONE:
            fprintf(stderr, "%s: missing RPC reply type!\n", context);
            break;

	case AMQP_RESPONSE_LIBRARY_EXCEPTION:
            fprintf(stderr, "%s: %s\n", context, amqp_error_string2(x.library_error));
            break;

	case AMQP_RESPONSE_SERVER_EXCEPTION:
            switch (x.reply.id) {
		case AMQP_CONNECTION_CLOSE_METHOD: {
                    amqp_connection_close_t *m =
                            (amqp_connection_close_t *)x.reply.decoded;
                    fprintf(stderr, "%s: server connection error %uh, message: %.*s\n",
                            context, m->reply_code, (int)m->reply_text.len,
                            (char *)m->reply_text.bytes);
                    break;
		}
		case AMQP_CHANNEL_CLOSE_METHOD: {
                    amqp_channel_close_t *m = (amqp_channel_close_t *)x.reply.decoded;
                    fprintf(stderr, "%s: server channel error %uh, message: %.*s\n",
                            context, m->reply_code, (int)m->reply_text.len,
                            (char *)m->reply_text.bytes);
                    break;
		}
		default:
                    fprintf(stderr, "%s: unknown server error, method id 0x%08X\n",
                            context, x.reply.id);
                    break;
            }
            break;
    }

    return 1;
}

static void dump_row(long count, int numinrow, int *chs) {
  int i;

  printf("%08lX:", count - numinrow);

  if (numinrow > 0) {
    for (i = 0; i < numinrow; i++) {
      if (i == 8) {
        printf(" :");
      }
      printf(" %02X", chs[i]);
    }
    for (i = numinrow; i < 16; i++) {
      if (i == 8) {
        printf(" :");
      }
      printf("   ");
    }
    printf("  ");
    for (i = 0; i < numinrow; i++) {
      if (isprint(chs[i])) {
        printf("%c", chs[i]);
      } else {
        printf(".");
      }
    }
  }
  printf("\n");
}

static int rows_eq(int *a, int *b) {
  int i;

  for (i = 0; i < 16; i++)
    if (a[i] != b[i]) {
      return 0;
    }

  return 1;
}

void amqp_dump(void const *buffer, size_t len) {
  unsigned char *buf = (unsigned char *)buffer;
  long count = 0;
  int numinrow = 0;
  int chs[16];
  int oldchs[16] = {0};
  int showed_dots = 0;
  size_t i;

  for (i = 0; i < len; i++) {
    int ch = buf[i];

    if (numinrow == 16) {
      int j;

      if (rows_eq(oldchs, chs)) {
        if (!showed_dots) {
          showed_dots = 1;
          printf(
              "          .. .. .. .. .. .. .. .. : .. .. .. .. .. .. .. ..\n");
        }
      } else {
        showed_dots = 0;
        dump_row(count, numinrow, chs);
      }

      for (j = 0; j < 16; j++) {
        oldchs[j] = chs[j];
      }

      numinrow = 0;
    }

    count++;
    chs[numinrow++] = ch;
  }

  dump_row(count, numinrow, chs);

  if (numinrow != 0) {
    printf("%08lX:\n", count);
  }
}

int
main(int argc, char *argv[]) {
    int ret  = 0;
    std::string hostname = "127.0.0.1";
    int port = 4242;
    int status;
    amqp_bytes_t queuename;
    char const *exchange = "amq.direct";
    char const *bindingkey = "broadcast";

    try {
        // Register signals
        app::SignalRegister();

        // Check parameters
        if (!app::config.parse_cmd(argc, argv))
            return 0;

        // Set log level from options
        app::log.SetLogLevel(app::config.log_level);

        // Ready to start ?
        if (app::config.MissingMandatory()) {
            std::cerr << "Some arguments are missing, please check " \
            "configuration or use --help" << std::endl;
            return 0;
        }

        app::log.Info("butterfly starts");

        // Prepare & run packetgraph
        if (!app::graph.Start(app::config.dpdk_args)) {
            app::log.Error("cannot start packetgraph, exiting");
            app::request_exit = true;
        }
        InitCgroup(POLL_THREAD_MULTIPLIER);
        // Prepare & run API server
	amqp_connection_state_t conn;
	amqp_socket_t *socket = NULL;

	conn = amqp_new_connection();

#define die(...)				\
	do {fprintf(stderr, __VA_ARGS__); ret = 1; goto out;} while (0)

#define die_on_amqp_error(func, err_msg)				\
	if ((ret = chk_on_amqp_error(func, err_msg)) != 0)              \
            goto out;

#define die_on_error(f, ...)                    \
        if (f < 0)                              \
            die(__VA_ARGS__);

	socket = amqp_tcp_socket_new(conn);
	if (!socket) {
            die("creating TCP socket %s %d", hostname.c_str(), port);
	}

	printf("yay %s\n", app::config.api_endpoint.c_str());
	status = amqp_socket_open(socket, hostname.c_str(), port);
	if (status) {
            die("opening TCP socket %s %d %s", hostname.c_str(), port, strerror(-status));
	}

	die_on_amqp_error(amqp_login(conn, "/", 0, 131072, 0, AMQP_SASL_METHOD_PLAIN,
				     "guest", "guest"),
			  "Logging in");
	amqp_channel_open(conn, 1);
	die_on_amqp_error(amqp_get_rpc_reply(conn), "Opening channel");

	{
            amqp_queue_declare_ok_t *r = amqp_queue_declare(
                conn, 1, amqp_empty_bytes, 0, 0, 0, 1, amqp_empty_table);
            die_on_amqp_error(amqp_get_rpc_reply(conn), "Declaring queue");
            queuename = amqp_bytes_malloc_dup(r->queue);
            if (queuename.bytes == NULL) {
                fprintf(stderr, "Out of memory while copying queue name");
                return 1;
            }
	}

	amqp_queue_bind(conn, 1, queuename, amqp_cstring_bytes(exchange),
			amqp_cstring_bytes(bindingkey), amqp_empty_table);
	die_on_amqp_error(amqp_get_rpc_reply(conn), "Binding queue");

	amqp_basic_consume(conn, 1, queuename, amqp_empty_bytes, 0, 1, 0,
			   amqp_empty_table);
	die_on_amqp_error(amqp_get_rpc_reply(conn), "Consuming");
	while (1) {
            LOG_DEBUG_("RabbitMQ received a message");

            amqp_rpc_reply_t res;
            amqp_envelope_t envelope;

            amqp_maybe_release_buffers(conn);

            res = amqp_consume_message(conn, &envelope, NULL, 0);

            if (AMQP_RESPONSE_NORMAL != res.reply_type) {
                break;
            }

            printf("Delivery %u, exchange %.*s routingkey %.*s\n",
                   (unsigned)envelope.delivery_tag, (int)envelope.exchange.len,
                   (char *)envelope.exchange.bytes, (int)envelope.routing_key.len,
                   (char *)envelope.routing_key.bytes);

            if (envelope.message.properties._flags & AMQP_BASIC_CONTENT_TYPE_FLAG) {
                printf("Content-type: %.*s\n",
                       (int)envelope.message.properties.content_type.len,
                       (char *)envelope.message.properties.content_type.bytes);
            }
            printf("----\n");

            amqp_dump(envelope.message.body.bytes, envelope.message.body.len);

            amqp_destroy_envelope(&envelope);
	}
	amqp_bytes_free(queuename);

	die_on_amqp_error(amqp_channel_close(conn, 1, AMQP_REPLY_SUCCESS),
			  "Closing channel");
	die_on_amqp_error(amqp_connection_close(conn, AMQP_REPLY_SUCCESS),
			  "Closing connection");
	die_on_error(amqp_destroy_connection(conn), "Ending connection");

	LOG_DEBUG_("RabbitMQ send");
    } catch (std::exception & e) {
        LOG_ERROR_("%s", e.what());
        ret = 1;
    }

out:
    // Ask graph to stop
    app::graph.Stop();

    app::log.Info("butterfly exit");
    return ret;
}
