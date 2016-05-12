#include "common/config.h"
#include "rgw_common.h"

#include "civetweb/civetweb.h"

#define dout_subsys ceph_subsys_civetweb


int rgw_civetweb_log_callback(const struct mg_connection *conn, const char *buf) {
  dout(0) << "DSS API LOGGING: " << (void *)conn << ": " << buf << dendl;
  return 0;
}

int rgw_civetweb_log_access_callback(const struct mg_connection *conn, const char *buf) {
  dout(1) << "DSS API LOGGING: " << (void *)conn << ": " << buf << dendl;
  return 0;
}


