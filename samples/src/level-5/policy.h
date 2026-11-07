#ifndef REVERSESHIELD_POLICY_H
#define REVERSESHIELD_POLICY_H

#include <stddef.h>
#include <stdint.h>

/* Resource kinds and roles are deliberately small. The numeric values are
 * part of the sample's observable policy; source-level protection experiments
 * may transform them, but the C API must keep its meaning. */
enum resource_kind { RESOURCE_REPORT = 1, RESOURCE_ARCHIVE = 2, RESOURCE_EXPORT = 3 };
enum access_role { ROLE_VIEWER = 1, ROLE_EDITOR = 2, ROLE_OWNER = 3 };

/* Request shape used by all Level 5 functions. Field order is observable in
 * the compiled struct layout and is intentionally stable for comparisons. */
struct access_request {
    enum resource_kind resource;
    enum access_role role;
    uint32_t flags;
    uint32_t tenant_id;
};

int policy_allows(const struct access_request *request);
const char *policy_reason(const struct access_request *request);

#endif
