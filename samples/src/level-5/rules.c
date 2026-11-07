/*
 * Sample: Level 5 - Policy Engine (rules).
 * Purpose: deterministic local policy decision. The resource -> minimum-role
 *          table is intentionally small and readable for comparison exercises.
 * Input: a populated access_request. Output: allow/deny and a static message.
 * Safety: compiled only; the workbench never executes this file.
 */
#include "policy.h"

static int valid_role(enum access_role role) {
    return role == ROLE_VIEWER || role == ROLE_EDITOR || role == ROLE_OWNER;
}

static int resource_minimum_role(enum resource_kind resource) {
    switch (resource) {
        case RESOURCE_REPORT: return ROLE_VIEWER;
        case RESOURCE_ARCHIVE: return ROLE_EDITOR;
        case RESOURCE_EXPORT: return ROLE_OWNER;
        default: return 99;
    }
}

int policy_allows(const struct access_request *request) {
    if (request == 0 || request->tenant_id == 0u || !valid_role(request->role)) return 0;
    if ((request->flags & 0x80000000u) != 0u) return 0;
    return (int)request->role >= resource_minimum_role(request->resource);
}

const char *policy_reason(const struct access_request *request) {
    if (request == 0) return "missing request";
    if (request->tenant_id == 0u) return "tenant is not set";
    if (!valid_role(request->role)) return "unknown role";
    if ((request->flags & 0x80000000u) != 0u) return "blocked by policy flag";
    if (!policy_allows(request)) return "role is below the required level";
    return "allowed by sample policy";
}
