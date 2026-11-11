/*
 * Sample: Level 5 - Policy Engine (rules).
 * Purpose: deterministic local policy decision. The resource -> minimum-role
 *          table is intentionally small and readable for comparison exercises.
 * Input: a populated access_request. Output: allow/deny and a static message.
 * Safety: compiled only; the workbench never executes this file.
 */
#include "policy.h"

#ifdef RS_OLLVM_STRINGS
#include <string.h>
/* OLLVM's string-encryption pass decrypts literals into a temporary buffer.
 * Returning a pointer to that temporary would expose an empty string after
 * the function returns, so the protected build copies the selected message
 * into this static buffer. The public API and the text are unchanged. */
static char protected_reason[128];
#endif

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
    const char *reason;
    if (request == 0) reason = "missing request";
    else if (request->tenant_id == 0u) reason = "tenant is not set";
    else if (!valid_role(request->role)) reason = "unknown role";
    else if ((request->flags & 0x80000000u) != 0u) reason = "blocked by policy flag";
    else if (!policy_allows(request)) reason = "role is below the required level";
    else reason = "allowed by sample policy";
#ifdef RS_OLLVM_STRINGS
    strncpy(protected_reason, reason, sizeof protected_reason - 1u);
    protected_reason[sizeof protected_reason - 1u] = '\0';
    return protected_reason;
#else
    return reason;
#endif
}
