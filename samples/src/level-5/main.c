/*
 * Sample: Level 5 - Policy Engine (entry point).
 * Purpose: coordinate a small access-request policy across translation units;
 *          gives the analyzer named functions, enums, structs and calls.
 * Input: none. Output: process exit code (0 = allowed, 1 = denied).
 * Safety: compiled only; the workbench never executes this file.
 */
#include "policy.h"

static struct access_request make_request(enum resource_kind resource,
                                          enum access_role role,
                                          uint32_t tenant,
                                          uint32_t flags) {
    struct access_request request = {resource, role, flags, tenant};
    return request;
}

int main(void) {
    struct access_request request = make_request(RESOURCE_ARCHIVE, ROLE_EDITOR, 7u, 0u);
    return policy_allows(&request) ? 0 : 1;
}
