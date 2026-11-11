/* Self-authored, static-analysis-only hardened variant of Level 5.
 * The workbench never launches this program. The local buffer makes stack
 * canary and FORTIFY imports observable with the build flags; snprintf is
 * bounded. Compiler flags are evidence of mitigation properties, not proof
 * of memory safety or exploit resistance. */
#include "policy.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    const struct access_request request = {RESOURCE_ARCHIVE, ROLE_EDITOR, 0u, 7u};
    char reason[128];
    const char *message = policy_reason(&request);
    if (strlen(message) >= sizeof reason) return 2;
    strcpy(reason, message); /* safe after the length bound; compiler may optimize the check */
    printf("policy decision: %s\n", reason);
    return policy_allows(&request) ? 0 : 1;
}
