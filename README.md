# cpuid

cpuid tool modified for macOS, forked from https://www.etallen.com/cpuid.html .

NB: `thread_policy_set(THREAD_AFFINITY_POLICY)` cannot force bind threads to a specific core, so per-core info is not reliable. (`process local APIC physical ID` may be duplicated)
