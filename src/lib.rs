extern crate libc;
/*
 * seccomp actions
 */
#[allow(non_camel_case_types)]
pub type scmp_filter_ctx = libc::c_void;

/**
 * Error return value
 */
pub const __NR_SCMP_ERROR: libc::c_int = -1;

/**
 * Kill the calling process
 */
pub const SCMP_ACT_KILL_PROCESS: u32 = 0x80000000;
/**
 * Kill the thread
 */
pub const SCMP_ACT_KILL_THREAD: u32 = 0x00000000;
/**
 * Kill the thread, defined for backward compatibility
 */
pub const SCMP_ACT_KILL: u32 = SCMP_ACT_KILL_THREAD;
/**
 * Throw a SIGSYS signal
 */
pub const SCMP_ACT_TRAP: u32 = 0x00030000;
/**
 * Return the specified error code
 */
#[allow(non_snake_case)]
pub fn SCMP_ACT_ERRNO(x: u32) -> u32 {
    0x00050000 | ((x) & 0x0000ffff)
}
/**
 * Notify a tracing process with the specified value
 */
#[allow(non_snake_case)]
pub fn SCMP_ACT_TRACE(x: u32) -> u32 {
    0x7ff00000 | ((x) & 0x0000ffff)
}
/**
 * Allow the syscall to be executed after the action has been logged
 */
pub const SCMP_ACT_LOG: u32 = 0x7ffc0000;
/**
 * Allow the syscall to be executed
 */
pub const SCMP_ACT_ALLOW: u32 = 0x7fff0000;
/**
 * Notify userspace
 */
pub const SCMP_ACT_NOTIFY: u32 = 0x7fc00000;

/**
 * Version information
 */
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct scmp_version {
    major: libc::c_uint,
    minor: libc::c_uint,
    micro: libc::c_uint,
}

/**
 * Filter attributes
 */
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum scmp_filter_attr {
    _SCMP_FLTATR_MIN = 0,
    /** default filter action */
    SCMP_FLTATR_ACT_DEFAULT = 1,
    /** bad architecture action */
    SCMP_FLTATR_ACT_BADARCH = 2,
    /** set NO_NEW_PRIVS on filter load */
    SCMP_FLTATR_CTL_NNP = 3,
    /** sync threads on filter load */
    SCMP_FLTATR_CTL_TSYNC = 4,
    /** allow rules with a -1 syscall */
    SCMP_FLTATR_API_TSKIP = 5,
    /** log not-allowed actions */
    SCMP_FLTATR_CTL_LOG = 6,
    /** disable SSB mitigation */
    SCMP_FLTATR_CTL_SSB = 7,
    /** filter optimization level:
     * 0 - currently unused
     * 1 - rules weighted by priority and complexity (DEFAULT)
     * 2 - binary tree sorted by syscall number
     */
    SCMP_FLTATR_CTL_OPTIMIZE = 8,
    /** return the system return codes */
    SCMP_FLTATR_API_SYSRAWRC = 9,
    _SCMP_FLTATR_MAX = 10,
}

/**
 * Comparison operators
 */
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum scmp_compare {
    _SCMP_CMP_MIN = 0,
    /** not equal */
    SCMP_CMP_NE = 1,
    /** less than */
    SCMP_CMP_LT = 2,
    /** less than or equal */
    SCMP_CMP_LE = 3,
    /** equal */
    SCMP_CMP_EQ = 4,
    /** greater than or equal */
    SCMP_CMP_GE = 5,
    /** greater than */
    SCMP_CMP_GT = 6,
    /** masked equality */
    SCMP_CMP_MASKED_EQ = 7,
    _SCMP_CMP_MAX,
}

/**
 * Architecutres
 */
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub enum scmp_arch {
    /** The native architecture token */
    SCMP_ARCH_NATIVE = 0x0,
    /** The x86 (32-bit) architecture token */
    SCMP_ARCH_X86 = 0x40000003,
    /** The x86-64 (64-bit) architecture token */
    SCMP_ARCH_X86_64 = 0xc000003e,
    /** The x32 (32-bit x86_64) architecture token
        NOTE: this is different from the value used by the kernel because we need to
        be able to distinguish between x32 and x86_64 */
    SCMP_ARCH_X32 = 0x4000003e,
    /** The ARM architecture tokens */
    SCMP_ARCH_ARM = 0x40000028,
    /** AArch64 support for audit was merged in 3.17-rc1 */
    SCMP_ARCH_AARCH64 = 0xc00000b7,
    /** The MIPS architecture tokens */
    SCMP_ARCH_MIPS = 0x8,
    SCMP_ARCH_MIPS64 = 0x80000008,
    SCMP_ARCH_MIPS64N32 = 0xa0000008,
    SCMP_ARCH_MIPSEL = 0x40000008,
    SCMP_ARCH_MIPSEL64 = 0xc0000008,
    SCMP_ARCH_MIPSEL64N32 = 0xe0000008,
    /** The PowerPC architecture tokens */
    SCMP_ARCH_PPC = 0x14,
    SCMP_ARCH_PPC64 = 0x80000015,
    SCMP_ARCH_PPC64LE = 0xc0000015,
    /** The S390 architecture tokens */
    SCMP_ARCH_S390 = 0x16,
    SCMP_ARCH_S390X = 0x80000016,
    /** The PA-RISC hppa architecture tokens */
    SCMP_ARCH_PARISC = 0xf,
    SCMP_ARCH_PARISC64 = 0x8000000f,
    /** The RISC-V architecture tokens */
    SCMP_ARCH_RISCV64 = 0xc00000f3,
    /** The SuperH architecture tokens */
    SCMP_ARCH_SHEB = 0x4000002a,
}

/**
 * Argument datum
 */
#[allow(non_camel_case_types)]
pub type scmp_datum_t = u64;

/**
 * Argument / Value comparison definition
 */
#[derive(Debug)]
#[repr(C)]
pub struct scmp_arg_cmp {
    /** argument number, starting at 0 */
    pub arg: libc::c_uint,
    /** the comparison op, e.g. SCMP_CMP_* */
    pub op: scmp_compare,
    pub datum_a: scmp_datum_t,
    pub datum_b: scmp_datum_t,
}

/**
 * struct seccomp_data - the format the BPF program executes over.
 * @nr: the system call number
 * @arch: indicates system call convention as an AUDIT_ARCH_* value
 *        as defined in <linux/audit.h>.
 * @instruction_pointer: at the time of the system call.
 * @args: up to 6 system call arguments always stored as 64-bit values
 *        regardless of the architecture.
 */
#[derive(Debug)]
#[repr(C)]
pub struct seccomp_data {
    pub nr: libc::c_int,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[derive(Debug)]
#[repr(C)]
pub struct seccomp_notif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: seccomp_data,
}

#[derive(Debug)]
#[repr(C)]
pub struct seccomp_notif_resp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

#[link(name = "seccomp")]
extern "C" {
    /**
     * Query the library version information
     *
     * This function returns a pointer to a populated scmp_version struct, the
     * caller does not need to free the structure when finished.
     */
    pub fn seccomp_version() -> *const scmp_version;
    /**
     * Query the library's level of API support
     *
     * This function returns an API level value indicating the current supported
     * functionality.  It is important to note that this level of support is
     * determined at runtime and therefore can change based on the running kernel
     * and system configuration (e.g. any previously loaded seccomp filters).  This
     * function can be called multiple times, but it only queries the system the
     * first time it is called, the API level is cached and used in subsequent
     * calls.
     *
     * The current API levels are described below:
     *  0 : reserved
     *  1 : base level
     *  2 : support for the SCMP_FLTATR_CTL_TSYNC filter attribute
     *      uses the seccomp(2) syscall instead of the prctl(2) syscall
     *  3 : support for the SCMP_FLTATR_CTL_LOG filter attribute
     *      support for the SCMP_ACT_LOG action
     *      support for the SCMP_ACT_KILL_PROCESS action
     *  4 : support for the SCMP_FLTATR_CTL_SSB filter attrbute
     *  5 : support for the SCMP_ACT_NOTIFY action and notify APIs
     *  6 : support the simultaneous use of SCMP_FLTATR_CTL_TSYNC and notify APIs
     */
    pub fn seccomp_api_get() -> libc::c_uint;
    /**
     * Set the library's level of API support
     *
     * This function forcibly sets the API level of the library at runtime.  Valid
     * API levels are discussed in the description of the seccomp_api_get()
     * function.  General use of this function is strongly discouraged.
     *
     */
    pub fn seccomp_api_set(level: libc::c_uint);
    /**
     * Initialize the filter state
     *
     * @param def_action the default filter action
     *
     * This function initializes the internal seccomp filter state and should
     * be called before any other functions in this library to ensure the filter
     * state is initialized.  Returns a filter context on success, NULL on failure.
     *
     */
    pub fn seccomp_init(def_action: u32) -> *mut scmp_filter_ctx;
    /**
     * Reset the filter state
     *
     * @param ctx the filter context
     * @param def_action the default filter action
     *
     * This function resets the given seccomp filter state and ensures the
     * filter state is reinitialized.  This function does not reset any seccomp
     * filters already loaded into the kernel.  Returns zero on success, negative
     * values on failure.
     *
     */
    pub fn seccomp_reset(ctx: *mut scmp_filter_ctx, def_action: u32) -> libc::c_int;
    /**
     * Destroys the filter state and releases any resources
     *
     * @param ctx the filter context
     *
     * This functions destroys the given seccomp filter state and releases any
     * resources, including memory, associated with the filter state.  This
     * function does not reset any seccomp filters already loaded into the kernel.
     * The filter context can no longer be used after calling this function.
     *
     */
    pub fn seccomp_release(ctx: *mut scmp_filter_ctx);
    /**
     * Merge two filters
     * @param ctx_dst the destination filter context
     * @param ctx_src the source filter context
     *
     * This function merges two filter contexts into a single filter context and
     * destroys the second filter context.  The two filter contexts must have the
     * same attribute values and not contain any of the same architectures; if they
     * do, the merge operation will fail.  On success, the source filter context
     * will be destroyed and should no longer be used; it is not necessary to
     * call seccomp_release() on the source filter context.  Returns zero on
     * success, negative values on failure.
     */
    pub fn seccomp_merge(ctx_dst: *mut scmp_filter_ctx, ctx_src: *mut scmp_filter_ctx) -> libc::c_int;
    /**
     * Return the native architecture token
     *
     * This function returns the native architecture token value, e.g. SCMP_ARCH_*.
     */
    pub fn seccomp_arch_native() -> u32;
    /**
     * Check to see if an existing architecture is present in the filter
     * @param ctx the filter context
     * @param arch_token the architecture token, e.g. SCMP_ARCH_*
     *
     * This function tests to see if a given architecture is included in the filter
     * context.  If the architecture token is SCMP_ARCH_NATIVE then the native
     * architecture will be assumed.  Returns zero if the architecture exists in
     * the filter, -EEXIST if it is not present, and other negative values on
     * failure.
     */
    pub fn seccomp_arch_exist(ctx: *const scmp_filter_ctx, arch_token: u32) -> libc::c_int;
    /**
     * Adds an architecture to the filter
     * @param ctx the filter context
     * @param arch_token the architecture token, e.g. SCMP_ARCH_*
     *
     * This function adds a new architecture to the given seccomp filter context.
     * Any new rules added after this function successfully returns will be added
     * to this architecture but existing rules will not be added to this
     * architecture.  If the architecture token is SCMP_ARCH_NATIVE then the native
     * architecture will be assumed.  Returns zero on success, negative values on
     * failure.
     *
     */
    pub fn seccomp_arch_add(ctx: *mut scmp_filter_ctx, arch_token: u32) -> libc::c_int;

    /**
     * Removes an architecture from the filter
     * @param ctx the filter context
     * @param arch_token the architecture token, e.g. SCMP_ARCH_*
     *
     * This function removes an architecture from the given seccomp filter context.
     * If the architecture token is SCMP_ARCH_NATIVE then the native architecture
     * will be assumed.  Returns zero on success, negative values on failure.
     *
     */
    pub fn seccomp_arch_remove(ctx: *mut scmp_filter_ctx, arch_token: u32) -> libc::c_int;

    /**
     * Resolve the architecture name to a architecture token
     * @param arch_name the architecture name
     *
     * This function resolves the given architecture name to a token suitable for
     * use with libseccomp, returns zero on failure.
     *
     */
    pub fn seccomp_arch_resolve_name(arch_name: *const libc::c_char) -> u32;

    /**
     * Loads the filter into the kernel
     *
     * @param ctx the filter context
     *
     * This function loads the given seccomp filter context into the kernel.  If
     * the filter was loaded correctly, the kernel will be enforcing the filter
     * when this function returns.  Returns zero on success, negative values on
     * error.
     *
     */
    pub fn seccomp_load(ctx: *const scmp_filter_ctx) -> libc::c_int;

    /**
     * Get the value of a filter attribute
     *
     * @param ctx the filter context
     * @param attr the filter attribute name
     * @param value the filter attribute value
     *
     * This function fetches the value of the given attribute name and returns it
     * via @value.  Returns zero on success, negative values on failure.
     *
     */
    pub fn seccomp_attr_get(
        ctx: *const scmp_filter_ctx,
        attr: scmp_filter_attr,
        value: *mut u32,
    ) -> libc::c_int;

    /**
     * Set the value of a filter attribute
     *
     * @param ctx the filter context
     * @param attr the filter attribute name
     * @param value the filter attribute value
     *
     * This function sets the value of the given attribute.  Returns zero on
     * success, negative values on failure.
     *
     */
    pub fn seccomp_attr_set(
        ctx: *mut scmp_filter_ctx,
        attr: scmp_filter_attr,
        value: u32,
    ) -> libc::c_int;

    /**
     * Resolve a syscall name to a number
     * @param arch_token the architecture token, e.g. SCMP_ARCH_*
     * @param name the syscall name
     *
     * Resolve the given syscall name to the syscall number for the given
     * architecture.  Returns the syscall number on success, including negative
     * pseudo syscall numbers (e.g. __PNR_*); returns __NR_SCMP_ERROR on failure.
     */
    pub fn seccomp_syscall_resolve_name_arch(arch_token: u32, name: *const libc::c_char) -> libc::c_int;

    /**
     * Resolve a syscall number to a name
     * @param arch_token the architecture token, e.g. SCMP_ARCH_*
     * @param num the syscall number
     *
     * Resolve the given syscall number to the syscall name for the given
     * architecture; it is up to the caller to free the returned string.  Returns
     * the syscall name on success, NULL on failure.
     *
     */
    pub fn seccomp_syscall_resolve_num_arch(
        arch_token: u32,
        num: libc::c_int,
    ) -> *const libc::c_char;

    /**
     * Resolve a syscall name to a number and perform any rewriting necessary
     * @param arch_token the architecture token, e.g. SCMP_ARCH_*
     * @param name the syscall name
     *
     * Resolve the given syscall name to the syscall number for the given
     * architecture and do any necessary syscall rewriting needed by the
     * architecture.  Returns the syscall number on success, including negative
     * pseudo syscall numbers (e.g. __PNR_*); returns __NR_SCMP_ERROR on failure.
     *
     */
    pub fn seccomp_syscall_resolve_name_rewrite(
        arch_token: u32,
        name: *const libc::c_char
    ) -> libc::c_int;

    /**
     * Resolve a syscall name to a number
     * @param name the syscall name
     *
     * Resolve the given syscall name to the syscall number.  Returns the syscall
     * number on success, including negative pseudo syscall numbers (e.g. __PNR_*);
     * returns __NR_SCMP_ERROR on failure.
     *
     */
    pub fn seccomp_syscall_resolve_name(name: *const libc::c_char) -> libc::c_int;

    /**
     * Set the priority of a given syscall
     *
     * @param ctx the filter context
     * @param syscall the syscall number
     * @param priority priority value, higher value == higher priority
     *
     * This function sets the priority of the given syscall; this value is used
     * when generating the seccomp filter code such that higher priority syscalls
     * will incur less filter code overhead than the lower priority syscalls in the
     * filter.  Returns zero on success, negative values on failure.
     *
     */
    pub fn seccomp_syscall_priority(
        ctx: *mut scmp_filter_ctx,
        syscall: libc::c_int,
        priority: u8,
    ) -> libc::c_int;

    /**
     * Add a new rule to the filter
     *
     * @param ctx the filter context
     * @param action the filter action
     * @param syscall the syscall number
     * @param arg_cnt the number of argument filters in the argument filter chain
     * @param ... scmp_arg_cmp structs (use of SCMP_ARG_CMP() recommended)
     *
     * This function adds a series of new argument/value checks to the seccomp
     * filter for the given syscall; multiple argument/value checks can be
     * specified and they will be chained together (AND'd together) in the filter.
     * If the specified rule needs to be adjusted due to architecture specifics it
     * will be adjusted without notification.  Returns zero on success, negative
     * values on failure.
     *
     */
    pub fn seccomp_rule_add(
        ctx: *mut scmp_filter_ctx,
        action: u32,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        ...
    ) -> libc::c_int;

    /**
     * Add a new rule to the filter
     *
     * @param ctx the filter context
     * @param action the filter action
     * @param syscall the syscall number
     * @param arg_cnt the number of elements in the arg_array parameter
     * @param arg_array array of scmp_arg_cmp structs
     *
     * This function adds a series of new argument/value checks to the seccomp
     * filter for the given syscall; multiple argument/value checks can be
     * specified and they will be chained together (AND'd together) in the filter.
     * If the specified rule needs to be adjusted due to architecture specifics it
     * will be adjusted without notification.  Returns zero on success, negative
     * values on failure.
     *
     */
    pub fn seccomp_rule_add_array(
        ctx: *mut scmp_filter_ctx,
        action: u32,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        arg_array: *const scmp_arg_cmp,
    ) -> libc::c_int;

    /**
     * Add a new rule to the filter
     *
     * @param ctx the filter context
     * @param action the filter action
     * @param syscall the syscall number
     * @param arg_cnt the number of argument filters in the argument filter chain
     * @param ... scmp_arg_cmp structs (use of SCMP_ARG_CMP() recommended)
     *
     * This function adds a series of new argument/value checks to the seccomp
     * filter for the given syscall; multiple argument/value checks can be
     * specified and they will be chained together (AND'd together) in the filter.
     * If the specified rule can not be represented on the architecture the
     * function will fail.  Returns zero on success, negative values on failure.
     *
     */
    pub fn seccomp_rule_add_exact(
        ctx: *mut scmp_filter_ctx,
        action: u32,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        ...
    ) -> libc::c_int;

    /**
     * Add a new rule to the filter
     *
     * @param ctx the filter context
     * @param action the filter action
     * @param syscall the syscall number
     * @param arg_cnt  the number of elements in the arg_array parameter
     * @param arg_array array of scmp_arg_cmp structs
     *
     * This function adds a series of new argument/value checks to the seccomp
     * filter for the given syscall; multiple argument/value checks can be
     * specified and they will be chained together (AND'd together) in the filter.
     * If the specified rule can not be represented on the architecture the
     * function will fail.  Returns zero on success, negative values on failure.
     *
     */
    pub fn seccomp_rule_add_exact_array(
        ctx: *mut scmp_filter_ctx,
        action: u32,
        syscall: libc::c_int,
        arg_cnt: libc::c_uint,
        arg_array: *const scmp_arg_cmp,
    ) -> libc::c_int;

    /**
     * Generate seccomp Pseudo Filter Code (PFC) and export it to a file
     *
     * @param ctx the filter context
     * @param fd the destination fd
     *
     * This function generates seccomp Pseudo Filter Code (PFC) and writes it to
     * the given fd.  Returns zero on success, negative values on failure.
     *
     */
    pub fn seccomp_export_pfc(ctx: *const scmp_filter_ctx, fd: libc::c_int) -> libc::c_int;

    /**
     * Generate seccomp Berkley Packet Filter (BPF) code and export it to a file
     *
     * @param ctx the filter context
     * @param fd the destination fd
     *
     * This function generates seccomp Berkley Packer Filter (BPF) code and writes
     * it to the given fd.  Returns zero on success, negative values on failure.
     *
     */
    pub fn seccomp_export_bpf(ctx: *const scmp_filter_ctx, fd: libc::c_int) -> libc::c_int;

    /**
     * Allocate a pair of notification request/response structures
     * @param req the request location
     * @param resp the response location
     *
     * This function allocates a pair of request/response structure by computing
     * the correct sized based on the currently running kernel. It returns zero on
     * success, and negative values on failure.
     *
     */
    #[cfg(seccomp_notify)]
    pub fn seccomp_notify_alloc(
        req: *mut *mut seccomp_notif,
        resp: *mut *mut seccomp_notif_resp,
    ) -> libc::c_int;

    /**
     * Free a pair of notification request/response structures.
     * @param req the request location
     * @param resp the response location
     */
    #[cfg(seccomp_notify)]
    pub fn seccomp_notify_free(
        req: *mut seccomp_notif,
        resp: *mut seccomp_notif_resp,
    );

    /**
     * Receive a notification from a seccomp notification fd
     * @param fd the notification fd
     * @param req the request buffer to save into
     *
     * Blocks waiting for a notification on this fd. This function is thread safe
     * (synchronization is performed in the kernel). Returns zero on success,
     * negative values on error.
     *
     */
    #[cfg(seccomp_notify)]
    pub fn seccomp_notify_receive(fd: libc::c_int, req: *mut seccomp_notif) -> libc::c_int;

    /**
     * Send a notification response to a seccomp notification fd
     * @param fd the notification fd
     * @param resp the response buffer to use
     *
     * Sends a notification response on this fd. This function is thread safe
     * (synchronization is performed in the kernel). Returns zero on success,
     * negative values on error.
     *
     */
    #[cfg(seccomp_notify)]
    pub fn seccomp_notify_respond(fd: libc::c_int, resp: *mut seccomp_notif_resp) -> libc::c_int;

    /**
     * Check if a notification id is still valid
     * @param fd the notification fd
     * @param id the id to test
     *
     * Checks to see if a notification id is still valid. Returns 0 on success, and
     * negative values on failure.
     *
     */
    #[cfg(seccomp_notify)]
    pub fn seccomp_notify_id_valid(fd: libc::c_int, id: u64) -> libc::c_int;

    /**
     * Return the notification fd from a filter that has already been loaded
     * @param ctx the filter context
     *
     * This returns the listener fd that was generated when the seccomp policy was
     * loaded. This is only valid after seccomp_load() with a filter that makes
     * use of SCMP_ACT_NOTIFY.
     *
     */
    #[cfg(seccomp_notify)]
    pub fn seccomp_notify_fd(ctx: *const scmp_filter_ctx) -> libc::c_int;
}

#[test]
fn does_it_even_work() {
    unsafe {
        let context = seccomp_init(SCMP_ACT_ALLOW);
        let comparator = scmp_arg_cmp {
            arg: 0,
            op: scmp_compare::SCMP_CMP_EQ,
            datum_a: 1000,
            datum_b: 0,
        };
        assert!(seccomp_rule_add(context, SCMP_ACT_KILL, 105, 1, comparator) == 0);
        assert!(seccomp_load(context) == 0);
        //assert!(libc::setuid(1000) == 0);
    }
}
