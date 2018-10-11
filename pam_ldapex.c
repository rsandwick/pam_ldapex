#include <syslog.h> /* #define LOG_* */
#include <pwd.h>    /* getpwnam(), struct passwd */

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

#if defined(__GNUC__)
#define UNUSED(x) x##_UNUSED __attribute__((unused))
#else
#define UNUSED(x) x##_UNUSED
#endif


struct options_t {
    const char* binddn;
    const char* uri;
};
typedef struct options_t options_t;


static int _pam_parse_args(pam_handle_t* pamh,
                           int argc,
                           const char** argv,
                           options_t* opts)
{
    opts->binddn = "";
    opts->uri = "";

    for (; argc-- > 0; ++argv)
    {
        if (!strncmp(*argv, "binddn=", 7)) {
            opts->binddn = *argv+7;
        } else if (!strncmp(*argv, "uri=", 4)) {
            opts->uri = *argv+4;
        } else {
            pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
        }
    }
    return PAM_SUCCESS;
}


static int _pam_format(pam_handle_t* pamh,
                       const char* format,
                       char** dest)
{
    char buffer[PAM_MAX_MSG_SIZE];
    char* output = buffer;

    const char* head = strchr(format, '%');
    const char* tail = format;

    size_t available = PAM_MAX_MSG_SIZE;
    size_t length;

    const char* str = NULL;

    while (head) {
        length = (head - tail);
        if (available < length) {
            return PAM_AUTH_ERR;
        } else {
            /***TODO: error check */
            strncpy(output, tail, length);
            output += length;
            available -= length;
        }
        switch (*++head) {

        case 's':
        case 'u':
            head++;
            if (pam_get_user(pamh, &str, NULL) != PAM_SUCCESS)
                return PAM_AUTH_ERR;
            break;
        case '\0':
            str = "";
            break;

        default:
            pam_syslog(pamh, LOG_ERR, "unexpected format character: %c", *head);
        case '%':
            *output++ = *head++;
            *output = '\0';
            available--;
            tail = head;

        }
        tail = head++;
        if (str) {
            length = strlen(str);
            strncpy(output, str, length);
            output += length;
            available -= length;
            *output = '\0';
        }
        if (!(head = strchr(head, '%'))) {
            /* end of string */
            length = strlen(tail);
            strncpy(output, tail, length);
            output += length;
            available -= length;
            *output = '\0';
        }
    }

    length = strlen(buffer) + 1;
    *dest = (char*)malloc(length);
    memset(*dest, 0, length);

    if (!dest) {
        pam_syslog(pamh, LOG_ERR, "memory error: needed %ld bytes", length);
        return PAM_BUF_ERR;
    }
    strncpy(*dest, buffer, length);

    return PAM_SUCCESS;
}


static inline int _ldap_to_pam_rc(int ldap_rc)
{
    switch (ldap_rc) {
    case LDAP_SUCCESS:
        /* everything was fine */
        return PAM_SUCCESS;
    case LDAP_UNAVAILABLE:
    case LDAP_TIMELIMIT_EXCEEDED:
    case LDAP_OPERATIONS_ERROR:
    case LDAP_BUSY:
    case LDAP_LOOP_DETECT:
    case LDAP_SERVER_DOWN:
    case LDAP_TIMEOUT:
    case LDAP_CONNECT_ERROR:
    case LDAP_NO_RESULTS_RETURNED:
        /* cannot access LDAP correctly */
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* something else went wrong */
    return PAM_AUTH_ERR;
}

static inline int _ldap_verify(const char* host,
                               const char* binddn,
                               const char* pw)
{
    LDAP* ld;
    int ldap_rc, pam_rc;

    ldap_rc = ldap_initialize(&ld, host);
    pam_rc = _ldap_to_pam_rc(ldap_rc);
    if (pam_rc != PAM_SUCCESS)
        return pam_rc;

    ldap_rc = ldap_simple_bind_s(ld, binddn, pw);
    return _ldap_to_pam_rc(ldap_rc);
}


PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh,
                                   int UNUSED(flags),
                                   int argc,
                                   const char** argv)
{
    const char* user;
    const char* pass;
    struct passwd* pwd;
    int ret;
    options_t opts;

    ret = _pam_parse_args(pamh, argc, argv, &opts);
    if (ret != PAM_SUCCESS) {
        return ret;
    }

    ret = pam_get_user(pamh, &user, NULL);
    if (ret != PAM_SUCCESS) {
        return ret;
    }

    ret = pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);
    if (ret != PAM_SUCCESS) {
        return ret;
    }

    /* ensure uri and binddn PAM parameters were specified */
    if (strlen(opts.uri) == 0 || strlen(opts.binddn) == 0) {
        pam_syslog(pamh, LOG_NOTICE, "unable to find URI and/or BINDDN");
        return PAM_AUTH_ERR;
    }

    /* get passwd entry for desired user. This is required for UID checking. */
    pwd = getpwnam(user);
    if (!pwd) {
        pam_syslog(pamh, LOG_NOTICE, "unable to get uid for user %s", user);
        return PAM_AUTH_ERR;
    }

    /* ldap_simple_bind_s accepts empty passwords for all users, therefore we
       catch and deny them here... */
    if (strlen(pass) == 0) {
        pam_syslog(pamh, LOG_NOTICE, "ldap authentication failure: "
                   "empty password for user %s", user);
        return PAM_AUTH_ERR;
    }

    /* parse & prepare binddn */
    ret = _pam_format(pamh, opts.binddn, (char**)&opts.binddn);
    if (ret != PAM_SUCCESS) {
        return ret;
    }
    pam_syslog(pamh, LOG_NOTICE, "using binddn=%s", opts.binddn);

    /* check against ldap database */
    ret = _ldap_verify(opts.uri, opts.binddn, pass);
    if (ret != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_NOTICE, "ldap authentication failure: "
                   "user=<%s> uri=<%s> binddn=<%s>",
                   user, opts.uri, opts.binddn);
    }
    return ret;
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t* UNUSED(pamh),
                              int UNUSED(flags),
                              int UNUSED(argc),
                              const char** UNUSED(argv))
{
    return PAM_SUCCESS;
}
