#include <jni.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "engine/engine.h"
#include "security/grant.h"
#include "security/sign.h"
#include "tunnel/tun.h"
#include "core/internal/diag_json.h"
#include "userspace_gateway.h"

void bowie_android_set_vpn_authorized(int authorized);

typedef struct android_engine {
    bowie_engine_t *engine;
    bowie_tun_t *tun;
    bowie_android_userspace_gateway_t *userspace_gateway;
    char *stun_host;
    char *turn_host;
    char *turn_user;
    char *turn_pass;
    char *signal_relay_host;
    char *signal_metered_api_key;
    char *signal_metered_channel;
} android_engine_t;

static android_engine_t *from_handle(jlong handle)
{
    return (android_engine_t *)(intptr_t)handle;
}

/* A valid Android arm64 pointer can have its top-byte tag set, making its
 * signed jlong representation negative. Reserve zero as the only failure
 * sentinel and report native startup errors as Java exceptions. */
static jlong throw_start_error(JNIEnv *env, bowie_error_t error)
{
    jclass exception_class = (*env)->FindClass(env, "java/lang/IllegalStateException");
    if (exception_class != NULL) {
        char message[64];
        (void)snprintf(message, sizeof(message), "Bowie engine start failed (%d)", (int)error);
        (*env)->ThrowNew(env, exception_class, message);
        (*env)->DeleteLocalRef(env, exception_class);
    }
    return 0;
}

static char *copy_jstring(JNIEnv *env, jstring value)
{
    if (value == NULL) return NULL;
    const char *utf = (*env)->GetStringUTFChars(env, value, NULL);
    if (utf == NULL) return NULL;
    size_t len = strlen(utf);
    char *copy = (char *)malloc(len + 1u);
    if (copy != NULL) memcpy(copy, utf, len + 1u);
    (*env)->ReleaseStringUTFChars(env, value, utf);
    return copy;
}

static void free_jni_config(android_engine_t *handle)
{
    if (handle->stun_host != NULL) free(handle->stun_host);
    if (handle->turn_host != NULL) free(handle->turn_host);
    if (handle->turn_user != NULL) free(handle->turn_user);
    if (handle->turn_pass != NULL) {
        memset(handle->turn_pass, 0, strlen(handle->turn_pass));
        free(handle->turn_pass);
    }
    if (handle->signal_relay_host != NULL) free(handle->signal_relay_host);
    if (handle->signal_metered_api_key != NULL) {
        memset(handle->signal_metered_api_key, 0, strlen(handle->signal_metered_api_key));
        free(handle->signal_metered_api_key);
    }
    if (handle->signal_metered_channel != NULL) free(handle->signal_metered_channel);
}

static void empty_string_to_null(char **value)
{
    if (*value != NULL && (*value)[0] == '\0') {
        free(*value);
        *value = NULL;
    }
}

JNIEXPORT jlong JNICALL Java_org_bowie_BowieVpnService_nativeStart(
    JNIEnv *env, jclass cls, jint tun_fd, jstring bootstrap_host,
    jint bootstrap_port, jstring stun_host, jint stun_port,
    jstring turn_host, jint turn_port, jstring turn_user, jstring turn_pass,
    jstring signal_relay_host, jint signal_relay_port,
    jstring signal_metered_api_key, jstring signal_metered_channel,
    jbyteArray identity_seed_bytes)
{
    (void)cls;
    {
        char details[128];
        (void)snprintf(details, sizeof(details),
            "{\"bootstrap_configured\":%s,\"stun_configured\":%s,\"turn_configured\":%s}",
            bootstrap_port > 0 ? "true" : "false",
            stun_port > 0 ? "true" : "false",
            turn_port > 0 ? "true" : "false");
        bowie_diag_json_emit("INFO", "JNI", "NATIVE_START_BEGIN", NULL, details);
    }
    android_engine_t *handle;
    bowie_engine_config_t cfg;
    uint8_t identity_seed[BOWIE_SIGN_SEED_LEN] = {0};
    bowie_error_t rc;
    if (identity_seed_bytes == NULL ||
        (*env)->GetArrayLength(env, identity_seed_bytes) != BOWIE_SIGN_SEED_LEN ||
        bootstrap_port < 0 || bootstrap_port > 65535 ||
        (bootstrap_port != 0 && bootstrap_host == NULL) ||
        stun_port < 0 || stun_port > 65535 ||
        (stun_port != 0 && stun_host == NULL) ||
        turn_port < 0 || turn_port > 65535 ||
        (turn_port != 0 && turn_host == NULL) ||
        signal_relay_port < 0 || signal_relay_port > 65535 ||
        (signal_relay_port != 0 && signal_relay_host == NULL)) {
        close(tun_fd);
        return throw_start_error(env, BOWIE_ERR_INVAL);
    }
    handle = (android_engine_t *)calloc(1u, sizeof(*handle));
    if (handle == NULL) {
        close(tun_fd);
        return throw_start_error(env, BOWIE_ERR_NOMEM);
    }
    handle->stun_host = copy_jstring(env, stun_host);
    handle->turn_host = copy_jstring(env, turn_host);
    handle->turn_user = copy_jstring(env, turn_user);
    handle->turn_pass = copy_jstring(env, turn_pass);
    handle->signal_relay_host = copy_jstring(env, signal_relay_host);
    handle->signal_metered_api_key = copy_jstring(env, signal_metered_api_key);
    handle->signal_metered_channel = copy_jstring(env, signal_metered_channel);
    if ((stun_host != NULL && handle->stun_host == NULL) ||
        (turn_host != NULL && handle->turn_host == NULL) ||
        (turn_user != NULL && handle->turn_user == NULL) ||
        (turn_pass != NULL && handle->turn_pass == NULL) ||
        (signal_relay_host != NULL && handle->signal_relay_host == NULL) ||
        (signal_metered_api_key != NULL && handle->signal_metered_api_key == NULL) ||
        (signal_metered_channel != NULL && handle->signal_metered_channel == NULL)) {
        rc = BOWIE_ERR_NOMEM;
        goto fail;
    }
    empty_string_to_null(&handle->stun_host);
    empty_string_to_null(&handle->turn_host);
    empty_string_to_null(&handle->turn_user);
    empty_string_to_null(&handle->turn_pass);
    empty_string_to_null(&handle->signal_relay_host);
    empty_string_to_null(&handle->signal_metered_api_key);
    empty_string_to_null(&handle->signal_metered_channel);
    if ((handle->stun_host == NULL) != (stun_port == 0) ||
        (handle->turn_host == NULL) != (turn_port == 0) ||
        ((handle->turn_user == NULL) != (handle->turn_pass == NULL)) ||
        (handle->turn_host == NULL && handle->turn_user != NULL)) {
        rc = BOWIE_ERR_INVAL;
        goto fail;
    }
    if ((handle->signal_relay_host == NULL) != (signal_relay_port == 0)) {
        rc = BOWIE_ERR_INVAL;
        goto fail;
    }
    if ((handle->signal_metered_api_key == NULL) != (handle->signal_metered_channel == NULL) ||
        (handle->signal_metered_api_key != NULL && handle->signal_relay_host != NULL)) {
        rc = BOWIE_ERR_INVAL;
        goto fail;
    }
    rc = bowie_tun_wrap_fd(&handle->tun, tun_fd, 1);
    if (rc != BOWIE_OK) {
        close(tun_fd);
        goto fail;
    }
    bowie_engine_default_config(&cfg);
    if (!bowie_android_userspace_gateway_new(&handle->userspace_gateway)) {
        rc = BOWIE_ERR_NOMEM;
        goto fail;
    }
    (*env)->GetByteArrayRegion(env, identity_seed_bytes, 0,
        BOWIE_SIGN_SEED_LEN, (jbyte *)identity_seed);
    if ((*env)->ExceptionCheck(env)) { rc = BOWIE_ERR_INVAL; goto fail; }
    cfg.identity_seed = identity_seed;
    cfg.source_egress = bowie_android_userspace_gateway_process;
    cfg.source_egress_context = handle->userspace_gateway;
    if (stun_port != 0 || turn_port != 0) cfg.allow_server = 1;
    cfg.stun_host = handle->stun_host;
    cfg.stun_port = (uint16_t)stun_port;
    cfg.turn_host = handle->turn_host;
    cfg.turn_port = (uint16_t)turn_port;
    cfg.turn_user = handle->turn_user;
    cfg.turn_pass = handle->turn_pass;
    cfg.signal_relay_host = handle->signal_relay_host;
    cfg.signal_relay_port = (uint16_t)signal_relay_port;
    if (handle->signal_metered_api_key != NULL) {
        cfg.signal_backend = BOWIE_SIGNAL_BACKEND_METERED;
        cfg.signal_metered_api_key = handle->signal_metered_api_key;
        cfg.signal_metered_channel = handle->signal_metered_channel;
    }
    rc = bowie_engine_new(&cfg, &handle->engine);
    memset(identity_seed, 0, sizeof(identity_seed));
    if (rc != BOWIE_OK) goto fail;
    if (bootstrap_port != 0) {
        const char *host_utf = (*env)->GetStringUTFChars(env, bootstrap_host, NULL);
        if (host_utf == NULL) {
            rc = BOWIE_ERR_NOMEM;
            goto fail;
        }
        rc = bowie_engine_add_bootstrap(handle->engine, host_utf,
                                        (uint16_t)bootstrap_port);
        (*env)->ReleaseStringUTFChars(env, bootstrap_host, host_utf);
        if (rc != BOWIE_OK) goto fail;
    }
    rc = bowie_engine_start(handle->engine, handle->tun);
    if (rc != BOWIE_OK) goto fail;
    bowie_android_set_vpn_authorized(1);
    {
        char details[96];
        (void)snprintf(details, sizeof(details),
                       "{\"signal_port\":%u,\"bootstrap_configured\":%s,\"stun_configured\":%s,\"turn_configured\":%s}",
                       (unsigned)bowie_engine_signal_port(handle->engine),
                       bootstrap_port != 0 ? "true" : "false",
                       stun_port != 0 ? "true" : "false",
                       turn_port != 0 ? "true" : "false");
        bowie_diag_json_emit("INFO", "JNI", "NATIVE_START_OK", NULL, details);
    }
    return (jlong)(intptr_t)handle;
fail:
    memset(identity_seed, 0, sizeof(identity_seed));
    {
        char details[64];
        (void)snprintf(details, sizeof(details), "{\"error_code\":%d}", (int)rc);
        bowie_diag_json_emit("ERROR", "JNI", "NATIVE_START_FAILED", NULL, details);
    }
    if (handle->engine != NULL) bowie_engine_free(handle->engine);
    if (handle->tun != NULL) bowie_tun_close(handle->tun);
    bowie_android_userspace_gateway_free(handle->userspace_gateway);
    free_jni_config(handle);
    free(handle);
    return throw_start_error(env, rc);
}

JNIEXPORT jbyteArray JNICALL Java_org_bowie_BowieVpnService_nativePeerId(
    JNIEnv *env, jclass cls, jlong raw_handle)
{
    (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    if (handle == NULL || handle->engine == NULL) return NULL;
    bowie_peer_id_t peer;
    bowie_engine_peer_id(handle->engine, &peer);
    jbyteArray result = (*env)->NewByteArray(env, BOWIE_PEER_ID_LEN);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, BOWIE_PEER_ID_LEN,
                                   (const jbyte *)peer.bytes);
    }
    return result;
}

JNIEXPORT jbyteArray JNICALL Java_org_bowie_BowieVpnService_nativeConnectedPeerId(
    JNIEnv *env, jclass cls, jlong raw_handle)
{
    (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    bowie_peer_id_t peer;
    if (handle == NULL || handle->engine == NULL ||
        bowie_engine_connected_peer_id(handle->engine, &peer) != BOWIE_OK)
        return NULL;
    jbyteArray result = (*env)->NewByteArray(env, BOWIE_PEER_ID_LEN);
    if (result != NULL)
        (*env)->SetByteArrayRegion(env, result, 0, BOWIE_PEER_ID_LEN,
                                   (const jbyte *)peer.bytes);
    return result;
}

JNIEXPORT jint JNICALL Java_org_bowie_BowieVpnService_nativeSignalPort(
    JNIEnv *env, jclass cls, jlong raw_handle)
{
    (void)env; (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    return (handle == NULL || handle->engine == NULL) ? 0 :
           (jint)bowie_engine_signal_port(handle->engine);
}

JNIEXPORT jint JNICALL Java_org_bowie_BowieVpnService_nativeDisconnect(
    JNIEnv *env, jclass cls, jlong raw_handle)
{
    (void)env; (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    if (handle == NULL || handle->engine == NULL) return BOWIE_ERR_INVAL;
    return (jint)bowie_engine_disconnect(handle->engine);
}

JNIEXPORT jint JNICALL Java_org_bowie_BowieVpnService_nativeRevokeGrant(
    JNIEnv *env, jclass cls, jlong raw_handle, jbyteArray grant_id_bytes)
{
    (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    bowie_grant_id_t grant_id;
    if (handle == NULL || handle->engine == NULL || grant_id_bytes == NULL ||
        (*env)->GetArrayLength(env, grant_id_bytes) != BOWIE_GRANT_ID_LEN)
        return BOWIE_ERR_INVAL;
    (*env)->GetByteArrayRegion(env, grant_id_bytes, 0, BOWIE_GRANT_ID_LEN,
                               (jbyte *)grant_id.bytes);
    return (jint)bowie_engine_revoke_grant(handle->engine, &grant_id);
}

static int copy_peer(JNIEnv *env, jbyteArray input, bowie_peer_id_t *peer);

JNIEXPORT jbyteArray JNICALL Java_org_bowie_BowieVpnService_nativeIssueGrant(
    JNIEnv *env, jclass cls, jlong raw_handle, jbyteArray subject_bytes,
    jlong ttl_ms, jlong max_egress_bytes)
{
    (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    bowie_peer_id_t subject;
    bowie_grant_t grant;
    uint8_t wire[BOWIE_GRANT_WIRE_LEN];
    long written;
    if (handle == NULL || handle->engine == NULL || ttl_ms <= 0 || max_egress_bytes < 0 ||
        !copy_peer(env, subject_bytes, &subject)) return NULL;
    memset(&grant, 0, sizeof(grant));
    bowie_error_t rc = bowie_engine_issue_limited_grant(handle->engine, &subject,
        BOWIE_GRANT_INTERNET_USE, (uint64_t)ttl_ms,
        (uint64_t)max_egress_bytes, &grant);
    if (rc != BOWIE_OK) {
        memset(&grant, 0, sizeof(grant));
        return NULL;
    }
    written = bowie_grant_serialize(&grant, wire, sizeof(wire));
    if (written != (long)(sizeof(wire) - sizeof(grant.signature))) {
        memset(&grant, 0, sizeof(grant));
        memset(wire, 0, sizeof(wire));
        return NULL;
    }
    memcpy(wire + written, grant.signature, sizeof(grant.signature));
    jbyteArray result = (*env)->NewByteArray(env, (jsize)sizeof(wire));
    if (result != NULL)
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)sizeof(wire), (const jbyte *)wire);
    memset(&grant, 0, sizeof(grant));
    memset(wire, 0, sizeof(wire));
    return result;
}

JNIEXPORT jint JNICALL Java_org_bowie_BowieVpnService_nativeSetGrant(
    JNIEnv *env, jclass cls, jlong raw_handle, jbyteArray grant_wire)
{
    (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    bowie_grant_t grant;
    uint8_t wire[BOWIE_GRANT_WIRE_LEN];
    if (handle == NULL || handle->engine == NULL || grant_wire == NULL ||
        (*env)->GetArrayLength(env, grant_wire) != (jsize)sizeof(wire))
        return BOWIE_ERR_INVAL;
    (*env)->GetByteArrayRegion(env, grant_wire, 0, (jsize)sizeof(wire),
                               (jbyte *)wire);
    if ((*env)->ExceptionCheck(env)) {
        memset(wire, 0, sizeof(wire));
        return BOWIE_ERR_INVAL;
    }
    bowie_error_t rc = bowie_grant_deserialize(wire, sizeof(wire), &grant);
    memset(wire, 0, sizeof(wire));
    if (rc == BOWIE_OK) rc = bowie_engine_set_grant(handle->engine, &grant);
    memset(&grant, 0, sizeof(grant));
    return (jint)rc;
}

static int copy_peer(JNIEnv *env, jbyteArray input, bowie_peer_id_t *peer)
{
    if (input == NULL || (*env)->GetArrayLength(env, input) != BOWIE_PEER_ID_LEN) return 0;
    (*env)->GetByteArrayRegion(env, input, 0, BOWIE_PEER_ID_LEN, (jbyte *)peer->bytes);
    return !(*env)->ExceptionCheck(env);
}

JNIEXPORT jint JNICALL Java_org_bowie_BowieVpnService_nativeAccept(
    JNIEnv *env, jclass cls, jlong raw_handle, jbyteArray expected_peer)
{
    (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    bowie_peer_id_t peer;
    if (handle == NULL || handle->engine == NULL || !copy_peer(env, expected_peer, &peer))
        return BOWIE_ERR_INVAL;
    bowie_diag_json_emit("INFO", "JNI", "ACCEPT_BEGIN", NULL,
                         "{\"timeout_ms\":120000}");
    jint rc = (jint)bowie_engine_accept_from(handle->engine, &peer, 120000u);
    {
        char details[64];
        (void)snprintf(details, sizeof(details), "{\"result\":%d}", (int)rc);
        bowie_diag_json_emit(rc == BOWIE_OK ? "INFO" : "ERROR", "JNI",
                             "ACCEPT_END", NULL, details);
    }
    return rc;
}

JNIEXPORT jint JNICALL Java_org_bowie_BowieVpnService_nativeAnnounceRoom(
    JNIEnv *env, jclass cls, jlong raw_handle, jstring room_name)
{
    (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    char *room = copy_jstring(env, room_name);
    if (handle == NULL || handle->engine == NULL || room == NULL) {
        free(room);
        return BOWIE_ERR_INVAL;
    }
    bowie_error_t rc = bowie_engine_announce_room(handle->engine, room);
    free(room);
    return (jint)rc;
}

JNIEXPORT jint JNICALL Java_org_bowie_BowieVpnService_nativeAcceptDiscovered(
    JNIEnv *env, jclass cls, jlong raw_handle)
{
    (void)env; (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    if (handle == NULL || handle->engine == NULL) return BOWIE_ERR_INVAL;
    return (jint)bowie_engine_accept_discovered(handle->engine, 120000u);
}

JNIEXPORT jint JNICALL Java_org_bowie_BowieVpnService_nativeConnectRoom(
    JNIEnv *env, jclass cls, jlong raw_handle, jstring room_name)
{
    (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    char *room = copy_jstring(env, room_name);
    if (handle == NULL || handle->engine == NULL || room == NULL) {
        free(room);
        return BOWIE_ERR_INVAL;
    }
    bowie_error_t rc = bowie_engine_connect_room(handle->engine, room, 120000u);
    free(room);
    return (jint)rc;
}

JNIEXPORT jint JNICALL Java_org_bowie_BowieVpnService_nativeConnect(
    JNIEnv *env, jclass cls, jlong raw_handle, jbyteArray expected_peer,
    jstring host, jint port)
{
    (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    bowie_peer_id_t peer;
    bowie_addr_t endpoint;
    if (handle == NULL || handle->engine == NULL || host == NULL || port <= 0 || port > 65535 ||
        !copy_peer(env, expected_peer, &peer)) return BOWIE_ERR_INVAL;
    memset(&endpoint, 0, sizeof(endpoint));
    const char *host_utf = (*env)->GetStringUTFChars(env, host, NULL);
    if (host_utf == NULL) return BOWIE_ERR_NOMEM;
    endpoint.family = BOWIE_AF_INET;
    endpoint.port = (uint16_t)port;
    int parsed = inet_pton(AF_INET, host_utf, endpoint.addr);
    (*env)->ReleaseStringUTFChars(env, host, host_utf);
    if (parsed != 1) return BOWIE_ERR_INVAL;
    {
        char details[128];
        (void)snprintf(details, sizeof(details),
            "{\"destination_ip\":\"%u.%u.%u.%u\",\"destination_port\":%u,\"timeout_ms\":120000}",
            endpoint.addr[0], endpoint.addr[1], endpoint.addr[2], endpoint.addr[3],
            (unsigned)endpoint.port);
        bowie_diag_json_emit("INFO", "JNI", "CONNECT_DIRECT_BEGIN", NULL, details);
    }
    jint rc = (jint)bowie_engine_connect_direct(handle->engine, &peer, &endpoint, 120000u);
    {
        char details[64];
        (void)snprintf(details, sizeof(details), "{\"result\":%d}", (int)rc);
        bowie_diag_json_emit(rc == BOWIE_OK ? "INFO" : "ERROR", "JNI",
                             "CONNECT_DIRECT_END", NULL, details);
    }
    return rc;
}

JNIEXPORT jint JNICALL Java_org_bowie_BowieVpnService_nativeConnectDht(
    JNIEnv *env, jclass cls, jlong raw_handle, jbyteArray expected_peer)
{
    (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    bowie_peer_id_t peer;
    if (handle == NULL || handle->engine == NULL ||
        !copy_peer(env, expected_peer, &peer)) return BOWIE_ERR_INVAL;
    bowie_diag_json_emit("INFO", "JNI", "CONNECT_DHT_BEGIN", NULL,
                         "{\"timeout_ms\":120000}");
    jint rc = (jint)bowie_engine_connect(handle->engine, &peer, 120000u);
    {
        char details[64];
        (void)snprintf(details, sizeof(details), "{\"result\":%d}", (int)rc);
        bowie_diag_json_emit(rc == BOWIE_OK ? "INFO" : "ERROR", "JNI",
                             "CONNECT_DHT_END", NULL, details);
    }
    return rc;
}

JNIEXPORT jint JNICALL Java_org_bowie_BowieVpnService_nativeConnectRelay(
    JNIEnv *env, jclass cls, jlong raw_handle, jbyteArray expected_peer)
{
    (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    bowie_peer_id_t peer;
    if (handle == NULL || handle->engine == NULL ||
        !copy_peer(env, expected_peer, &peer)) return BOWIE_ERR_INVAL;
    bowie_diag_json_emit("INFO", "JNI", "CONNECT_RELAY_BEGIN", NULL,
                         "{\"timeout_ms\":120000}");
    jint rc = (jint)bowie_engine_connect_relay(handle->engine, &peer, 120000u);
    {
        char details[64];
        (void)snprintf(details, sizeof(details), "{\"result\":%d}", (int)rc);
        bowie_diag_json_emit(rc == BOWIE_OK ? "INFO" : "ERROR", "JNI",
                             "CONNECT_RELAY_END", NULL, details);
    }
    return rc;
}

JNIEXPORT jint JNICALL Java_org_bowie_BowieVpnService_nativeReplaceTunFd(
    JNIEnv *env, jclass cls, jlong raw_handle, jint tun_fd)
{
    (void)env; (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    if (handle == NULL || handle->engine == NULL) {
        if (tun_fd >= 0) close(tun_fd);
        return BOWIE_ERR_INVAL;
    }
    jint rc = (jint)bowie_engine_replace_tun_fd(handle->engine, tun_fd);
    if (rc == BOWIE_OK) {
        bowie_diag_json_emit("INFO", "JNI", "TUN_FD_REPLACED", NULL,
                             "{\"peer_session_preserved\":true}");
    } else {
        char details[64];
        (void)snprintf(details, sizeof(details), "{\"result\":%d}", (int)rc);
        bowie_diag_json_emit("ERROR", "JNI", "TUN_FD_REPLACE_FAILED", NULL, details);
    }
    return rc;
}

JNIEXPORT void JNICALL Java_org_bowie_BowieVpnService_nativeStop(
    JNIEnv *env, jclass cls, jlong raw_handle)
{
    (void)env; (void)cls;
    android_engine_t *handle = from_handle(raw_handle);
    if (handle == NULL) return;
    bowie_engine_free(handle->engine);
    bowie_tun_close(handle->tun);
    bowie_android_userspace_gateway_free(handle->userspace_gateway);
    bowie_android_set_vpn_authorized(0);
    free_jni_config(handle);
    free(handle);
}
