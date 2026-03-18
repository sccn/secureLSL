// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_ESP32_H
#define LSL_ESP32_H

#include "lsl_esp32_types.h"

/* --- Clock --- */

/* Returns the current time in seconds (monotonic, high-resolution).
 * This is the timestamp source for LSL samples on ESP32. */
double lsl_esp32_local_clock(void);

/* --- Resolver --- */

/* Resolve a stream by property.
 * prop: "name", "type", or "source_id" (NULL means find all)
 * value: value to match (NULL means find all)
 * timeout: seconds to wait for discovery responses
 * result: receives the first matching stream info (caller must free with
 *         lsl_esp32_destroy_streaminfo if not passed to create_inlet)
 *
 * Returns 1 if a stream was found, 0 if not found within timeout. */
int lsl_esp32_resolve_stream(const char *prop, const char *value, double timeout,
                             lsl_esp32_stream_info_t *result);

/* Resolve all visible streams.
 * results: array of stream info pointers (caller must free each)
 * max_results: size of results array
 *
 * Returns number of streams found. */
int lsl_esp32_resolve_streams(double timeout, lsl_esp32_stream_info_t *results, int max_results);

/* --- Stream info --- */

/* Create a stream info descriptor.
 * name: human-readable stream name, must not be NULL (e.g., "EEG_Stream")
 * type: content type, or NULL for empty (e.g., "EEG", "Markers")
 * channel_count: number of channels (1 to LSL_ESP32_MAX_CHANNELS)
 * nominal_srate: nominal sampling rate in Hz (0 for irregular, must be >= 0)
 * channel_format: data type per channel (must be a valid LSL_ESP32_FMT_* value)
 * source_id: unique identifier for this data source, or NULL for empty */
lsl_esp32_stream_info_t lsl_esp32_create_streaminfo(const char *name, const char *type,
                                                    int channel_count, double nominal_srate,
                                                    lsl_esp32_channel_format_t channel_format,
                                                    const char *source_id);

/* Stream info accessors (read-only access to opaque handle fields).
 * All are NULL-safe: string accessors return "" if info is NULL,
 * get_channel_count returns 0, get_nominal_srate returns 0.0,
 * get_channel_format returns 0 (not a valid enum value). */
const char *lsl_esp32_get_name(lsl_esp32_stream_info_t info);
const char *lsl_esp32_get_type(lsl_esp32_stream_info_t info);
int lsl_esp32_get_channel_count(lsl_esp32_stream_info_t info);
double lsl_esp32_get_nominal_srate(lsl_esp32_stream_info_t info);
lsl_esp32_channel_format_t lsl_esp32_get_channel_format(lsl_esp32_stream_info_t info);

/* Free a stream info descriptor.
 * Do not call if the info was passed to lsl_esp32_create_outlet
 * (the outlet takes ownership and frees it on destroy). */
void lsl_esp32_destroy_streaminfo(lsl_esp32_stream_info_t info);

/* --- Security --- */

/* --- Key Management --- */

/* Key sizes for Ed25519 */
#define LSL_ESP32_KEY_PUBLIC_SIZE  32
#define LSL_ESP32_KEY_SECRET_SIZE  64
#define LSL_ESP32_KEY_BASE64_SIZE  45 /* base64 of 32-byte public key + null */
#define LSL_ESP32_KEY_SBASE64_SIZE 89 /* base64 of 64-byte secret key + null */

/* Generate a new Ed25519 keypair and store in NVS.
 * Requires sodium_init() to have been called.
 * Returns LSL_ESP32_OK on success. */
lsl_esp32_err_t lsl_esp32_generate_keypair(void);

/* Import a keypair from base64-encoded strings and store in NVS.
 * Both keys must be valid base64 with correct sizes.
 * Returns LSL_ESP32_OK on success. */
lsl_esp32_err_t lsl_esp32_import_keypair(const char *base64_pub, const char *base64_priv);

/* Export the public key as a base64 string.
 * out must be at least LSL_ESP32_KEY_BASE64_SIZE bytes.
 * Returns LSL_ESP32_OK on success, LSL_ESP32_ERR_NOT_FOUND if no key. */
lsl_esp32_err_t lsl_esp32_export_pubkey(char *out, size_t out_len);

/* Check if a keypair is provisioned in NVS.
 * Returns 1 if keys exist, 0 if not. */
int lsl_esp32_has_keypair(void);

/* Enable secureLSL encryption for all subsequent outlets and inlets.
 * Must be called BEFORE creating outlets/inlets. Requires a keypair
 * to be provisioned in NVS (via key_manager_generate or key_manager_import).
 * This is a one-way toggle for the process lifetime; there is no
 * disable function. ESP32 lab devices typically run one security mode
 * for their entire uptime. To switch modes, reboot.
 * Returns LSL_ESP32_OK on success, LSL_ESP32_ERR_NOT_FOUND if no keypair,
 * or LSL_ESP32_ERR_SECURITY if libsodium initialization fails. */
lsl_esp32_err_t lsl_esp32_enable_security(void);

/* Check if security is currently enabled.
 * Returns 1 if enabled, 0 if not. */
int lsl_esp32_security_enabled(void);

/* --- Outlet --- */

/* Create an outlet for pushing samples to the network.
 * Starts UDP discovery and TCP data servers automatically.
 * Requires WiFi to be connected (uses STA interface for IP).
 *
 * info: stream info descriptor (ownership transferred to outlet on success;
 *       caller must free on failure)
 * chunk_size: preferred chunk size (0 = per-sample)
 * max_buffered: reserved for future use (currently ignored; fixed 64-slot buffer) */
lsl_esp32_outlet_t lsl_esp32_create_outlet(lsl_esp32_stream_info_t info, int chunk_size,
                                           int max_buffered);

/* Destroy the outlet, stopping all network servers and freeing all resources
 * including the associated stream info. */
void lsl_esp32_destroy_outlet(lsl_esp32_outlet_t outlet);

/* Push a single sample. timestamp=0 means use local_clock().
 * The type suffix must match the outlet's channel_format:
 *   _f = float32, _d = double64, _i = int32, _s = int16, _c = int8.
 * Returns LSL_ESP32_ERR_INVALID_ARG on format mismatch. */
lsl_esp32_err_t lsl_esp32_push_sample_f(lsl_esp32_outlet_t outlet, const float *data,
                                        double timestamp);

lsl_esp32_err_t lsl_esp32_push_sample_d(lsl_esp32_outlet_t outlet, const double *data,
                                        double timestamp);

lsl_esp32_err_t lsl_esp32_push_sample_i(lsl_esp32_outlet_t outlet, const int32_t *data,
                                        double timestamp);

lsl_esp32_err_t lsl_esp32_push_sample_s(lsl_esp32_outlet_t outlet, const int16_t *data,
                                        double timestamp);

lsl_esp32_err_t lsl_esp32_push_sample_c(lsl_esp32_outlet_t outlet, const int8_t *data,
                                        double timestamp);

/* Returns 1 if any consumers are connected, 0 otherwise */
int lsl_esp32_have_consumers(lsl_esp32_outlet_t outlet);

/* --- Inlet --- */

/* Create an inlet to receive samples from a remote outlet.
 * info: stream info from resolve (ownership transferred to inlet on success;
 *       caller must free on failure)
 * Connects to the outlet's TCP port and validates test patterns.
 * Returns the inlet handle on success, or NULL on failure. */
lsl_esp32_inlet_t lsl_esp32_create_inlet(lsl_esp32_stream_info_t info);

/* Destroy the inlet, closing the TCP connection and freeing all resources
 * including the associated stream info. */
void lsl_esp32_destroy_inlet(lsl_esp32_inlet_t inlet);

/* Pull a single float32 sample from the inlet.
 * buf: output buffer (must hold channel_count floats)
 * buf_len: size of buf in bytes
 * timestamp: receives the sample timestamp
 * timeout: seconds to wait (0 = non-blocking)
 * Returns LSL_ESP32_OK, LSL_ESP32_ERR_TIMEOUT, LSL_ESP32_ERR_INVALID_ARG,
 * or LSL_ESP32_ERR_NO_MEMORY. */
lsl_esp32_err_t lsl_esp32_inlet_pull_sample_f(lsl_esp32_inlet_t inlet, float *buf, int buf_len,
                                              double *timestamp, double timeout);

#endif /* LSL_ESP32_H */
