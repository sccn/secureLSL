// Copyright (C) 2026 The Regents of the University of California. All Rights Reserved.
// Author: Seyed Yahya Shirazi, SCCN, INC, UCSD
// See LICENSE in the repository root for terms.

#ifndef LSL_XML_PARSER_H
#define LSL_XML_PARSER_H

#include "lsl_stream_info.h"
#include <stddef.h>

/* Parse LSL shortinfo/fullinfo XML into a stream_info struct.
 * Handles the fixed <info> schema emitted by liblsl outlets.
 * xml must be null-terminated within xml_len bytes.
 * Returns 0 on success, -1 on parse error. */
int xml_parse_stream_info(const char *xml, size_t xml_len, struct lsl_esp32_stream_info *out);

/* Extract the text content of an XML tag from a buffer.
 * Searches for <tag_name>content</tag_name> and copies content to out.
 * Returns length of content, or -1 if tag not found. */
int xml_extract_tag(const char *xml, const char *tag_name, char *out, size_t out_len);

#endif /* LSL_XML_PARSER_H */
