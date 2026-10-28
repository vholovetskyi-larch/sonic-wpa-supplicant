/*
 * hostapd / Downloadable ACL (Cisco ISE/ACS style) second-pass download
 *
 * An Access-Accept may name a dACL instead of carrying it:
 * "ACS:CiscoSecure-Defined-ACL=#ACSACL#-IP-<name>-<version>".  authmgr then
 * asks for the dACL with the DACL_DOWNLOAD control interface command.  The
 * download is a separate Access-Request with the dACL name as User-Name and
 * the "aaa:service=ip_admission" and "aaa:event=acl-download" Cisco AV-pairs;
 * the server answers with the "ip:inacl#<n>=" AV-pairs, in several parts
 * (Access-Challenge with State) if they don't fit in one packet.  The result
 * goes back to authmgr as a RADIUS_DACL_INFO client status.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "radius/radius.h"
#include "radius/radius_client.h"
#include "radius/radius_attr_parse.h"
#include "hostapd.h"
#include "sta_info.h"
#include "ap_drv_ops.h"
#include "ieee802_1x.h"
#include "ieee802_1x_dacl.h"

#define DACL_DOWNLOAD_TIMEOUT 15   /* seconds, for the whole download */
#define DACL_MAX_ROUNDS       16   /* Access-Challenges, i.e. parts */


static void dacl_finish(struct dacl_download *dl, int ok);


static void dacl_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct dacl_download *dl = eloop_ctx;

	wpa_printf(MSG_INFO, "dACL %s: download timed out", dl->name);
	dacl_finish(dl, 0);
}


static int dacl_add_cisco_avpair(struct radius_msg *msg, const char *avpair)
{
	u8 buf[RADIUS_VENDOR_ID_SIZE + 2 + 128];
	size_t len = os_strlen(avpair);

	if (len > sizeof(buf) - RADIUS_VENDOR_ID_SIZE - 2)
		return -1;
	WPA_PUT_BE32(buf, RADIUS_VENDOR_ID_CISCO);
	buf[RADIUS_VENDOR_ID_SIZE] = RADIUS_VENDOR_ATTR_CISCO_AV_PAIR;
	buf[RADIUS_VENDOR_ID_SIZE + 1] = 2 + len;
	os_memcpy(buf + RADIUS_VENDOR_ID_SIZE + 2, avpair, len);
	if (!radius_msg_add_attr(msg, RADIUS_ATTR_VENDOR_SPECIFIC, buf,
				 RADIUS_VENDOR_ID_SIZE + 2 + len))
		return -1;
	return 0;
}


static int dacl_request_send(struct dacl_download *dl)
{
	struct hostapd_data *hapd = dl->hapd;
	struct radius_msg *msg;

	dl->identifier = radius_client_get_id(hapd->radius);
	msg = radius_msg_new(RADIUS_CODE_ACCESS_REQUEST, dl->identifier);
	if (!msg)
		return -1;

	if (radius_msg_make_authenticator(msg) < 0 ||
	    !radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME, (u8 *) dl->name,
				 os_strlen(dl->name)) ||
	    dacl_add_cisco_avpair(msg, "aaa:service=ip_admission") < 0 ||
	    dacl_add_cisco_avpair(msg, "aaa:event=acl-download") < 0 ||
	    add_common_radius_attr(hapd, hapd->conf->radius_auth_req_attr,
				   dl->sta, msg) < 0 ||
	    (dl->state_len &&
	     !radius_msg_add_attr(msg, RADIUS_ATTR_STATE, dl->state,
				  dl->state_len))) {
		wpa_printf(MSG_INFO, "dACL %s: could not build the request",
			   dl->name);
		goto fail;
	}

	/* radius_client_send() adds Message-Authenticator */
	if (radius_client_send(hapd->radius, msg, RADIUS_AUTH, dl->sta->addr) < 0)
		goto fail;
	dl->in_flight = 1;
	return 0;

fail:
	radius_msg_free(msg);
	return -1;
}


/* Append the dACL AV-pairs of an Access-Accept or Access-Challenge. */
static int dacl_collect(struct dacl_download *dl, struct radius_msg *msg)
{
	attrInfo_t parsed;
	char *buf;
	unsigned int pos;

	os_memset(&parsed, 0, sizeof(parsed));
	if (radiusClientAcceptProcess(msg, &parsed) != 0 ||
	    (parsed.daclCount && !parsed.daclLen) ||
	    dl->len + parsed.daclLen > RADIUS_DACL_MAX_LEN) {
		radiusDaclFree(&parsed);
		return -1;
	}
	if (!parsed.daclLen)
		return 0;

	buf = os_realloc(dl->avpairs, dl->len + parsed.daclLen);
	if (!buf) {
		radiusDaclFree(&parsed);
		return -1;
	}
	os_memcpy(buf + dl->len, parsed.dacl, parsed.daclLen);
	for (pos = 0; pos < parsed.daclLen; pos += os_strlen(parsed.dacl + pos) + 1)
		dl->count++;
	dl->avpairs = buf;
	dl->len += parsed.daclLen;
	radiusDaclFree(&parsed);
	return 0;
}


static RadiusRxResult
dacl_receive(struct radius_msg *msg, struct radius_msg *req,
	     const u8 *shared_secret, size_t shared_secret_len, void *data)
{
	struct hostapd_data *hapd = data;
	struct radius_hdr *hdr = radius_msg_get_hdr(msg);
	struct dacl_download *dl = NULL;
	struct sta_info *sta;
	int len;

	for (sta = hapd->sta_list; sta; sta = sta->next) {
		if (sta->dacl_dl && sta->dacl_dl->in_flight &&
		    sta->dacl_dl->identifier == hdr->identifier) {
			dl = sta->dacl_dl;
			break;
		}
	}
	if (!dl)
		return RADIUS_RX_UNKNOWN;

	/* The Response Authenticator is always checked; Message-Authenticator
	 * only when present, since a reply without EAP-Message need not carry
	 * it (FreeRADIUS before 3.2.5 doesn't) */
	if (radius_msg_verify(msg, shared_secret, shared_secret_len, req,
			      radius_msg_get_attr(msg,
						  RADIUS_ATTR_MESSAGE_AUTHENTICATOR,
						  NULL, 0) >= 0)) {
		wpa_printf(MSG_INFO, "dACL %s: invalid authenticator", dl->name);
		return RADIUS_RX_INVALID_AUTHENTICATOR;
	}
	dl->in_flight = 0;

	switch (hdr->code) {
	case RADIUS_CODE_ACCESS_ACCEPT:
		dacl_finish(dl, dacl_collect(dl, msg) == 0);
		break;
	case RADIUS_CODE_ACCESS_CHALLENGE:
		/* one part of the dACL, ask for the next one */
		len = radius_msg_get_attr(msg, RADIUS_ATTR_STATE, dl->state,
					  sizeof(dl->state));
		if (dacl_collect(dl, msg) < 0 || len <= 0 ||
		    (size_t) len > sizeof(dl->state) ||
		    ++dl->rounds >= DACL_MAX_ROUNDS) {
			dacl_finish(dl, 0);
			break;
		}
		dl->state_len = len;
		if (dacl_request_send(dl) < 0)
			dacl_finish(dl, 0);
		break;
	default:
		wpa_printf(MSG_INFO, "dACL %s: download rejected (code %d)",
			   dl->name, hdr->code);
		dacl_finish(dl, 0);
		break;
	}

	return RADIUS_RX_PROCESSED;
}


/* Report the result to authmgr and forget the download. */
static void dacl_finish(struct dacl_download *dl, int ok)
{
	struct hostapd_data *hapd = dl->hapd;
	struct sta_info *sta = dl->sta;

	if (!ok || dl->count < 2) {
		/* only the name: the download failed */
		dl->len = os_strlen(dl->avpairs) + 1;
		dl->count = 1;
	}
	wpa_printf(MSG_INFO, "dACL %s: download %s (%u AV-pairs)", dl->name,
		   dl->count > 1 ? "done" : "failed", dl->count - 1);

	hostapd_drv_auth_resp_send(hapd, hapd->conf->iface, sta->addr,
				   "radius_dacl_info", sta);
	ieee802_1x_dacl_free(sta);
}


/* DACL_DOWNLOAD <addr>: download the dACL named in the station's Accept */
int ieee802_1x_dacl_download(struct hostapd_data *hapd, const char *txtaddr)
{
	struct dacl_download *dl;
	struct sta_info *sta;
	u8 addr[ETH_ALEN];
	const char *name = NULL;
	unsigned int pos;
	size_t plen = os_strlen(DACL_NAME_AVPAIR);

	if (hwaddr_aton(txtaddr, addr))
		return -1;
	sta = ap_get_sta(hapd, addr);
	if (!sta)
		return -1;

	for (pos = 0; sta->attr_info.dacl && pos < sta->attr_info.daclLen;
	     pos += os_strlen(sta->attr_info.dacl + pos) + 1) {
		if (os_strncasecmp(sta->attr_info.dacl + pos, DACL_NAME_AVPAIR,
				   plen) == 0)
			name = sta->attr_info.dacl + pos + plen;
	}
	if (!name || !*name || os_strlen(name) >= sizeof(dl->name))
		return -1;

	ieee802_1x_dacl_free(sta);
	dl = os_zalloc(sizeof(*dl));
	if (!dl)
		return -1;
	dl->hapd = hapd;
	dl->sta = sta;
	os_strlcpy(dl->name, name, sizeof(dl->name));
	dl->len = plen + os_strlen(name) + 1;
	dl->avpairs = os_malloc(dl->len);
	if (!dl->avpairs) {
		os_free(dl);
		return -1;
	}
	os_snprintf(dl->avpairs, dl->len, "%s%s", DACL_NAME_AVPAIR, name);
	dl->count = 1;
	sta->dacl_dl = dl;

	if (dacl_request_send(dl) < 0) {
		ieee802_1x_dacl_free(sta);
		return -1;
	}
	eloop_register_timeout(DACL_DOWNLOAD_TIMEOUT, 0, dacl_timeout, dl, NULL);
	wpa_printf(MSG_INFO, "dACL %s: downloading for " MACSTR, dl->name,
		   MAC2STR(sta->addr));
	return 0;
}


void ieee802_1x_dacl_free(struct sta_info *sta)
{
	struct dacl_download *dl = sta->dacl_dl;

	if (!dl)
		return;
	eloop_cancel_timeout(dacl_timeout, dl, NULL);
	sta->dacl_dl = NULL;
	os_free(dl->avpairs);
	os_free(dl);
}


int ieee802_1x_dacl_init(struct hostapd_data *hapd)
{
	return radius_client_register(hapd->radius, RADIUS_AUTH, dacl_receive,
				      hapd);
}
