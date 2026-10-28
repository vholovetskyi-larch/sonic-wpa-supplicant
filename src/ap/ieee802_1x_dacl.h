/*
 * hostapd / Downloadable ACL (Cisco ISE/ACS style) second-pass download
 */

#ifndef IEEE802_1X_DACL_H
#define IEEE802_1X_DACL_H

struct hostapd_data;
struct sta_info;

/* The AV-pair of an Access-Accept that names a dACL to download */
#define DACL_NAME_AVPAIR "ACS:CiscoSecure-Defined-ACL="

/* A download in progress for a station */
struct dacl_download {
	struct hostapd_data *hapd;
	struct sta_info *sta;
	char name[254];
	u8 identifier;          /* of the outstanding Access-Request */
	int in_flight;          /* an Access-Request is outstanding */
	u8 state[253];          /* State of the last Access-Challenge */
	size_t state_len;
	unsigned int rounds;    /* Access-Challenges received */
	/* the result for authmgr: DACL_NAME_AVPAIR "<name>", then the
	 * downloaded AV-pairs, NUL-separated */
	char *avpairs;
	size_t len;
	unsigned int count;     /* strings in avpairs */
};

int ieee802_1x_dacl_init(struct hostapd_data *hapd);
int ieee802_1x_dacl_download(struct hostapd_data *hapd, const char *txtaddr);
void ieee802_1x_dacl_free(struct sta_info *sta);

#endif /* IEEE802_1X_DACL_H */
