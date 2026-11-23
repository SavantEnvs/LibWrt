/*
 * libFuzzer harness for the ead (Emergency Access Daemon) packet handler.
 *
 * ead listens on the LAN for broadcast UDP frames (pre-auth) and feeds each captured
 * frame to handle_packet(), its pcap callback. handle_packet()/parse_message() are
 * static, so the daemon's translation unit is included here (main renamed by build.sh
 * with -Dmain=ead_main).
 *
 * Input: a sequence of frames, each a 2-byte big-endian length followed by that many
 * bytes of raw Ethernet frame. Each frame is copied into an exactly-sized heap buffer
 * (so ASan sees overreads past the captured length) and handed to handle_packet(),
 * like pcap_dispatch() does; several frames let the session state machine advance
 * (SET_USERNAME -> GET_PRIME -> SEND_A -> SEND_AUTH).
 *
 * State kept across inputs, on purpose: the passwd file written once at init (read-only
 * afterwards) and tinysrp's random pool. Per-input state (session state, username,
 * SRP server) is reset at the start of every input via ead's own set_state().
 *
 * SEND_CMD frames are skipped: after successful SRP authentication ead fork()s and
 * system()s the client's command - its intended function - which a harness must not do.
 * Reaching it would require forging the SRP proof for a random session anyway.
 */
#include "ead.c"

#include <stdint.h>
#include <stdlib.h>

static char passwd_path[256];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	static struct ead_instance inst;
	static const char pw[] =
		"root:$1$MCGAgYw.$Ip1GcyeUliId3wzVcKR/e/:0:0:root:/root:/bin/ash\n"
		"nobody:*:65534:65534:nobody:/var:/bin/false\n";
	const char *tmp = getenv("TMPDIR");
	int fd;

	snprintf(passwd_path, sizeof(passwd_path), "%s/ead_passwd_XXXXXX",
		 (tmp && *tmp) ? tmp : "/tmp");
	fd = mkstemp(passwd_path);
	if (fd < 0 || write(fd, pw, sizeof(pw) - 1) != (ssize_t)(sizeof(pw) - 1))
		abort();
	close(fd);
	passwd_file = passwd_path;

	memset(&inst, 0, sizeof(inst));
	strcpy(inst.ifname, "eth0");
	inst.id = 0;
	instance = &inst;
	INIT_LIST_HEAD(&instances);

	pcap_fp = pcap_open_dead(DLT_EN10MB, PCAP_MRU);
	if (!pcap_fp)
		abort();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* reset the per-session state the previous input left behind */
	set_state(EAD_TYPE_SET_USERNAME);
	username[0] = 0;

	while (size >= 2) {
		size_t len = ((size_t)data[0] << 8) | data[1];
		data += 2;
		size -= 2;
		if (len > size)
			len = size;

		if (len >= sizeof(struct ead_packet)) {
			const struct ead_packet *p = (const struct ead_packet *)data;
			if (ntohl(p->msg.type) == EAD_TYPE_SEND_CMD)
				goto next;
		}
		{
			u_char *buf = malloc(len ? len : 1);
			struct pcap_pkthdr h;
			memcpy(buf, data, len);
			memset(&h, 0, sizeof(h));
			h.caplen = h.len = len;
			handle_packet(NULL, &h, buf);
			free(buf);
		}
next:
		data += len;
		size -= len;
	}
	return 0;
}
