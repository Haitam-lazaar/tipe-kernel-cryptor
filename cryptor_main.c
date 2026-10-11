#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "sha256.h"

/* netfilter includess */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/ctype.h> // For isprint()
#include <crypto/hash.h> // For SHA256
///////////////////////////////////

static struct nf_hook_ops nf_in_ops;


// Define the IP address as a string
#define MY_IP "10.0.0.2"
#define REMOTE_IP "10.0.1.2"

/**
 * - Derives key using standard sha256
 * BUG: Calculate sha256 may gives errors if the byte array isn't 32 bytes long
 */
void derive_key(BYTE * pkt_id, BYTE * key)// , BYTE out_hash[])
{
	BYTE input_key[SHA256_BLOCK_SIZE];
	BYTE hash_buff[SHA256_BLOCK_SIZE];

	// memset(input_key, 0, SHA256_BLOCK_SIZE);
	memcpy(input_key, key, SHA256_BLOCK_SIZE);

	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, input_key, SHA256_BLOCK_SIZE);

	memset(input_key, 0, SHA256_BLOCK_SIZE);
	memcpy(input_key, pkt_id, 2);

	sha256_update(&ctx, input_key, SHA256_BLOCK_SIZE);
	sha256_final(&ctx, hash_buff); // out_key

	memcpy(key, hash_buff, SHA256_BLOCK_SIZE);
}


/*void print_key_hash(BYTE key[])
{
	printk( KERN_CONT "sha256 hash: ");
	size_t x;
    for (x = 0; x < SHA256_BLOCK_SIZE; x++)
		printk( KERN_CONT "%02x", key[x]);

	printk(KERN_CONT "\n");
}*/

void cipher_packet_data(BYTE * payload, unsigned int payload_len, BYTE * pkt_id)
{
	// BYTE key[SHA256_BLOCK_SIZE] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // FIRST KEY
	 BYTE key[SHA256_BLOCK_SIZE] = {
	    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b,
	    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
	    0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
	    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03
	};
	size_t b_Index, p_Index;

	for (p_Index = 0; p_Index < payload_len; p_Index += SHA256_BLOCK_SIZE) {

		size_t xor_len = (p_Index + SHA256_BLOCK_SIZE < payload_len) ? SHA256_BLOCK_SIZE : payload_len - p_Index;

		derive_key(pkt_id, key);
		for (b_Index = 0; b_Index < xor_len; b_Index++)
		{
			payload[p_Index + b_Index] ^= key[b_Index];
		}
		// print_key_hash(key);

	}
}


bool isCryptable(struct iphdr* ip_header)
{
	return (ip_header->saddr == in_aton(MY_IP) && ip_header->daddr == in_aton(REMOTE_IP) ) ||
			(ip_header->saddr == in_aton(REMOTE_IP) && ip_header->daddr == in_aton(MY_IP) );
}

// NF HOOK Func
static unsigned int my_hook_func(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    unsigned char *payload;
    unsigned int payload_len;
    unsigned int i; // for for loop
    unsigned char pkt_id[2];

    // Ensure the skb is not NULL
    if (!skb || !skb_network_header(skb)) {
        return NF_ACCEPT;
    }
    // Check if it's an IPv4 packet
    if (skb->protocol != htons(ETH_P_IP)) {
        return NF_ACCEPT;
    }


    // Extract the IP header
    ip_header = ip_hdr(skb);

    if (!ip_header) {
        return NF_ACCEPT;
    }

    // Tmp function !!
    if (!isCryptable(ip_header))
    	return NF_ACCEPT;

    if (skb_linearize(skb) < 0)
    	printk(KERN_ALERT "CAN'T LINEARIZE!\n");

    // Calculate the payload offset
    unsigned int ip_header_len = ip_header->ihl * 4; // IP header length in bytes

    payload = skb->data + ip_header_len;
    payload_len = skb->len - ip_header_len; // ntohs(ip_header->tot_len) - ip_header_len;

    // Pass through without modifying if there is no payload data
    if (payload_len <= 0) {
    	return NF_ACCEPT;
	}

    pkt_id[0] = ip_header->id & 0xff;
    pkt_id[1] = (ip_header->id >> 8) & 0xff;

    cipher_packet_data(payload, payload_len, pkt_id);



	ip_header->check = 0;  // Zero out the old checksum
	ip_header->check = ip_fast_csum((unsigned char *)ip_header, ip_header->ihl);

    return NF_ACCEPT;
}


static int __init custom_init(void) {
	printk(KERN_INFO "Hello world module.\n");

	// Initialize the Netfilter hook
    nf_in_ops.hook = my_hook_func;
    nf_in_ops.pf = PF_INET; // IPv4
    nf_in_ops.hooknum = NF_INET_FORWARD; // Hook to capture forwarded packets traversing the router
    nf_in_ops.priority = NF_IP_PRI_FIRST;


    // Register the hook
    if ( nf_register_net_hook(&init_net, &nf_in_ops) ) {
        printk(KERN_ERR "Failed to register Netfilter hook\n");
        return -1;
    }

	return 0;
}

static void __exit custom_exit(void) {
	printk(KERN_INFO "Goodbye my friend, I shall miss you dearly...\n");

	// Unregister the Netfilter hooks
    nf_unregister_net_hook(&init_net, &nf_in_ops);
}


MODULE_AUTHOR("Haitam Lazaar");
MODULE_DESCRIPTION("Inline IP packet encryption Netfilter module - CPGE TIPE 2025");
MODULE_LICENSE("GPL");

// Custom init and exit methods
module_init(custom_init);
module_exit(custom_exit);
