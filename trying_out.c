
/*
 * Copyright (c) 2023, Oluwatobi Giwa
 * All rights reserved.
 *
 * This software is licensed under the 3-Clause BSD License.
 * See the LICENSE file or visit https://opensource.org/license/bsd-3-clause/ for details.
 */

#include <bpf/bpf.h>
#include <linux/ip.h>
// #include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("sk_skb")
int packet_capture(struct __sk_buff *skb)
{
    struct ethhdr eth;
    struct iphdr ip;

    __u32 src_ip;
    __u32 dest_ip;

    __u32 pid;

    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));
    bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip));

    __u32 packet_size = skb->len;

    src_ip = ip.saddr;
    dest_ip = ip.daddr;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u64 uid = uid_gid >> 32;
    __u64 gid = uid_gid & 0xFFFFFFFF;

    char comm[16];
    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_printk("Packet size: %u, Src IP: %u, Dest IP: %u, User ID: %u, Group ID: %u,PID: %u, Process name: %s\n", packet_size, src_ip, dest_ip, uid, gid, pid, comm);

    return 0;
}

char _license[] SEC("license") = "GPL";

// #include <linux/bpf.h>
// #include <linux/skbuff.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/tcp.h>
// #include <bpf/bpf_helpers.h>

// SEC("sk_skb")
// int packet_capture_another(struct __sk_buff *skb)
// {
//     struct ethhdr *eth = bpf_hdr_pointer(skb); // seems unsafe???
//     struct iphdr *ip = (struct iphdr *)(eth + 1);

//     __u32 packet_size = skb->len;

//     __u32 src_ip = ip->saddr;
//     __u32 dest_ip = ip->daddr;

//     __u32 uid = bpf_get_current_uid_gid() >> 32;
//     __u32 gid = bpf_get_current_uid_gid();

//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     __u32 pid = bpf_get_task_pid(task, 0);

//     char comm[16];
//     bpf_get_current_comm(comm, sizeof(comm));

//     bpf_printk("Packet size: %u, Src IP: %u, Dest IP: %u, User ID: %u, Group ID: %u, PID: %u, Process name: %s\n", packet_size, src_ip, dest_ip, uid, gid, pid, comm);

//     return 0;
// }

// char _license[] SEC("license") = "GPL";
