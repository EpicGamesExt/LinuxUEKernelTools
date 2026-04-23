// SPDX-License-Identifier: GPL-2.0-only
// Copyright Epic Games, Inc. All Rights Reserved.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "LinuxUEKernelToolsShared.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile uint64_t NamespaceDevice = 0;
const volatile uint64_t NamespaceInode = 0;
const volatile uint32_t FilterByParentTgid = 0;

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} BPFEvents SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, uint64_t);	// global pid_tgid
	__type(value, uint8_t);	// unused
} ChildProcesses SEC(".maps");

static bool __always_inline ShouldFilter()
{
	// always use global ids as we don't know local ids at fork time
	const uint64_t PidTgid = bpf_get_current_pid_tgid();
	if (bpf_map_lookup_elem(&ChildProcesses, &PidTgid))
	{
		return false;
	}
	return true;
}

static void __always_inline ReportCOW(const uint64_t VirtualAddress)
{
	BPFEvent * Event = bpf_ringbuf_reserve(&BPFEvents, sizeof(BPFEvent), 0);
	if (!Event)
	{
		return;
	}

	struct bpf_pidns_info PidNSInfo = {};
	bpf_get_ns_current_pid_tgid(NamespaceDevice, NamespaceInode, &PidNSInfo, sizeof(struct bpf_pidns_info));

	Event->Type = BPFEventCOW;
	Event->Pid = PidNSInfo.tgid;
	Event->Tid = PidNSInfo.pid;
	Event->COW.VirtualAddress = VirtualAddress;

	bpf_ringbuf_submit(Event, 0);
}

// note: preferably use this instead of do_wp_page if available as impossible to know for sure 
// whether do_wp_page actually did a copy.
// the user space program should not attach both though as then CoWs will be double counted
SEC("fentry/wp_page_copy")
int BPF_PROG(fentry_wp_page_copy, struct vm_fault* VMF)
{
	if (ShouldFilter())
	{
		return 0;
	}

	const uint64_t RealAddress = BPF_CORE_READ(
		VMF,
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
		real_address
	#else
		address
	#endif
	);
	
	ReportCOW(RealAddress);
	return 0;
}

// not included in vmlinux.h because it's a macro, annoying to hardcode but the value hasn't changed in decades
#define VM_SHARED 0x8

SEC("fexit/do_wp_page")
int BPF_PROG(fexit_do_wp_page, struct vm_fault* VMF, vm_fault_t Ret)
{
	if (ShouldFilter())
	{
		return 0;
	}

	const uint32_t Flags = BPF_CORE_READ(VMF, flags);
	const uint32_t VMAFlags = BPF_CORE_READ(VMF, vma, vm_flags);
	if ((Flags & FAULT_FLAG_WRITE) && !(VMAFlags & VM_SHARED))
	{
		const uint64_t RealAddress = BPF_CORE_READ(
			VMF,
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
			real_address
		#else
			address
		#endif
		);

		ReportCOW(RealAddress);
	}

	return 0;
}

SEC("raw_tracepoint/sched_process_fork")
int raw_tracepoint_sched_process_fork(struct bpf_raw_tracepoint_args* Ctx)
{
	struct bpf_pidns_info PidNSInfo = {};
	bpf_get_ns_current_pid_tgid(NamespaceDevice, NamespaceInode, &PidNSInfo, sizeof(struct bpf_pidns_info));

	if (PidNSInfo.tgid == FilterByParentTgid)
	{
		// note: this is global pid/tgid, we can't know the local ones because the calling process is the parent
		const uint64_t ChildPidTgid = 	((uint64_t)BPF_CORE_READ((struct task_struct*)Ctx->args[1], tgid) << 32) 
										| BPF_CORE_READ((struct task_struct*)Ctx->args[1], pid);

		uint8_t Value = 1;
		bpf_map_update_elem(&ChildProcesses, &ChildPidTgid, &Value, BPF_ANY);
	}

	return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int raw_tracepoint_sched_process_exit(struct bpf_raw_tracepoint_args* Ctx)
{
	const uint64_t PidTgid = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&ChildProcesses, &PidTgid);
	
	return 0;
}
