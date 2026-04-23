// Copyright Epic Games, Inc. All Rights Reserved.
// SPDX-License-Identifier: GPL-2.0-only

#define TEXT(x) x
#define UE_LOG_S(...) {printf(__VA_ARGS__); printf("\n");}
#define UE_LOG_V(format, args) {vfprintf(stdout, format, args);}
#define UE_LOG(Tag, Verbosity, ...) UE_LOG_S(#Verbosity ": " __VA_ARGS__)
#define PRINTF_ANSI_STR "%s"

#include <bpf/btf.h>
#include <dirent.h>
#include <linux/version.h>
#include <memory>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include "BPFProgs.skel.h"
#include "LinuxUEKernelToolsSender.h"


static uint32_t GetLinuxVersionCodeRuntime();

void PrintHelp()
{
#if DEBUG
	UE_LOG_S("Usage:\n./UELinuxKernelTools -ParentProcessName <name> [-SocketBasePath <path> -PrintEventsToConsole -PrintEventsToFile]");
#else
	UE_LOG_S("Usage:\n./UELinuxKernelTools -ParentProcessName <name> [-SocketBasePath <path>]");
#endif
}

int main(int argc, char **argv)
{
	const char* ParentProcessName = nullptr;
	char AltSocketBasePath[sizeof(sockaddr_un::sun_path)];
	const char* SocketBasePath = "/tmp/LinuxUEKernelTools";
#if DEBUG
	bool bPrintEventsToFile = false;
	bool bPrintEventsToConsole = false;
#endif
	for (int ArgI = 1; ArgI < argc; ++ArgI)
	{
		const bool bIsLast = ArgI == (argc - 1);
		if (strcasecmp(argv[ArgI], "-ParentProcessName") == 0)
		{
			if (!bIsLast)
			{
				ParentProcessName = argv[ArgI + 1];
				++ArgI;
			}
		}
		else if (strcasecmp(argv[ArgI], "-SocketBasePath") == 0)
		{
			if (!bIsLast)
			{
				SocketBasePath = argv[ArgI + 1];
				++ArgI;

				if (strlen(SocketBasePath) > LinuxUEKernelToolsIPC::SocketBasePathMaxLen)
				{
					strncpy(AltSocketBasePath, SocketBasePath, LinuxUEKernelToolsIPC::SocketBasePathMaxLen);
					AltSocketBasePath[LinuxUEKernelToolsIPC::SocketBasePathMaxLen] = 0; // strncpy won't null-terminate if src length is >= n
					SocketBasePath = AltSocketBasePath;
					UE_LOG_S("socket base path exceeds max length %lu, truncating to '%s'", LinuxUEKernelToolsIPC::SocketBasePathMaxLen, SocketBasePath);
				}
			}
		}
#if DEBUG
		else if (strcasecmp(argv[ArgI], "-PrintEventsToConsole") == 0)
		{
			bPrintEventsToConsole = true;
		}
		else if (strcasecmp(argv[ArgI], "-PrintEventsToFile") == 0)
		{
			bPrintEventsToFile = true;
		}
#endif
		else if (strcasecmp(argv[ArgI], "-help") == 0)
		{
			PrintHelp();
			return 0;
		}
		else
		{
			UE_LOG_S("Unrecognised arg '%s'", argv[ArgI]);
			PrintHelp();
			return 1;
		}
	}

	if (!ParentProcessName)
	{
		UE_LOG_S("No parent process specified");
		PrintHelp();
		return 1;
	}

	if (geteuid() != 0)
	{
		UE_LOG_S("WARNING! Not running as root");
	}
	UE_LOG_S("getuid() = %i geteuid() = %i", getuid(), geteuid());

	const uint32_t LinuxVersionCode = GetLinuxVersionCodeRuntime();
	UE_LOG_S("LinuxVersionCode = %u", LinuxVersionCode);

	UE_LOG_S("libbpf_version_string = %s", libbpf_version_string());

	static volatile sig_atomic_t Stop;
	if (signal(SIGINT, [](int){Stop = 1;}) == SIG_ERR)
	{
		UE_LOG_S("Failed to set signal handler, errno = %i (%s)", errno, strerror(errno));
		return 1;
	}

	libbpf_set_print([](enum libbpf_print_level, const char *format, va_list args)
	{
		UE_LOG_V(format, args);
		return 0;
	});

	BPFProgs* Skeleton = BPFProgs__open();
	if (!Skeleton)
	{
		UE_LOG_S("Failed to open BPF skeleton");
		return 1;
	}

	pid_t ParentPid = 0;
	{
		UE_LOG_S("Waiting for parent process %s", ParentProcessName);
		DIR* ProcDir = opendir("/proc");
		if (!ProcDir)
		{
			UE_LOG_S("Failed to open /proc");
			return 1;
		}
		while (true)
		{
			// scan /proc for parent
			while (true)
			{
				dirent* ProcDirEnt = readdir(ProcDir);
				if (!ProcDirEnt)
				{
					break;
				}
				
				// skip non-numeric
				if (ProcDirEnt->d_name[0] < '0' || ProcDirEnt->d_name[0] > '9')
				{
					continue;
				}

				char LinkPath[266];
				snprintf(LinkPath, sizeof(LinkPath), "/proc/%s/exe", ProcDirEnt->d_name);

				char Buffer[PATH_MAX];
				ssize_t Len = readlink(LinkPath, Buffer, sizeof(Buffer) - 1);
				if (Len > 0)
				{
					Buffer[Len] = 0;
					// skip any slashes in the path
					const char* Name = Buffer;
					for (const char* Iter = Name; *Iter; ++Iter)
					{
						if (*Iter == '/')
						{
							Name = Iter + 1;
						}
					}

					if (strcmp(ParentProcessName, Name) == 0)
					{
						ParentPid = atoi(ProcDirEnt->d_name);
						break;
					}
				}
			}

			if (ParentPid)
			{
				UE_LOG_S("Found parent pid:%d", ParentPid);
				// note: userspace pid is kernel space tgid
				Skeleton->rodata->FilterByParentTgid = ParentPid;
				break;
			}

			if (Stop)
			{
				return 0;
			}

			sleep(1);
			rewinddir(ProcDir);
		}
		closedir(ProcDir);
	}

	struct stat Stat;
	if (stat("/proc/self/ns/pid", &Stat))
	{
		UE_LOG_S("stat(\"/proc/self/ns/pid\") failed, errno=%d:%s", errno, strerror(errno));
		return 1;
	}
	Skeleton->rodata->NamespaceDevice = Stat.st_dev;
	Skeleton->rodata->NamespaceInode = Stat.st_ino;

	btf* BTF = btf__parse("/sys/kernel/btf/vmlinux", nullptr);
	if (BTF)
	{
		// some linux kernels don't allow attaching to wp_page_copy (e.g. WSL2 at time of writing), 
		// so we'll try wp_page_copy first and fall back to do_wp_page
		bool bHasWPPageCopy = btf__find_by_name_kind(BTF, "wp_page_copy", BTF_KIND_FUNC) >= 0;
		if (bHasWPPageCopy)
		{
			bpf_program__set_autoload(Skeleton->progs.fexit_do_wp_page, false);
		}
		else
		{
			UE_LOG_S("Warning: COW detection falling back to do_wp_page which may overcount\n");
			bpf_program__set_autoload(Skeleton->progs.fentry_wp_page_copy, false);
		}

		btf__free(BTF);
	}
	else
	{
		UE_LOG_S("Failed to parse btf\n");
	}

	if (BPFProgs__load(Skeleton) != 0)
	{
		UE_LOG_S("Failed to load BPF skeleton\n");
		return 1;
	}

	// basically a struct of globals
	struct FContext
	{
		LinuxUEKernelToolsIPCSender* IPC;
#if DEBUG
		FILE* DebugFile;
		bool bPrintEventsToFile;
		bool bPrintEventsToConsole;
#endif
	};
	FContext Context = {};
	LinuxUEKernelToolsIPCSender IPC = LinuxUEKernelToolsIPCSender(SocketBasePath);
	Context.IPC = &IPC;
#if DEBUG
	Context.bPrintEventsToFile = bPrintEventsToFile;
	Context.bPrintEventsToConsole = bPrintEventsToConsole;
	if (bPrintEventsToFile)
	{
		Context.DebugFile = fopen("_trace_all.txt", "wb+");
	}
#endif

	auto EventHandler = [](void* ctx, void * data, size_t size)->int
	{
		FContext* Context = (FContext*)ctx;
		if (size != sizeof(BPFEvent) || data == nullptr)
		{
			return 1;
		}

		const BPFEvent* Event = static_cast<BPFEvent*>(data);

#ifdef DEBUG
		if (Context->bPrintEventsToFile || Context->bPrintEventsToConsole)
		{
			char Temp[1024];
			Event->ToString(Temp, sizeof(Temp));

			if (Context->bPrintEventsToFile)
			{
				fprintf(Context->DebugFile, "%s\n", Temp);
				fflush(Context->DebugFile);
			}
			if (Context->bPrintEventsToConsole)
			{
				UE_LOG_S("%s", Temp);
			}
		}
#endif
		Context->IPC->Send(Event);
		
		return 0;
	};

	std::unique_ptr<ring_buffer, decltype(&ring_buffer__free)> EventRingBuf(ring_buffer__new(bpf_map__fd(Skeleton->maps.BPFEvents), EventHandler, &Context, NULL), &ring_buffer__free);
	if (!EventRingBuf)
	{
		UE_LOG_S("Failed to create a ring buffer");
		return 1;
	}

	if (BPFProgs__attach(Skeleton) != 0)
	{
		UE_LOG_S("Failed to attach BPF skeleton");
		return 1;
	}

	char ParentProcPath[32];
	snprintf(ParentProcPath, sizeof(ParentProcPath), "/proc/%d", ParentPid);
	while (!Stop)
	{
		ring_buffer__poll(EventRingBuf.get(), 100);
		IPC.Update();

		if (IPC.ConnectedProcesses.size() == 0 && IPC.PendingProcesses.size() == 0)
		{
			if (access(ParentProcPath, F_OK) != 0)
			{
				UE_LOG_S("All children and parent process have exited");
				break;
			}
		}
	}

#ifdef DEBUG
	if (bPrintEventsToFile)
	{
		fflush(Context.DebugFile);
	}
#endif

	return 0;
}

static uint32_t GetLinuxVersionCodeRuntime()
{
	uint32_t Major = 0, Minor = 0, Patch = 0;

	bool bSuccess = false;

	FILE* UbuntuVersionFile = fopen("/proc/version_signature", "r");
	if (UbuntuVersionFile)
	{
		bSuccess = fscanf(UbuntuVersionFile, "%*s %*s %u.%u.%u\n", &Major, &Minor, &Patch);
		fclose(UbuntuVersionFile);
	}

	if (!bSuccess)
	{
		struct utsname Name;
		uname(&Name);

		bSuccess = 	sscanf(Name.version, "Debian %u.%u.%u", &Major, &Minor, &Patch) == 3 ||
					sscanf(Name.release, "%u.%u.%u", &Major, &Minor, &Patch) == 3;
	}
	
	if (bSuccess)
	{
		return KERNEL_VERSION(Major, Minor, Patch);
	}

	// failed to obtain runtime code, fallback to kernel headers
	return LINUX_VERSION_CODE;
}