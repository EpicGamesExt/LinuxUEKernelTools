// Copyright Epic Games, Inc. All Rights Reserved.
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#include <unordered_map>
#include <unordered_set>
#include <sys/stat.h>

#include "LinuxUEKernelToolsShared.h"


struct FPendingProcess
{
	sockaddr_un Address;
	FILE* TempFile;
};

struct LinuxUEKernelToolsIPCSender : public LinuxUEKernelToolsIPC
{
	const char* BasePath;
	std::unordered_map<pid_t, sockaddr_un> ConnectedProcesses;
	std::unordered_map<pid_t, FPendingProcess> PendingProcesses;

	LinuxUEKernelToolsIPCSender(const char* InBasePath)
		: LinuxUEKernelToolsIPC()
		, BasePath(InBasePath)
		, ConnectedProcesses()
		, PendingProcesses()
	{
	}

	bool Send(const BPFEvent* Event)
	{
		if (Fd == INVALID_FD || Event == nullptr)
		{
			return false;
		}

		// first try already connected processes
		{
			const auto Iter = ConnectedProcesses.find(Event->Pid);
			if (Iter != ConnectedProcesses.end())
			{
				const sockaddr_un& Address = Iter->second;
				return sendto(Fd, Event, sizeof(BPFEvent), 0, (const struct sockaddr*)&Address, sizeof(Address)) == sizeof(BPFEvent);
			}
		}
		// next try already pending processes
		{
			auto Iter = PendingProcesses.find(Event->Pid);
			if (Iter != PendingProcesses.end())
			{
				const FPendingProcess& PendingProcess = Iter->second;
				return fwrite(Event, 1, sizeof(BPFEvent), PendingProcess.TempFile) == sizeof(BPFEvent);
			}
		}

		sockaddr_un Address;
		FillSockAddrUn(&Address, BasePath, Event->Pid);

		// if socket has been created we can start sending events already
		if (access(Address.sun_path, F_OK) == 0)
		{
			ConnectedProcesses.emplace(Event->Pid, Address);
			return sendto(Fd, Event, sizeof(BPFEvent), 0, (const struct sockaddr*)&Address, sizeof(Address)) == sizeof(BPFEvent);
		}

		// socket doesn't exist yet so buffer to a temp file
		FILE* TmpFile = tmpfile64();
		if (TmpFile)
		{
			PendingProcesses.emplace(Event->Pid, FPendingProcess{.Address = Address, .TempFile = TmpFile});

			return fwrite(Event, 1, sizeof(BPFEvent), TmpFile) == sizeof(BPFEvent);
		}
		else
		{
			UE_LOGF(LogUELinuxKernelTools, Error, "failed to create temp file, errno=%d:%s", errno, strerror(errno));
			return false;
		}
	}

	void Update()
	{
		// I tried using inotify for this but /proc doesn't generate inotify events :(
		std::unordered_set<pid_t> ToRemove;
		for (auto& Iter : ConnectedProcesses)
		{
			const pid_t Pid = Iter.first;
			char Path[32];
			snprintf(Path, sizeof(Path), "/proc/%d", Pid);
			if (access(Path, F_OK) != 0)
			{
				UE_LOGF(LogUELinuxKernelTools, Log, "Connected process %d dead", Pid);
				ToRemove.emplace(Pid);
			}
		}

		for (auto Pid : ToRemove)
		{
			ConnectedProcesses.erase(Pid);
		}

		ToRemove.clear();
		for (auto& Iter : PendingProcesses)
		{
			const pid_t Pid = Iter.first;
			FPendingProcess& PendingProcess = Iter.second;
			
			// see if socket file now exists
			if (access(PendingProcess.Address.sun_path, F_OK) == 0)
			{
				char Buffer[MAX_EVENTS_PER_PACKET * sizeof(BPFEvent)];
				fseek(PendingProcess.TempFile, 0, SEEK_SET);
				while (true)
				{
					const size_t EventCount = fread(Buffer, sizeof(BPFEvent), MAX_EVENTS_PER_PACKET, PendingProcess.TempFile);
					if (EventCount > 0)
					{
						UE_LOG_S("flushing %lu events", EventCount);
						const size_t EventsSize = EventCount * sizeof(BPFEvent);
						if (sendto(Fd, Buffer, EventsSize, 0, (const struct sockaddr*)&PendingProcess.Address, sizeof(PendingProcess.Address)) != EventsSize)
						{
							UE_LOG_S("sendto failed while sending buffered events, errno=%d:%s", errno, strerror(errno));
						}
					}

					if (EventCount < MAX_EVENTS_PER_PACKET)
					{
						// eof
						break;
					}
				}

				fclose(PendingProcess.TempFile);
				ToRemove.emplace(Pid);

				ConnectedProcesses.emplace(Pid, PendingProcess.Address);
			}
			// if no socket file exists, check the /proc still exists
			else
			{
				char Path[32];
				snprintf(Path, sizeof(Path), "/proc/%d", Pid);
				if (access(Path, F_OK) != 0)
				{
					UE_LOGF(LogUELinuxKernelTools, Log, "Pending connection pid %d dead", Pid);
					ToRemove.emplace(Pid);
				}
			}
		}

		for (auto Pid : ToRemove)
		{
			PendingProcesses.erase(Pid);
		}
	}
};