# Writing a Windows ARM64 Debugger for Reverse Engineering - KoiDbg

Author: João Vitor (@Keowu) - Security Researcher

## Introduction

The goal of this article is to demonstrate the development steps of a debugger focused on Windows ARM64. Not too long ago, I had the privilege of analyzing a rather specific attack scenario that affected Windows ARM64 users (which I can't provide details about due to an NDA), which forced me to analyze everything using WinDbg for ARM. Let's just say it wasn't the best experience — especially for us, security researchers, who are used to tools like x64dbg or other similar debuggers. This experience sparked my interest in how debuggers work and are created.

In July 2024, I began working on a project initially called HarukaMirai Dbg, which was later acquired by a Brazilian security company named Maldec Labs and rebranded as KoiDbg. Alongside the company's owner, a long-time great friend, we worked together to complete the project, which was eventually released as open-source on GitHub for the community.

This article will provide a wealth of information about how KoiDbg works: experiences, details, techniques, and the full operation of debuggers for Windows ARM64, as well as the development and analysis of malware for this architecture, internal system structures, and much more.

![#0](/imgs/intro.png)

## Table of Contents

1. [Introduction](#introduction)
2. [A small message before we continue](#a-small-message-before-we-continue)
3. [The saga of HarukaMiraiDbg to KoiDbg](#the-saga-of-harukamiraidbg-to-koidbg)
4. [Windows Debuggers 101 - Any Architecture](#windows-debuggers-101---any-architecture)
5. [KoiDbg Internals](#koidbg-internals)
    1. [KoiDbg Init-DebugLoop](#koidbg-init-debugloop)
        1. [handleExceptionDebugEvent](#handleexceptiondebugevent)
        2. [handleCreateThreadDebugEvent](#handlecreatethreaddebugevent)
        3. [handleCreateProcessDebugEvent](#handlecreateprocessdebugevent)
        4. [handleExitThreadDebugEvent](#handleexitthreaddebugevent)
        5. [handleExitProcessDebugEvent](#handleexitprocessdebugevent)
        6. [handleLoadDllDebugEvent](#handleloaddlldebugevent)
        7. [handleUnloadDllDebugEvent](#handleunloaddlldebugevent)
        8. [handleOutputDebugStringEvent](#handleoutputdebugstringevent)
        9. [handleRipEvent](#handleripevent)
    2. [KoiDbg Engine Functions](#koidbg-engine-functions)
        1. [ListAllHandleObjectsForDebugeeProcess](#listallhandleobjectsfordebugeeprocess)
        2. [AnalyseDebugProcessVirtualMemory](#analysedebugprocessvirtualmemory)
        3. [updateRegistersContext](#updateregisterscontext)
        4. [updateCallStackContext](#updatecallstackcontext)
        5. [updateStackContext](#updatestackcontext)
        6. [UpdateDisassemblerView](#updatedisassemblerview)
        7. [SetInterrupting](#setinterrupting)
        8. [RemoveInterrupting](#removeinterrupting)
        9. [UpdateActualIPContext](#updateactualipcontext)
        10. [stepInto](#stepinto)
        11. [stepOver](#stepover)
        12. [stepOut](#stepout)
        13. [DebugCommandProcessingLoop](#debugcommandprocessingloop)
        14. [SetNewPatch](#setnewpatch)
        15. [extractPdbFileFunctions](#extractpdbfilefunctions)
    3. [Kurumi Engine](#kurumi-engine)
        1. [Modularization](#modularization)
        2. [InitKurumiKOPDB](#initkurumikopdb)
        3. [DownloadKoiPdb](#downloadkoipdb)
        4. [FindPdbField](#findpdbfield)
        5. [FindPdbStructField](#findpdbstructfield)
        6. [ParsePdbFunctionsAndGetListInternal](#parsepdbfunctionsandgetlistinternal)
    4. [KoiDbg Utils](#koidbg-utils)
        1. [GetFileNameFromHandle](#getfilenamefromhandle)
        2. [symbol_from_address](#symbol_from_address)
        3. [GetDebuggerProcessHandleTable](#getdebuggerprocesshandletable)
        4. [GetRemoteHandleTableHandleInformation](#getremotehandletablehandleinformation)
        5. [GetDebuggerProcessHandleTable && GetRemoteHandleTableHandleInformation](#getdebuggerprocesshandletable--getremotehandletablehandleinformation)
    5. [Assembler Engine](#assembler-engine)
        1. [assembleX64Code && assembleArm64Code](#assemblex64code--assemblearm64code)
    6. [Disassembler Engine](#disassembler-engine)
        1. [RunCapstoneEnginex86 && RunCapstoneEngineAarch64](#runcapstoneenginex86--runcapstoneengineaarch64)
        2. [RunCapstoneForSingleStepARM64 && RunCapstoneForSingleStepx86](#runcapstoneforsinglesteparm64--runcapstoneforsinglestepx86)
        3. [RunCapstoneForStepOutARM64 && RunCapstoneForStepOutx86](#runcapstoneforsinglesteparm64--runcapstoneforsinglestepx86)
        4. [Syntaxe-Highlight Haruka](#syntaxe-highlight-haruka)
    7. [Extracting Windows Loader Struct Information - KoiDbg](#extracting-windows-loader-struct-information---koidbg)
        1. [extractLdrpVectorHandlerListInformation](#extractldrpvectorhandlerlistinformation)
        2. [extractNirvanaCallbackPresentOnDebugeeProcess](#extractnirvanacallbackpresentondebugeeprocess)
        3. [extractNtDelegateTableCallbacks](#extractntdelegatetablecallbacks)
            1. [Simple fields](#simple-fields)
            2. [RtlpDynamicFunctionTable](#rtlpdynamicfunctiontable)
            3. [LdrpDllNotificationList](#ldrpdllnotificationlist)
            4. [RtlpSecMemListHead](#rtlpsecmemlisthead)
            5. [KernelCallbackTable](#kernelcallbacktable)
    8. [Decompiler engine](#decompiler-engine)
    9. [Analyzing a Packer for ARM64, reversing and debugging with KoiDbg](#analyzing-a-packer-for-arm64-reversing-and-debugging-with-koidbg)
        1. [Exploring the PEB on Windows ARM64 to write a loader](#exploring-the-peb-on-windows-arm64-to-write-a-loader)
            1. [Loader](#loader)
            2. [Shellcode](#shellcode)
            3. [PEB](#peb)
        2. [Analyzing our code with KoiDbg](#analyzing-our-code-with-koidbg)
            1. [Shellcode Adventure](#shellcode-adventure)
    10. [KoiDbg Future](#koidbg-future)
    11. [One last message](#one-last-message)
    12. [References](#references)

#### A small message before we continue

In the past few months, I’ve been very busy: with friends’ projects, work, studies/research, learning and reinforcing my knowledge of other languages, other side projects I’m working on, and even preparing material for other articles. And, of course, I’ve also been resting—because no one is made of iron. I’m grateful to those who follow me and, in one way or another, found ways to get in touch: through Discord, email, YouTube comments, and even in person (even though I’ve never shown my face—strange, right?). I never imagined that so many people would enjoy reading my content. I’m truly grateful to you all. Really. Thank you!

I’d like to give a special shoutout to the Discord friends who followed the development of the project, took part in the research, and closely reviewed this article:

- rem0obb(https://github.com/rem0obb)
- Buzzer-re(https://github.com/buzzer-re)
- Lusty(https://github.com/lustywastaken)

And finally, as usual, here’s a music recommendation to listen to while reading the article: [Legião Urbana - Tempo Perdido](https://www.youtube.com/watch?v=tI9kSZgMLsc).

**Note:** Before continuing, please keep in mind that this article, while detailed and written in a beginner-friendly language for Reverse Engineering/Windows Internals, may not be fully understood if you don’t have an **excellent foundation in Reverse Engineering or Windows Internals.**

I hope you have an excellent read!

### The saga of HarukaMiraiDbg to KoiDbg

When I started developing **HarukaMirai Dbg** in mid-2024, I had no idea how complex it would be to find suitable hardware to continue the project. This might not make much sense to you if you're not living in Brazil, but a simple piece of hardware can cost up to 5x more than usual due to outrageous taxes and the pseudo-protection of local industries — which, in practice, hinders innovation, favors the purchase of white-label products, and promotes the importation of goods through tax-free zones. Meanwhile, the population is left dealing with a problem that should be solved to generate jobs and innovation.
**Anyway**, this article isn’t political. I hate politics — and how some aspects of my home country function — so let’s get straight to what matters and what we love.

After a lot of research, I managed to find some alternatives:

Get a **Raspberry Pi 5** and invest in the necessary modules, spending an absurd amount due to taxes and the high dollar rate.

Buy a **Samsung Galaxy Book Go** from the local market — the only option — used.

Obviously, my preference was the **Samsung Galaxy Book Go**, which had more efficient hardware. It came with a **Snapdragon 7c** processor and **Windows 11 ARM64** — exactly what I needed. And guess what? After browsing a platform for used hardware, I began negotiating with the seller. After a few minutes of conversation, I managed to convince him to sell it to me for 1/3 of the original price. A win, considering he had bought the device hoping to play games (!?), but gave up due to the lack of ARM64-compatible games (and also because, according to him, the translation layer didn’t deliver good performance).

**Update:** while writing this article, the price of this hardware has doubled.

In August 2024, I finally started the project with the hardware in hand. By this time, I had already decided that the name of the debugger would be a reference to a song by the Japanese band **Kankaku Piero**, the opening of one of my favorite animes: **Black Clover**. I had also decided to use **Qt with C++**, as it would be the most efficient, stable, and practical way to support Windows ARM64 via build with MSVC. My adventure was just beginning.

I had nearly completed the debug engine and had solved many of the problems related to the operating system's internal structures, which were different (we'll look into this in detail later in the article). By October 2024 — three months into the project — I shared my idea with a trusted friend, **rem0obb**. At the time, he was starting his own tech company and invited me to join **Maldec Labs** as a researcher, bringing **HarukaMirai Dbg** along, as it would add knowledge for both sides.

After several months of continuous development, in December 2024, the project began to be treated as a standalone product, aiming to generate knowledge and material for future products, like the **Decompiler**. During a review meeting, everyone was very excited about HarukaMirai Dbg. But the name didn’t have the impact we wanted — we needed something with more of an edge. A meeting that was supposed to last an hour ended up taking three, with the entire Maldec Labs team involved in choosing the new name for the project. That’s when **KoiDbg** was born, and along with it, we set a **deadline** for the launch in January 2025.

When the date arrived, we had everything ready. **On the night of January 11-12**, we launched the project — but without the source code, as we still wanted to extract more knowledge before releasing it.

Check out the introduction video:

[![MalDec Labs presents： KoiDbg](https://img.youtube.com/vi/vCgGMcGksp8/0.jpg)](https://www.youtube.com/watch?v=vCgGMcGksp8)

Unfortunately, the following month, I had to step away from the KoiDbg development and research team, taking on the role of **advisor, security lead, and tester at Maldec Labs**. This happened because the project was taking up too much of my free time — and that wasn't my main job. Result: long hours without rest. Bad idea, right?

At the same time, my friends at Maldec were focusing on other company products and beginning their transition to becoming a game developer. **KoiDbg** was no longer supported, so we decided, together, to release the project’s source code. Along with it, we also prepared this detailed article explaining how a debugger for Windows ARM64 works, the system internals, and the entire experience, serving as a guide for anyone who wants to use KoiDbg as a base, build their own from scratch, or simply learn something new.

### Windows Debuggers 101 - Any Architecture

![#1](/imgs/img01.png)

Before we continue with the technical part, dear reader, can you exercise your imagination — or even visualize — how a debugger, such as x64dbg, WinDbg, or IDA Server, works? If not, no worries. Let’s understand that now!

A debugger is simply an application that receives and handles ```DEBUG_EVENT``` events (which are essentially exceptions) generated by the application being debugged (the debugee). These events are captured by the debugger, as long as it has a ```HANDLE``` obtained via ```CreateProcess``` with the ```DEBUG_ONLY_THIS_PROCESS``` flag, or by attaching to a running process using the ```DebugActiveProcess``` API.

In **KoiDbg**, or any other debugger, we centralize this capture in a single routine — well-known to those who develop this type of tool — called the **Debug Loop**. This routine calls ```WaitForDebugEvent```, which returns a ```DEBUG_EVENT``` structure with the new exception context. From there, we determine the type of event to handle through the ```dwDebugEventCode``` field, implementing specific cases for each type of event. The most common ones are:

- EXCEPTION_DEBUG_EVENT
- CREATE_THREAD_DEBUG_EVENT
- CREATE_PROCESS_DEBUG_EVENT
- EXIT_THREAD_DEBUG_EVENT
- EXIT_PROCESS_DEBUG_EVENT
- LOAD_DLL_DEBUG_EVENT
- UNLOAD_DLL_DEBUG_EVENT
- OUTPUT_DEBUG_STRING_EVENT
- RIP_EVENT

For each of these events, there is a specific field inside the ```DEBUG_EVENT``` structure, as shown below:

```c++
typedef struct _DEBUG_EVENT {
  DWORD dwDebugEventCode;
  DWORD dwProcessId;
  DWORD dwThreadId;
  union {
    EXCEPTION_DEBUG_INFO      Exception;
    CREATE_THREAD_DEBUG_INFO  CreateThread;
    CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
    EXIT_THREAD_DEBUG_INFO    ExitThread;
    EXIT_PROCESS_DEBUG_INFO   ExitProcess;
    LOAD_DLL_DEBUG_INFO       LoadDll;
    UNLOAD_DLL_DEBUG_INFO     UnloadDll;
    OUTPUT_DEBUG_STRING_INFO  DebugString;
    RIP_INFO                  RipInfo;
  } u;
} DEBUG_EVENT, *LPDEBUG_EVENT;
```

To better understand how it works, imagine that your debugged application has a breakpoint (whether it's hardware or software). When this breakpoint is hit, an event will be generated with the code ```EXCEPTION_DEBUG_EVENT```, which should be handled with the information in the ```EXCEPTION_DEBUG_INFO``` structure. This is where we identify the type of breakpoint, allowing us to make decisions — whether to remove the breakpoint or just continue the execution.

Every time a debug exception is captured, you must use the ```ContinueDebugEvent``` API, passing ```DBG_EXCEPTION_NOT_HANDLED``` to repeat the exception while no action is taken, or ```DBG_CONTINU```E to continue after the action has been executed — such as when a breakpoint has been removed. **We’ll talk more about how breakpoints work shortly.**

Only with the implementation of handlers for each of these structures and events do we have the basic cycle and core of a debugger. However, there is much more involved, such as stack, call stack, registers, disassemblers, and more.

Some debuggers, such as **IDA Server** and **WinDbg**, use the [IDebugClient](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nn-dbgeng-idebugclient) interface, which provides many ready-to-use features. But this is not the case for all of them. Some, like x64Dbg and **KoiDbg** itself, use custom implementations based on the Debug Loop structure with the [system debugging APIs](https://learn.microsoft.com/en-us/windows/win32/debug/debugging-functions) — which will be our main focus from now on, so we can understand how they work.

### KoiDbg Internals

![#2](/imgs/img02.jpg)

In this topic, we will explore the internal workings of KoiDbg, starting from the moment a process is created in a suspended state or attached. We will explain how we handle each event in the DebugLoop, how we process and organize each piece of information for reuse — such as threads, modules, memory, stack, and others — before diving into more direct concepts related to the ARM64 architecture.

First and foremost, it's important to emphasize that, although KoiDbg is a debugger exclusively for ARM64, it does indeed support Intel. During the development phase, not everyone who worked with me on the project had access to an ARM processor. Therefore, we needed a way for them to test it and contribute to the development, addressing the differences between Intel and ARM64 later on.

#### KoiDbg Init-DebugLoop

In KoiDbg, the Qt graphical interface is entirely independent from the engine's logic, which is mostly responsible for displaying information. Our focus begins with the process of creating a new debug session.

When a new debug process is created by the engine, the method ```DebuggerEngine::InitDebuggeeProcess``` is called. Its logic is focused solely on invoking ```CreateProcessW```, with the flags ```DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE | CREATE_SUSPENDED```. Each of these flags ensures important aspects for the application being debugged, adding relevant information for analysis. One example is the console output, **often used by malware** during the development phase but usually hidden. With this flag, we can capture the console output if the attacker forgets to hide it. Additionally, the suspended process creation allows us to capture all stages of the application's execution, acting as a second layer of assurance.

Immediately after the process creation, starting from the engine's class constructor itself, there is a call to ```DebuggerEngine::DebugLoop```, which runs in a separate thread from the main one — where the Qt graphical interface runs — to give us full control over the debug session without interfering with the graphical interface’s performance at any point.

Upon reviewing the logic implemented in ```DebuggerEngine::DebugLoop```, it’s clear that it closely resembles the basic concept of a debugger, as explained earlier in the **Windows debuggers 101 - Any architecture** section:

![#3](/imgs/img03.png)

The only significant difference here is the presence of specific ***handlers*** that handle each of the events separately, following the necessary logic to process them and provide useful information to the person performing the debug. Let's focus on understanding each of them.

###### handleExceptionDebugEvent

![#4](/imgs/img04.png)

When we encounter an **EXCEPTION_DEBUG_EVENT**, it's most often linked to hardware or software breakpoints. However, other exceptions can also trigger this event — the most well-known being **EXCEPTION_ACCESS_VIOLATION**. When KoiDbg receives an unexpected exception, it always waits for user input before resuming the execution of the debugged process, similar to how many other debuggers on the market operate. A full list of exceptions that can generate this event is available on the [MSDN page](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record#members), and KoiDbg is fully compatible with all of them.

As soon as a debugging exception is received — regardless of its type — the debugger's previous context is discarded by default, and a new one is stored (this is Koi's debugger update context). You might be wondering: what exactly is a context? Every debugger handles this step a bit differently. In Koi, we maintain our own debug session context. With each new event, we clear the entire stack and register context from the last exception and rebuild it based on the TID of the thread that caused the exception. This is a key point. Have you ever thought about how a debugger keeps track of each thread’s context? It does so through the TID. Each thread has its own context that needs to be managed. In Koi, this update is handled by the method ```DebuggerEngine::UpdateAllDebuggerContext```:

![#5](/imgs/img05.png)

Exceptions handled in the methods ```ListAllHandleObjectsForDebugeeProcess``` and ```AnalyseDebugProcessVirtualMemory``` require more complex processing. The other two methods, which receive the TID directly as an argument, are mainly responsible for updating the user interface — and will be explained in more detail later in this article.

###### handleCreateThreadDebugEvent

When a ```CREATE_THREAD_DEBUG_EVENT``` exception is received from the process under debug, this handler is triggered to capture basic information about the newly created thread, such as the **HANDLE** with full access, **TID, Thread Basic Information, base address, TEB address, and Priority Level**. All this data is stored in a class responsible for managing the lifecycle and state of each thread in the debugging session, called ```DebugThread```:

![#6](/imgs/img06.png)

! If you're interested in the logic used to query the TBI (Thread Basic Information), check out the section [KoiDbg Utils](#koidbg-utils).

###### handleCreateProcessDebugEvent

Whenever a ```CREATE_PROCESS_DEBUG_EVENT``` is received, it's associated with the first thread of the loader that's running, which will later be transferred to the executable code. This event is triggered alongside **LdrpDoDebuggerBreak**, which notifies us that the process and its memory space have been initialized—giving us the chance to modify the process's behavior before the original code actually starts executing.

Usually, this event is followed by an ```EXCEPTION_DEBUG_EVENT```. In Koi’s case, we take advantage of this second opportunity to update the debugger’s contexts and handle the interruption alongside the user. However, in this particular handling, we use this moment for a different reason: this is the only chance we have to capture the first thread (the main one) of the application being debugged — along with, of course, the executable module itself (so it can appear in our list of modules loaded by the process).

**Since you've studied how the operating system works, you know that an main executable is also considered a module within a process, just like any other.**

Here’s the implementation:

![#7](/imgs/img07.png)

###### handleExitThreadDebugEvent

This handler is always triggered when an ```EXIT_THREAD_DEBUG_EVENT``` is received. The logic here is entirely self-explanatory and predictable. When a thread exit notification occurs, Koi retrieves the corresponding thread object from the global thread list using the event's TID, and moves it to the global list of past threads. This allows the user to see which threads have existed, in case any detail was missed during the analysis. This feature is very important, and not all debuggers offer it.

###### handleExitProcessDebugEvent

When we receive an ```EXIT_PROCESS_DEBUG_EVENT```, it’s always tied to the main thread of the application, whose lifecycle has ended. Koi handles this event as an opportunity to reset the entire debugging session context and notify the user that the session has ended, providing the thread’s exit code and the most recent stored call stack, in case something didn’t go as the user expected.

![#8](/imgs/img08.png)

###### handleLoadDllDebugEvent

When a ```LOAD_DLL_DEBUG_EVENT``` is received, Koi stores the handle of the loaded module, retrieves the DLL name from the handle table of the process being debugged, and also obtains the module’s base address. Each of the loaded modules is then stored in a global module list, allowing the user to have full control over them. See the implementation:

![#9](/imgs/img09.png)

**! Note: Don’t worry about every detail of this part/image—for example, ```GetFileNameFromHandle``` and the Kurumi engine class will be covered later in the article.**

###### handleUnloadDllDebugEvent

When we receive an ```UNLOAD_DLL_DEBUG_EVENT``` in Koi, it’s always related to the unloading of a module in the debugged process. In this case, we retrieve the module from the global module list and add it to the list of past modules, so the user has metrics and information about the unloaded modules without losing any detail during analysis. See the implementation:

![#10](/imgs/img10.png)

###### handleOutputDebugStringEvent

In the case of the ```OUTPUT_DEBUG_STRING_EVENT```, there’s not much mystery. We simply capture the string passed as a parameter to the WinAPI function [OutputDebugStringW](https://learn.microsoft.com/pt-br/windows/win32/api/debugapi/nf-debugapi-outputdebugstringw) and display it in the KoiDbg status bar.

###### handleRipEvent

Similar to the previous event, the ```RIP_EVENT``` is also a specific case where we render the information in the KoiDbg status bar. This event is quite rare and, most of the time, occurs when the process fails for some unexpected reason, causing us to lose the ability to continue debugging it.

#### KoiDbg Engine Functions

Let’s now explore some of the internal logic of the KoiDbg engine that supports the core debugging functionality, such as the handle table, virtual memory analysis, register context, disassembler engine, hardware and software interrupts, stepping (into, over, out), debug commands, and the patch/assembler engine.

##### ListAllHandleObjectsForDebugeeProcess

One of the most interesting features that good debugging can offer is the ability to retrieve all the handles from the handle table of the debugged process. In Koi, this feature is certainly present — including a dedicated view, with a specific tab where the user can see which handles the process has opened, the type, and whether any name/path is associated with them:

![#11](/imgs/img11.png)

This feature works based on the **systemcall** ```NtQuerySystemInformation```, with the specific ```SystemInformationClass``` ```SystemHandleInformation```, which returns the ```SYSTEM_HANDLE_INFORMATION``` structure:

```c++
typedef struct _SYSTEM_HANDLE {

    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;

} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {

    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];

} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
```

With this, we get information about the handles of all processes in the operating system. But, for context, we focus only on the handles of our debug PID. This is done through the helper ```UtilsWindowsSyscall::GetDebuggerProcessHandleTable```:

![#12](/imgs/img12.png)

The routine above is called from the routine in Koi's engine, which is responsible for notifying the user interface about each new value received by the handle table check procedure for the process in question:

![#13](/imgs/img13.png)

In many attacks, the attacker needs to obtain handles for files, mutexes, IPC mechanisms, and much more. From this, we can successfully retrieve information for an efficient analysis of the process.

##### AnalyseDebugProcessVirtualMemory

Analyzing the full memory of the debugged process is an essential feature for any debugging task. The same goes for Koi: it can enumerate all memory regions, retrieving the address, size, mapped files/information, type, state, and, of course, the page protection/permissions. This feature is even available in a dedicated tab in the ```Memory View```:

![#14](/imgs/img14.png)

This resource was implemented directly into Koi’s engine, and its foundation relies on queries performed through the WinAPI function ```VirtualQueryEx```, analyzing the information in the ```MEMORY_BASIC_INFORMATION``` structure for the entire possible memory range of the application — of course, inspecting each type, state, and protection using well-defined helpers and constants:

![#15](/imgs/img15.png)

Other information is also taken into account, with specific logic to identify the ```KUSER_SHARED_DATA_ADDRESS``` on ARM64 and Intel architectures. Additionally, we also find and map the ```HYPERVISOR_SHARED_DATA```. Every valid address that contains consistent information is associated with a DebugMemory model class, ensuring that each region is later **analyzed to capture any changes — for example, a newly allocated region without execution permission that suddenly changes to have execution permission.** Here’s an example of the implementation of this feature:

![#16](/imgs/img16.png)

##### updateRegistersContext

As mentioned in the [Debug Loop](#koidbg-init-debugloop) section, updating the register context is one of the main features a debugger needs to offer when receiving a debug event and waiting for a user decision. An example of this is a breakpoint event, where the debugging program is fully paused, and the user needs to see the entire execution context of the involved threads.

When you, dear reader, think about how this works, can you imagine the concept of Windows threads? If you focus a bit, you'll remember that we previously mentioned in the specific section for these events that this procedure is called with the TID (Thread ID) that triggered the exception. This is the best approach because, in Windows, each thread has its own context, and generally, when an exception is received, this is exactly the information the user wants to access.

In Koi, this view is directly available in the ```Debug View```:

![#17](/imgs/img17.png)

In the screenshot above, we have an ```EXCEPTION_DEBUG_EVENT``` generated from ```LdrpDoDebuggerBreak```, directly in the main thread, even before the debug process and any associated code is executed. Notice that Koi is waiting for a user interaction event, and the debugged process is in a **paused state**. Let's understand how the capture of this information is made and organized to be displayed in Koi.

The capture starts from the thread ID, gaining full access to it via the WinAPI ```OpenThread``` with the ```THREAD_ALL_ACCESS``` flag. From there, if Koi is debugging an ARM64 process, we use the ```GetThreadContext``` API, providing the new ARM64-specific context structure, [ARM64_NT_CONTEXT](https://learn.microsoft.com/pt-br/windows/win32/api/winnt/ns-winnt-arm64_nt_context). As you may know, Koi also supports the Intel architecture, even though it's not the main focus, and if an x86_64 process is being debugged, the older [CONTEXT](https://learn.microsoft.com/pt-br/windows/win32/api/winnt/ns-winnt-context) structure is used.

![#18](/imgs/img18.png)

With the information from each struct, a pair representing the name of the information and its value is created, to be rendered in Koi's **Register-View** widget:

![#19](/imgs/img19.png)

Some more specific cases, such as the **EFLAGS** or **CPSR** flags, are treated specially, as each bit represents different information. In this case, we also parse each bit of information before rendering it on the graphical interface:

![#20](/imgs/img20.png)

More specialized multimedia registers, like **AVX** or **NEON**, are handled separately. For ARM64, the NEON registers are represented by the [ARM64_NT_NEON128](https://github.com/wine-mirror/wine/blob/master/include/winnt.h#L1796) structure, which is not officially documented. Therefore, we use the documented structure from the Wine project, in the **wine-winnt.h** header, to interpret the logic and render it in Koi's interface:

![#21](/imgs/img21.png)

You, dear reader, might think that this logic for parsing a thread's registers is simple. However, you are completely mistaken. Just imagine the synchronization work required to keep the information for each thread of the debugged process always up to date. This is why managing the lifecycle of these threads is essential.

##### updateCallStackContext

Another essential capability that a debugger must offer is the ability to update the ***call stack*** context. This information is crucial and contains many valuable details, such as the full sequence of calls leading to the current function. In Koi, this feature is available in a dedicated tab aptly named ```Call Stack```, where not only the entire ***call stack*** flow up to the current procedure is displayed, but also the thread to which it belongs. Here's how this feature works:

![#22](/imgs/img22.png)

Let’s take a look at how this data is captured by the engine. It’s based on previously saved thread register contexts, where the Instruction Pointer, Frame Pointer, and Stack Pointer — **(PC, FP, SP)** — are used by the ```StackWalk64``` API to retrieve the information into a [STACKFRAME64](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-stackframe64) structure.

![#23](/imgs/img23.png)

Each address in the stack can be retrieved using the ```AddrPC.offset``` field. This offset is added to a base defined in the stack structure configuration. By default, the stack uses Flat addressing mode, which is standard across all debuggers in the market:

![#25](/imgs/img25.png)

The names associated with symbols, when available, are retrieved through the ```GetSymbolName``` lambda, which uses the ```SymFromAddr``` API to fetch the corresponding name, if present:

![#24](/imgs/img24.png)

In addition to the ```Call Stack```, we’ll also cover another feature: the ```Local Stack``` view, in the section [updateStackContext](#updatestackcontext).

##### updateStackContext

The ```Local Stack``` is of great importance for a debugger, as it is through it that information such as the return address, (extra) arguments, and local variables of the analyzed routine are obtained. In Koi, this feature is available under the ```Debug View``` tab:

![#26](/imgs/img26.png)

In Koi’s ```Local Stack```, we retrieve each address present in the stack along with the corresponding symbols associated with them (if available), adding much more insight for analysis. **However**, I had planned another feature—such as string identification—which unfortunately wasn't implemented. See [KoiDbg Future](#koidbg-future) for a full list of planned features that weren’t completed.

Let’s understand how this data is collected and the logic behind building the ```Local Stack```. As with other features, a handle to the debugged process’s thread is required, with ```THREAD_ALL_ACCESS``` permission. The first step in rendering the stack is obtaining the thread context in order to access the Stack Pointer (RSP for Intel and SP for ARM64). From there, we begin the logic to build our stack:

![#27](/imgs/img27.png)

The logic for building the stack is quite simple: for every 8 bytes subtracted (this being the **Addressing Mode Size**) or added to the **RSP**, up to a total of **0xFFA** — a limit I personally defined, which is expressive and probably more than sufficient for solid analysis. For each address between ```RSP - 0xFFA``` and ```RSP + 0xFFA```, we use the ```ReadProcessMemory``` API to retrieve the actual address referenced by our stack, and, if available, recover the symbol associated with that address. This gives us a complete view of:

```Stack Address -> Referenced Address -> Associated Symbol```.

The logic is very straightforward, take a look:

![#28](/imgs/img28.png)

Fairly simple logic, isn’t it? Even so, it provides a lot of valuable information and allows us—on both **ARM64 and Intel—to** obtain exactly the same data with no added complexity, simply by adjusting the address of the relevant **"Rsp/Sp"** register.

##### UpdateDisassemblerView

The logic behind Koi’s ```Disassembler View``` is quite practical and follows the standard found in virtually all debuggers on the market. It allows the user to analyze the memory region where a specific debug event occurred, making it an essential feature. This functionality is available within the ```Debug View```:

![#29](/imgs/img29.png)

This feature operates based on the register context of the thread that triggered the debug event and is now waiting for user input through the graphical interface. It is split between the main engine and the disassembler engine, which uses the [Capstone](https://www.capstone-engine.org/) project as its backend. Initially, using either the ```CONTEXT``` or ```ARM64_NT_CONTEXT``` structure, we retrieve the equivalent Instruction/Program Pointer/Counter register (RIP for Intel and PC for ARM64). With the value of these registers, we use the ```VirtualQueryEx API``` to query the ```MEMORY_BASIC_INFORMATION``` structure, which includes the fields ```BaseAddress``` — the starting address of valid executable code within that memory page — and ```RegionSize```, which represents the size of the memory region.

The goal here is not only to find the exact point where the executable code begins but also to determine its size. To achieve this, we apply a simple mathematical formula to pinpoint the exact section to be analyzed:

![mathformula](/imgs/math_formula_because_github_latex_suck.png)

In this formula, ```R``` is the size of the ```RegionSize```, ```A``` is the value of the Instruction/Program Pointer/Counter, and ```B``` is the base address where the code region begins. The objective is to extract the precise portion of the code to be disassembled — in other words, the part that actually matters to the user. Here’s a practical implementation of this logic:

![#30](/imgs/img30.png)

You’ll also notice the initialization of a ```DisasmEngineConfig``` structure, which is crucial, as it sets up the configuration for our disassembler engine. Once everything is in place, it's time to initialize Koi’s analysis and disassembly engine. This process differs depending on the architecture, as we support both Intel and ARM64. We use the functions ```RunCapstoneEngineAarch64``` and ```RunCapstoneEnginex86```. Here’s the call:

![#31](/imgs/img31.png)

The focus here isn’t on the disassembler engine or instruction analysis — that will be covered in the dedicated section on the [Disassembler Engine](#disassembler-engine). As a quick overview, this engine is capable of analyzing each instruction individually, resolving symbols for addresses, and enabling syntax highlighting in the widget based on the instruction type. This is achieved using a script language similar to HTML syntax, called **"harukageneric"**, which is interpreted by Qt to render the colors you see in the disassembler widget.

##### SetInterrupting

A breakpoint is the foundation of any good debugger, as it's typically the user's main point of interaction (of course, there are other techniques like memory hooks, VEH, etc.). But at the core of a solid debugger lies breakpoints, ensuring a reliable debugging session. In Koi, two types of breakpoints are supported: Hardware and Software. However, **others were planned but never implemented**. Check [KoiDbg Future](#koidbg-future) for a full list of planned but unimplemented features. In Koi, breakpoints are set via the ```Debug View``` or ```Console View``` and managed through the ```HWSFT Interrupt tab```:

![#32](/imgs/img32.png)

The concept of hardware and software breakpoints differs significantly when comparing Intel and ARM64 architectures. And dear reader, I’ll try to make things as clear as possible.

Let’s begin by explaining how a hardware breakpoint works on Intel processors, taking into account how Windows handles and manages threads. You can define up to **four hardware breakpoints**, which are placed in registers ```DR0–DR3``` and activated based on flags in ```DR7```, using a simple OR operation between the current value and the corresponding flag bit. For example, if we want to set a breakpoint in register ```DR3```, we first assign the desired address to the register, then enable the corresponding flag by OR’ing the current ```DR7``` value with ```0b10000```. This setup is done through the ```CONTEXT``` structure obtained from a thread handle. It’s important to note that this configuration applies only to the thread whose context is currently being modified—not the entire process. Once everything is configured, a ```BREAKPOINT``` event will be triggered exactly at the specified location:

![#33](/imgs/img33.png)

On ARM64, the concept changes entirely—again considering Windows thread management. ARM64 supports up to **8 hardware breakpoints**, defined via the [```Bvr```(Breakpoint Value Registers)](https://developer.arm.com/documentation/ddi0338/g/debug/debug-registers/cp14-c64-c69--breakpoint-value-registers--bvr-) and [```Bcr```(Breakpoint Control Register)](https://developer.arm.com/documentation/ddi0211/k/Cegfgdih). As usual, there's no public Microsoft documentation for this—only ARM’s. To define a breakpoint, you write the target address into one of the ```Bvr``` registers **(indices 0 through 7)**, then configure the corresponding ```Bcr``` register with the flags **BCR_BAS_ALL (0xF << 5) and BCR_E (0xF << 5)**. This enables the breakpoint and ensures it will be caught as a debug event, all via the ```ARM64_NT_CONTEXT``` structure:

![#34](/imgs/img34.png)

Regardless of whether the hardware breakpoint in Koi is on ARM64 or Intel, once configured, it is represented by the ```DebugBreakpoint``` class and stored in a global list of breakpoints for management.

Now let’s dive into how software breakpoints work and how they’re set.

Starting with the Intel architecture—probably more familiar to those who’ve worked on Windows—a software breakpoint is created by modifying a single byte in the instruction stream to [```0xCC(INT 3)```](https://www.felixcloutier.com/x86/intn:into:int3:int1), which triggers a trap caught as a debug event. The original byte is saved so the breakpoint can be removed later, restoring normal execution of the thread. Like so:

![#35](/imgs/img35.png)

On ARM64, the concept is similar, though naturally different due to the architecture. The breakpoint instruction ```(0xD43E0000) BRK 0xF000``` is 4 bytes long—the standard size for a valid instruction. This same instruction is used by the [__debugbreak intrinsic recommended by Microsoft](https://learn.microsoft.com/pt-br/cpp/intrinsics/debugbreak?view=msvc-170): “On ARM64, the __debugbreak intrinsic compiles to the brk #0xF000 instruction.” As with Intel, we store the 4-byte instruction sequence so that the breakpoint can be removed later, allowing execution to resume normally:

![#36](/imgs/img36.png)

Just like hardware breakpoints, software breakpoints are also represented by the ```DebugBreakpoint``` class and stored in the global list of breakpoints for management.

##### RemoveInterrupting

As discussed in the [SetInterrupting](#setinterrupting) section, all Koi breakpoints are stored in a model class called ```DebugBreakpoint``` and kept in a global list of breakpoints. When a user removes a breakpoint—whether through the ```Console View``` or via ```HWSFT Interrupt``` by clicking on the breakpoint—the corresponding object is removed from the global list and the removal process is triggered. The logic behind it is quite straightforward.

If the **interrupt is software-based**, the original opcode of the instruction is restored, since the DebugBreakpoint model class stores the original backup value in its ```m_ucOriginalOpcodes``` field. Based on another field, ```m_szOriginalOpcodes```, which holds the instruction size (always 1 byte for Intel and 4 bytes for ARM64), the same logic applies to both architectures. The only difference here is that the thread context (```CONTEXT``` or ```ARM64_NT_CONTEXT```) has its instruction pointer subtracted by 1 (for Intel) or 4 (for ARM64), so the exception handler can resume execution at the beginning of the restored opcode. Take a look:

![#37](/imgs/img37.png)

If you're a careful reader, you might notice another flag being used by the Koi engine: ```DebuggerEngine::CurrentDebuggerRule::BKPT_CONTINUE```. This flag indicates that the debugger has handled the exception or some action, and that execution should resume using the ```DBG_CONTINUE``` flag in the ```ContinueDebugEvent``` API.

As for the **hardware interrupt** logic, it works a bit differently, as mentioned in the previous section.

On ARM64, based on the ```DebugBreakpoint``` model class, we locate the corresponding index in the ```ARM64_NT_CONTEXT``` context and set the values at that index in ```Bvr and Bcr``` to zero. Here's how it's done:

![#38](/imgs/img38.png)

And on Intel, we clear the value from the ```Dr0–Dr3``` register based on the slot it uses. Naturally, we also remove the corresponding flag from the Dr7 register using an ```AND + NOT``` operation with the negated flag to flip the bit we want to clear. Take a look:

![#39](/imgs/img39.png)

##### UpdateActualIPContext

Updating the ```Instruction Pointer``` is a basic yet very useful action when the user wants to control where a given thread should execute — whether it's jumping back to a specific location or redirecting execution to a new region that wasn't originally under the thread's control. **A good example of this is during shellcode debugging**.

In Koi, this feature is available in the ```Debug View```(through the right-click interaction menu) and, of course, also via the ```Console View```. Take a look:

![#40](/imgs/img40.png)

On ARM64, this is done using the ```ARM64_NT_CONTEXT``` structure by modifying the ```Pc register``` to the address the user interacted with in the graphical interface. On Intel, the same process uses the ```CONTEXT``` structure and the ```RIP register```. In both cases, as expected, the change affects only the context of the thread that triggered the debug event.

##### stepInto

A feature called ```stepInto``` might seem super complex at first glance. But in reality, it only looks that way—its implementation is actually simpler than it appears. In Koi, this feature is available in the ```Debug View``` and can be accessed through the ```Debug Commands``` menu. Take a look:

![#41](/imgs/img41.png)

Using the thread context—either ```ARM64_NT_CONTEXT``` or ```CONTEXT```—Koi retrieves the value of the ```Instruction Pointer``` (whether it's ```Pc``` or ```RIP```). Based on this value, Koi uses the ```DisassemblerEngine```, specifically the ```RunCapstoneForSingleStepARM64``` procedure, to extract the immediate value, address, or branch from the instruction currently pointed to by the Instruction Pointer. This resulting value is then set as the new Instruction Pointer.

To do this, we use the [Capstone Engine](https://www.capstone-engine.org/). For a full overview of the disassembler engine, check out [Disassembler Engine](#disassembler-engine). Here’s how it works:

![#42](/imgs/img42.png)

##### stepOver

A ```StepOver``` feature is nothing more than a simple ```EXCEPTION_DEBUG_EVENT``` (in this case, with the event code ```SingleStep```) triggered for the next instruction the processor is about to execute. It’s a very straightforward mechanism, as this break is triggered through a single bit set in a flag register. In Koi, this feature was implemented in a very intuitive way, either via the ```Debug Commands``` menu or the ```Console View```. Take a look:

![#43](/imgs/img43.png)

While on Intel architectures this feature is managed via the EFLAGS register using the TF (Trap Flag) bit, on ARM64 single-step is controlled by the debug register [MDSCR_EL1](https://developer.arm.com/documentation/ddi0487/latest), specifically by the SS bit (bit 21) — also known as the [T-Bit](https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/MDSCR-EL1--Monitor-Debug-System-Control-Register). **There is no public mention of this kind of single-step event in Microsoft’s documentation**, but its implementation is quite straightforward. See below:

![#44](/imgs/img44.png)

##### stepOut

To wrap up the Step features, the last one to be covered is ```Step Out```. As the name suggests, it is responsible for finding the closest ```ret``` instruction relative to the current Instruction Pointer. This is done by analyzing the entire region around the Instruction Pointer until a return instruction is found. In Koi, this feature is available through the ```Debug Commands``` menu or the ```Console View```, as shown below:

![#45](/imgs/img45.png)

Based on the ```CONTEXT``` or ```ARM64_NT_CONTEXT``` structures, Koi’s engine retrieves the ```Instruction Pointer``` from the appropriate register ```(Pc/RIP)``` and uses the ```VirtualQueryEx``` API to obtain a ```MEMORY_BASIC_INFORMATION``` structure for the sole purpose of calculating the size of the executable code region following the Instruction Pointer. This allows the engine to begin scanning for return opcodes using the ```Disassembler Engine```. The calculation is straightforward: a simple subtraction between two values — the ```Instruction Pointer``` minus the ```Allocation Base```. This gives us the value X (previous size of the executable page), which should be disregarded and subtracted from the full executable ```page size```. Based on this new size, we isolate only the relevant portion of executable code that will be used to extract the final execution address:

![#46](/imgs/img46.png)

The procedure is implemented in the disassembler engine, which will be covered in more detail in the topic about the [disassembler engine](#disassembler-engine). The functions ```RunCapstoneForStepOutARM64``` and ```RunCapstoneForStepOutx86``` are responsible for finding the nearest return instruction — one that would conventionally terminate a flow of execution, such as ```ret``` or ```retn``` — using a buffer of valid opcodes, and returning the address where a software breakpoint should be set. See below:

![#47](/imgs/img47.png)

##### DebugCommandProcessingLoop

Now let’s talk about the most fun part, in my opinion — the ability to control our debug session using commands in KoiDbg’s ```Console View```. Most debuggers offer this feature, and it’s incredibly useful for quick or automated analysis. In Koi, it’s located just below the ```Debug View``` tab:

![#48](/imgs/img48.png)

Koi’s command support is made up of several components, including its own lexer that parses commands and their arguments, adding them to a lexer instance stored in a global variable called ```m_commandProcessingQueue```. This queue uses a straightforward implementation for batch command processing, through the ```SafeCommandQueue``` class, as shown below:

![#49](/imgs/img49.png)

Each command entered in the ```Console View``` interface is parsed by a new ```Lexer``` object and then added to the global ```m_commandProcessingQueue```. This queue is safely shared between the interface thread and the command processing thread (**DebugCommandProcessingLoop**) in a synchronized manner.

The DebugCommand thread has full access to the engine, but not to the debug session thread, for security reasons. Still, it can interact with various debug session resources through secure wrappers. Every time a command is added to the queue, the thread picks it up and begins processing, executing the user’s intended action. Once done, it removes the item from the queue — always processing one command at a time:

![#50](/imgs/img50.png)

Many commands are supported, including:

| Comando | Funcionalidades |
|--|--|
| !mem index address | Displays a specific address in the Hex View defined by the index. |
| !memclear index | Clears the Hex View display. |
| !memsave address size path | 	Saves a buffer starting at a given address and of a given size to the file system, at the specified path. |
| !ko | Displays help, documentation, and engine support info. |
| !bs address | Sets a new software breakpoint. |
| !bh address | Sets a new hardware breakpoint. |
| !br address | Removes a breakpoint (software or hardware) at the specified address. |
| !vw address | Displays the Disassembler View for a region based on the provided address. |
| !imgbase | Gets the image base of the debugee's main module. |

Many other automation commands were envisioned for [future implementation](#koidbg-future), but have yet to be developed.

##### SetNewPatch

A good debugger needs to have functionality for patching, saving, and importing changes. In Koi, this was implemented through the context menu that appears when right-clicking an instruction in the ```Disassembler View```, which opens the ```Patch Code View```:

![#51](/imgs/img51.png)

The way this feature works is quite straightforward. When the interaction happens in the ```Disassembler View```, some information — such as the instruction address — is passed as an argument to the constructor of the ```PatchCode``` class. From there, the disassembler engine itself uses the ```RunCapstoneForSimpleOpcodeBlocARM64``` or ```RunCapstoneForSimpleOpcodeBlocX86``` procedure to disassemble the instruction and display it in an input field so the user can start editing it.

![#52](/imgs/img52.png)

Once the user finishes editing the patch and clicks the apply button, the actual patching process begins: the modified string is converted into machine code using Koi's ```Assembler Engine```, which is backed by [Keystone](https://www.keystone-engine.org/). This engine will be covered in a [later section of this article](#assembler-engine). The procedures responsible for this assembly process are ```assembleArm64Code``` and ```assembleX64Code```. Koi can also automatically detect and validate whether there were any errors during the patch assembly process, ensuring everything is correct before replacing the original opcodes with the new ones. Take a look:

![#53](/imgs/img53.png)

After a successful patch, all changes are stored in a model class called ```DebugCodePatchs``` and passed to the core engine through a callback, so they can be managed throughout the entire debug session lifecycle. This allows the user to export or restore patch data at any time — a very useful feature for malware analysts, CTF participants, or anyone looking to crack a binary.

##### extractPdbFileFunctions

Sometimes, a reverse engineer can get really lucky and come across a symbol file (PDB), or even a curious developer analyzing their own application (or system binary symbols). The fact is, these files carry extremely useful information and add significant value to the analysis process. With that in mind, Koi includes a feature for parsing user-supplied PDB files, which are imported into the debug session to enrich the analysis details. Take a look:

![#54](/imgs/img54.png)

This feature works through two separate engines: the ```Debug Engine```, which is responsible for notifying the [Kurumi Engine](#kurumi-engine), the component that directly handles symbol files. It manages tasks such as downloading, parsing, and importing them into the analysis session. The method used by the ```Kurumi Engine``` for this task is ```ParsePdbFunctionsAndSymbolsByPath```. Only the file path is required as an argument, and it returns the complete symbol and address map from the file for later synchronization. Check it out:

![#55](/imgs/img55.png)

The implementation of the parsing feature in the ```Kurumi Engine``` is also quite straightforward, relying only on APIs provided by DbgHelper (everything will be covered in detail in the section about this engine):

![#56](/imgs/img56.png)

#### Kurumi Engine

The Kurumi Engine is one of the most important components of Koi, as it is responsible for handling symbol files—managing, retrieving, parsing, and adding them to the active debug analysis session. It can extract any kind of information from a symbol, whether it comes from the system, is fetched from Microsoft, or is a file provided directly by the user. In this section, my goal is to explain how it works in detail, focusing on the logic behind its design and the key engineering aspects.

##### Modularization

Unlike the other Koi components we've covered in previous sections, the Kurumi Engine is a completely separate component — in other words, an independent lib file that is integrated via linking and a reference header. This design led to the creation of many export wrappers to help keep the project organized.

##### InitKurumiKOPDB

This procedure is one of the first to run in the ```Kurumi Engine``` during a standard debugging session. It is called by the debug engine itself at startup with the purpose of retrieving module symbols from the system — the most important of which is **ntdll.dll**. These metadata files are saved in a directory named ```KoiDbgPdbs```, located at the root of the Koi project, following a naming convention based on the module name with the ```.KOPDB``` extension. Take a look:

![#57](/imgs/img57.png)

##### DownloadKoiPdb

When a new system module is ready to be analyzed by the ```Kurumi Engine```, it's necessary to fetch its symbol directly from Microsoft’s msdl-cdn. This is done quite simply by manually crafting the URL, extracting the module name and its GUID in the process.

In Koi, after crafting the URL to download the symbol, we use the WinAPI ```URLDownloadToFileW```, which performs a synchronous download of the file and saves it to disk for later processing:

![#58](/imgs/img58.png)

It's worth noting that using ```URLDownloadToFileW``` is not the best practice; however, an improvement was already planned for [Koi’s future](#koidbg-future). For a first version, though, it worked surprisingly well.

##### FindPdbField

The Kurumi Engine can retrieve the offset of a given symbol from a PDB file using only its name. This is crucial for more specific analyses, such as the [Windows Loader Structure Analysis](#extracting-windows-loader-struct-information---koidbg). It all works by using the standard APIs provided by DbgHelp.

The process is fairly straightforward: after initializing with ```SymInitialize```, setting the symbol search path with ```SymSetSearchPath```, and loading the PDB file using ```SymLoadModuleEx```, we simply call ```SymGetTypeFromName``` to retrieve information about the desired symbol into a ```SYMBOL_INFO``` structure:

```c++
typedef struct _SYMBOL_INFO {
  ULONG   SizeOfStruct;
  ULONG   TypeIndex;
  ULONG64 Reserved[2];
  ULONG   Index;
  ULONG   Size;
  ULONG64 ModBase;
  ULONG   Flags;
  ULONG64 Value;
  ULONG64 Address;
  ULONG   Register;
  ULONG   Scope;
  ULONG   Tag;
  ULONG   NameLen;
  ULONG   MaxNameLen;
  CHAR    Name[1];
} SYMBOL_INFO, *PSYMBOL_INFO;
```

From there, you can extract the ```Address``` field, which stores the offset of the procedure in question. This allows the ```Debug Engine``` to continue its analysis without any issues. Take a look:

![#59](/imgs/img59.png)

##### FindPdbStructField

Another heavily used feature in the Koi engine, implemented by the Kurumi Engine, is the ability to extract a field or parse a structure and its fields (children) from a PDB file. This is widely used by several analysis features within Koi. Similar to the [FindPdbField](#findpdbfield) feature, this functionality is directly related to the [Windows Loader Structure Analysis](#extracting-windows-loader-struct-information---koidbg). Its implementation also relies on initializing ```SymInitialize```, setting a symbol search path with ```SymSetSearchPath```, and loading the PDB file using ```SymLoadModuleEx```.

The main difference is that it walks through the fields (children) using ```SymGetTypeInfo``` with the ```TI_FINDCHILDREN``` flag from a parent node, and uses the ```TI_GET_SYMNAME``` flag to locate the correct offset based on the field name, as provided by the debugging engine. Although this feature might seem complex, its implementation is quite straightforward. Check it out:

![#60](/imgs/img60.png)

##### ParsePdbFunctionsAndGetListInternal

Another feature present in the ```Kurumi Engine``` is the ability to extract all function symbols declared in a PDB file and retrieve a vector with all relevant data, all based on the system module’s path. This is done in a very simple way, using only DbgHelp APIs. The process starts with initializing via ```SymInitialize```, setting the symbol search path to the KoiPdbs folder using ```SymSetSearchPath```, loading the PDB file with ```SymLoadModule64```, and finally enumerating all symbols into a vector via ```SymEnumSymbols```:

![#61](/imgs/img61.png)

The callback defined for ```SymEnumSymbols``` is intended to filter each ```SYMBOL_INFO``` that has the **SymTagFunction** tag, allowing only the name and offset of declared functions in the PDB file to be collected and stored in a vector, for later use in Koi’s analysis engine. Take a look:

![#62](/imgs/img62.png)

#### KoiDbg Utils

As mentioned in earlier sections of this article, Koi includes some utility procedures that help aggregate and extract specific types of information but don’t fall under any of the main feature categories. The goal here is to cover how each of these procedures works and why they are important for the debugger engine's operation.

##### GetFileNameFromHandle

When you read about the [handleLoadDllDebugEvent](#handleloaddlldebugevent), you saw that upon receiving an event related to the loading of a module in the debuggee process, the only information we get is the module’s handle. This procedure is quite useful because it can translate (or more precisely, map) this handle to a valid path — in other words, to the name associated with it — allowing us to retrieve the name and full path of the module that was loaded.

The logic behind this is relatively simple. If you've studied the basics in the Windows Internals (7th edition), you know that Windows keeps a copy of names and paths for certain handle types, such as file handles. So, even if this handle isn't directly associated with the process's handle table (and without cloning it into our own handle table), we can create a mapping using the [```CreateFileMapping```](https://learn.microsoft.com/pt-br/windows/win32/api/winbase/nf-winbase-createfilemappinga) API to obtain limited information — which, by coincidence, includes the file name and path.

This mapping is then followed, of course, by projecting the file into the debugger process memory with [```MapViewOfFile```](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile), and finally retrieving the path using this new mapping via [```GetMappedFileNameA```](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamea). Check out the implementation:

![#63](/imgs/img63.png)

##### symbol_from_address

When we study the parsing process of the [stack local](#updatestackcontext) and the [call stack](#updatecallstackcontext), we realize that this procedure is used to effectively retrieve the name associated with a given address (symbol), leveraging the DbgHelper APIs. This process relies on a specific configuration of the [```SymSetOptions```](https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symsetoptions) function, applying the ```SYMOPT_DEFERRED_LOADS``` flag to load symbols on demand as needed by the debugger, and ```SYMOPT_LOAD_LINES``` to read source code symbols, if available (similarly to how WinDbg extracts symbols from source files).

This ensures that no symbol goes unnoticed by Koi. Then, it’s just a matter of initializing with ```SymInitialize``` and calling the API that, almost magically, does all the heavy lifting and returns the ```SYMBOL_INFO``` structure via [```SymFromAddr```](https://learn.microsoft.com/pt-br/windows/win32/api/dbghelp/nf-dbghelp-symfromaddr). Check out the implementation:

![#64](/imgs/img64.png)

##### GetDebuggerProcessHandleTable && GetRemoteHandleTableHandleInformation

Handling the handle table is a crucial feature for any debugging tool. This functionality was inspired by a feature found in the x64Dbg debugger project, although the implementation differs considerably. First, a query is made for all open handles in the system using the [```NtQuerySystemInformation```](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation) system call with the SystemHandleInformation flag. The goal here is to obtain the ```SYSTEM_HANDLE_INFORMATION``` structure:

```c++
typedef struct _SYSTEM_HANDLE_INFORMATION {

	ULONG NumberOfHandles;
	SYSTEM_HANDLE Handles[ANYSIZE_ARRAY];

} SYSTEM_HANDLE_INFORMATION *PSYSTEM_HANDLE_INFORMATION;
```

In this structure, two fields are especially important. The first is the number of handles open at the time of the query, defined by ```NumberOfHandles```, followed by the handle array itself, represented by the ```SYSTEM_HANDLE``` structure, which is our main point of interest:

```c++
typedef struct _SYSTEM_HANDLE {

    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;

} SYSTEM_HANDLE, *PSYSTEM_HANDLE;
```

Since this feature uses **undocumented resources**, the way we determine whether a handle belongs to the debugged process is by checking the ```ProcessId``` field and comparing its value with the PID of the debugee for all handle entries at the time of the snapshot. In Koi, we store these values in a vector, which lets us proceed to the second step of data collection. See below:

![#65](/imgs/img65.png)

With the handle values collected, we move on to the second stage: retrieving as much information about them as possible. As previously mentioned in the [GetFileNameFromHandle](#getfilenamefromhandle) section, not all system objects (handles) can be queried unless they are first duplicated into a process under our control. In this case, from the debugee to the debugger (KoiDbg), which is done using the [```ZwDuplicateObject```](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject) system call, specifying a handle to the debugged process along with the ```PROCESS_DUP_HANDLE``` flag. After this, we can use other system calls to gather more information about the handle, such as [```ZwQueryObject```](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwqueryobject). These include details like ```OBJECT_TYPE_INFORMATION``` and the ```ObjectName```. See the implementation:

![#66](/imgs/img66.png)

Finally, all this information is displayed in the ```Handles``` tab in Koi:

![#67](/imgs/img67.png)

This data proves extremely useful during analysis. Imagine you're investigating a malicious artifact and it creates a file on disk, or even opens a handle to another process to perform code injection. You’d be able to identify that and focus your attention accordingly.

#### Assembler Engine

Koi’s assembler engine is a necessary component when the user wants to create a patch during a debug session. For this, the assembler engine uses a stable backend — in this case, [KeyStone](https://www.keystone-engine.org/). Keystone allows us to build specific abstractions for our engine, focusing only on the logic to validate its output based on user-written assembly code, for both Intel and ARM64 platforms. The goal of this section is to provide a full overview of how this abstraction was built and how it works.

##### assembleX64Code && assembleArm64Code

The Keystone abstraction implementation doesn't hold many secrets. The only difference between Intel and ARM64 architectures lies in the initialization flags: for Intel, we use ```KS_ARCH_X86```, and for ARM64, ```KS_ARCH_ARM64```. The integration flow is straightforward: initialize with ```ks_open```, then assemble using ```ks_asm```, retrieving the new opcodes to be replaced during the patch process. The main point here is Koi’s ability to manage state and errors during this processing to inform users of any issues in their code. For that, we use an enum called ```ASSEMBLERENGINEERROR```, which returns a few possible states. The first is ```ERROR_KS```, which relates to backend and configuration issues with Keystone. The second, ```ERROR_CODE```, handles all processing errors from user-written code. Lastly, ```SUCCESS``` signals that the process succeeded and a new opcode is ready to be patched. See the implementation:

![#68](/imgs/img68.png)

#### Disassembler Engine

This section covers one of the most important features of any debugger: the ability to disassemble code, adapted to the debugger’s specific logic. Koi uses [Capstone](https://www.capstone-engine.org/) as its backend. We’ll explain the structure of Koi’s ```Disassembler Engine``` integration in detail, ending with a discussion of Haruka, the markup language used by Koi for syntax highlighting in the ```Disassembler View```.

##### RunCapstoneEnginex86 && RunCapstoneEngineAarch64

The purpose of this procedure is the same for both ARM64 and Intel, differing only in configuration flags. It manages the entire logic behind the ```Disassembler View```, making it more user-friendly and functional, while integrating with other features such as [Syntaxe-Highlight Haruka](#syntaxe-highlight-haruka), which we’ll cover shortly. In general, the goal of this procedure is to identify: branches, syscalls, direct and indirect references, for individual processing — and of course, to disassemble all opcodes in the executable page extracted by the ```Debugger Engine```.

The process of disassembling code from opcodes extracted by the debug engine is simple. We start with ```cs_open``` using architecture-specific configuration in the ```platform``` struct — ```CS_ARCH_ARM64``` and ```CS_MODE_ARM``` for ARM, for example — and then call ```cs_disasm``` to obtain and process each instruction individually. See below:

![#69](/imgs/img69.png)

Following the disassembler output, instructions are further processed to extract symbols and apply highlighting. This is done based on specific conditions. The current logic includes:

###### is_imm_or_branch

We check all documented control flow mnemonics from the ARM reference manual (```b, bl, br, blr, cbz, cbnz, tbz, tbnz, b., bl., br., blr., cbz., cbnz., tbz., tbnz.```) and verify if the mnemonic type is ```ARM64_OP_IMM``` (offset or address). The goal is to extract the address and retrieve the associated symbol, like so:

![#70](/imgs/img70.png)

This logic uses the procedure described earlier in [symbol_from_address](#symbol_from_address), allowing us to retrieve the symbol as shown above. See the implementation detail:

![#71](/imgs/img71.png)

###### is_mnem_syscalling

We check for the two mnemonics responsible for system calls (```svc and swi```), with the sole purpose of assigning a Haruka tag for better visual identification in the ```Disassembler View```:

![#72](/imgs/img72.png)

###### is_imm_reference

We check whether either mnemonic A or B contains the ```ARM64_OP_IMM``` flag, so we can define a Haruka marker to make it easier to identify in the ```Disassembler View```, allowing the user to quickly recognize its usage:

![#73](/imgs/img73.png)

The logic behind the ```Disassembler Engine``` may seem simple, but it adds a lot of information — both visual and qualitative — to the debugging session, making long and complex analysis much more manageable.

##### RunCapstoneForSingleStepARM64 && RunCapstoneForSingleStepx86

As discussed in the [stepInto](#stepinto) section, the purpose of this implementation is to locate the address of a direct or indirect conditional jump, extract that address, and use it within the Engine so a software breakpoint can be set at the first byte of that address. The check used here is the same as in [is_imm_or_branch](#is_imm_or_branch). See the implementation:

![#74](/imgs/img74.png)

##### RunCapstoneForStepOutARM64 && RunCapstoneForStepOutx86

Similar to what we covered in the [stepOut](#stepout) section, this implementation is solely focused on finding the nearest ```ret``` (return) instruction from the code region where the Instruction Pointer is currently located and returning its address. The engine provides the opcodes for the executable page, and from there, the ```is_returning``` checker is used to find the ```ret``` instruction. See the implementation:

![#75](/imgs/img75.png)

##### Syntaxe-Highlight Haruka

In Koi, we use a very interesting feature to render colors (a.k.a. syntax highlighting) in the ```Disassembler View```, using a custom HTML-like markup language we call **Haruka**. This language is essentially HTML with our own set of tags:

| Markup Tag | Description |
|---|---|
| harukageneric | Used to add color highlighting to disassembled instruction text, usually in "red". |
| harukabranch | Used to highlight disassembled branch instructions, usually in "pink". |
| harukasyscalling | Used to highlight syscall instructions, usually in "purple". |
| harukacontrolflow | Used to highlight control flow instructions (e.g., call, jmp, and similar — indirect branches without comparison), usually in "gold". |

Here’s an example of how the ```Disassembler Engine``` uses it:

![#76](/imgs/img76.png)

Behind the scenes, all the parsing magic happens inside the ```Disassembler View``` widget, using a ```Qt6``` feature called [QStyledItemDelegate](https://doc.qt.io/qt-6/qstyleditemdelegate.html). Its implementation overrides the paint method, allowing us to control how elements are rendered. In this case, we can interpret the string from the ```Disassembler Engine``` as HTML with CSS, so all the highlighting happens automatically by applying CSS styles to each Haruka syntax tag. See it in action:

![#77](/imgs/img77.png)

As a result, this processing delivers an excellent user experience during debugging sessions:

![#78](/imgs/img78.png)

#### Extracting Windows Loader Struct Information - KoiDbg

In this section, we’ll cover Koi’s ability to retrieve loader-related information from the system — incredibly useful during a debugging session. For example: installed VEH handlers by the debuggee, detection of potential [Nirvana Callback](https://github.com/keowu/InstrumentationCallbackToolKit) techniques configured in the target process, and, of course, extraction of all information from the NtDelegateTable. All of this is available in the ```Process Container Callbacks``` tab of KoiDbg. See for yourself:

![#79](/imgs/img79.png)

##### extractLdrpVectorHandlerListInformation

This feature is based on the ```ntdll!LdrpVectorHandlerList``` structure, which stores the addresses of VEH routines registered using the [```AddVectoredExceptionHandler```](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler) API. If you’re familiar with the concept of doubly linked lists in Windows using ```flink and blink```, this structure works in exactly the same way — with the difference that it’s undocumented (and its offsets differ between ```ARM64```, ```Intel64```, ```ARM32```, and ```Intel86```).

The ```VectorHandlerList``` structure consists of a base structure and a substructure, respectively: ```_VEH_HANDLER_ENTRY``` and ```_VECTORED_HANDLER_LIST```. Here are their declarations:

```c++
typedef struct _VEH_HANDLER_ENTRY {
    LIST_ENTRY  Entry;
    PVOID   SyncRefs;
    PVOID Idk;
    PVOID VectoredHandler;
} VEH_HANDLER_ENTRY, * PVEH_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST {
    PVOID              MutexException;
    VEH_HANDLER_ENTRY* FirstExceptionHandler;
    VEH_HANDLER_ENTRY* LastExceptionHandler;
    PVOID              MutexContinue;
    VEH_HANDLER_ENTRY* FirstContinueHandler;
    VEH_HANDLER_ENTRY* LastContinueHandler;
} VECTORED_HANDLER_LIST, * PVECTORED_HANDLER_LIST;
```

During Koi’s research phase, we found that the main differences in this structure are only present in systems with smaller address widths (4-byte or 32-bit Windows). So, the same structure and offsets can be safely used across both Windows x64 and Windows ARM64.

This feature’s implementation is relatively simple and entirely dynamic, thanks to the ```Kurumi Engine``` — a major differentiator of Koi. First, we retrieve the address of ```LdrpVectorHandlerList``` using the [Kurumi Engine](#kurumi-engine) through the [FindFieldKoiPDB](#findpdbfield) procedure. Take a look:

![#80](/imgs/img80.png)

After this initial step, we use the helper ```UtilsWindowsSyscall::VEHList::GetVehList``` to get a vector with both the encrypted and decrypted addresses of the VEH registered by the debuggee process. This is done using the ```ReadProcessMemory``` API to read the address of ```LdrpVectorHandlerList``` and store the relevant data in a ```VECTORED_HANDLER_LIST``` structure. From the ```FirstExceptionHandler``` field, we get the first ```VEH_HANDLER_ENTRY``` and begin traversing the list via ```flink```. Check it out:

![#81](/imgs/img81.png)

Once we retrieve the first entry, we begin iterating via ```flink``` to extract the ```VectoredHandler``` field from each ```VEH_HANDLER_ENTRY```. However, this isn’t as straightforward as it seems. We can’t use the value directly because it’s encoded using a 4-byte ```cookie``` generated by [RtlEncodePointer](https://doxygen.reactos.org/d3/d4d/sdk_2lib_2rtl_2process_8c.html#ad52c0f8f48ce65475a02a5c334b3e959).

So, we must implement logic to decode this value. This can be done using a call to ```RtlDecodePointer``` with the debug handle of the process. But that alone isn’t enough — we also have to manually implement the cookie decoding algorithm. **This is necessary because we don't have access to the target process’s DecodePointer (although ```RtlDecodeRemotePointer``` exists, it didn’t work reliably on Windows ARM64 during testing)**. The decode logic can be reversed from ntdll, as shown here:

![#82](/imgs/img82.png)

The cookie decoding logic stays consistent across different OS versions within the same architecture. However, across different architectures, the constants used in the algorithm vary. For example, the image above shows the algorithm used on Windows x64, which is different from Windows ARM64. Still, it's sufficient for decoding any Windows x64 version. As such, we maintain two decoding rules: one for ARM64 and one for Intel.

Fortunately, we’ve implemented an excellent solution to decode the protection cookie, as shown here:

![#83](/imgs/img83.png)

With this issue resolved, we can finally retrieve the real address of the VEH registered in the target process, store it in our vector, and move to the next entry using ```flink``` and the ```ReadProcessMemory``` API to collect all the necessary data for our feature to work correctly. See below:

![#84](/imgs/img84.png)

##### extractNirvanaCallbackPresentOnDebugeeProcess

This feature allows us to analyze whether a  [Nirvana Callback](https://github.com/keowu/InstrumentationCallbackToolKit) has been set for any thread of the target process. If one is detected, we notify the user so they can add this information to their debugging session.

The technique works by analyzing the ```InstrumentationCallbackPreviousPc```, ```InstrumentationCallbackPreviousSp```, and ```Instrumentation``` fields of the TEB (Thread Environment Block) of each thread. These fields are extracted using the [Kurumi Engine](#kurumi-engine), and then a call is made to ```UtilsWindowsSyscall::NtAndProcessCallbacks::detectNirvanaCallback```. Check out the implementation:

![#85](/imgs/img85.png)

In practice, implementing this feature is quite straightforward: we use ```ZwNtQueryInformationThread``` with the ```ThreadBasicInformation``` flag to obtain the ```THREAD_BASIC_INFORMATION``` structure and extract the TebBaseAddress. From there, we add the offsets extracted by the ```Kurumi Engine``` and read the values using ```ReadProcessMemory```, checking the content of each entry. If any entry is being used (when it shouldn't be), we have successfully detected a nirvana callback. See the example:

![#86](/imgs/img86.png)

Obviously, this technique has a small limitation — the only one so far — which is that it does not recover the address of the callback defined by the debuggee. We can only detect its existence. However, this can be improved in the near future.

##### extractNtDelegateTableCallbacks

This feature is capable of extracting all callbacks from the Delegated NtDll, along with the WoW64 Table, to provide information to the user during the analysis session. These callbacks are often used by attackers trying to avoid detection, or even by security mechanisms — either to collect data or to implement protection techniques within the executable itself. In Koi, they are monitored so that if something deviates from the expected pattern, it is properly captured during the debugging session.

**This section will not fully cover the workings of all collection techniques or how the structures were adapted and reversed — only the general operation. Check Koi’s source code for more details on the structures.**

The following callbacks are monitored:

| Name |  |
|--|--|
| LdrInitializeThunk |  |
| RtlUserThreadStart |  |
| RtlDispatchAPC |  |
| KiUserExceptionDispatcher |  |
| KiUserCallbackDispatcherHandler |  |
| KiUserApcDispatcher |  |
| KiUserCallbackDispatcher |  |
| KiRaiseUserExceptionDispatcher |  |
| LdrSystemDllInitBlock |  |
| LdrpChildNtdll |  |
| LdrParentInterlockedPopEntrySList |  |
| LdrParentRtlInitializeNtUserPfn |  |
| LdrParentRtlResetNtUserPfn |  |
| LdrParentRtlRetrieveNtUserPfn |  |
| RtlpWow64SuspendLocalProcess |  |
| LdrpInitialize |  |
| RtlAddVectoredExceptionHandler |  |
| RtlpDynamicFunctionTable |  |
| LdrpDllNotificationList |  |
| RtlpSecMemListHead |  |
| KernelCallbackTable |  |

###### Simple fields

Excluding the logic behind tables and lists (```RtlpDynamicFunctionTable```, ```LdrpDllNotificationList```, ```RtlpSecMemListHead```, and ```KernelCallbackTable```), the checks are very simple and are based on the [Kurumi Engine](#kurumi-engine), which retrieves the address and associated name and notifies the user interface. Check it out:

![#87](/imgs/img87.png)

###### RtlpDynamicFunctionTable

The parsing logic for the ```RtlpDynamicFunctionTable``` is based on a custom routine, responsible for obtaining the table’s address using the [Kurumi Engine](#kurumi-engine), extracting debuggee data with the helper ```UtilsWindowsSyscall::DynamicFunctionTableList::GetDynFunctTableList```, and collecting entries when a callback has been installed, so the user interface can be notified. Check how the ```Flink``` process is handled in this implementation:

![#88](/imgs/img88.png)

###### LdrpDllNotificationList

The parsing logic for the ```LdrpDllNotificationList``` is also quite simple. The [Kurumi Engine](#kurumi-engine) obtains the associated address, and the debuggee data is extracted with the helper ```UtilsWindowsSyscall::DLLNotificationsList::GetDllNotificationList```, where the implementation performs the Flink between data to extract the information. Take a look:

![#89](/imgs/img89.png)


###### RtlpSecMemListHead

Similar to what we've seen before, the logic implementation for ```RtlpSecMemListHead``` also uses the [Kurumi Engine](#kurumi-engine) to obtain the address, and a dedicated helper, ```UtilsWindowsSyscall::SecMemListHead::GetSecMemListHead```, which handles the Flink between data for extraction. Check it out:

![#90](/imgs/img90.png)

###### KernelCallbackTable

To wrap up our parsing of Koi callbacks, we have the implementation for extracting and analyzing the ```KCT Table```. The procedure offset is extracted using the [Kurumi Engine](#kurumi-engine) and parsed by the helper ```UtilsWindowsSyscall::KernelKCT::GetKctTable```, which is responsible for obtaining the debuggee process's PEB and reading the KCT field using the extracted offset. Each address is stored in a key-value format, associating the procedure name with its address. Take a look (we cropped the screenshot a bit since the table contains many items):

![#91](/imgs/img91.png)

##### Decompiler engine

Initially, we had planned and implemented a decompiler for Koi, available in the ```Decompiler View``` tab. This feature used [llama.cpp](https://github.com/ggml-org/llama.cpp) as its backend along with a modified version of the [LLM4Decompile](https://huggingface.co/LLM4Binary/llm4decompile-6.7b-v1.5) model, offering improved performance. Everything was handled through an API integration and a cloud-based server for processing, where only the code from the ```Assembly View``` and symbol metadata were sent for analysis, with the results returned for display. However, this project was part of another Maldec Labs product, preventing it from being released.

## Analyzing a Packer for ARM64, reversing and debugging with KoiDbg

In this topic, we’ll write a simple packer using a binary that leverages the PEB and a shellcode whose sole responsibility is to launch ```calc.exe```. This serves as an example of how the PEB is used on Windows ARM64. The goal is simply to demonstrate the analysis and reverse engineering experience using KoiDbg.

##### Exploring the PEB on Windows ARM64 to write a loader

When talking about a loader/packer using shellcode, we often think of the PEB (Process Environment Block). It’s an essential requirement for writing dynamic shellcode on Windows. However, there are a few small but important differences between how the PEB works on Intel and ARM64 architectures. Let’s take a look at those differences and write a simple shellcode simulating a multi-stage packer that starts a process.

The main difference between ARM64 and Intel lies in how the PEB is accessed. While on Intel we use ```gs:[60h]``` for ```x86_64``` and ```fs:[30h]``` for ```x86```, on ```ARM64```, access is done through ```register x18```.

In ARM64, the value of the register is easily accessible using the intrinsic ```__getReg(18)```. The key difference is that we first retrieve the address of the ```TEB (Thread Environment Block)``` and, from there, access offset ```0x60 (ProcessEnvironmentBlock)``` within that structure to finally get the PEB. To fully explore ARM64 intrinsics, I recommend reading []"ARM64 Intrinsics"](https://learn.microsoft.com/pt-br/cpp/intrinsics/arm64-intrinsics?view=msvc-170#A). Here’s how the logic to retrieve the PEB was implemented:

![#92](/imgs/img92.png)

In most cases, there are only minor differences compared to the standard OS structures, and generally, they aren't particularly relevant for our purposes. In general, you can find up-to-date structure definitions through the [Vergilius Project](https://www.vergiliusproject.com/) or even with [PDBRipper](https://github.com/horsicq/PDBRipper). In this article, we’re using unmodified structures when comparing Intel and ARM64, such as ```_PEB_LDR_DATA``` and ```_LIST_ENTRY```.

Based on the explanation above, I’ve written a simple code that, in a Windows ARM64 process, uses the PEB to execute shellcode, which in turn launches ```calc.exe```. Let’s look at this code implementation before diving into analysis with Koi:

###### Loader

The first step in our test is a simple loader. Using our PEB implementation for ARM64, it allocates memory with execution permissions, copies the shellcode, adds the entry point offset, and creates a new thread.

![#93](/imgs/img93.png)

This is a very basic loader example, but that’s exactly the point: just a test case so we can observe how KoiDbg behaves during analysis.

###### Shellcode

The second step also makes use of the PEB, but this time within a shellcode that’s executed by the thread created by the loader. Its goal is to locate Kernel32, call ```LoadLibraryA``` to load ```shell32.dll```, and then call ```ShellExecuteA``` to launch ```calc.exe```.

![#94](/imgs/img94.png)

As always, good old ```calc.exe```:

![#95](/imgs/img95.png)

###### PEB

Here’s what the PEB implementation looks like:

![#96](/imgs/img96.png)

Very straightforward. In the ```module_from_peb``` method, we inspect the ```LDR_DATA_TABLE``` to find the specified module and retrieve its base address. Then, in ```GetFunctionAddressByName```, we walk through the export directory to locate the offset of the desired procedure, simulating a call to ```GetProcAddress```.

Lastly, if you’re interested in trying out this simple code, **you can find it in the KoiDbg source code**.

Take a look at the result before we proceed to the analysis phase:

![#97](/imgs/img97.gif)

##### Analyzing our code with KoiDbg

Now let's analyze our test binary using KoiDbg.

![#98](/imgs/img98.gif)

First, we’ll start a new debug session for the file ```loader.exe``` from the ```KoiDbg -> Open Executable``` menu:

![#99](/imgs/img99.png)

At this point, our session is paused at ```LdrDoDebugBreak```. Let's take this opportunity to load the symbol file (PDB) through the ```Pdb Inspector``` tab by clicking "Load PDB," and also set a breakpoint at our main function (so we don’t have to dig through the CRT Runtime):

![#100](/imgs/img100.png)

From there, we let the debug session run until it hits the breakpoint we just set:

![#101](/imgs/img101.png)

Now, let’s locate the ```branch``` to ```VirtualAlloc``` and set a hardware breakpoint on its address so we can capture the return value in ```x0```, and of course, store the size of the allocated page from the instruction ```mov x1, 0x801```:

![#102](/imgs/img102.png)

Notice in the image above that Koi was able to recover the symbol names associated with the procedure responsible for retrieving the function from ```kernel32``` exports. Let's now let the debug session continue until it hits our breakpoint so we can retrieve the allocated address:

![#103](/imgs/img103.png)

Let’s inspect the allocated memory region with the following command in Koi’s ```Console View```:

```
!mem 0x000001D536540000 0
```

The command above will render the specified address in the first ```HexView``` (index 0). Here's the result:

![#104](/imgs/img104.png)

Let’s move a bit further and find where our thread is created, setting a breakpoint right before that so we can finally capture the full shellcode:

![#105](/imgs/img105.png)

Now let’s run the ```!mem``` command again in Koi’s ```Console View``` to visualize the shellcode:

![#106](/imgs/img106.png)

Finally, let's use the ```!memsave``` command to dump the shellcode to disk:

```
!memsave 0x000001D536540000 0x801 C:\Users\joaov\OneDrive\Documents\DUMPS\sc.bin
```

![#107](/imgs/img107.png)

Let’s take a look at our output file:

![#108](/imgs/img108.png)

##### Shellcode Adventure

**Reader asks: Wait a second… where’s the Shellcode? Doesn’t KoiDbg support debugging it? After all, it’s still just a thread.**

![#109](/imgs/img109.jpg)

I won’t go through debugging the entire shellcode from the loader we built, but I’ll show that yes, KoiDbg is fully capable of analyzing it. In fact, our debug session already has everything we need to make that happen—we just need to understand a bit more about how the debug session works.

What we’re seeing now is the main thread of KoiDbg, specifically at our last breakpoint before we dumped the shellcode using the ```Console View```. What we need to do is:

1. Identify the exact address where the shellcode starts.
2. Update Koi’s ```Disassembler View``` to that address.
3. Set a software breakpoint and let Koi capture the new thread so debugging can proceed.

Simple enough, right? Let’s do it.

First, we already know where the shellcode will begin. It’s loaded into register ```x2``` when calling ```CreateThread```, at the same spot where we previously set the breakpoint. We need to retrieve that address:

![#110](/imgs/img110.png)

In this case, the address we need is ```0x00000190D8C40458```. Now let’s update Koi’s ```Disassembler View``` with the following command:

```
!vw 0x00000190D8C40458
```

![#111](/imgs/img111.png)

There we go—we can now see our shellcode’s code. Let’s set a breakpoint and let it hit so Koi can capture the thread’s execution:

![#112](/imgs/img112.png)

Now we just resume the debug session (```Debug Commands -> Run```) and break into the shellcode thread right at the beginning:

![#113](/imgs/img113.png)

So, the answer to the question above is: yes, KoiDbg is fully capable of debugging shellcodes and multilayer malware!

## KoiDbg Future

Many future plans were in place for KoiDbg before I, personally—Keowu—decided to discontinue its development. In this section, I want us to explore each of the features that were on the roadmap.

###### Emulation

One of the features we planned to introduce in KoiDbg was emulation support. This feature was already being tested, but wasn’t implemented because compilation support still needed adjustments, and that wasn’t a current priority. The emulation backend would have been powered by the [Unicorn Engine](https://www.unicorn-engine.org/). Some test files for this functionality can still be found in KoiDbg’s test code, under the name ```TestesUnicornIntegration.hh```. Check out the test implementation:

![#114](/imgs/img114.png)

###### Retrieve Strings for display in the Local Stack View

Another feature we had planned for Koi involved a special capability for the [Local Stack View](#updatestackcontext), which would allow analyzing whether an address within the stack contained a valid ASCII or Unicode string. This would let the user view the string without needing to use Koi’s ```Hex View```.

###### Graph View

A very useful feature for any debugger—the graph view for the disassembler—was also in our plans, and we even wrote a test implementation for it. In Koi, we intended to use the [Dot language](https://graphviz.org/doc/info/lang.html), and the idea was to leverage the Chromium Embedded project to render the JavaScript library, which would be easier than trying to port an interpreter using Qt APIs. The test code can be found in the file ```TestesChromiumEmbeddedIntegration.hh```. Check it out:

![#115](/imgs/img115.png)

###### Support for Scripts and Automation via Lua

Currently, Koi offers some basic script support, but not for automation. It merely accepts commands, like the ones shown throughout this article, which are executed in the ```Console View```. An idea suggested by a friend, ```rem0obb```, was to integrate the [LuaCpp](https://github.com/jordanvrtanoski/luacpp) library so we could use it as a backend and offer full debugging session automation using the Lua language. It’s worth mentioning that Lua is a Brazilian language, making it a perfect fit for this debugger project, which is also Brazilian.

###### Improving the Disassembler with AsmJit

We had plans to unify the Disassembler Engine and the Assembler Engine into a single library, giving users much more low-latency control over the disassembled code produced by Koi and enabling countless customizations. The plan was to achieve this by integrating the backends we were already using—like the [Capstone Engine](https://www.capstone-engine.org/), the Keystone Engine](https://www.keystone-engine.org/)—and adding support for the [AsmJit Engine](https://asmjit.com/).

###### Using the Microsoft Debug Engine to support Kernel Mode

Lastly, one of the future features we envisioned for Koi was kernel mode debugging support. This would be implemented using the [Microsoft Debug Engine](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nn-dbgeng-idebugclient). We had already conducted a thorough study on how this would work once implemented, including creating the [COM](https://learn.microsoft.com/pt-br/windows/win32/learnwin32/what-is-a-com-interface-) interface and implementing the basic methods—initially to support debugging via COM Port. However, we chose to prioritize other features.

## One last message

Developing KoiDbg was without a doubt an incredible learning experience—something I believe many should go through. Creating a debugger brings together and reinforces many foundational concepts in reverse engineering, programming, and Windows Internals—essential knowledge that every security researcher should master. I hope this article has helped to share a bit of that experience and clear up some doubts about how debugger development works. Building Koi certainly wasn't easy—it demanded a lot of time and effort—but the best part was meeting people along the way who supported the project and even became part of it, helping with research, bug fixes, and other challenges. Now, I truly hope this article can help many others, whether to improve Koi or to build their own debugger from scratch.

Keowu

![#116](/imgs/img116.gif)

## References

**"A good article is never written without references; knowledge is built by the community. No one builds knowledge alone."**
With that in mind, I’d like to express my gratitude to the work of other incredible researchers who, like me, share a passion for research and writing (I’ve followed [ABNT](https://www.marilia.unesp.br/#!/laboratorio-editorial/editorial-laboratory/publication-procedures/abnt-standards---citations-and-references/) citation norms as a sign of respect to each of you authors).


- OGILVIE, Duncan. **TitanEngine.** [S. l.]. Disponível em: https://github.com/x64dbg/TitanEngine.
- OGILVIE, Duncan. **x64dbg.** [S. l.]. Disponível em: https://github.com/x64dbg/x64dbg.
- DONIEC, Aleksandra. **From a C Project Through Assembly to ShellCode Paper.** [S. l.]. Disponível em: https://vxug.fakedoma.in/papers/VXUG/Exclusive/FromaCprojectthroughassemblytoshellcodeHasherezade.pdf.
- MISIAK. Tim. **Writing a debugger from scratch.** [S. l.]. Disponível em: https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-1/.
REDP. **PsKernelRangeList on arm64 kernel** [S. l.]. Disponível em: https://redplait.blogspot.com/2020/04/pskernelrangelist-on-arm64-kernel.html.
- ARZILLI. Alessandro. **Notes on Hardware Breakpoints and Watchpoints** [S. l.]. Disponível em: https://aarzilli.github.io/debugger-bibliography/hwbreak.html.
- George. **async_wake-fun** [S. l.]. Disponível em: https://github.com/ninjaprawn/async_wake-fun/blob/6ffb822e153fd98fc6f9d09604317f316c3b0577/async_wake_ios/kdbg.c#L686.
- SIGUZA. **ARM64 - spsr_el1 Explanation.** [S. l.]. Disponível em: https://stackoverflow.com/a/69487245.
- ODZHAN. **Delegated NT DLL.** [S. l.]. Disponível em: https://modexp.wordpress.com/2024/02/13/delegated-nt-dll/.
- ODZHAN. **Windows Data Structures and Callbacks.** [S. l.]. Disponível em: https://modexp.wordpress.com/2020/08/06/windows-data-structures-and-callbacks-part-1/#ftl.

To the referenced authors: in some cases, only nicknames were available in your publications. If you need any adjustments, feel free to reach out.