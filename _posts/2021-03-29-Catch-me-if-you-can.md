---
title: Catch me if you can: Sharing the Hunting Ideas of Windows Kernel Extraction Sample
description: With the introduction of sandboxed mechanism in several major browsers (Chrome, Edge, IE) and word processing software (Office, Adobe Reader) on Windows platform, the demand of Windows kernel privilege vulnerability is also rising.
categories:
 - Windows Analysis
tags:
 - 0day
 - Windows Analysis
 - Windows Kernel Extraction
---


## *Background*

With the introduction of sandboxed mechanism in several major browsers (Chrome, Edge, IE) and word processing software (Office, Adobe Reader) on Windows platform, the demand of Windows kernel privilege vulnerability is also rising. In this context, the 0day attack of Windows kernel privilege, which was disclosed in recent years, is also at a high level. The following table shows the 0day numbers of the Windows kernel rights promotion disclosed worldwide from 2017 to 2021 (up to now) and the corresponding disclosing manufacturers. The above phenomenon can be intuitively felt from the table.

![image.png]({{site.url}}/upload/2021-03-29-Catch-me-if-you-can/wcdIBKPkCh1XeMJ.png)

These Windows kernel 0day vulnerabilities are costly, so they are usually behind APT organizations with high level or strong strength. For the threat intelligence department, how to effectively hunt these samples of the Windows kernel vulnerability in the wild has become a problem that needs to be deeply considered.



On this issue, Kaspersky, as the pioneer of 0day hunting in the Windows kernel, has publicly shared some of their experiences in this area; CheckPoint has also shared three research articles on the hunting of core empowerment samples in the last six months, which are worth learning (the references to these materials will be listed at the end of this paper for readers' reference).



This article will share some thoughts of the Shadow Hunting Lab of Anheng Threat Intelligence Center in this respect, and the discussion focuses on the vulnerability of memory destruction kernel. We are still in the exploratory stage, so please correct the shortcomings.



## *Memory corruption kernel privilege vulnerability*

The vulnerability of memory corruption kernel is usually caused by unsafe operation of C/C++ language, and the most common one is UAF vulnerability caused by Callback mechanism in win32k component.

### *Why is win32k component prone to problems*

Why are there so many UAF vulnerabilities in win32k components? This should start with the design history of Windows NT. At the early stage of Windows operating system design, win32k subsystem was in user mode (the upper part of solid line), as follows:

![image.png]({{site.url}}/upload/2021-03-29-Catch-me-if-you-can/8HzDMaAiPfptZ1O.png)

However, since Windows NT4, this part of the code has been moved to the kernel state (the lower half of the solid line), and a new win32k.sys module has been added in the kernel state:

![image.png]({{site.url}}/upload/2021-03-29-Catch-me-if-you-can/2vpz4Yhj1NrF6VS.png)

The above redesign introduces the following three unsafe factors:

1. new system call (1100+ syscalls)

2. user mode callback (User-mode Callback)

3. Shared data between user mode and kernel mode

After the redesign, all of the above three points may lead to new security vulnerabilities, and the Windows kernel team is aware of these points, so it has made targeted reinforcement, but security researchers still keep finding security vulnerabilities.



At the Blackhat USA conference in 2011, Tarjei Mandt disclosed his research results on the User-Mode Callback mechanism of win32k. from then on, a large number of researchers began to pay attention to the attack surface of User-Mode Callback in win32k module, and found many new UAF vulnerabilities in win32k module.



##  *How to collect samples for rights in hunting*

Students who have had the foundation of vulnerability research know that a typical vulnerability exploitation process probably has these links:



Trigger vulnerability



Stack injection (not required)



Information disclosure



Construct read-write primitives



Code execution

We can start from each of the above stages and think about some potential hunting spots in each stage.



### *Trigger vulnerability stage*

At the static level, first of all, we can check whether the following functions in the user32.dll are imported into the import table of PE file, because most win32k exploits need to create windows or menus:

- CreateWindowExA / CreateWindowExW
- RegisterClassExA / RegisterClassExW
- DestroyWindow
- CreateMenu
- CreatePopupMenu



Secondly, there must be Hook callback table operation in Win32k User-Mode Callback vulnerability, which is a suspicious behavior (64-bit sample will have a code fragment similar to the following):

```
mov rax, gs:[60h]

lea rax, [rax+58h]

mov rax, [rax]

ret
```

On the dynamic level, UAF vulnerabilities and some cross-border read-write vulnerabilities can be detected by opening Driver Virifier. UAF vulnerability samples will trigger blue screen anomalies in the environment where Driver Virifier is opened. The simplest criterion for judging 0day is:



Full patch environment blue screen = 0day



Of course, there are some kernel privilege-raising vulnerabilities of memory corruption that cannot be detected by Driver Virifier. A typical example is CVE-2021-1732 captured by us.



### *Stack injection stage (optional)*

There are many changes in the heap injection stage, and you can create multiple Windows or multiple Bitmaps, such as CVE-2018-8453 in the wild; You can also create multiple accelerators, such as the open source utilization code of CVE-2017-8465; You can also create multiple tagCLS structures, such as << LPE vulnerabilities exploitation on windows 10 annual update>>, which is the method proposed on page 36 of PPT.



### *Information leakage stage*

There is a project on Github (the project address is listed at the end of the article) that summarizes the information leakage skills of Windows kernel. There is a table in the project, which lists all kinds of skills of Windows kernel information leakage in detail, and shows the availability of these skills in various versions of Windows operating systems through different icons.

![image.png]({{site.url}}/upload/2021-03-29-Catch-me-if-you-can/AG1O6sgIpmq7f2o.png)

This table only writes the operating system to Windows 1703(Redstone 2), but according to the information in the table, we can also find that only the skill of HMValidateHandle has been stable (it has been alleviated since 1803).



On the static level, we can find the clues of kernel information leakage by looking for the code characteristics of HMValidateHandle. The following is a typical code to find HMValidateHandle. if you encounter similar code fragments during static analysis, it should be noted:

```
PVOID find_HMValidateHandle(PVOID pIsMenu)

{

  ULONG HMValidateHandleAddr = 0;

  while (TRUE)

  {

​    if (*(BYTE*)pIsMenu == 0xE8)

​    {

​      HMValidateHandleAddr = *(DWORD*)((ULONG)pIsMenu + 1);

​      HMValidateHandleAddr += (ULONG)pIsMenu + 0x05 - 0x100000000;

​      return (PVOID)HMValidateHandleAddr;

​    }

​    pIsMenu = (BYTE*)pIsMenu + 1;

  }

  return 0;

}
```

On the dynamic analysis level, because HMValidateHandle is an unexported function, when the system calls this function normally, the address of its call comes from inside the user32.dll; However, when this function is used for information disclosure, its calling address is located in the exploit module, and this address is not located in the user32.dll module. We can use this principle for runtime detection: the call from outside user32.dll to HMValidateHandle is marked as suspicious behavior and recorded. Some foreign researchers have made examples in this field, which are listed at the end of this paper.



### *Construction of reading and writing primitives*

In the history of Windows kernel utilization, APIs for operating tagWND,Bitmap,Palette,Menu and other related structures have appeared one after another. up to now, only SetWindowLong* series functions and Menu related functions are left in the auxiliary functions for reading and writing primitives at any address that have been disclosed and have not been completely alleviated, so it is an idea to check whether there are the following functions in the user32.dll in the import table:

- SetWindowLongA / SetWindowLongW
- SetWindowLongPtrA / SetWindowLongPtrW
- GetMenuItemRect / SetMenuItemInfo
- GetMenuBarInfo
- (CVE-2021-1732 was first discovered in wild utilization)



In addition to the above API, some utilization codes of earlier versions can also include the following import functions:

```
▲GetBitmapBits / SetBitmapBits / CreateCompatibleBitmap / CreateBitmapIndirect / CreateDiscardableBitmap / CreateDIBitma

▲GetPaletteEntries / SetPaletteEntries

▲SetWindowTextA / SetWindowTextW / InternalGetWindowText

▲NtUserDefSetText
```



### *Code execution phase*

As for the windows kernel privilege raising vulnerability, its main purpose is to enhance the privilege, and the main method to enhance the privilege is to replace the token. Therefore, it can be checked through the following characteristics:

After the implementation of any address read-write primitive, is there any operation of searching structure with the help of leaked kernel address, such as traversing EPROCESS chain

At an appropriate point in time (such as before the current process exits), check whether the Token of the current process has been replaced by that of other high privilege processes (such as System process), or check whether the Token of the child process created by the current process is System permission



## *Attack and defense history of windows kernel vulnerability exploitation*

The windows kernel team and vulnerability mitigation team have been committed to reducing the vulnerability of windows kernel & exploiting attack surface. A simple understanding of the kernel security attack and defense timeline in Windows system will help us understand the history of windows kernel utilization and predict the trend of windows kernel utilization, which is helpful for hunting.



### *Windows 7*

#### *\- KASLR*

Additional kernel information disclosure is required to bypass kaslr

■ bypass method: https://github.com/sam-b/windows_kernel_address_leaks

### *Windows 8.1*

#### - *SMEP (Supervisor Mode Execution Prevention)*

■ requires processor support (introduced in 2011), with bit 20 of the Cr4 register as a switch

When the CPU is in ring0 mode, if the RING3 code is executed, a page error will be triggered

■ bypass method: cve-2015-2360 Duqu 2.0 in the wild

#### - *The use of 0 address page is prohibited*

■ previous kernel null pointer reference vulnerability exploitation: apply for 0 address, and read and write any address with the help of 0 address

■ subsequent kernel null pointer reference vulnerability exploitation: 0 address page cannot be applied and cannot be exploited. For example, cve-2018-8120 cannot be exploited in Windows 8 and above



### *Windows 10 1607 (Redstone 1 )*

#### - *Improve the difficulty of bypass kaslr*

■ GDI_The pKernelAddress member of the cell structure is set to null, and the kernel information disclosure is alleviated by GdiSharedHandleTable

#### - *Ease the use of using SetWindowText to manipulate tagwnd.strname to read and write any kernel address*

■ restrict the tagWND.strName pointer to the desktop heap only (alleviate the wild exploitation of cve-2015-2360 and cve-2016-7255)

#### - *The font resolution module is separated into independent components and its permission is restricted to appcontainer*

■ alleviate win32k font parsing class rights lifting vulnerability and limit file reading and writing in the process of exploiting such vulnerabilities (ease the exploitation of cve-2016-7256 and cve-2020-0938 on Windows 10)



### *Windows 10 1703 （Redstone2）*

#### - *Improve the difficulty of bypass kaslr*

■ alleviate the leakage of pvScan0 kernel pointer information through gSharedInfo

■ ways to alleviate kernel information disclosure through desktop heap: the ulClientDelta pointer in the win32ClientInfo structure is removed, and kernel information disclosure through ulClientDelta is no longer possible

#### - *Ease the construction of arbitrary address reading and writing primitives with tagWND*

■ the extrabytes memory pointer of SetwindowLongPtr operation has been moved to user mode, and tagWND.strName cannot be modified with it

#### - *Ease the use of bitmap*

■ the bitmap object header size has been increased by 8 bytes



### *Windows 10 1709 （Redstone 3 ）*

#### - *Win32k Type Isolation for Bitmap: separate Bitmap header from Bitmap data*

Further ease the way to construct arbitrary address read-write primitives with the help of bitmap object

#### - *Bypass method: construct any address read-write primitive with the help of palette object. Refer to <<Demystifying Windows Kernel Exploitation by Abusing GDI objects*>>



### *Windows 10 1803 （Redstone 4）*



#### - *Win32k Type Isolation for Palette*

■ ease the way to construct arbitrary address read-write primitives with the help of palette objects

■ the sample of lifting rights to bypass type isolation mitigation measures: cve-2018-8453 samples for field use. For details, refer to Overview of the latest Windows OS kernel exploits found in the wild

#### - *How to mitigate kernel information leakage through HMValidateHandle*

■ in the kernel tagWND copy leaked by HMValidateHandle, the relevant pointer value no longer exists



### *Windows 10 1809 (Redstone 5)*

#### - *Continue to increase the difficulty of bypass kaslr*

■ create multiple desktop heaps and greatly modify the relevant API ■ bypass method: leak and calculate the absolute address of the object containing the kernel mode pointer in a new way. Refer to the article "development of a new windows 10 kaslr bypass (in one WinDbg command)"



### *Windows 10 1903*

Further alleviate the attack surface of kernel vulnerability exploitation

■ bypass method: cve-2021-1732 uses samples in the wild, uses spmenu to leak kernel information, and uses getmenubarinfo / SetWindowLong function to read and write any address, which can be used on the latest version of windows 20h2 system



## *Attack and defense history of mainstream browsers and win32k vulnerabilities*

### *Chrome/Edge(Chromium-based)*

#### *Win32k Lockdown*

■ chrome was first introduced in 2016. In chrome + windows 8.1 and above, it is forbidden to call the API of win32k module

■ bypass method: adopt kernel vulnerabilities other than win32k module, such as cve-2018-8611 and cve-2020-17087



### *Edge(Chakra)*

#### *Win32k System Call Filter*

■ windows 8.1 support

■ limit the calling of some win32k APIs: in RS3, edge can call 349 win32k APIs; in RS4, the number of win32k APIs that edge can call is reduced to 78, and all GDI objects cannot be created in edge

■ bypass method: for those loopholes in win32k API that are not filtered, such as DirectX vulnerability, please refer to the subverting direct x kernel for gainning remote system



## *Trend prediction of windows kernel privilege raising vulnerability*

1. The difficulty of kernel vulnerability mining on Windows 10 may not change much, but it has become very difficult to exploit

2. Sandbox mechanism has been introduced into mainstream browser / document processing software, and apt organizations will have more and more demand for sandbox escape / authorization vulnerability

3. The traditional win32k component kernel authorization vulnerability is gradually rejected by mainstream browsers

4. The demand for non win32k module kernel authorization vulnerability will continue to increase in APT market, but the cost will be higher and higher. The exploitation of highly complex vulnerability like cve-2018-8611 will appear in the future

5. The number of logic class privilege vulnerabilities will increase slightly (as a substitute for memory corruption vulnerabilities)

6. The number of sandbox escape vulnerabilities of browser's own components will also increase. This kind of vulnerability is the browser's own vulnerability, but it can also realize sandbox escape, which can be transferred from low to medium, such as the sandbox escape vulnerability of chrome mojo component and the Windows printer authorization vulnerability



## *Reference link*

##### *0day "In the Wild" (by Google Project Zero)*

https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/view#gid=1123292625



##### *Hunting for Privilege Escalation in Windows Environment (by Kaspersky)*

https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment



##### *Three Windows zero-days in three months: how we found them in the wild (by Kaspersky)*

https://www.brighttalk.com/webcast/15591/348704/three-windows-zero-days-in-three-months-how-we-found-them-in-the-wild



##### *Overview of the latest Windows OS kernel exploits found in the wild (by Kaspersky)*

https://github.com/oct0xor/presentations/blob/master/2019-02-Overview%20of%20the%20latest%20Windows%20OS%20kernel%20exploits%20found%20in%20the%20wild.pdf



##### *Retrospective on the latest zero-days found in the wild (by Kaspersky)*

https://github.com/oct0xor/presentations/blob/master/2020-01-Retrospective%20on%20the%20latest%20zero-days%20found%20in%20the%20wild.pdf



##### *Graphology of an Exploit - Hunting for exploits by looking for the author's fingerprints (by CheckPoint)*

https://research.checkpoint.com/2020/graphology-of-an-exploit-volodya/



##### *Exploit Developer Spotlight: The Story of PlayBit (by CheckPoint)*

https://research.checkpoint.com/2020/graphology-of-an-exploit-playbit/



##### *The Story of Jian - How APT31 Stole and Used an Unknown Equation Group 0-Day (by CheckPoint)*

https://research.checkpoint.com/2021/the-story-of-jian/



##### *The State of Win32k Security (by MSRC)*

https://github.com/Microsoft/MSRC-Security-Research/blob/master/presentations/2018_10_DerbyCon/2018_10_DerbyCon_State_of%20_Win32k_Security.pptx



##### *Kernel Attacks through User-Mode Callbacks (by Tarjei Mandt)*

https://docs.huihoo.com/blackhat/usa-2011/BH_US_11_Mandt_win32k_Slides.pdf



##### *Driver Virifier*

https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier



##### *Windows Kernel Address Leaks*

https://github.com/sam-b/windows_kernel_address_leaks



##### *A simple protection against HMValidateHandle technique*

https://theevilbit.github.io/posts/a_simple_protection_against_hmvalidatehandle_technique/



##### *Windows SMEP Bypass (by Core Security)*

https://www.coresecurity.com/sites/default/files/2020-06/Windows%20SMEP%20bypass%20U%20equals%20S_0.pdf



##### *Duqu 2.0 Win32k Exploit Analysis (by MSRC)*

https://github.com/ohjeongwook/Publications/blob/master/Duqu%202.0%20Win32k%20Exploit%20Analysis.pdf



##### *Hardening Windows 10 with zero-day exploit mitigations (by MSRC)*

https://www.microsoft.com/security/blog/2017/01/13/hardening-windows-10-with-zero-day-exploit-mitigations/



##### *Taking Windows 10 Kernel Exploitation To The Next Level–Leveraging Write What Where Vulnerabilities In Creators Update-wp (by Morten Schenk)*

https://github.com/MortenSchenk/BHUSA2017/blob/master/us-17-Schenk-Taking-Windows-10-Kernel-Exploitation-To-The-Next-Level%E2%80%93Leveraging-Write-What-Where-Vulnerabilities-In-Creators-Update-wp.pdf



##### *The Life & Death of Kernel Object Abuse by Type Isolation (by MSRC)*

https://conference.hitb.org/hitbsecconf2018ams/materials/D1%20COMMSEC%20-%20Saif%20Elsherei%20and%20Ian%20Kronquist%20-%20The%20Life%20&%20Death%20of%20Kernel%20Object%20Abuse.pdf



##### *Demystifying Windows Kernel Exploitation by Abusing GDI Objects (by Saif El-Sherei)*

https://github.com/sensepost/gdi-palettes-exp/blob/master/5A1F_Defcon_25_Demystifying_Kernel_Exploitation_By_Abusing_GDI_Objects_slides_final.pdf



##### *WINDOWS 10 RS2 RS3 GDI DATA-ONLY EXPLOITATION TALES (by NIKOLAOS SAMPANIS)*

https://census-labs.com/media/windows_10_rs2_rs3_exploitation_primitives.pdf



##### *Zero-day exploit (CVE-2018-8453) used in targeted attacks (by Kaspersky)*

https://securelist.com/cve-2018-8453-used-in-targeted-attacks/88151/



##### *DEVELOPMENT OF A NEW WINDOWS 10 KASLR BYPASS (IN ONE WINDBG COMMAND) (by Morten Schenk)*

https://www.offensive-security.com/vulndev/development-of-a-new-windows-10-kaslr-bypass-in-one-windbg-command/



##### *WINDOWS KERNEL ZERO-DAY EXPLOIT (CVE-2021-1732) IS USED BY BITTER APT IN TARGETED ATTACK (by DBAPPSecurity)*

https://ti.dbappsecurity.com.cn/blog/index.php/2021/02/10/windows-kernel-zero-day-exploit-is-used-by-bitter-apt-in-targeted-attack/



##### *Breaking the Chain (by Google Project Zero)*

https://googleprojectzero.blogspot.com/2016/11/breaking-chain.html



##### *Win32k System Call Filtering Deep Dive (by Morten Schenk)*

https://improsec.com/tech-blog/win32k-system-call-filtering-deep-dive



##### *Subverting Direct X Kernel For Gaining Remote System (by Rancho Han & ChenNan)*

[https://github.com/RanchoIce/44Con2018/blob/master/44Con-Gaining%20Remote%20System%20Subverting%20The%20DirectX%20Kernel.pdf](https://github.com/RanchoIce/44Con2018/blob/master/44Con-Gaining Remote System Subverting The DirectX Kernel.pdf)



## *Author*

> Lieying.Lab - DBAPPSecurity

## *Topic*

#APT
