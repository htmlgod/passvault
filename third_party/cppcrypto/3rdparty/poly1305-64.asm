; Optimized implementations of Poly1305, a fast message-authentication-code 
; by Andrew Moon
; https://github.com/floodyberry/poly1305-opt
; LICENSE: Public Domain, or MIT
;
; Modified by kerukuro for use in cppcrypto.
;

%ifndef BASE_YASM
%define BASE_YASM

; 1.1.0 and earlier incorrectly parsed movsw/movzw in gas mode: https://github.com/yasm/yasm/commit/2678cb3c3a42b3870a209ed8de38c1a16449695a
%if (__YASM_VERSION_ID__ < 01020000h) ; 1.2.0
	%error Requires Yasm 1.2.0 or higher
%endif

%define HAVE_XOP 0
%define HAVE_AVX2 0
%define HAVE_AVX512 0

%if (__YASM_VERSION_ID__ >= 01000000h) ; 1.0.0
	%define HAVE_XOP 1
%endif

%if (__YASM_VERSION_ID__ >= 01020000h) ; 1.2.0
	%define HAVE_AVX2 1
%endif

%if (__YASM_VERSION_ID__ >= 999999999) ; avx-512 isn't supported yet
	%define HAVE_AVX512 1
%endif


%define BITS32 0
%define BITS64 0
%define WIN 0
%define ELF 0
%define MACH 0

%ifidn __YASM_OBJFMT__, win32
	%define BITS32 1
	%define WIN 1
%elifidn __YASM_OBJFMT__, elf
	%error Specify bits with -f [elf32,elf64]
%elifidn __YASM_OBJFMT__, elf32
	%define BITS32 1
	%define ELF 1
%elifidn __YASM_OBJFMT__, macho
	%error Specify bits with -f [macho32,macho64]
%elifidn __YASM_OBJFMT__, macho32
	%define BITS32 1
	%define MACH 1
%elifidn __YASM_OBJFMT__, win64
	%define BITS64 1
	%define WIN 1
%elifidn __YASM_OBJFMT__, x64
	%define BITS64 1
	%define WIN 1
%elifidn __YASM_OBJFMT__, elf64
	%define BITS64 1
	%define ELF 1
%elifidn __YASM_OBJFMT__, macho64
	%define BITS64 1
	%define MACH 1
%else
	%error "Unable to determine output format"
%endif

%if (WIN)
	%if (BITS64)
		; name, args, xmmused
		%macro win64stubfn 3
			%1:
			_ %+ %1:

			subq $184, %rsp
			movdqa %xmm6, 0(%rsp)
			movdqa %xmm7, 16(%rsp)
			%if (%3 > 8)
				movdqa %xmm8, 32(%rsp)
				movdqa %xmm9, 48(%rsp)
				movdqa %xmm10, 64(%rsp)
				movdqa %xmm11, 80(%rsp)
				movdqa %xmm12, 96(%rsp)
				movdqa %xmm13, 112(%rsp)
				movdqa %xmm14, 128(%rsp)
				movdqa %xmm15, 144(%rsp)
			%endif
			movq %rdi, 160(%rsp)
			movq %rsi, 168(%rsp)
			movq %rcx, %rdi
			movq %rdx, %rsi
			movq %r8, %rdx
			movq %r9, %rcx
			%if (%2 >= 5)
				movq 224(%rsp), %r8
			%endif
			%if (%2 >= 6)
				movq 232(%rsp), %r9
			%endif
			call thunk_ %+ %1
			movdqa 0(%rsp), %xmm6
			movdqa 16(%rsp), %xmm7
			%if (%3 > 8)
				movdqa 32(%rsp), %xmm8
				movdqa 48(%rsp), %xmm9
				movdqa 64(%rsp), %xmm10
				movdqa 80(%rsp), %xmm11
				movdqa 96(%rsp), %xmm12
				movdqa 112(%rsp), %xmm13
				movdqa 128(%rsp), %xmm14
				movdqa 144(%rsp), %xmm15
			%endif
			movq 160(%rsp), %rdi
			movq 168(%rsp), %rsi
			addq $184, %rsp
			ret
		thunk_ %+ %1:
		%endmacro

		; FN name
		%macro FN 1
			win64stubfn %1, 4, 16
		%endmacro

		; FN_EXT name, args, xmmused
		%macro FN_EXT 3
			win64stubfn %1, %2, %3
		%endmacro

		; FN_END name
		%macro FN_END 1
		%endmacro
	%else
		; FN name
		%macro FN 1
			%1:
			_ %+ %1:
		%endmacro

		; FN_EXT name, args, xmmused
		%macro FN_EXT 3
			%1:
			_ %+ %1:
		%endmacro

		; FN_END name
		%macro FN_END 1
		%endmacro
	%endif

	%macro HIDDEN 1
	%endmacro
%elif (ELF)
	; FN name
	%macro FN 1
		%1:
		_ %+ %1:
	%endmacro

	; FN_EXT name, args, xmmused
	%macro FN_EXT 3
		%1:
		_ %+ %1:
	%endmacro

	; FN_END name
	%macro FN_END 1
		.size %1, .-%1
		.type %1, @function
	%endmacro

	; declares a global is hidden: HIDDEN name
	%macro HIDDEN 1
	%if (__YASM_VERSION_ID__ >= 09999999h) ; .hidden isn't in yasm yet?
		.hidden %1
		.hidden _ %+ %1
	%endif
	%endmacro

	; set NX for stack
	.section .note.GNU-stack,"",@progbits
%elif (MACH)
	; FN name
	%macro FN 1
		%1:
		_ %+ %1:
	%endmacro

	; FN_EXT name, args, xmmused
	%macro FN_EXT 3
		%1:
		_ %+ %1:
	%endmacro

	; FN_END name
	%macro FN_END 1
	%endmacro

	; declares a global is hidden: HIDDEN name
	%macro HIDDEN 1
	%if (__YASM_VERSION_ID__ >= 09999999h) ; .private_extern isn't in yasm yet?
		.private_extern %1
		.private_extern _ %+ %1
	%endif
	%endmacro
%endif

; put everything in the code segment to simplify things
%define SECTION_TEXT .section .text
%define SECTION_RODATA .section .text

; declares a global function: GLOBAL name
%macro GLOBAL 1
	.globl %1
	.globl _ %+ %1
%endmacro

%macro FN_LOCAL_PREFIX 1
	FN PROJECT_NAME %+ _ %+ %1
%endmacro

%macro FN_EXT_LOCAL_PREFIX 3
	FN_EXT PROJECT_NAME %+ _ %+ %1, %2, %3
%endmacro

%macro FN_END_LOCAL_PREFIX 1
	FN_END PROJECT_NAME %+ _ %+ %1
%endmacro

%macro GLOBAL_LOCAL_PREFIX 1
	GLOBAL PROJECT_NAME %+ _ %+ %1
	HIDDEN PROJECT_NAME %+ _ %+ %1
%endmacro

; name
%macro GLOBAL_HIDDEN_FN 1
	GLOBAL %1
	HIDDEN %1
	FN %1
%endmacro

; name, args, xmmused
%macro GLOBAL_HIDDEN_FN_EXT 3
	GLOBAL %1
	HIDDEN %1
	FN_EXT %1, %2, %3
%endmacro


; pic support: LOAD_VAR_PIC var, reg
%macro LOAD_VAR_PIC 2
	%if (BITS32)
		call 1f
		1:
		popl %2
		leal %1 - 1b(%2), %2
	%else
		leaq %1(%rip), %2
	%endif
%endmacro

%macro INCLUDE 1
	%include %1
%endmacro

; include the file with the variable(s) if variable 'name' is not already included: INCLUDE_VAR_FILE file, name
%macro INCLUDE_VAR_FILE 2
	%ifndef INCLUDED_%2
		%define INCLUDED_%2
		%include %1
	%endif
%endmacro

; stupid helpers so we can have cpuid in one file

%macro CPUID_PROLOGUE 0
%if (BITS32)
	pushl %ebx
	pushl %esi
	pushl %edi
	pushl %ebp

	; check that cpuid is supported
	pushfl
	popl %eax
	movl %eax, %ecx
	xorl $0x200000, %eax
	pushl %eax
	popfl
	pushfl
	popl %eax
	xorl %ecx, %eax
	shrl $21, %eax
	andl $1, %eax
	pushl %ecx
	popfl
	andl %eax, %eax
	jz Lcpuid_x86_done
%else
	pushq %rbx
	pushq %rsi
	pushq %rdi
	pushq %rbp
%endif
%endmacro

%macro CPUID_EPILOGUE 0
%if (BITS32)
	popl %ebp
	popl %edi
	popl %esi
	popl %ebx
%else
	popq %rbp
	popq %rdi
	popq %rsi
	popq %rbx
%endif
	ret
%endmacro

%macro CPUCYCLES 0
	rdtsc
%if (BITS64)
	shlq $32, %rdx
	orq %rdx, %rax
%endif
	ret
%endmacro

%define CPUID_GENERIC  (0     )
%define CPUID_X86      (1 << 0)
%define CPUID_MMX      (1 << 1)
%define CPUID_SSE      (1 << 2)
%define CPUID_SSE2     (1 << 3)
%define CPUID_SSE3     (1 << 4)
%define CPUID_SSSE3    (1 << 5)
%define CPUID_SSE4_1   (1 << 6)
%define CPUID_SSE4_2   (1 << 7)
%define CPUID_AVX      (1 << 8)
%define CPUID_XOP      (1 << 9)
%define CPUID_AVX2     (1 << 10)
%define CPUID_AVX512   (1 << 11)

%define CPUID_RDTSC     (1 << 25)
%define CPUID_RDRAND    (1 << 26)
%define CPUID_POPCNT    (1 << 27)
%define CPUID_FMA4      (1 << 28)
%define CPUID_FMA3      (1 << 29)
%define CPUID_PCLMULQDQ (1 << 30)
%define CPUID_AES       (1 << 31)

%endif ; BASE_YASM

SECTION_TEXT

GLOBAL_HIDDEN_FN poly1305_block_size_sse2
movl $32, %eax
ret
FN_END poly1305_block_size_sse2

GLOBAL_HIDDEN_FN poly1305_init_ext_sse2
poly1305_init_ext_sse2_local:
pushq %r15
xorps %xmm0, %xmm0
testq %rdx, %rdx
pushq %r14
movq %rdx, %r11
movq $-1, %rax
cmove %rax, %r11
pushq %r13
movabsq $17575274610687, %r9
pushq %r12
pushq %rbp
movq %r11, %r13
movabsq $17592186044415, %rbp
pushq %rbx
xorl %ebx, %ebx
movdqu %xmm0, 32(%rdi)
movdqu %xmm0, (%rdi)
movdqu %xmm0, 16(%rdi)
movq 8(%rsi), %rcx
movq (%rsi), %rax
movq %rcx, %rdx
shrq $24, %rcx
andq %rax, %r9
salq $20, %rdx
shrq $44, %rax
movq %r9, %r8
orq %rax, %rdx
shrq $26, %r8
movabsq $17592181915647, %rax
andq %rax, %rdx
movabsq $68719475727, %rax
andq %rax, %rcx
movl %r9d, %eax
andl $67108863, %eax
movl %eax, 40(%rdi)
movl %edx, %eax
sall $18, %eax
orl %r8d, %eax
movq %rdx, %r8
andl $67108863, %eax
shrq $34, %r8
movl %eax, 44(%rdi)
movq %rdx, %rax
shrq $8, %rax
andl $67108863, %eax
movl %eax, 48(%rdi)
movl %ecx, %eax
sall $10, %eax
orl %r8d, %eax
movq %rdi, %r8
andl $67108863, %eax
movl %eax, 52(%rdi)
movq %rcx, %rax
shrq $16, %rax
movl %eax, 56(%rdi)
movq 16(%rsi), %rax
movq %rax, 104(%rdi)
movq 24(%rsi), %rax
movq %rdx, %rsi
movq %rax, 112(%rdi)
poly1305_init_ext_sse2_7:
testq %rbx, %rbx
jne poly1305_init_ext_sse2_4
cmpq $16, %r13
jbe poly1305_init_ext_sse2_5
leaq 60(%r8), %rdi
jmp poly1305_init_ext_sse2_6
poly1305_init_ext_sse2_4:
cmpq $96, %r13
jb poly1305_init_ext_sse2_5
leaq 80(%r8), %rdi
poly1305_init_ext_sse2_6:
imulq $20, %rcx, %r10
movq $0, -48(%rsp)
movq $0, -32(%rsp)
leaq (%rsi,%rsi), %r14
leaq (%r9,%r9), %r11
movq %r10, %rax
mulq %r14
movq %rax, %r14
movq %r9, %rax
movq %rdx, %r15
mulq %r9
addq %rax, %r14
movq %r14, %rax
adcq %rdx, %r15
leaq (%rcx,%rcx), %rdx
andq %rbp, %rax
movq %rax, -16(%rsp)
movq %r11, %rax
movq %rdx, -24(%rsp)
mulq %rsi
movq %rax, %r11
movq %r10, %rax
movq %rdx, %r12
mulq %rcx
movq -16(%rsp), %rcx
addq %rax, %r11
movq %r14, %rax
adcq %rdx, %r12
shrdq $44, %r15, %rax
movq %rax, -56(%rsp)
movq -24(%rsp), %rax
addq -56(%rsp), %r11
adcq -48(%rsp), %r12
mulq %r9
movq %r11, %r14
andq %rbp, %r14
movq %rax, %r9
movq %rsi, %rax
movq %rdx, %r10
mulq %rsi
addq %rax, %r9
movq %r11, %rax
adcq %rdx, %r10
shrdq $44, %r12, %rax
movq %rax, -40(%rsp)
movabsq $4398046511103, %rax
addq -40(%rsp), %r9
adcq -32(%rsp), %r10
andq %r9, %rax
incq %rbx
shrdq $42, %r10, %r9
leaq (%r9,%r9,4), %r9
addq %r9, %rcx
movq %rcx, %r9
shrq $44, %rcx
addq %r14, %rcx
andq %rbp, %r9
movq %rcx, %rsi
shrq $44, %rcx
movq %r9, %rdx
addq %rax, %rcx
movl %r9d, %eax
andq %rbp, %rsi
andl $67108863, %eax
shrq $26, %rdx
movl %eax, (%rdi)
movl %esi, %eax
sall $18, %eax
orl %edx, %eax
movq %rsi, %rdx
andl $67108863, %eax
shrq $34, %rdx
movl %eax, 4(%rdi)
movq %rsi, %rax
shrq $8, %rax
andl $67108863, %eax
movl %eax, 8(%rdi)
movl %ecx, %eax
sall $10, %eax
orl %edx, %eax
andl $67108863, %eax
movl %eax, 12(%rdi)
movq %rcx, %rax
shrq $16, %rax
cmpq $2, %rbx
movl %eax, 16(%rdi)
jne poly1305_init_ext_sse2_7
poly1305_init_ext_sse2_5:
movq $0, 120(%r8)
popq %rbx
popq %rbp
popq %r12
popq %r13
popq %r14
popq %r15
ret
FN_END poly1305_init_ext_sse2


GLOBAL_HIDDEN_FN poly1305_blocks_sse2
poly1305_blocks_sse2_local:
pushq %rbp
movq %rsp, %rbp
pushq %rbx
andq $-64, %rsp
subq $328, %rsp
movq $(1 << 24), %rax
movd %rax, %xmm1
movq $((1 << 26) - 1), %rax
movd %rax, %xmm0
pshufd $68, %xmm1, %xmm1
pshufd $68, %xmm0, %xmm0
movq 120(%rdi), %rax
movaps %xmm1, 312(%rsp)
testb $4, %al
je poly1305_blocks_sse2_11
movaps 312(%rsp), %xmm1
psrldq $8, %xmm1
movaps %xmm1, 312(%rsp)
poly1305_blocks_sse2_11:
testb $8, %al
je poly1305_blocks_sse2_12
xorps %xmm1, %xmm1
movaps %xmm1, 312(%rsp)
poly1305_blocks_sse2_12:
testb $1, %al
jne poly1305_blocks_sse2_13
movq 16(%rsi), %xmm1
movaps %xmm0, %xmm3
movaps %xmm0, %xmm9
movq (%rsi), %xmm15
orq $1, %rax
subq $32, %rdx
movq 8(%rsi), %xmm12
punpcklqdq %xmm1, %xmm15
movq 24(%rsi), %xmm1
movaps %xmm15, %xmm8
pand %xmm15, %xmm3
psrlq $52, %xmm15
addq $32, %rsi
punpcklqdq %xmm1, %xmm12
movaps %xmm12, %xmm1
psrlq $26, %xmm8
psllq $12, %xmm1
pand %xmm0, %xmm8
movq %rax, 120(%rdi)
por %xmm1, %xmm15
psrlq $40, %xmm12
pand %xmm15, %xmm9
por 312(%rsp), %xmm12
psrlq $26, %xmm15
pand %xmm0, %xmm15
jmp poly1305_blocks_sse2_14
poly1305_blocks_sse2_13:
movdqu (%rdi), %xmm8
movdqu 16(%rdi), %xmm15
movdqu 32(%rdi), %xmm12
pshufd $80, %xmm8, %xmm3
pshufd $250, %xmm8, %xmm8
pshufd $80, %xmm15, %xmm9
pshufd $250, %xmm15, %xmm15
pshufd $80, %xmm12, %xmm12
poly1305_blocks_sse2_14:
movq 120(%rdi), %rax
testb $48, %al
je poly1305_blocks_sse2_15
testb $16, %al
movd 56(%rdi), %xmm2
leaq 40(%rdi), %rax
je poly1305_blocks_sse2_16
movdqu 60(%rdi), %xmm1
movdqu (%rax), %xmm4
movd %xmm2, %eax
movd 76(%rdi), %xmm2
movaps %xmm1, %xmm7
movd %eax, %xmm5
punpckldq %xmm4, %xmm7
punpckhdq %xmm4, %xmm1
punpcklqdq %xmm5, %xmm2
jmp poly1305_blocks_sse2_17
poly1305_blocks_sse2_16:
movdqu (%rax), %xmm1
movl $1, %r8d
movd %r8d, %xmm4
movaps %xmm1, %xmm7
punpckldq %xmm4, %xmm7
punpckhdq %xmm4, %xmm1
poly1305_blocks_sse2_17:
pshufd $80, %xmm7, %xmm11
pshufd $80, %xmm1, %xmm4
pshufd $250, %xmm7, %xmm7
movaps %xmm11, 168(%rsp)
pshufd $250, %xmm1, %xmm1
jmp poly1305_blocks_sse2_18
poly1305_blocks_sse2_15:
movdqu 60(%rdi), %xmm1
movd 76(%rdi), %xmm2
pshufd $0, %xmm2, %xmm2
pshufd $0, %xmm1, %xmm11
pshufd $85, %xmm1, %xmm7
pshufd $170, %xmm1, %xmm4
movaps %xmm11, 168(%rsp)
pshufd $255, %xmm1, %xmm1
poly1305_blocks_sse2_18:
movaps %xmm1, %xmm14
movaps %xmm7, %xmm5
movaps %xmm4, %xmm13
movaps %xmm1, 264(%rsp)
movaps %xmm2, %xmm1
cmpq $63, %rdx
movq $(5), %r8
movd %r8, %xmm6
pshufd $68, %xmm6, %xmm6
pmuludq %xmm6, %xmm5
movaps %xmm4, 296(%rsp)
pmuludq %xmm6, %xmm13
movaps %xmm2, 152(%rsp)
pmuludq %xmm6, %xmm14
pmuludq %xmm6, %xmm1
movaps %xmm5, 88(%rsp)
movaps %xmm13, 72(%rsp)
movaps %xmm14, 56(%rsp)
movaps %xmm1, 40(%rsp)
jbe poly1305_blocks_sse2_19
movdqu 80(%rdi), %xmm1
movd 96(%rdi), %xmm2
movq %rdx, %rcx
pshufd $0, %xmm2, %xmm2
movaps %xmm2, 24(%rsp)
pmuludq %xmm6, %xmm2
pshufd $85, %xmm1, %xmm4
movaps %xmm4, 280(%rsp)
pmuludq %xmm6, %xmm4
pshufd $255, %xmm1, %xmm13
pshufd $170, %xmm1, %xmm5
movaps 72(%rsp), %xmm14
movaps %xmm5, 216(%rsp)
pmuludq %xmm6, %xmm5
movq %rsi, %rax
movaps %xmm4, -24(%rsp)
movaps %xmm13, %xmm4
pshufd $0, %xmm1, %xmm1
pmuludq %xmm6, %xmm4
movaps %xmm14, -8(%rsp)
movaps %xmm5, 8(%rsp)
movaps 168(%rsp), %xmm5
movaps %xmm1, 248(%rsp)
movaps 56(%rsp), %xmm1
movaps %xmm4, 120(%rsp)
movaps 40(%rsp), %xmm4
movaps %xmm13, 136(%rsp)
movaps %xmm2, 200(%rsp)
movaps %xmm1, 104(%rsp)
movaps %xmm4, 184(%rsp)
movaps %xmm5, 232(%rsp)
jmp poly1305_blocks_sse2_20
.p2align 6
poly1305_blocks_sse2_20:
movaps -24(%rsp), %xmm5
movaps %xmm8, %xmm13
subq $64, %rcx
movaps 8(%rsp), %xmm4
movaps 120(%rsp), %xmm10
pmuludq %xmm12, %xmm5
pmuludq %xmm15, %xmm4
movaps 8(%rsp), %xmm2
pmuludq %xmm9, %xmm10
movaps 120(%rsp), %xmm11
movaps 200(%rsp), %xmm14
pmuludq %xmm12, %xmm2
paddq %xmm4, %xmm5
pmuludq %xmm15, %xmm11
movaps 120(%rsp), %xmm1
paddq %xmm10, %xmm5
pmuludq %xmm8, %xmm14
movaps 200(%rsp), %xmm10
movaps 200(%rsp), %xmm4
pmuludq %xmm12, %xmm1
movaps 248(%rsp), %xmm8
pmuludq %xmm15, %xmm10
paddq %xmm11, %xmm2
pmuludq %xmm12, %xmm4
paddq %xmm14, %xmm5
movaps 200(%rsp), %xmm11
movaps 248(%rsp), %xmm14
pmuludq %xmm15, %xmm8
pmuludq 248(%rsp), %xmm12
pmuludq %xmm9, %xmm11
paddq %xmm10, %xmm1
movaps 248(%rsp), %xmm10
pmuludq 280(%rsp), %xmm15
pmuludq %xmm3, %xmm14
paddq %xmm15, %xmm12
paddq %xmm8, %xmm4
pmuludq %xmm13, %xmm10
movq 24(%rax), %xmm15
movaps 248(%rsp), %xmm8
paddq %xmm11, %xmm2
movaps %xmm3, %xmm11
movaps 280(%rsp), %xmm3
paddq %xmm14, %xmm5
pmuludq %xmm9, %xmm8
paddq %xmm10, %xmm2
movq 16(%rax), %xmm14
movaps 280(%rsp), %xmm10
pmuludq %xmm9, %xmm3
pmuludq 216(%rsp), %xmm9
paddq %xmm9, %xmm12
paddq %xmm8, %xmm1
movq (%rax), %xmm8
pmuludq %xmm11, %xmm10
paddq %xmm3, %xmm4
movaps 216(%rsp), %xmm3
punpcklqdq %xmm14, %xmm8
movaps 280(%rsp), %xmm14
pmuludq %xmm13, %xmm3
paddq %xmm10, %xmm2
movq 8(%rax), %xmm10
pmuludq %xmm13, %xmm14
pmuludq 136(%rsp), %xmm13
paddq %xmm13, %xmm12
punpcklqdq %xmm15, %xmm10
movaps %xmm10, %xmm9
movaps 216(%rsp), %xmm15
paddq %xmm3, %xmm4
psllq $12, %xmm9
movaps %xmm0, %xmm3
paddq %xmm14, %xmm1
pmuludq %xmm11, %xmm15
pand %xmm8, %xmm3
movaps 136(%rsp), %xmm14
movaps %xmm3, -40(%rsp)
movaps %xmm8, %xmm3
movdqu 48(%rax), %xmm13
psrlq $52, %xmm8
pmuludq %xmm11, %xmm14
paddq %xmm15, %xmm1
por %xmm9, %xmm8
pmuludq 24(%rsp), %xmm11
paddq %xmm11, %xmm12
movdqu 32(%rax), %xmm11
movaps %xmm10, %xmm9
psrlq $40, %xmm10
pand %xmm0, %xmm8
movaps %xmm11, %xmm15
paddq %xmm14, %xmm4
xorps %xmm14, %xmm14
punpckldq %xmm13, %xmm15
psrlq $14, %xmm9
addq $64, %rax
pand %xmm0, %xmm9
psrlq $26, %xmm3
cmpq $63, %rcx
por 312(%rsp), %xmm10
movaps %xmm13, -72(%rsp)
movaps %xmm15, %xmm13
punpckldq %xmm14, %xmm13
punpckhdq -72(%rsp), %xmm11
movaps %xmm13, -56(%rsp)
movaps %xmm11, %xmm13
punpckhdq %xmm14, %xmm11
pand %xmm0, %xmm3
psllq $18, %xmm11
punpckhdq %xmm14, %xmm15
punpckldq %xmm14, %xmm13
paddq %xmm11, %xmm4
movaps -8(%rsp), %xmm11
psllq $6, %xmm15
psllq $12, %xmm13
movaps 88(%rsp), %xmm14
paddq %xmm15, %xmm2
pmuludq %xmm10, %xmm11
paddq %xmm13, %xmm1
movaps -8(%rsp), %xmm13
pmuludq %xmm10, %xmm14
paddq -56(%rsp), %xmm5
paddq 312(%rsp), %xmm12
pmuludq %xmm9, %xmm13
movaps 104(%rsp), %xmm15
paddq %xmm11, %xmm2
movaps 184(%rsp), %xmm11
paddq %xmm14, %xmm5
movaps 104(%rsp), %xmm14
pmuludq %xmm9, %xmm15
pmuludq %xmm10, %xmm11
paddq %xmm13, %xmm5
movaps 104(%rsp), %xmm13
pmuludq %xmm10, %xmm14
pmuludq 232(%rsp), %xmm10
paddq %xmm10, %xmm12
pmuludq %xmm8, %xmm13
paddq %xmm15, %xmm2
movaps %xmm8, %xmm10
paddq %xmm11, %xmm4
pmuludq %xmm7, %xmm10
movaps 232(%rsp), %xmm11
movaps 184(%rsp), %xmm15
paddq %xmm14, %xmm1
pmuludq %xmm9, %xmm11
paddq %xmm13, %xmm5
movaps 184(%rsp), %xmm13
movaps 184(%rsp), %xmm14
pmuludq %xmm3, %xmm15
pmuludq %xmm9, %xmm13
paddq %xmm11, %xmm4
pmuludq %xmm8, %xmm14
movaps 232(%rsp), %xmm11
paddq %xmm10, %xmm4
paddq %xmm15, %xmm5
pmuludq %xmm7, %xmm9
pmuludq %xmm8, %xmm11
paddq %xmm13, %xmm1
movaps 232(%rsp), %xmm13
movaps 296(%rsp), %xmm10
paddq %xmm14, %xmm2
pmuludq 296(%rsp), %xmm8
movaps -40(%rsp), %xmm14
pmuludq %xmm3, %xmm13
paddq %xmm9, %xmm12
paddq %xmm11, %xmm1
movaps %xmm3, %xmm11
paddq %xmm8, %xmm12
movaps 232(%rsp), %xmm15
pmuludq %xmm7, %xmm11
pmuludq %xmm3, %xmm10
paddq %xmm13, %xmm2
movaps %xmm14, %xmm13
movaps 296(%rsp), %xmm9
pmuludq %xmm14, %xmm15
pmuludq 264(%rsp), %xmm3
paddq %xmm11, %xmm1
pmuludq %xmm7, %xmm13
paddq %xmm3, %xmm12
movaps 264(%rsp), %xmm11
paddq %xmm10, %xmm4
pmuludq %xmm14, %xmm9
paddq %xmm15, %xmm5
pmuludq %xmm14, %xmm11
movaps %xmm5, %xmm8
paddq %xmm13, %xmm2
psrlq $26, %xmm8
paddq %xmm9, %xmm1
pand %xmm0, %xmm5
pmuludq 152(%rsp), %xmm14
paddq %xmm14, %xmm12
paddq %xmm8, %xmm2
paddq %xmm11, %xmm4
movaps %xmm2, %xmm9
movaps %xmm2, %xmm8
movaps %xmm4, %xmm3
psrlq $26, %xmm9
pand %xmm0, %xmm4
psrlq $26, %xmm3
paddq %xmm9, %xmm1
pand %xmm0, %xmm8
paddq %xmm3, %xmm12
movaps %xmm1, %xmm10
movaps %xmm1, %xmm9
movaps %xmm12, %xmm3
psrlq $26, %xmm10
pand %xmm0, %xmm12
psrlq $26, %xmm3
paddq %xmm10, %xmm4
pand %xmm0, %xmm9
pmuludq %xmm6, %xmm3
movaps %xmm4, %xmm1
movaps %xmm4, %xmm15
psrlq $26, %xmm1
pand %xmm0, %xmm15
paddq %xmm1, %xmm12
paddq %xmm3, %xmm5
movaps %xmm5, %xmm2
movaps %xmm5, %xmm3
psrlq $26, %xmm2
pand %xmm0, %xmm3
paddq %xmm2, %xmm8
ja poly1305_blocks_sse2_20
leaq -64(%rdx), %rax
andl $63, %edx
andq $-64, %rax
leaq 64(%rsi,%rax), %rsi
poly1305_blocks_sse2_19:
cmpq $31, %rdx
jbe poly1305_blocks_sse2_21
movaps 56(%rsp), %xmm11
movaps %xmm15, %xmm1
movaps %xmm15, %xmm14
movaps 72(%rsp), %xmm5
movaps %xmm12, %xmm4
movaps %xmm15, %xmm10
movaps 88(%rsp), %xmm2
pmuludq %xmm11, %xmm14
movaps %xmm8, %xmm15
pmuludq %xmm5, %xmm1
movaps 40(%rsp), %xmm13
testq %rsi, %rsi
pmuludq %xmm12, %xmm2
pmuludq %xmm12, %xmm5
pmuludq %xmm11, %xmm4
paddq %xmm1, %xmm2
pmuludq %xmm9, %xmm11
movaps %xmm12, %xmm1
paddq %xmm14, %xmm5
pmuludq %xmm13, %xmm15
movaps %xmm9, %xmm14
pmuludq %xmm13, %xmm14
pmuludq %xmm13, %xmm1
paddq %xmm11, %xmm2
movaps 168(%rsp), %xmm11
pmuludq %xmm10, %xmm13
paddq %xmm15, %xmm2
movaps %xmm9, %xmm15
paddq %xmm14, %xmm5
pmuludq %xmm11, %xmm12
movaps %xmm3, %xmm14
pmuludq %xmm11, %xmm14
movaps %xmm13, 248(%rsp)
movaps %xmm10, %xmm13
pmuludq %xmm7, %xmm15
paddq 248(%rsp), %xmm4
pmuludq %xmm11, %xmm13
pmuludq %xmm7, %xmm10
paddq %xmm14, %xmm2
movaps %xmm13, 280(%rsp)
movaps %xmm8, %xmm13
pmuludq %xmm11, %xmm13
paddq %xmm10, %xmm12
movaps 296(%rsp), %xmm10
paddq 280(%rsp), %xmm1
pmuludq %xmm9, %xmm11
pmuludq 296(%rsp), %xmm9
pmuludq %xmm3, %xmm10
paddq %xmm9, %xmm12
paddq %xmm13, %xmm5
movaps %xmm3, %xmm13
paddq %xmm15, %xmm1
pmuludq %xmm7, %xmm13
paddq %xmm11, %xmm4
movaps 296(%rsp), %xmm11
pmuludq %xmm8, %xmm7
pmuludq %xmm8, %xmm11
pmuludq 264(%rsp), %xmm8
paddq %xmm8, %xmm12
paddq %xmm13, %xmm5
paddq %xmm7, %xmm4
movaps 264(%rsp), %xmm7
paddq %xmm11, %xmm1
paddq %xmm10, %xmm4
pmuludq %xmm3, %xmm7
pmuludq 152(%rsp), %xmm3
paddq %xmm3, %xmm12
paddq %xmm7, %xmm1
je poly1305_blocks_sse2_22
movdqu (%rsi), %xmm7
xorps %xmm3, %xmm3
paddq 312(%rsp), %xmm12
movdqu 16(%rsi), %xmm8
movaps %xmm7, %xmm9
punpckldq %xmm8, %xmm9
punpckhdq %xmm8, %xmm7
movaps %xmm9, %xmm10
movaps %xmm7, %xmm8
punpckldq %xmm3, %xmm10
punpckhdq %xmm3, %xmm9
punpckhdq %xmm3, %xmm7
punpckldq %xmm3, %xmm8
movaps %xmm8, %xmm3
psllq $6, %xmm9
paddq %xmm10, %xmm2
psllq $12, %xmm3
paddq %xmm9, %xmm5
psllq $18, %xmm7
paddq %xmm3, %xmm4
paddq %xmm7, %xmm1
poly1305_blocks_sse2_22:
movaps %xmm2, %xmm8
movaps %xmm1, %xmm3
movaps %xmm1, %xmm15
psrlq $26, %xmm8
pand %xmm0, %xmm2
pand %xmm0, %xmm15
psrlq $26, %xmm3
paddq %xmm5, %xmm8
paddq %xmm12, %xmm3
movaps %xmm8, %xmm9
pand %xmm0, %xmm8
movaps %xmm3, %xmm1
psrlq $26, %xmm9
movaps %xmm3, %xmm12
psrlq $26, %xmm1
paddq %xmm4, %xmm9
pand %xmm0, %xmm12
pmuludq %xmm1, %xmm6
movaps %xmm9, %xmm3
pand %xmm0, %xmm9
psrlq $26, %xmm3
paddq %xmm3, %xmm15
paddq %xmm6, %xmm2
movaps %xmm15, %xmm3
pand %xmm0, %xmm15
movaps %xmm2, %xmm1
psrlq $26, %xmm3
psrlq $26, %xmm1
paddq %xmm3, %xmm12
movaps %xmm0, %xmm3
paddq %xmm1, %xmm8
pand %xmm2, %xmm3
poly1305_blocks_sse2_21:
testq %rsi, %rsi
je poly1305_blocks_sse2_23
pshufd $8, %xmm3, %xmm3
pshufd $8, %xmm8, %xmm8
pshufd $8, %xmm9, %xmm9
pshufd $8, %xmm15, %xmm15
pshufd $8, %xmm12, %xmm12
punpcklqdq %xmm8, %xmm3
punpcklqdq %xmm15, %xmm9
movdqu %xmm3, (%rdi)
movdqu %xmm9, 16(%rdi)
movq %xmm12, 32(%rdi)
jmp poly1305_blocks_sse2_10
poly1305_blocks_sse2_23:
movaps %xmm3, %xmm0
movaps %xmm8, %xmm4
movaps %xmm9, %xmm2
psrldq $8, %xmm0
movaps %xmm15, %xmm10
paddq %xmm0, %xmm3
psrldq $8, %xmm4
movaps %xmm12, %xmm0
movd %xmm3, %edx
paddq %xmm4, %xmm8
psrldq $8, %xmm2
movl %edx, %ecx
movd %xmm8, %eax
paddq %xmm2, %xmm9
shrl $26, %ecx
psrldq $8, %xmm10
andl $67108863, %edx
addl %ecx, %eax
movd %xmm9, %ecx
paddq %xmm10, %xmm15
movl %eax, %r9d
shrl $26, %eax
psrldq $8, %xmm0
addl %ecx, %eax
movd %xmm15, %ecx
paddq %xmm0, %xmm12
movl %eax, %esi
andl $67108863, %r9d
movd %xmm12, %r10d
shrl $26, %esi
andl $67108863, %eax
addl %ecx, %esi
salq $8, %rax
movl %r9d, %ecx
shrl $18, %r9d
movl %esi, %r8d
shrl $26, %esi
andl $67108863, %r8d
addl %r10d, %esi
orq %r9, %rax
salq $16, %rsi
movq %r8, %r9
shrl $10, %r8d
salq $26, %rcx
orq %r8, %rsi
salq $34, %r9
orq %rdx, %rcx
movq %rsi, %r11
shrq $42, %rsi
movabsq $17592186044415, %rdx
orq %r9, %rax
movabsq $4398046511103, %r8
andq %rdx, %rcx
andq %rdx, %rax
andq %r8, %r11
leaq (%rsi,%rsi,4), %rsi
addq %rsi, %rcx
movq %rcx, %r10
shrq $44, %rcx
addq %rcx, %rax
andq %rdx, %r10
movq %rax, %r9
shrq $44, %rax
addq %r11, %rax
andq %rdx, %r9
movabsq $-4398046511104, %r11
movq %rax, %rcx
andq %r8, %rcx
shrq $42, %rax
leaq (%rax,%rax,4), %rsi
addq %rcx, %r11
addq %r10, %rsi
movq %rsi, %r8
shrq $44, %rsi
andq %rdx, %r8
addq %r9, %rsi
leaq 5(%r8), %r9
movq %r9, %rbx
andq %rdx, %r9
shrq $44, %rbx
addq %rsi, %rbx
movq %rbx, %rax
andq %rbx, %rdx
shrq $44, %rax
addq %rax, %r11
movq %r11, %rax
shrq $63, %rax
decq %rax
movq %rax, %r10
andq %rax, %r9
andq %rax, %rdx
notq %r10
andq %r11, %rax
andq %r10, %r8
andq %r10, %rsi
andq %r10, %rcx
orq %r9, %r8
orq %rdx, %rsi
orq %rax, %rcx
movq %r8, (%rdi)
movq %rsi, 8(%rdi)
movq %rcx, 16(%rdi)
poly1305_blocks_sse2_10:
movq -8(%rbp), %rbx
leave
ret
FN_END poly1305_blocks_sse2

GLOBAL_HIDDEN_FN poly1305_finish_ext_sse2
poly1305_finish_ext_sse2_local:
pushq %r12
movq %rcx, %r12
pushq %rbp
movq %rdx, %rbp
pushq %rbx
movq %rdi, %rbx
subq $32, %rsp
testq %rdx, %rdx
je poly1305_finish_ext_sse2_27
xorl %eax, %eax
movq %rsp, %rdi
movl $8, %ecx
rep stosl
subq %rsp, %rsi
testb $16, %dl
movq %rsp, %rax
je poly1305_finish_ext_sse2_28
movdqu (%rsp,%rsi), %xmm0
addq $16, %rax
movaps %xmm0, (%rsp)
poly1305_finish_ext_sse2_28:
testb $8, %bpl
je poly1305_finish_ext_sse2_29
movq (%rax,%rsi), %rdx
movq %rdx, (%rax)
addq $8, %rax
poly1305_finish_ext_sse2_29:
testb $4, %bpl
je poly1305_finish_ext_sse2_30
movl (%rax,%rsi), %edx
movl %edx, (%rax)
addq $4, %rax
poly1305_finish_ext_sse2_30:
testb $2, %bpl
je poly1305_finish_ext_sse2_31
movw (%rax,%rsi), %dx
movw %dx, (%rax)
addq $2, %rax
poly1305_finish_ext_sse2_31:
testb $1, %bpl
je poly1305_finish_ext_sse2_32
movb (%rax,%rsi), %dl
movb %dl, (%rax)
poly1305_finish_ext_sse2_32:
cmpq $16, %rbp
je poly1305_finish_ext_sse2_33
movb $1, (%rsp,%rbp)
poly1305_finish_ext_sse2_33:
cmpq $16, %rbp
movl $32, %edx
movq %rsp, %rsi
sbbq %rax, %rax
movq %rbx, %rdi
andl $4, %eax
addq $4, %rax
orq %rax, 120(%rbx)
call poly1305_blocks_sse2_local
poly1305_finish_ext_sse2_27:
movq 120(%rbx), %rax
testb $1, %al
je poly1305_finish_ext_sse2_35
decq %rbp
cmpq $15, %rbp
jbe poly1305_finish_ext_sse2_36
orq $16, %rax
jmp poly1305_finish_ext_sse2_40
poly1305_finish_ext_sse2_36:
orq $32, %rax
poly1305_finish_ext_sse2_40:
movq %rax, 120(%rbx)
movl $32, %edx
xorl %esi, %esi
movq %rbx, %rdi
call poly1305_blocks_sse2_local
poly1305_finish_ext_sse2_35:
movq 8(%rbx), %rax
movq 112(%rbx), %rsi
movq %rax, %rdx
movq %rax, %rcx
movq 16(%rbx), %rax
shrq $20, %rcx
salq $44, %rdx
orq (%rbx), %rdx
salq $24, %rax
orq %rcx, %rax
movq 104(%rbx), %rcx
addq %rcx, %rdx
adcq %rsi, %rax
xorps %xmm0, %xmm0
movdqu %xmm0, (%rbx)
movdqu %xmm0, 16(%rbx)
movdqu %xmm0, 32(%rbx)
movdqu %xmm0, 48(%rbx)
movdqu %xmm0, 64(%rbx)
movdqu %xmm0, 80(%rbx)
movdqu %xmm0, 96(%rbx)
movdqu %xmm0, 112(%rbx)
movq %rdx, (%r12)
movq %rax, 8(%r12)
addq $32, %rsp
popq %rbx
popq %rbp
popq %r12
ret
FN_END poly1305_finish_ext_sse2

