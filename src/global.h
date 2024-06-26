#pragma once

#include "ntdll.h"
#include <ntstatus.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PAGE_SIZE 0x1000

#if defined(__cplusplus) && \
	((defined(_MSC_VER) && (_MSC_VER >= 1900)) || defined(__clang__))
#define CONSTEXPR constexpr
#else
#define CONSTEXPR
#endif

#if defined(__clang__)
#undef FIELD_OFFSET
#undef UFIELD_OFFSET
#define FIELD_OFFSET(type, field)	((LONG)__builtin_offsetof(type, field))
#define UFIELD_OFFSET(type, field)	((ULONG)__builtin_offsetof(type, field))
#endif

// swind2.cpp

void CIInfo();
	

// pe.cpp
NTSTATUS
MapFileSectionView(
	_In_ PCWCHAR Filename,
	_In_ BOOLEAN ForceDisableAslr,
	_Out_ PVOID *ImageBase,
	_Out_ PSIZE_T ViewSize
	);

PVOID
GetProcedureAddress(
	_In_ ULONG_PTR DllBase,
	_In_ PCSTR RoutineName
	);


CONSTEXPR
FORCEINLINE
LONGLONG
RtlMsToTicks(
	_In_ ULONG Milliseconds
	)
{
	return 10000LL * static_cast<LONGLONG>(Milliseconds);
}

// Ntdll string functions, not in ntdll.h as they are incompatible with the CRT
typedef CONST WCHAR *LPCWCHAR, *PCWCHAR;

#ifdef __cplusplus
extern "C" {
#endif
NTSYSAPI
int
__cdecl
_snwprintf(
	_Out_ PWCHAR Buffer,
	_In_ size_t BufferCount,
	_In_ PCWCHAR Format,
	...
	);

NTSYSAPI
int
__cdecl
_vsnwprintf(
	_Out_ PWCHAR Buffer,
	_In_ size_t BufferCount,
	_In_ PCWCHAR Format,
	_In_ va_list ArgList
	);
#ifdef __cplusplus
}
#endif

// Debug functions
inline
VOID
Printf(
	_In_ PCWCHAR Format,
	...
	)
{
	WCHAR Buffer[512];
	va_list VaList;
	va_start(VaList, Format);
	ULONG N = _vsnwprintf(Buffer, 512, Format, VaList);
	va_end(VaList);
	WriteConsoleW(NtCurrentPeb()->ProcessParameters->StandardOutput, Buffer, N, &N, nullptr);
}

#ifdef NT_ANALYSIS_ASSUME
// wdm.h's asserts are incompatible with both clang and MS's own analyzer
#undef NT_ANALYSIS_ASSUME
#undef NT_ASSERT_ACTION
#undef NT_ASSERTMSG_ACTION
#undef NT_ASSERTMSGW_ACTION
#undef NT_ASSERT_ASSUME
#undef NT_ASSERTMSG_ASSUME
#undef NT_ASSERTMSGW_ASSUME
#undef NT_ASSERT
#undef NT_ASSERTMSG
#undef NT_ASSERTMSGW
#endif

#ifdef _PREFAST_
#define NT_ANALYSIS_ASSUME(...) _Analysis_assume_(__VA_ARGS__)
#elif defined(_DEBUG) || defined(DBG)
#define NT_ANALYSIS_ASSUME(...) ((void) 0)
#else
#define NT_ANALYSIS_ASSUME(...) __noop(__VA_ARGS__)
#endif

#if !defined(__clang__)
#if !defined(DbgRaiseAssertionFailure)
#define DbgRaiseAssertionFailure() __int2c()
#endif

#define NT_ASSERT_ACTION(_exp) \
	((!(_exp)) ? \
		(__annotation((PWCHAR)L"Debug", L"AssertFail", L#_exp), \
			DbgRaiseAssertionFailure(), FALSE) : \
		TRUE)

#define NT_ASSERTMSG_ACTION(_msg, _exp) \
	((!(_exp)) ? \
		(__annotation((PWCHAR)L"Debug", L"AssertFail", L##_msg), \
			DbgRaiseAssertionFailure(), FALSE) : \
		TRUE)

#define NT_ASSERTMSGW_ACTION(_msg, _exp) \
	((!(_exp)) ? \
		(__annotation((PWCHAR)L"Debug", L"AssertFail", _msg), \
			DbgRaiseAssertionFailure(), FALSE) : \
		TRUE)
#else
#define NT_ASSERT_ACTION(_exp) \
	((!(_exp)) ? (__debugbreak(), FALSE) : TRUE)
#define NT_ASSERTMSG_ACTION(_msg, _exp) \
	NT_ASSERT_ACTION(_exp)
#define NT_ASSERTMSGW_ACTION(_msg, _exp) \
	NT_ASSERT_ACTION(_exp)
#endif

#if defined(_DEBUG) || defined(DBG)
#define NT_ASSERT_ASSUME(_exp) \
	(NT_ANALYSIS_ASSUME(_exp), NT_ASSERT_ACTION(_exp))

#define NT_ASSERTMSG_ASSUME(_msg, _exp) \
	(NT_ANALYSIS_ASSUME(_exp), NT_ASSERTMSG_ACTION(_msg, _exp))

#define NT_ASSERTMSGW_ASSUME(_msg, _exp) \
	(NT_ANALYSIS_ASSUME(_exp), NT_ASSERTMSGW_ACTION(_msg, _exp))

#define NT_ASSERT					NT_ASSERT_ASSUME
#define NT_ASSERTMSG				NT_ASSERTMSG_ASSUME
#define NT_ASSERTMSGW				NT_ASSERTMSGW_ASSUME
#else
#define NT_ASSERT(_exp)				((void) 0)
#define NT_ASSERTMSG(_msg, _exp)	((void) 0)
#define NT_ASSERTMSGW(_msg, _exp)	((void) 0)
#endif

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#pragma warning(push)
#pragma warning(disable:4309)
template<ULONG N>
struct static_print // Usage: static_print<FIELD_OFFSET(S, v)>()() prints the value as a compiler warning
{
	CHAR operator()() CONST { return N + 256; }
};
#pragma warning(pop)

template<typename T>
void print_size() { static_print<sizeof(T)>()(); }
#endif
