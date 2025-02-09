#ifndef PROTECTPP_H
#define PROTECTPP_H
#include <windows.h>
#ifdef __cplusplus
extern "C" {
#endif

	bool IsLibraryLoaded();
	bool IsSimpleDebuggerPresent();
	bool CheckRemoteDebugger();
	bool CheckProcessDebugPort();
	bool CheckForByte();
	bool CheckForBreakpoint();
	bool CheckForVM();
	bool IsMemoryBreakpoints();

#ifdef __cplusplus
}
#endif

#endif // PROTECTPP_H
