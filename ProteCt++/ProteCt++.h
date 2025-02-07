#ifndef PROTECTPP_H
#define PROTECTPP_H

#ifdef __cplusplus
extern "C" {
#endif

	bool IsLibraryLoaded();
	bool IsSimpleDebuggerPresent();
	bool CheckRemoteDebugger();
	bool CheckProcessDebugPort();
	bool CheckForByte();
	bool CheckForBreakpoint();

#ifdef __cplusplus
}
#endif

#endif // PROTECTPP_H
