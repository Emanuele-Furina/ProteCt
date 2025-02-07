# ProteCt++

ProteCt++ è una libreria statica progettata per rilevare la presenza di debugger in un processo. Include diverse funzioni per verificare se un processo è in esecuzione sotto un debugger.

## Funzionalità

- **IsLibraryLoaded**: Verifica se la libreria è caricata correttamente.
- **IsSimpleDebuggerPresent**: Verifica se un debugger è presente utilizzando la funzione `IsDebuggerPresent` di Windows.
- **CheckRemoteDebugger**: Verifica se un debugger remoto è presente utilizzando la funzione `CheckRemoteDebuggerPresent` di Windows.
- **CheckProcessDebugPort**: Verifica se il processo è in debug controllando il valore del `ProcessDebugPort`.
- **CheckDebugFlagsEFLAGS**: Verifica se il bit 16 del registro EFLAGS è impostato, indicando la presenza di un debugger.
- **CheckDebugFlagsDR7**: Verifica se il bit 0 del registro DR7 è impostato, indicando un punto di interruzione hardware.
- **CheckDebugFlagsDR6**: Verifica se il bit 0 del registro DR6 è impostato, indicando un punto di interruzione hardware.


...WIP...

## Requisiti

- Windows
- Visual Studio
- C++14
