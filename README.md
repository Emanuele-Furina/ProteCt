# ProteCt++

ProteCt++ è una libreria statica progettata per rilevare la presenza di debugger in un processo. Include diverse funzioni per verificare se un processo è in esecuzione sotto un debugger.

## Funzionalità

- **IsLibraryLoaded**: Verifica se la libreria è caricata correttamente.
- **IsSimpleDebuggerPresent**: Verifica se un debugger è presente utilizzando la funzione `IsDebuggerPresent` di Windows.
- **CheckRemoteDebugger**: Verifica se un debugger remoto è presente utilizzando la funzione `CheckRemoteDebuggerPresent` di Windows.
- **CheckProcessDebugPort**: Verifica se il processo è in debug controllando il valore del `ProcessDebugPort`.
- **CheckForByte**: Controlla se un byte specifico è presente in una determinata area di memoria.
- **CheckForBreakpoint**: Controlla se un breakpoint è presente nei registri di debug del thread corrente.
- **CheckForVM**: Verifica se il processo è in esecuzione in una macchina virtuale controllando la presenza di moduli noti di VM.
- **IsMemoryBreakpoints**: Verifica se il processo è in debug utilizzando una pagina di memoria con protezione di guardia.

## Requisiti

- Windows
- Visual Studio
- C++14

## Utilizzo

Esempio di utilizzo delle funzioni fornite dalla libreria:

