## What is IDA Extras?

IDA extras is a (growing) collection of IDA UI and other enhancements to overcome some challenges when using IDA. If what has been implemented is possible already in IDA, please file an [issue](https://github.com/Still34/IDAExtras/issues).

## How To Install?

1. Clone the repository
2. Copy the `IDAExtras.py` file and `/idaextras` directory to your choice of plugin installation path (`%IDAUSR%/plugins` / `%IDADIR%/plugins`).

## What Are These Enhancements?

### 1. Exports

`IDA Extras: Exports` renders another tab similar to the default Exports tab but will provide additional detail about the exports.  This interface came about due to wanting a quick way to find exports of interest when dealing with many exports where a number of them are just retn statements.  There is even an `AutoFilter` option to remove all of the ones with `retn` mnemonic or where the `Is Code` flag is `False`.

![](./documentation/IDAExtrasExports.png)

**Video**

[IDAExtrasExports.webm](https://github.com/xorhex/IDAExtras/assets/40742023/7ad9dc0c-976b-4b35-9310-9c7188f8e19d)

The export screen is started in the video using the shortcut key.  The menu item was not clicked; just shown.

### 2. Copy Bytes

`Copy Bytes` works in both the dissembler view and the hex view.  This enchancement copies the bytes selected on the screen.  It's not perfect, but it gets the job done.

The build-in IDA shortcut is `Shift-E` which gives the user more options but sometimes it's nice to have a quick copy bytes in the right click menu.

Caveat 1: When copying selected bytes in the dissassembler view it makes use of `idc.read_selection_end()` and `idc.read_selection_start()` which, when in the dissassembler view, means all of the bytes on each line are captured.  So if the highlight starts in the middle of one line and ends in the middle of the next line then all of the instructions for both will be copied.

Caveat 2: When copying the bytes in the hex viewer, sometimes one additional byte gets added to the contents copied.

Caveat 3: When copying bytes in the hex viewer, the start and stop positions are determined by when the mouse was clicked and then let up - it does NOT match the contents that get highlighted!

**Video: Dissassembler View**

[CopyBytes_DissassemblerView.webm](https://github.com/xorhex/IDAExtras/assets/40742023/fa330440-197a-46a1-9df5-a16216f32ede)

https://github.com/xorhex/IDAExtras/assets/40742023/e0a652bc-28ce-4d81-a6f9-da779c0dc4eb

**Video: Hex Viewer**

https://github.com/xorhex/IDAExtras/assets/40742023/fd186a49-ad25-410f-8cdc-615e3379d6dc

### 3. sockaddr_in.sin_addr and sockaddr_in.sin_port

Right click on a DWORD or WORD in the dissassembly view to have the sin_addr and/or the sin_port number representation of those bytes displayed.  Upon selecting the value in the context menu, the string representation is then added as a comment.

**sockaddr_in.sin_addr representation**

![](./documentation/IDAExtraIPAddr.png)

**sockaddr_in.sin_port representation**

![](./documentation/IDAExtrasPort.png)

## History

This repository/plugin was originally developed by @xorhex and its management rights were transferred to @Still34 on 2025/09/15 as the original maintainer has migrated to a different disassembler and no longer uses IDA.

