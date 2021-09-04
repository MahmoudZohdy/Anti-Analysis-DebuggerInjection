# Anti-Analysis-DebuggerInjection

In This Project i try to highlight some interesting Anti-Analysis technique, it works by injecting ShellCode inside the debugger itself while it debug our process and control what event the debugger receive from us.

### i divided the work to the folowning steps:

[1] detect the presence of debugger (i used Enumerate runninng process technique, you can change it you can find lots of ways to detect debugger online).

[2] inject the shellcode inside the debugger (used CreateRemoteThread injection Technique, you can see my other project for more injection technique [link](https://github.com/MahmoudZohdy/Process-Injection-Techniques)).

[3] sleep for 4 second to let our ShellCode Hook **WaitForDebugEvent** without causing any event which will lead to crash the debugger.



### the Demo ShellCode Works as Follow:

[1] it resolve all the function that it uses during execution.

[2] locate our function that will get called when **WaitForDebugEvent** Gets Called.

[3] replace the first instruction of **WaitForDebugEvent** (mov edi,edi) with short jump to 5 Bytes Before the Function (Some int 3 or nop instruction), then far jump to our ShellCode.

[4] the ShellCode Call the Original **WaitForDebugEvent** and see the return value of the function, if the event is caused by EXCEPTION_SINGLE_STEP (HW Break Point) it remove the break point and Calls **WaitForDebugEvent** again and the debugger will not notice the ocarance of the event.


# Note:
it does not work on Windbg as Windbg call **ntdll!ZwWaitForDebugEvent** directly and does not call **WaitForDebugEvent** (the one we hook)

This is just a POC there is lots of things that you can do here it depends only on your **imagination** and **creativity**.

i am not very experinced it writing windows ShellCode so in case of any crash please let me know.
