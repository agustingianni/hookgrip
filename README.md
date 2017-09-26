# Hookgrip

Small command line utility used to hook functions in a target process. Its design gravitates toward the instrumentation of the heap, but it can be used for other purposes with little effort.

## Usage

To get a resume of what `hookgrip` can do, execute the following command `python hookgrip.py -h`

```
$ python hookgrip.py -h
usage: hookgrip.py [-h] [-V] (-p PROC_PID | -n PROC_NAME | -l | -d DEVICE)
                   [-m MOD_NAMES] [-e {flash,malloc,rtlheap}]

Hookgrip.

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -p PROC_PID           Process PID.
  -n PROC_NAME          Process name (follows unix wildcard patterns).
  -l                    Display running processes.
  -d DEVICE             Select a device by ID. Specify `list` to get a list of
                        available devices.
  -m MOD_NAMES          Specify zero or more modules that need to be loaded in
                        the target process.
  -e {flash,malloc,rtlheap}
                        Enable one or more hooks.
```

## Device listing and selection

Frida allows us to use external devices like phones. To select a device to operate on, you can list the devices using the command line option `-d list` to see the available devices ID.

```
$ python hookgrip.py -d list
INFO:root:Available devices:
INFO:root:  ID         Name
INFO:root:  local      Local System
INFO:root:  tcp        Local TCP
```

Once you have selected the device on which you will operate, take its ID and use it with the `-d [DEV_ID]` option. In the example, we have selected the `local` device just as an example because if you don't specify a device, `hookgrip` will default to it.

```
$ python hookgrip.py -d local -l
INFO:root:Using device Device(id="local", name="Local System", type='local').
INFO:root:Local processes list:
INFO:root:  PID    Name
INFO:root:  1      launchd
INFO:root:  38     UserEventAgent
```

## Process listing

To get a list of processes running in the selected system (by default, `local`) use the `-l` option. The list will be sorted by PID in ascending order.

```
$ python hookgrip.py -l
INFO:root:Using device Device(id="local", name="Local System", type='local').
INFO:root:Local processes list:
INFO:root:  PID    Name
INFO:root:  1      launchd
INFO:root:  38     UserEventAgent
INFO:root:  39     syslogd
...
```

## Process selection

You can select a process either by `name` or by `PID`. Attaching by name can be convenient since that way you don't need to lookup for the PID of the process you are interested in. Nevertheless, in some cases (like browsers) you will find that there are multiple processes with the same name. In this case, you need to manually lookup the `PID` of the process you want to attach to.

For instance in order to attach to a process whose name is `cat`, use the `-n` (name) option.

```
$ python hookgrip.py -n cat
INFO:root:Using device Device(id="local", name="Local System", type='local').
INFO:root:Defaulting to first process `cat:16851`.
INFO:root:Attaching to process `16851`.
malloc @ 0x7fffaa5741e8
free @ 0x7fffaa576dd5
calloc @ 0x7fffaa577d61
realloc @ 0x7fffaa577f10
INFO:root:Ctrl+D on UNIX, Ctrl+Z on Windows to detach.
```

You can achieve the same result by attaching to a `PID` using the `-p` (PID) option.

```
$ python hookgrip.py -p 16851
INFO:root:Using device Device(id="local", name="Local System", type='local').
INFO:root:Attaching to process pid `16851`.
INFO:root:Attaching to process `16851`.
malloc @ 0x7fffaa5741e8
free @ 0x7fffaa576dd5
calloc @ 0x7fffaa577d61
realloc @ 0x7fffaa577f10
INFO:root:Ctrl+D on UNIX, Ctrl+Z on Windows to detach.
```

## Process disambiguation by loaded modules

In some cases you can disambiguate which process you want to attach to by specifying a list of loaded modules. For instance, if you want to attach to the `Edge browser` tab that has flash loaded you can specify that the module `Flash.ocx` needs to be loaded. In order to do that you can use the `-m` option.

```
python hookgrip.py -n edge.exe -m Flash.ocx
```

When you specify a process name and one or more modules, `hookgrip` will check that the target process has indeed loaded the specified module/s.

## Hook handling

By default, `hookgrip` comes with a couple hooks you can enable. The list can be seen in the help message printed when the `-h` option is specified.

To enable a hook, use the `-e HOOK_NAME` option. You can enable as many hooks as you want.

```
$ python hookgrip.py -e malloc -n mc
INFO:root:Using device Device(id="local", name="Local System", type='local').
INFO:root:Defaulting to first process `mc:17259`.
INFO:root:Attaching to process `17259`.
malloc @ 0x7fffaa5741e8
free @ 0x7fffaa576dd5
calloc @ 0x7fffaa577d61
realloc @ 0x7fffaa577f10
INFO:root:Ctrl+D on UNIX, Ctrl+Z on Windows to detach.
```