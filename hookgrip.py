import os
import sys
import glob
import frida
import fnmatch
import logging
import argparse

# Get the names of all the available hooks.
HOOKS_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "hooks")
HOOKS_GLOB = os.path.join(HOOKS_DIR, "*.js")
HOOKS_PATHS = glob.glob(HOOKS_GLOB)
HOOKS_NAMES = [os.path.splitext(os.path.basename(name))[0]
               for name in HOOKS_PATHS]

logging.basicConfig(level=logging.INFO, stream=sys.stdout)

parser = argparse.ArgumentParser(description="Hookgrip.")

# Show the program version.
parser.add_argument('-V', '--version', action="version",
                    version="%(prog)s 0.1")

# Required, mutually exclusive options.
group = parser.add_mutually_exclusive_group(required=True)

# Specify the process to which we will attach by PID.
group.add_argument("-p", action="store",
                   dest="proc_pid", type=int, help="Process PID.")

# Specify the process to which we will attach by NAME.
group.add_argument("-n", action="store", dest="proc_name",
                   help="Process name (follows unix wildcard patterns).")

# List running processes.
group.add_argument("-l", action="store_true",
                   dest="show_processes", help="Display running processes.")

# Add an option to select a device.
parser.add_argument("-d", action="store", dest="device", default="local",
                   help="Select a device by ID. Specify `list` to get a list of available devices.")

# Specify zero or mode modules.
parser.add_argument("-m", action="append", dest="mod_names", default=[],
                    help="Specify zero or more modules that need to be loaded in the target process.")

# Hook enable option.
parser.add_argument("-e", action="append", dest="hook_names", default=[], choices=HOOKS_NAMES,
                    help="Enable one or more hooks.")

# Parse command line arguments.
args = parser.parse_args()

# Remove duplicates from the hook names list.
args.hook_names = list(set(args.hook_names))

# Show available devices.
if args.device == "list":
    logging.info("Available devices:")
    logging.info("  %-10s %s" % ("ID", "Name"))
    for device in frida.enumerate_devices():
        logging.info("  %-10s %s" % (device.id, device.name))

    sys.exit()

# Lookup the desired device.
if args.device:
    devs = [dev.id for dev in frida.enumerate_devices()]
    if args.device not in devs:
        logging.error("Invalid device id `%s`." % args.device)
        sys.exit(-1)

    # Get the device.
    device = frida.get_device(args.device)

    logging.info("Using device %r." % device)

# Show processes.
if args.show_processes:
    # Enumerate process and sort them by pid in ascending order.
    processes = sorted(device.enumerate_processes(), reverse=True)

    # Show a tabel with the devices processes.
    logging.info("Local processes list:")
    logging.info("  %-6s %s" % ("PID", "Name"))
    for process in processes:
        logging.info("  %-6d %s" % (process.pid, process.name))

    sys.exit()

# Select the correct process to attach.
if args.proc_pid:
    logging.info("Attaching to process pid `%d`." % args.proc_pid)
    target_process = args.proc_pid

elif args.proc_name:
    # Get the list of local processes.
    processes = sorted(device.enumerate_processes(), reverse=True)

    # Filter processes that match our name.
    processes = [proc for proc in processes if fnmatch.fnmatch(
        proc.name, args.proc_name)]

    # Process name does not match any running processes.
    if len(processes) == 0:
        logging.error("Invalid process name `%s`." % args.proc_name)
        sys.exit(-1)

    # More than one process is available.
    if len(processes) > 1:
        logging.info("Multiple processes (%d) available." % len(processes))

    # Found a single module to attach to.
    found = False

    # Find which module
    for proc in processes:
        if not args.mod_names:
            break

        # Temporarily attach to the process to get a module list.
        session = frida.attach(proc.pid)

        # Search if one of the specified modules is loaded in the target.
        modules = [str(module.name) for module in session.enumerate_modules()]
        if any(mod_name in modules for mod_name in args.mod_names):
            logging.info("Process `%s:%d` matches module list." %
                         (proc.name, proc.pid))
            target_process = proc.pid
            found = True
            break

        session.detach()

    if not found:
        proc = processes[0]
        logging.info("Defaulting to first process `%s:%d`." %
                     (proc.name, proc.pid))
        target_process = proc.pid

else:
    logging.error("I need either a PID or a process name.")
    parser.print_usage()
    sys.exit(-1)

def on_message(message, data):
	print "[%s] -> %s" % (message, data)

# Attach to the target process.
logging.info("Attaching to process `%d`." % target_process)
session = frida.attach(target_process)

# Install hooks.
script = session.create_script(open("hooks/malloc.js").read())
script.on('message', on_message)
script.load()

# Wait until the user decides to detach.
logging.info("Ctrl+D on UNIX, Ctrl+Z on Windows to detach.")
sys.stdin.read()

# Detach from the process.
logging.info("Detaching from the target process.")
session.detach()
