# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import datetime
from typing import Any, Callable, Iterable, List, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.exceptions import PagedInvalidAddressException
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints, conversion
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import elf
from volatility3.plugins.linux import elfs


class PsList(interfaces.plugins.PluginInterface):
    """Lists the processes present in a particular linux memory image."""

    _required_framework_version = (2, 0, 0)

    _version = (2, 2, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="elfs", plugin=elfs.Elfs, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="threads",
                description="Include user threads",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="decorate_comm",
                description="Show `user threads` comm in curly brackets, and `kernel threads` comm in square brackets",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed processes",
                optional=True,
                default=False,
            ),
        ]

    @classmethod
    def create_pid_filter(cls, pid_list: List[int] = None) -> Callable[[Any], bool]:
        """Constructs a filter function for process IDs.

        Args:
            pid_list: List of process IDs that are acceptable (or None if all are acceptable)

        Returns:
            Function which, when provided a process object, returns True if the process is to be filtered out of the list
        """
        # FIXME: mypy #4973 or #2608
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:

            def filter_func(x):
                return x.pid not in filter_list

            return filter_func
        else:
            return lambda _: False

    @classmethod
    def get_task_fields(
        cls, task: interfaces.objects.ObjectInterface, decorate_comm: bool = False
    ) -> Tuple[int, int, int, str, int, int, float]:
        """Extract the fields needed for the final output

        Args:
            task: A task object from where to get the fields.
            decorate_comm: If True, it decorates the comm string of user threads in curly brackets,
                           and of Kernel threads in square brackets.
                           Defaults to False.
        Returns:
            A tuple with the fields to show in the plugin output.
        """
        pid = task.tgid
        tid = task.pid
        ppid = task.parent.tgid if task.parent else 0
        try:
            uid = task.cred.uid.val
            gid = task.cred.gid.val
        except PagedInvalidAddressException:
            uid = -1
            gid = -1

        if hasattr(task, "real_start_time"):
            start_time_ns = task.real_start_time
        else:
            start_time_ns = task.start_time
        start_time = start_time_ns / 0x989680 / 100

        name = utility.array_to_string(task.comm)
        if decorate_comm:
            if task.is_kernel_thread:
                name = f"[{name}]"
            elif task.is_user_thread:
                name = f"{{{name}}}"

        task_fields = (task.vol.offset, pid, tid, ppid, name, uid, gid, start_time)
        return task_fields

    def _get_time_boot(self, vmlinux_module_name: str) -> float:
        """Extract the time at boot in seconds
        """
        # tk_core structure will probably not be there for old kernels 3.19(ish)
        # See https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/linux/common.py#L253
        # for other methods
        vmlinux = self.context.modules[vmlinux_module_name]
        tkcore = vmlinux.object_from_symbol("tk_core")
        timekeeper = tkcore.timekeeper

        wall = timekeeper.wall_to_monotonic
        oreal = timekeeper.offs_real
        oboot = timekeeper.offs_boot

        # Copy from volatility
        # See https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/overlays/linux/linux.py#L2082
        if hasattr(oreal, "tv64"):
            tv64 = (oreal.tv64 & 0xffffffff) - (oboot.tv64 & 0xffffffff)
        else:
            tv64 = (oreal & 0xffffffff) - (oboot & 0xffffffff)

        if tv64:
            tv64 = (tv64 / 100000000) * -1
        # Original code below
        # if tv64:
        #     tv64 = (tv64 / 100000000) * -1
        #     timeo = timespec64(tv64, 0) # Maybe try to load this as timespec64 ?
        # else:
        #     timeo = None

        # Below code is not required anymore
        # if wall is None or timeo is None:
        #     return 0

        secs = wall.tv_sec + tv64
        nsecs = wall.tv_nsec
        # Original code below
        # secs = wall.tv_sec + timeo.tv_sec
        # nsecs = wall.tv_nsec + timeo.tv_nsec

        secs = secs * -1
        nsecs = nsecs * -1

        nsecs_per = 1000000000
        while nsecs >= nsecs_per:
            nsecs = nsecs - nsecs_per
            secs = secs + 1

        while nsecs < 0:
            nsecs = nsecs + nsecs_per
            secs = secs - 1

        boot_time = secs + (nsecs / nsecs_per / 100)

        return boot_time

    def _get_file_output(self, task: interfaces.objects.ObjectInterface) -> str:
        """Extract the elf for the process if requested
        Args:
            task: A task object to extract from.
        Returns:
            A string showing the results of the extraction, either
            the filename used or an error.
        """
        elf_table_name = intermed.IntermediateSymbolTable.create(
            self.context,
            self.config_path,
            "linux",
            "elf",
            class_types=elf.class_types,
        )
        proc_layer_name = task.add_process_layer()
        if not proc_layer_name:
            # if we can't build a proc layer we can't
            # extract the elf
            return renderers.NotApplicableValue()
        else:
            # Find the vma that belongs to the main ELF of the process
            file_output = "Error outputting file"
            for v in task.mm.get_vma_iter():
                if v.vm_start == task.mm.start_code:
                    file_handle = elfs.Elfs.elf_dump(
                        self.context,
                        proc_layer_name,
                        elf_table_name,
                        v,
                        task,
                        self.open,
                    )
                    if file_handle:
                        file_output = str(file_handle.preferred_filename)
                        file_handle.close()
                    break
            else:
                file_output = "VMA start matching task start_code not found"
        return file_output

    def _generator(
        self,
        pid_filter: Callable[[Any], bool],
        include_threads: bool = False,
        decorate_comm: bool = False,
        dump: bool = False,
    ):
        """Generates the tasks list.

        Args:
            pid_filter: A function which takes a process object and returns True if the process should be ignored/filtered
            include_threads: If True, the output will also show the user threads
                             If False, only the thread group leaders will be shown
                             Defaults to False.
            decorate_comm: If True, it decorates the comm string of
                            - User threads: in curly brackets,
                            - Kernel threads: in square brackets
                           Defaults to False.
            dump: If True, the main executable of the process is written to a file
                  Defaults to False.
        Yields:
            Each rows
        """
        wall = self._get_time_boot(self.config["kernel"])

        for task in self.list_tasks(
            self.context, self.config["kernel"], pid_filter, include_threads
        ):
            if dump:
                file_output = self._get_file_output(task)
            else:
                file_output = "Disabled"

            offset, pid, tid, ppid, name, uid, gid, start_time = self.get_task_fields(task, decorate_comm)

            yield 0, (
                format_hints.Hex(offset),
                pid,
                tid,
                ppid,
                name,
                uid,
                gid,
                conversion.unixtime_to_datetime(start_time + wall),
                file_output,
            )

    @classmethod
    def list_tasks(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        filter_func: Callable[[int], bool] = lambda _: False,
        include_threads: bool = False,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the tasks in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate
            filter_func: A function which takes a process object and returns True if the process should be ignored/filtered
            include_threads: If True, it will also return user threads.
        Yields:
            Task objects
        """
        vmlinux = context.modules[vmlinux_module_name]

        init_task = vmlinux.object_from_symbol(symbol_name="init_task")

        # Note that the init_task itself is not yielded, since "ps" also never shows it.
        for task in init_task.tasks:
            if filter_func(task):
                continue

            yield task

            if include_threads:
                yield from task.get_threads()

    def run(self):
        pids = self.config.get("pid")
        include_threads = self.config.get("threads")
        decorate_comm = self.config.get("decorate_comm")
        dump = self.config.get("dump")
        filter_func = self.create_pid_filter(pids)

        columns = [
            ("OFFSET (V)", format_hints.Hex),
            ("PID", int),
            ("TID", int),
            ("PPID", int),
            ("COMM", str),
            ("UID", int),
            ("GID", int),
            ("Start Time", datetime.datetime),
            ("File output", str),
        ]
        return renderers.TreeGrid(
            columns, self._generator(filter_func, include_threads, decorate_comm, dump)
        )
