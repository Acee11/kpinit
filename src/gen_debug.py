from utils import error, ctx, runcmd

kbase_template = """
set context-sections none

define vmemmmap_info
  if $argc != 1
    printf "usage: pfn <page-ptr>\n"
  else
    set $p   = (unsigned long)$arg0
    set $vmm = (unsigned long)vmemmap_base
    set $po  = (unsigned long)page_offset_base
    set $_pfn   = ($p - $vmm) >> 6
    set $_phys  = $_pfn << 12
    set $_kvirt = $_phys + $po
    printf "page  = 0x%lx\n",    $p
    printf "pfn   = 0x%lx (%lu)\n", $_pfn, $_pfn
    printf "phys  = 0x%lx\n",    $_phys
    printf "kvirt = 0x%lx\n",    $_kvirt
  end
end
document vmemmmap_info
Print PFN / physical addr / direct-map VA for a struct page *.
Usage: vmemmmap_info <page-ptr>
end

python
import gdb
kbase = 0
vmlinux = "{}"
try:
  kbase = int(gdb.execute("kbase", to_string=True).strip().split(" ")[-1][:18], 16)
  print(f"found kbase: {{hex(kbase)}}")
  offset = kbase - {}
  gdb.execute(f"symbol-file {{vmlinux}} -o {{hex(offset)}}")
except:
  gdb.execute(f"add-symbol-file {{vmlinux}}")
  print("cannot find kbase")
end
"""

finished_msg = """
python
print("finished sourcing files")
end
c
"""


def gen_debug():
    vmlinux_info = runcmd("readelf", "-l", ctx.vmlinux.get(), fail_on_error=True)
    base = None
    for line in vmlinux_info.splitlines():
        if "LOAD" in line:
            base = int(line.split()[2], 16)
            break
    if not base:
        error(f"Cannot find kernel base: {vmlinux_info}")
    if ctx.arch == "aarch64":
        # for some reason the first 0x10000 bytes of an aarch64 kernel is not mappped
        base += 0x10000
    content = ""
    content += "target remote localhost:$PORT\n"
    content += kbase_template.format(ctx.vmlinux.get(), base)
    if ctx.linux_src.get() is not None:
        content += f"set substitute-path ./ {ctx.linux_src.get()}\n"
        if ctx.build_path.get() is not None:
            content += (
                f"set substitute-path {ctx.build_path.get()} {ctx.linux_src.get()}\n"
            )
    content += f"add-symbol-file {ctx.expdir('exploit')}\n"

    extra = ctx.expdir("extra.gdb")
    content += f"source {extra}\n"
    content += finished_msg
    f = open(ctx.challdir("debug.gdb"), "w")
    f.write(content)
    f = open(extra, "w")
    content = "# default\n"
    content += "set show-flag on\n"
    content += "set exception-debugger on\n"
    f.write(content)
