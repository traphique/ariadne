# Example Julia REPL session. Requires Ariadne running in Binary Ninja and
# `ariadne-connect` completed inside pwndbg.
#
#   julia> include("examples.jl")

include(joinpath(@__DIR__, "Ariadne.jl"))
using .Ariadne

info = connect!()
println("Binary Ninja: ", info.bn)
println("GDB:          ", info.gdb)

# Query the function that contains this analysis address (change to match your BV).
addr = 0x401000
fn = func(addr)
if fn === nothing
    println("No function at ", string(addr, base = 16, pad = 0))
else
    println("function: ", fn["header"]["name"], "  ", fn["header"]["type_string"])
    println("stack vars:")
    for v in fn["stack_vars"]
        println("  ", v["offset"], "  ", v["type_name"], " ", v["name"])
    end
    println("basic blocks: ", length(blocks(addr)))
    println("HLIL:")
    for ins in il(addr, :hlil)
        println("  ", ins["address"], "  ", ins["text"])
    end
end

println("GDB \$pc = ", pc())
println("registers: ", regs())
println("breakpoints: ", breakpoints())

# Read 16 bytes at the current PC (runtime address).
runtime_pc = parse(UInt, replace(pc(), r"^0x" => ""), base = 16)
dump = mem(runtime_pc, 16)
println("bytes at pc: ", bytes2hex(dump))
