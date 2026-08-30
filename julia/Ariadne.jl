"""
Ariadne.jl — Julia REPL client for Binary Ninja and GDB/pwndbg.

    julia> include("Ariadne.jl")
    julia> using .Ariadne
    julia> connect!()
    julia> Ariadne.func(0x401000)
    julia> Ariadne.il(0x401000, :hlil)
    julia> Ariadne.mem(0x7fffffffde00, 16)
    julia> Ariadne.regs()
"""
module Ariadne

using Base64
using Downloads
using Sockets

export connect!, disconnect!, ping
export func, blocks, il, types, stackvars, header
export mem, mem!, regs, pc, breakpoints, gdb_eval

const DEFAULT_BN = ("127.0.0.1", 9337)
const DEFAULT_GDB = ("127.0.0.1", 9338)

mutable struct Session
    bn_url::String
    gdb_url::String
end

const SESSION = Ref{Union{Nothing,Session}}(nothing)

addrhex(x::Integer) = string("0x", string(x, base = 16))
addrhex(x::AbstractString) = String(x)

function connect!(; bn_host = DEFAULT_BN[1], bn_port = DEFAULT_BN[2],
                    gdb_host = DEFAULT_GDB[1], gdb_port = DEFAULT_GDB[2])
    session = Session(
        "http://$(bn_host):$(bn_port)/RPC2",
        "http://$(gdb_host):$(gdb_port)/RPC2",
    )
    SESSION[] = session
    bn = call(session.bn_url, "ping")
    gdb = try
        call(session.gdb_url, "ping")
    catch err
        (; ok = false, error = sprint(showerror, err))
    end
    return (; bn, gdb)
end

function disconnect!()
    SESSION[] = nothing
    return nothing
end

function session()
    s = SESSION[]
    s === nothing && error("Ariadne is not connected; call connect!() first")
    return s
end

ping() = (bn = call(session().bn_url, "ping"), gdb = call(session().gdb_url, "ping"))

# --- Binary Ninja analysis -------------------------------------------------

func(addr; as_runtime::Bool = false) =
    call(session().bn_url, "get_function", addrhex(addr), as_runtime)

header(addr; as_runtime::Bool = false) = let f = func(addr; as_runtime)
    f === nothing ? nothing : f["header"]
end

stackvars(addr; as_runtime::Bool = false) =
    call(session().bn_url, "get_stack_vars", addrhex(addr), as_runtime)

blocks(addr; as_runtime::Bool = false) =
    call(session().bn_url, "get_basic_blocks", addrhex(addr), as_runtime)

function il(addr, level::Symbol = :hlil; as_runtime::Bool = false)
    call(session().bn_url, "get_il", addrhex(addr), String(level), as_runtime)
end

types() = call(session().bn_url, "get_types")
types(name::AbstractString) = call(session().bn_url, "get_type", String(name))
types_c_header() = call(session().bn_url, "get_types_c_header")
updates(since::Integer = 0) = call(session().bn_url, "get_updates", Int(since))

# --- GDB session -----------------------------------------------------------

mem(addr, size::Integer) = call(session().gdb_url, "read_memory", addrhex(addr), Int(size))

function mem!(addr, data::Vector{UInt8})
    call(session().gdb_url, "write_memory", addrhex(addr), data)
end

mem!(addr, data::AbstractString) = mem!(addr, Vector{UInt8}(codeunits(String(data))))

regs() = call(session().gdb_url, "registers")
pc() = call(session().gdb_url, "pc")
breakpoints() = call(session().gdb_url, "breakpoints")
gdb_eval(expr::AbstractString) = call(session().gdb_url, "eval_expression", String(expr))

# --- Minimal XML-RPC client (stdlib only) ----------------------------------

struct XMLRPCFault <: Exception
    code::Int
    message::String
end

Base.showerror(io::IO, e::XMLRPCFault) = print(io, "XML-RPC fault $(e.code): $(e.message)")

function call(url::AbstractString, method::AbstractString, args...)
    body = encode_request(method, args)
    buf = IOBuffer()
    Downloads.download(
        String(url),
        buf;
        method = "POST",
        input = IOBuffer(body),
        headers = ["Content-Type" => "text/xml"],
        timeout = 5,
    )
    return decode_response(String(take!(buf)))
end

function encode_request(method::AbstractString, args)
    io = IOBuffer()
    write(io, "<?xml version=\"1.0\"?>\n<methodCall><methodName>")
    write(io, xml_escape(method))
    write(io, "</methodName><params>")
    for arg in args
        write(io, "<param><value>")
        encode_value(io, arg)
        write(io, "</value></param>")
    end
    write(io, "</params></methodCall>")
    return take!(io)
end

function encode_value(io::IO, x::Bool)
    write(io, "<boolean>")
    write(io, x ? "1" : "0")
    write(io, "</boolean>")
end

function encode_value(io::IO, x::Integer)
    if typemin(Int32) <= x <= typemax(Int32)
        write(io, "<int>")
        write(io, string(Int(x)))
        write(io, "</int>")
    else
        write(io, "<i8>")
        write(io, string(Int(x)))
        write(io, "</i8>")
    end
end

function encode_value(io::IO, x::AbstractFloat)
    write(io, "<double>")
    write(io, string(Float64(x)))
    write(io, "</double>")
end

function encode_value(io::IO, x::AbstractString)
    write(io, "<string>")
    write(io, xml_escape(String(x)))
    write(io, "</string>")
end

function encode_value(io::IO, x::Vector{UInt8})
    write(io, "<base64>")
    write(io, base64encode(x))
    write(io, "</base64>")
end

function encode_value(io::IO, x::AbstractVector)
    write(io, "<array><data>")
    for item in x
        write(io, "<value>")
        encode_value(io, item)
        write(io, "</value>")
    end
    write(io, "</data></array>")
end

function encode_value(io::IO, x::AbstractDict)
    write(io, "<struct>")
    for (k, v) in x
        write(io, "<member><name>")
        write(io, xml_escape(string(k)))
        write(io, "</name><value>")
        encode_value(io, v)
        write(io, "</value></member>")
    end
    write(io, "</struct>")
end

encode_value(io::IO, ::Nothing) = write(io, "<nil/>")

xml_escape(s::AbstractString) = replace(
    s,
    "&" => "&amp;",
    "<" => "&lt;",
    ">" => "&gt;",
    "\"" => "&quot;",
)

function decode_response(xml::AbstractString)
    if occursin("<fault>", xml)
        code = something(_capture(r"<int>(-?\d+)</int>", xml), 0)
        msg = something(_capture(r"<string>(.*?)</string>"s, xml), "unknown fault")
        throw(XMLRPCFault(parse(Int, string(code)), _unescape(string(msg))))
    end
    inner = extract_balanced(xml, "methodResponse")
    inner = extract_balanced(inner, "params")
    inner = extract_balanced(inner, "param")
    payload = extract_balanced(inner, "value")
    return parse_value(payload)
end

function _capture(re, text)
    m = match(re, text)
    return m === nothing ? nothing : m.captures[1]
end

function parse_value(xml::AbstractString)
    xml = strip(xml)
    if startswith(xml, "<nil") || startswith(xml, "<ex:nil")
        return nothing
    elseif (m = match(r"^<(int|i4|i8)>(-?\d+)</\1>", xml)) !== nothing
        return parse(Int, m.captures[2])
    elseif (m = match(r"^<boolean>([01])</boolean>", xml)) !== nothing
        return m.captures[1] == "1"
    elseif (m = match(r"^<double>([^<]+)</double>", xml)) !== nothing
        return parse(Float64, m.captures[1])
    elseif (m = match(r"^<string>(.*?)</string>"s, xml)) !== nothing
        return _unescape(m.captures[1])
    elseif (m = match(r"^<base64>(.*?)</base64>"s, xml)) !== nothing
        return base64decode(strip(m.captures[1]))
    elseif startswith(xml, "<array>")
        return parse_array(xml)
    elseif startswith(xml, "<struct>")
        return parse_struct(xml)
    elseif startswith(xml, "<value>")
        return parse_value(extract_balanced(xml, "value"))
    else
        return _unescape(xml)
    end
end

function parse_array(xml::AbstractString)
    data = extract_balanced(xml, "array")
    data = extract_balanced(data, "data")
    return [parse_value(chunk) for chunk in each_balanced(data, "value")]
end

function parse_struct(xml::AbstractString)
    result = Dict{String,Any}()
    body = extract_balanced(xml, "struct")
    for member in each_balanced(body, "member")
        name = _unescape(extract_balanced(member, "name"))
        result[name] = parse_value(extract_balanced(member, "value"))
    end
    return result
end

function _tag_bounds(xml::AbstractString, tag::AbstractString, from::Int = 1)
    open_tag = "<" * tag
    close_tag = "</" * tag * ">"
    start = findnext(open_tag, xml, from)
    start === nothing && return nothing
    gt = findnext('>', xml, first(start))
    gt === nothing && error("unterminated <$(tag)>")
    depth = 1
    i = nextind(xml, gt)
    while i <= lastindex(xml)
        rest = @view xml[i:end]
        if startswith(rest, close_tag)
            depth -= 1
            if depth == 0
                inner = xml[nextind(xml, gt):prevind(xml, i)]
                after = i + ncodeunits(close_tag)
                return (inner, after)
            end
            i += ncodeunits(close_tag)
        elseif startswith(rest, open_tag)
            depth += 1
            gt2 = findnext('>', xml, i)
            i = nextind(xml, something(gt2, i))
        else
            i = nextind(xml, i)
        end
    end
    error("unbalanced <$(tag)>")
end

function extract_balanced(xml::AbstractString, tag::AbstractString)
    found = _tag_bounds(xml, tag)
    found === nothing && error("missing <$(tag)> in XML-RPC payload")
    return found[1]
end

function each_balanced(xml::AbstractString, tag::AbstractString)
    chunks = String[]
    i = 1
    while true
        found = _tag_bounds(xml, tag, i)
        found === nothing && return chunks
        inner, after = found
        push!(chunks, inner)
        i = after > lastindex(xml) ? lastindex(xml) + 1 : after
        i > lastindex(xml) && return chunks
    end
end

_unescape(s::AbstractString) = replace(
    s,
    "&lt;" => "<",
    "&gt;" => ">",
    "&quot;" => "\"",
    "&apos;" => "'",
    "&amp;" => "&",
)

end # module
