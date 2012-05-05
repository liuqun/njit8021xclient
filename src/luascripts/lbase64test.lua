-- test base64 library

require"base64"

print(base64.version)
print""

local text="Lua-scripting-language"
for i=1,string.len(text) do
 local orig=string.sub(text,1,i)
 local a=base64.encode(orig)
 local b=base64.decode(a)
 print(a,b,string.len(b))
 assert(b==orig)
end

print""
print(base64.version)

-- eof
