
file_name = "/home/fippo/koding/psykoosi/tests/msg.exe"

p = psykoosi.Psykoosi()
p:SetDebug(true)
p:Load(file_name, ".")

entry_point = p:GetEntryPoint()
inj_inst = psykoosi.Inj_NOP(100)
base_inst = p:GetInstruction(entry_point)
base_inst:Inject(inj_inst)
p:Save(file_name)
