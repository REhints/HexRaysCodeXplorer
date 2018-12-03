from codeexplorer import *

animal = ReconstructableType.getReconstructableType("Animal")
animal_vtable = ReconstructableTypeVtable.getReconstructableTypeVtable("Animal::vtable", ida_idaapi.BADADDR)
member_vtbl = ReconstructableMember()
member_vtbl.offset = 0
member_vtbl.name = "vtable"
member_type = MemberTypePointer(animal_vtable.name)
member_vtbl.memberType = member_type
animal.AddMember(member_vtbl)



re_types_form_init()
