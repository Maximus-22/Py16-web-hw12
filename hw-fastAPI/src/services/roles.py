from fastapi import Request, Depends, HTTPException, status

from src.entity.models import Role, User
from src.services.auth import auth_service


# цей клас дрейфує у routes/xxx.py до вiдповiдних декораторiв
# наприклад: src/routes/birthday_contacts.py -> створення змiнної <access_elevated> з перелiком дозволених параметрiв
# класу Role - це функтор!
# Цей функтор буде пропускати тiльки тi запити, ролi в користувачiв яких спiвпадають; то ж вiн потрапляє до декораторiв
# тих функцiй у яких потрiбно використати ролi.
# Через кому можна скормити якусь iншу залежнiсть:
# dependencies=[Depends(access_elevated), Depends(<new_dependence>), ...]
class RoleAccess:
    def __init__(self, allowed_roles: list[Role]):
        self.allowed_roles = allowed_roles

    async def __call__(self, request: Request, user: User = Depends(auth_service.get_current_user)):
        # print(user.role, self.allowed_roles)
        if user.role not in self.allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="In your eyes (In your eyes), Forbidden love...")
