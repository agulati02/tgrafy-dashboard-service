from fastapi import APIRouter


installation_router = APIRouter(
    prefix="/installation",
    tags=["Installation Management"]
)

@installation_router.post("/")
async def register_new_installation():
    pass
