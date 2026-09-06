"""遊戲存檔、內容、留言板 endpoints。"""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import get_current_user, require_roles
from db import supabase

router = APIRouter()


class GameSaveUpdate(BaseModel):
    data: dict


class GameContentUpdate(BaseModel):
    data: dict


class GameMessageCreate(BaseModel):
    text: str


# ── 遊戲存檔:綁 uid,不信任前端身分
@router.get("/game/save")
def get_game_save(current_user: dict = Depends(get_current_user)):
    uid = current_user["sub"]
    res = supabase.table("game_saves").select("data").eq("uid", uid).limit(1).execute()
    if res.data:
        return {"data": res.data[0].get("data")}
    return {"data": None}


@router.put("/game/save")
def put_game_save(
    body: GameSaveUpdate,
    current_user: dict = Depends(get_current_user),
):
    uid = current_user["sub"]
    supabase.table("game_saves").upsert({
        "uid": uid,
        "data": body.data,
        "updated_at": datetime.utcnow().isoformat(),
    }).execute()
    return {"message": "已儲存"}


@router.delete("/game/save")
def delete_game_save(current_user: dict = Depends(get_current_user)):
    uid = current_user["sub"]
    supabase.table("game_saves").delete().eq("uid", uid).execute()
    return {"message": "已清除"}


# ── 遊戲內容(對話、道具文字):後台編輯,全遊戲共用
@router.get("/game/content")
def get_game_content():
    """公開:遊戲載入時抓最新內容。"""
    res = supabase.table("game_content").select("data").eq("id", 1).limit(1).execute()
    if res.data:
        return {"data": res.data[0].get("data") or {}}
    return {"data": {}}


@router.post("/game/content")
def save_game_content(
    body: GameContentUpdate,
    current_user: dict = Depends(require_roles("superadmin")),
):
    supabase.table("game_content").upsert({
        "id": 1,
        "data": body.data,
        "updated_at": datetime.utcnow().isoformat(),
    }).execute()
    return {"message": "已儲存"}


# ── 遊戲留言板
@router.post("/game/messages", status_code=201)
def post_game_message(
    body: GameMessageCreate,
    current_user: dict = Depends(get_current_user),
):
    text = (body.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="留言不能空白")
    supabase.table("game_messages").insert({
        "uid": current_user["sub"],
        "name": current_user.get("name"),
        "text": text[:500],
    }).execute()
    return {"message": "已送出"}


@router.get("/game/messages")
def get_game_messages(current_user: dict = Depends(get_current_user)):
    q = supabase.table("game_messages").select("id, uid, name, text, created_at")
    if current_user.get("role") != "superadmin":
        q = q.eq("uid", current_user["sub"])
    res = q.order("created_at", desc=True).limit(300).execute()
    return {"messages": res.data or []}


@router.delete("/game/messages/{msg_id}")
def delete_game_message(
    msg_id: int,
    current_user: dict = Depends(require_roles("superadmin")),
):
    supabase.table("game_messages").delete().eq("id", msg_id).execute()
    return {"message": "已刪除"}
