"""操作紀錄(GET/DELETE /logs)。"""
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends

from auth import require_roles
from db import supabase

router = APIRouter()


@router.get("/logs")
def get_logs(
    limit: int = 200,
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    res = supabase.table("shift_logs").select("*").order("created_at", desc=True).limit(limit).execute()
    return {"logs": res.data}


@router.delete("/logs")
def delete_logs(
    before_hours: Optional[int] = None,
    current_user: dict = Depends(require_roles("admin", "superadmin", "dual")),
):
    if before_hours is None:
        supabase.table("shift_logs").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        return {"message": "已清除所有操作紀錄"}
    cutoff = (datetime.utcnow() - timedelta(hours=before_hours)).isoformat()
    supabase.table("shift_logs").delete().lt("created_at", cutoff).execute()
    return {"message": f"已清除 {before_hours} 小時前的操作紀錄"}
