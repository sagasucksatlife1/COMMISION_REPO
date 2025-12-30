from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import io
import csv
from database import Database

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
db = Database()

class LoginRequest(BaseModel):
    username: str
    password: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str
    full_name: str

class CommissionRequest(BaseModel):
    sale_date: str
    unlisted_sales: float
    loans: float
    third_party_sales: float

class UpdateCommissionRequest(BaseModel):
    commission_id: int
    sale_date: str
    unlisted_sales: float
    loans: float
    third_party_sales: float

class UpdateStatusRequest(BaseModel):
    commission_id: int
    status: str

def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = db.verify_session(authorization.replace("Bearer ", ""))
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

@app.post("/api/auth/login")
def login(request: LoginRequest):
    user = db.verify_user(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = db.create_session(user["id"])
    return {"token": token, "user": user}

@app.post("/api/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization:
        db.delete_session(authorization.replace("Bearer ", ""))
    return {"message": "Logged out"}

@app.get("/api/auth/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

@app.post("/api/users/create")
def create_user(request: CreateUserRequest, _: dict = Depends(require_admin)):
    user_id = db.create_user(request.username, request.password, request.role, request.full_name)
    if not user_id:
        raise HTTPException(status_code=400, detail="Username exists")
    return {"message": "User created", "user_id": user_id}

@app.get("/api/users/employees")
def get_employees(_: dict = Depends(require_admin)):
    return {"employees": db.get_all_employees()}

@app.post("/api/commissions/create")
def create_commission(request: CommissionRequest, current_user: dict = Depends(get_current_user)):
    commission_id = db.create_commission(current_user["user_id"], request.sale_date, request.unlisted_sales, request.loans, request.third_party_sales)
    return {"message": "Created", "commission_id": commission_id}

@app.put("/api/commissions/update")
def update_commission(request: UpdateCommissionRequest, current_user: dict = Depends(get_current_user)):
    if not db.update_commission(request.commission_id, current_user["user_id"], request.sale_date, request.unlisted_sales, request.loans, request.third_party_sales):
        raise HTTPException(status_code=404, detail="Not found")
    return {"message": "Updated"}

@app.delete("/api/commissions/{commission_id}")
def delete_commission(commission_id: int, current_user: dict = Depends(get_current_user)):
    if not db.delete_commission(commission_id, current_user["user_id"]):
        raise HTTPException(status_code=404, detail="Not found")
    return {"message": "Deleted"}

@app.get("/api/commissions/my")
def get_my_commissions(months: int = 1, current_user: dict = Depends(get_current_user)):
    return {"commissions": db.get_user_commissions(current_user["user_id"], months)}

@app.get("/api/commissions/all")
def get_all_commissions(months: int = 1, employee_id: Optional[int] = None, _: dict = Depends(require_admin)):
    return {"commissions": db.get_all_commissions(months, employee_id)}

@app.put("/api/commissions/status")
def update_status(request: UpdateStatusRequest, _: dict = Depends(require_admin)):
    if not db.update_commission_status(request.commission_id, request.status):
        raise HTTPException(status_code=404, detail="Not found")
    return {"message": "Updated"}

@app.get("/api/commissions/export")
def export_commissions(months: int = 1, employee_id: Optional[int] = None, _: dict = Depends(require_admin)):
    commissions = db.get_all_commissions(months, employee_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Employee", "Date", "Unlisted", "Loans", "Third-Party", "Commission", "Status"])
    for c in commissions:
        writer.writerow([c["employee_name"], c["sale_date"], c["unlisted_sales"], c["loans"], c["third_party_sales"], c["calculated_commission"], c["status"]])
    output.seek(0)
    return StreamingResponse(io.BytesIO(output.getvalue().encode()), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=commissions_{datetime.now().strftime('%Y%m%d')}.csv"})

@app.get("/")
def root():
    return {"message": "Commission System API", "status": "running"}
