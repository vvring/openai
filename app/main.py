"""FastAPI application implementing a bastion management controller."""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.orm import Session

from . import crud, models, schemas
from .database import Base, SessionLocal, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Bastion Management Service", version="0.1.0")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/users", response_model=schemas.UserRead, status_code=status.HTTP_201_CREATED)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    db_user = crud.create_user(
        db,
        username=user.username,
        full_name=user.full_name,
        email=user.email,
        roles=user.roles,
    )
    db.refresh(db_user)
    return db_user


@app.get("/users", response_model=list[schemas.UserRead])
def get_users(db: Session = Depends(get_db)):
    return crud.list_users(db)


@app.post("/hosts", response_model=schemas.HostRead, status_code=status.HTTP_201_CREATED)
def create_host(host: schemas.HostCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Host).filter(models.Host.name == host.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Host name already exists")
    db_host = crud.create_host(
        db,
        name=host.name,
        hostname=host.hostname,
        port=host.port,
        operating_system=host.operating_system,
        protocols=host.protocols,
        tls_enabled=host.tls_enabled,
        rdp_nla=host.rdp_nla,
    )
    db.refresh(db_host)
    return db_host


@app.get("/hosts", response_model=list[schemas.HostRead])
def get_hosts(db: Session = Depends(get_db)):
    return crud.list_hosts(db)


@app.post("/authorizations", status_code=status.HTTP_204_NO_CONTENT)
def assign_authorization(payload: schemas.AuthorizationRequest, db: Session = Depends(get_db)):
    try:
        crud.authorize_user(db, payload.user_id, payload.host_id, payload.privileges)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return None


@app.post("/sessions", response_model=schemas.SessionRead, status_code=status.HTTP_201_CREATED)
def start_session(payload: schemas.SessionStartRequest, db: Session = Depends(get_db)):
    record = crud.start_session(
        db,
        user_id=payload.user_id,
        host_id=payload.host_id,
        protocol=payload.protocol,
    )
    db.refresh(record)
    return record


@app.post("/sessions/{record_id}/end", response_model=schemas.SessionRead)
def end_session(record_id: int, payload: schemas.SessionEndRequest, db: Session = Depends(get_db)):
    try:
        record = crud.end_session(
            db,
            record_id,
            recording_path=payload.recording_path,
            metadata=payload.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    db.refresh(record)
    return record


@app.get("/sessions", response_model=list[schemas.SessionRead])
def list_sessions(db: Session = Depends(get_db)):
    return crud.list_sessions(db)
