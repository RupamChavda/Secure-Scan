# pyrefly: ignore [missing-import]
import jwt  # type: ignore
import hashlib
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, status  # type: ignore
from fastapi.security import OAuth2PasswordBearer  # type: ignore
from backend.config import settings
from backend.models import UserLogin, UserCreate, UserSignup, UserResponse, TokenResponse, RoleEnum
from backend.storage import get_persisted_users, save_persisted_users

router = APIRouter(prefix="/auth", tags=["Authentication"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# Default seeded accounts: one Admin account and one standard User account.
DEFAULT_USERS_DB = {
    "admin": {
        "id": "usr-001",
        "username": "admin",
        "email": "admin@securescan.ai",
        "password_hash": hash_password("admin123"),
        "role": RoleEnum.ADMIN,
        "full_name": "Chief Security Officer",
        "created_at": "2026-01-01T00:00:00Z"
    },
    "user": {
        "id": "usr-002",
        "username": "user",
        "email": "user@securescan.ai",
        "password_hash": hash_password("user123"),
        "role": RoleEnum.ANALYST,
        "full_name": "Security Analyst",
        "created_at": "2026-01-15T00:00:00Z"
    },
    "alex": {
        "id": "usr-003",
        "username": "alex",
        "email": "alex@company.com",
        "password_hash": hash_password("alex123"),
        "role": RoleEnum.ANALYST,
        "full_name": "Alex Mercer (User 1)",
        "created_at": "2026-02-01T00:00:00Z"
    },
    "john": {
        "id": "usr-004",
        "username": "john",
        "email": "john@company.com",
        "password_hash": hash_password("john123"),
        "role": RoleEnum.ANALYST,
        "full_name": "John Doe (User 2)",
        "created_at": "2026-02-01T00:00:00Z"
    }
}

# Persisted (survives restarts). Falls back to DEFAULT_USERS_DB on first run.
USERS_DB = get_persisted_users(DEFAULT_USERS_DB)
# Make sure both default accounts always exist even if the persisted file predates them.
for _uname, _udata in DEFAULT_USERS_DB.items():
    USERS_DB.setdefault(_uname, _udata)
save_persisted_users(USERS_DB)


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Validates the bearer JWT and returns the authenticated user record.
    Every protected route in the platform depends on this."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Please log in to continue.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        users_db = get_persisted_users(DEFAULT_USERS_DB)
        if username is None or username not in users_db:
            raise HTTPException(status_code=401, detail="Invalid token credentials")
        return users_db[username]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    except Exception:
        raise HTTPException(status_code=401, detail="Could not validate authentication token")


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Restricts an endpoint to Admin-role accounts only."""
    if current_user.get("role") != RoleEnum.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires Administrator privileges."
        )
    return current_user


@router.post("/login", response_model=TokenResponse)
def login(form_data: UserLogin):
    users_db = get_persisted_users(DEFAULT_USERS_DB)
    user = users_db.get(form_data.username.strip().lower())
    if not user or user["password_hash"] != hash_password(form_data.password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": user["username"], "role": user["role"]})
    user_res = UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        role=user["role"],
        full_name=user["full_name"],
        created_at=user["created_at"]
    )
    return TokenResponse(access_token=access_token, user=user_res)


@router.post("/signup", response_model=TokenResponse)
def signup(user_in: UserSignup):
    """Allows new users to create a profile and sign up directly."""
    users_db = get_persisted_users(DEFAULT_USERS_DB)
    uname = user_in.username.strip().lower()
    if uname in users_db:
        raise HTTPException(status_code=400, detail="Username is already registered")

    new_user = {
        "id": f"usr-{uuid_suffix()}",
        "username": uname,
        "email": user_in.email,
        "password_hash": hash_password(user_in.password),
        "role": RoleEnum.ANALYST,
        "full_name": user_in.full_name,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    users_db[uname] = new_user
    save_persisted_users(users_db)

    access_token = create_access_token(data={"sub": new_user["username"], "role": new_user["role"]})
    user_res = UserResponse(
        id=new_user["id"],
        username=new_user["username"],
        email=new_user["email"],
        role=new_user["role"],
        full_name=new_user["full_name"],
        created_at=new_user["created_at"]
    )
    return TokenResponse(access_token=access_token, user=user_res)


@router.post("/register", response_model=UserResponse)
def register(user_in: UserCreate, current_user: dict = Depends(require_admin)):
    """Only Admins can create new accounts, keeping the user roster controlled."""
    uname = user_in.username.strip().lower()
    if uname in USERS_DB:
        raise HTTPException(status_code=400, detail="Username already registered")

    new_user = {
        "id": f"usr-{uuid_suffix()}",
        "username": uname,
        "email": user_in.email,
        "password_hash": hash_password(user_in.password),
        "role": user_in.role,
        "full_name": user_in.full_name,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    USERS_DB[uname] = new_user
    save_persisted_users(USERS_DB)
    return UserResponse(**new_user)


def uuid_suffix():
    import uuid
    return uuid.uuid4().hex[:6]


@router.get("/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(**current_user)
