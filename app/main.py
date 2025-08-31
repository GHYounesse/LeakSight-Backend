
import asyncio
from fastapi.middleware.cors import CORSMiddleware
from app.api.dashboard import cache_refresh_scheduler
from app.crud.user_crud import UserCRUD
from datetime import datetime
from contextlib import asynccontextmanager
from app.api import auth_router,  ioc_router,subs_router,enrichment_router, feeds_router,dashboard_router,ws_router
from app.database import connect_to_mongo, close_mongo_connection
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, status
from app.services.websocket_service import websocket_manager
from app.crud.user_crud import UserCRUD
import json
from app.config import settings
from jose import  jwt
from fastapi.responses import HTMLResponse
from app.models.auth.user import UserCreate
from app.dependencies import logger
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel



@asynccontextmanager
async def lifespan(app: FastAPI):
    
    print("🔄 Trying to connect to MongoDB...")
    await connect_to_mongo()
    
    user_crud = UserCRUD()
    if not await user_crud.is_admin_created():
        admin_user = await user_crud.create_user(UserCreate(
            email=settings.ADMIN_EMAIL,
            username=settings.ADMIN_USERNAME,
            password=settings.ADMIN_PASSWORD,
            role="admin"
        ))
    print("✅ Admin user created")
    
    try:
        #asyncio.create_task(cache_refresh_scheduler())
        yield
    finally:
        await close_mongo_connection()


app = FastAPI(
    title="Threat Intelligence Monitoring API",
    description="Threat Intelligence Monitoring API",
    version="1.0.0",lifespan=lifespan
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:4200", "http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],
)




app.mount("/static", StaticFiles(directory=f"{settings.STATIC_FILES_DIR}\\LeakSight-Backend\\static"), name="static")






#Routers
# Register the routers
app.include_router(auth_router)

app.include_router(ioc_router)

app.include_router(subs_router)

app.include_router(enrichment_router)

app.include_router(feeds_router)

app.include_router(dashboard_router)

app.include_router(ws_router)






@app.get("/", response_class=HTMLResponse)
async def api_health():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>LeakSight API - System Status</title>
        <link rel="icon" type="image/png" href="/static/images/icon.png">
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');
            
            :root {
                --primary-color: #1a1a2e;
                --secondary-color: #16213e;
                --accent-color: #0f3460;
                --danger-color: #e94560;
                --warning-color: #f39c12;
                --success-color: #27ae60;
                --info-color: #7de6e7;
                --text-light: #f8f9fa;
                --text-primary: #ffffff;
                --text-secondary: #b0b0b0;
                --text-muted: #6c757d;
                --critical-color: #dc2626;
                --high-color: #ea580c;
                --medium-color: #ca8a04;
                --low-color: #16a34a;
                --shadow: 0 4px 20px rgba(0, 212, 255, 0.1);
                --shadow-hover: 0 8px 30px rgba(0, 212, 255, 0.2);
                --background-dark: #0f0f23;
                --background-light: #1a1a2e;
                --border-color: #333366;
                --success-color-alt: #00ff88;
                --warning-color-alt: #ffaa00;
                --danger-color-alt: #ff4444;
                
                /* Derived colors for consistency */
                --primary-bg: var(--background-dark);
                --secondary-bg: var(--primary-color);
                --card-bg: rgba(26, 26, 46, 0.95);
                --accent-cyan: var(--info-color);
                --accent-green: var(--success-color-alt);
                --border-glow: var(--info-color);
                --shadow-cyan: 0 0 20px rgba(125, 230, 231, 0.3);
                --shadow-green: 0 0 15px rgba(0, 255, 136, 0.4);
            }

            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                background: linear-gradient(135deg, var(--background-dark) 0%, var(--primary-color) 50%, var(--secondary-color) 100%);
                font-family: 'Orbitron', monospace;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                overflow-x: hidden;
                position: relative;
            }

            /* Animated background grid */
            body::before {
                content: '';
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-image: 
                    linear-gradient(rgba(125, 230, 231, 0.1) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(125, 230, 231, 0.1) 1px, transparent 1px);
                background-size: 50px 50px;
                animation: gridMove 20s linear infinite;
                z-index: -1;
            }

            @keyframes gridMove {
                0% { transform: translate(0, 0); }
                100% { transform: translate(50px, 50px); }
            }

            /* Floating particles */
            .particle {
                position: absolute;
                width: 2px;
                height: 2px;
                background: var(--accent-cyan);
                border-radius: 50%;
                animation: float 6s ease-in-out infinite;
            }

            .particle:nth-child(1) { top: 20%; left: 20%; animation-delay: 0s; }
            .particle:nth-child(2) { top: 80%; left: 80%; animation-delay: 2s; }
            .particle:nth-child(3) { top: 40%; left: 70%; animation-delay: 4s; }

            @keyframes float {
                0%, 100% { transform: translateY(0px) rotate(0deg); opacity: 0.5; }
                50% { transform: translateY(-20px) rotate(180deg); opacity: 1; }
            }

            .container {
                position: relative;
                z-index: 10;
                max-width: 500px;
                width: 90%;
            }

            .status-card {
                background: var(--card-bg);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(0, 245, 255, 0.3);
                border-radius: 20px;
                padding: 3rem 2rem;
                text-align: center;
                position: relative;
                overflow: hidden;
                box-shadow: var(--shadow-cyan);
                transition: all 0.3s ease;
            }

            .status-card::before {
                content: '';
                position: absolute;
                top: -2px;
                left: -2px;
                right: -2px;
                bottom: -2px;
                background: linear-gradient(45deg, var(--accent-cyan), var(--success-color), var(--accent-cyan));
                border-radius: 20px;
                z-index: -1;
                animation: borderGlow 3s ease-in-out infinite alternate;
            }

            @keyframes borderGlow {
                0% { opacity: 0.5; }
                100% { opacity: 1; }
            }

            .status-card:hover {
                transform: translateY(-5px);
                box-shadow: var(--shadow-cyan), var(--shadow-green);
            }

            .logo-container {
                position: relative;
                margin-bottom: 2rem;
            }

            
            .logo {
                width: 120px;
                height: 120px;
                margin: 0 auto 1rem;
                background: linear-gradient(45deg, var(--background-light), var(--secondary-color));
                border: 2px solid var(--accent-cyan);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 2rem;
                color: var(--primary-bg);
                font-weight: 900;
                box-shadow: var(--shadow-cyan);
                animation: pulse 2s ease-in-out infinite;
            }

            
            .logo img {
                width: 115px;
                height: 115px;
                object-fit: contain;
            }
            

            @keyframes pulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.05); }
            }

            .title {
                font-size: 2rem;
                font-weight: 700;
                margin-bottom: 0.5rem;
                background: linear-gradient(45deg, var(--accent-cyan), var(--success-color));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }

            .subtitle {
                color: var(--text-secondary);
                font-size: 1rem;
                margin-bottom: 2rem;
                font-weight: 400;
            }

            .status-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 1rem;
                margin-bottom: 2rem;
            }

            .status-item {
                background: rgba(15, 52, 96, 0.3);
                border: 1px solid rgba(39, 174, 96, 0.3);
                border-radius: 10px;
                padding: 1rem;
                transition: all 0.3s ease;
            }

            .status-item:hover {
                border-color: var(--success-color);
                box-shadow: 0 0 10px rgba(39, 174, 96, 0.2);
            }

            .status-label {
                font-size: 0.8rem;
                color: var(--text-muted);
                margin-bottom: 0.5rem;
                text-transform: uppercase;
                letter-spacing: 1px;
            }

            .status-value {
                font-size: 1.1rem;
                font-weight: 700;
                color: var(--success-color-alt);
            }

            .main-status {
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 0.5rem;
                font-size: 1.2rem;
                font-weight: 700;
            }

            .status-indicator {
                width: 12px;
                height: 12px;
                border-radius: 50%;
                background: var(--success-color-alt);
                box-shadow: 0 0 10px var(--success-color-alt);
                animation: blink 2s ease-in-out infinite;
            }

            @keyframes blink {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }

            .scan-line {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 2px;
                background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
                animation: scan 3s linear infinite;
            }

            @keyframes scan {
                0% { transform: translateX(-100%); }
                100% { transform: translateX(100%); }
            }

            .timestamp {
                font-size: 0.8rem;
                color: var(--text-muted);
                margin-top: 1rem;
                font-family: 'Courier New', monospace;
            }

            @media (max-width: 768px) {
                .status-card {
                    padding: 2rem 1.5rem;
                }
                
                .title {
                    font-size: 1.5rem;
                }
                
                .status-grid {
                    grid-template-columns: 1fr;
                    gap: 0.8rem;
                }
            }
        </style>
    </head>
    <body>
        <div class="particle"></div>
        <div class="particle"></div>
        <div class="particle"></div>

        <div class="container">
            <div class="status-card">
                <div class="scan-line"></div>
                
                <div class="logo-container">
                    <div class="logo">
                        <!-- If using custom logo image, uncomment below and comment above emoji -->
                        <img src="/static/images/logo.png" alt="LeakSight Logo">
                    </div>
                </div>

                <h1 class="title">LeakSight API</h1>
                <p class="subtitle">Threat Intelligence Monitoring System Online</p>

                

                <div class="main-status">
                    <span class="status-indicator"></span>
                    <span style="color: var(--success-color-alt);">ALL SYSTEMS SECURE</span>
                </div>

                <div class="timestamp">
                    Last Updated: <span id="timestamp"></span>
                </div>
            </div>
        </div>

        <script>
            // Update timestamp
            function updateTimestamp() {
                const now = new Date();
                const timestamp = now.toLocaleString('en-US', {
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                    hour12: false
                });
                document.getElementById('timestamp').textContent = timestamp;
            }

            updateTimestamp();
            setInterval(updateTimestamp, 1000);
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)




