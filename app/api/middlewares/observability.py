import time
import logging
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("certior.slo_metrics")

class SLOMetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Log latency against SLO targets dynamically based on route
        # /decision targets <500ms
        # /promote targets <800ms
        path = request.url.path
        if "/decision" in path:
            if process_time > 0.5:
                # SLO Breach
                logger.warning(f"SLO Breach on /decision: {process_time:.2f}s (>500ms threshold)")
        elif "/promote" in path:
            if process_time > 0.8:
                # SLO Breach
                logger.warning(f"SLO Breach on /promote: {process_time:.2f}s (>800ms threshold)")
        
        return response
