from fastapi import FastAPI, Request, Form, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
import asyncio
import csv
import io
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import os
import sys
from urllib.parse import urlparse
import base64
import uuid
import time


# Import your existing hash lookup tool
from hash_lookup import HashLookupTool, _is_valid_hash, build_log_text, hash_algo_label, strip_hash_label
from url_lookup import (
    URLLookupTool, SSLLabsAPI, _is_valid_url,
    cross_check_url_and_hash, close_all as close_url_apis,
)
import config_store
from dotenv import load_dotenv


class InMemoryStorage:
    """In-memory storage for history, bookmarks, and sessions."""
    
    def __init__(self):
        self.search_history = []
        self.bookmarks = []
        self.bulk_sessions = {}
        self.api_health_cache = {}
        self.max_history = 100

        self.terminal_log = []
        self._terminal_seq = 0
        self.max_terminal_log = 500

        self.sandbox_sessions = {}
    
    def add_search_history(self, search_type: str, search_value: str, results_summary: str = None, threat_score: int = 0):
        """Add search to history."""
        entry = {
            'type': search_type,
            'value': search_value,
            'timestamp': datetime.now().isoformat(),
            'summary': results_summary or 'No summary',
            'threat_score': threat_score
        }
        
        self.search_history.insert(0, entry)
        
        # Keep only last max_history entries
        if len(self.search_history) > self.max_history:
            self.search_history = self.search_history[:self.max_history]
    
    def get_search_history(self, limit: int = 20) -> List[Dict]:
        """Get recent search history."""
        return self.search_history[:limit]
    
    def add_bookmark(self, search_type: str, search_value: str, title: str = None, notes: str = "") -> bool:
        """Add bookmark."""
        # Check if already bookmarked
        for bookmark in self.bookmarks:
            if bookmark['value'] == search_value:
                return False
        
        bookmark = {
            'type': search_type,
            'value': search_value,
            'title': title or search_value[:32],
            'notes': notes,
            'threat_score': 0,
            'created_at': datetime.now().isoformat()
        }
        
        self.bookmarks.insert(0, bookmark)
        return True
    
    def get_bookmarks(self) -> List[Dict]:
        """Get all bookmarks."""
        return self.bookmarks
    
    def remove_bookmark(self, search_value: str) -> bool:
        """Remove bookmark."""
        for i, bookmark in enumerate(self.bookmarks):
            if bookmark['value'] == search_value:
                del self.bookmarks[i]
                return True
        return False

    def add_terminal_entry(self, api_name: str, service_label: str, text: str) -> None:
        """Append a filtered, plain-text scan log entry (used by the Terminal tab)."""
        self._terminal_seq += 1
        self.terminal_log.append({
            'id': self._terminal_seq,
            'api': api_name,
            'service': service_label,
            'text': text,
            'timestamp': datetime.now().isoformat()
        })

        if len(self.terminal_log) > self.max_terminal_log:
            self.terminal_log = self.terminal_log[-self.max_terminal_log:]

    def get_terminal_entries_since(self, cursor: int) -> List[Dict]:
        """Return log entries with id > cursor."""
        return [entry for entry in self.terminal_log if entry['id'] > cursor]

    def clear_terminal_log(self) -> None:
        """Clear the terminal log buffer."""
        self.terminal_log = []

class ThreatAnalyzer:
    """Enhanced threat analysis and scoring."""

    # Weight scores based on API reliability. Shared by both hash results
    # (virustotal/metadefender/otx/etc. keys) and URL results (same keys,
    # since it's the same underlying provider, plus the URL-only providers
    # below) - a results dict only ever contains one kind, so there's no
    # collision in practice.
    API_WEIGHTS = {
        'virustotal': 30,
        'crowdstrike': 25,
        'triage_sandbox': 20,
        'hybrid_analysis': 15,
        'openphish': 15,
        'urlscan': 15,
        'malwarebazaar': 10,
        'threatfox': 10,
        'checkphish': 12,
        'urlhaus': 12,
        'ipqualityscore': 10,
        'metadefender': 8,
        'otx': 5,
    }

    # Informational panels, not detection engines - they never carry a
    # 'malicious' verdict and shouldn't dilute the confidence/consensus math.
    NON_SCORING_KEYS = {
        'certificate', 'cert_transparency', 'cross_check', 'domain_age', 'redirect_chain', 'typosquat',
        'idn_check', 'url_heuristics', 'favicon', 'download_content', 'hosting_reputation',
    }

    @staticmethod
    def calculate_threat_score(results: Dict[str, Any]) -> int:
        """Calculate overall threat score (0-100)."""
        scores = []
        total_apis = 0
        malicious_count = 0

        for api_name, result in results.items():
            if api_name in ThreatAnalyzer.NON_SCORING_KEYS:
                continue
            if isinstance(result, dict) and not result.get('error') and not result.get('not_found'):
                total_apis += 1
                if result.get('malicious', False):
                    malicious_count += 1
                    scores.append(ThreatAnalyzer.API_WEIGHTS.get(api_name, 10))

        if total_apis == 0:
            return 0

        # Calculate confidence based on consensus
        confidence = malicious_count / total_apis
        base_score = sum(scores)

        # Apply confidence multiplier
        final_score = min(100, int(base_score * confidence * 1.2))

        return final_score

    @staticmethod
    def generate_summary(results: Dict[str, Any]) -> str:
        """Generate human-readable threat summary."""
        threat_score = ThreatAnalyzer.calculate_threat_score(results)

        malicious_apis = []
        clean_apis = []
        error_apis = []

        for api_name, result in results.items():
            if api_name in ThreatAnalyzer.NON_SCORING_KEYS:
                continue
            if isinstance(result, dict):
                if result.get('error'):
                    error_apis.append(api_name)
                elif result.get('not_found'):
                    continue
                elif result.get('malicious', False):
                    malicious_apis.append(api_name)
                else:
                    clean_apis.append(api_name)

        total_checked = len(malicious_apis) + len(clean_apis)
        
        if threat_score >= 80:
            level = "🚨 HIGH THREAT"
        elif threat_score >= 50:
            level = "⚠️ MODERATE THREAT"
        elif threat_score >= 20:
            level = "🔍 LOW THREAT"
        else:
            level = "✅ CLEAN"
        
        summary = f"{level} (Score: {threat_score}/100) - {len(malicious_apis)}/{total_checked} APIs detected threats"

        return summary


class CompositeVerdict:
    """URL-only: merges category signals (from whichever providers reported
    one), the risk/threat score, certificate legitimacy, domain age,
    redirect-chain behavior, and a typosquat/brand-lookalike check into a
    single Whitelist / Caution / Block recommendation. The category part is
    the practical substitute for an authoritative Palo Alto/Symantec
    category verdict - see the URL-scanning plan for why those aren't
    queryable via a public API and are deliberately not integrated here."""

    CATEGORY_SOURCES = ('virustotal', 'metadefender', 'ipqualityscore')

    @staticmethod
    def build(results: Dict[str, Any], threat_score: int) -> Dict[str, Any]:
        category_votes: Dict[str, int] = {}
        for api_name in CompositeVerdict.CATEGORY_SOURCES:
            category = (results.get(api_name) or {}).get('category')
            if category:
                category_votes[category] = category_votes.get(category, 0) + 1

        if category_votes:
            category = max(category_votes, key=category_votes.get)
            agreeing_sources = category_votes[category]
            category_confidence = 'high' if agreeing_sources > 1 or len(category_votes) == 1 else 'low'
        else:
            category = 'Uncategorized - manual review'
            category_confidence = 'none'

        cert = results.get('certificate') or {}
        if cert.get('error'):
            cert_status = 'unknown'
        elif not cert.get('trusted', True) or cert.get('expired'):
            cert_status = 'fail'
        elif cert.get('warning'):
            cert_status = 'warn'
        else:
            cert_status = 'pass'

        # A close-but-not-exact match to a known brand domain is one of the
        # strongest phishing signals available before any reputation engine
        # has had a chance to see and report the domain - weighted like a
        # failed certificate check, not a soft warning.
        typosquat = results.get('typosquat') or {}
        is_typosquat = bool(typosquat.get('warning')) and not typosquat.get('is_known_brand')

        # An identical favicon on a domain that ISN'T the real brand is
        # harder evidence than the name similarity alone - a cloned
        # phishing kit, not just a coincidentally similar registration.
        favicon = results.get('favicon') or {}
        favicon_confirms_clone = bool(favicon.get('matches_brand'))

        # Same weight class as typosquat - a homoglyph/IDN domain is the
        # same attack, just executed with lookalike characters instead of
        # a near-miss spelling.
        idn_check = results.get('idn_check') or {}
        is_homoglyph = bool(idn_check.get('warning'))

        # Hosting on infrastructure with a substantial abuse history is
        # independent of anything about the domain name itself.
        hosting_reputation = results.get('hosting_reputation') or {}
        is_abusive_hosting = bool(hosting_reputation.get('warning'))

        # Softer signals - each nudges toward Caution on its own, but don't
        # individually justify a Block the way the harder signals above do.
        domain_age = results.get('domain_age') or {}
        is_very_new_domain = bool(domain_age.get('warning'))

        redirect_chain = results.get('redirect_chain') or {}
        redirects_off_domain = bool(redirect_chain.get('warning'))

        url_heuristics = results.get('url_heuristics') or {}
        has_url_heuristic_flags = bool(url_heuristics.get('flags'))

        download_content = results.get('download_content') or {}
        download_content_mismatch = bool(download_content.get('warning'))

        hard_block_signal = is_typosquat or favicon_confirms_clone or is_homoglyph or is_abusive_hosting

        if threat_score >= 50 or cert_status == 'fail' or hard_block_signal:
            verdict = 'Block'
        elif (threat_score >= 20 or cert_status == 'warn' or category_confidence == 'none'
              or is_very_new_domain or redirects_off_domain or has_url_heuristic_flags or download_content_mismatch):
            verdict = 'Caution - Manual Review'
        else:
            verdict = 'Whitelist'

        return {
            'category': category,
            'category_confidence': category_confidence,
            'cert_status': cert_status,
            'is_typosquat': is_typosquat,
            'favicon_confirms_clone': favicon_confirms_clone,
            'is_homoglyph': is_homoglyph,
            'is_abusive_hosting': is_abusive_hosting,
            'is_very_new_domain': is_very_new_domain,
            'redirects_off_domain': redirects_off_domain,
            'has_url_heuristic_flags': has_url_heuristic_flags,
            'download_content_mismatch': download_content_mismatch,
            'verdict': verdict,
        }


class BulkProcessor:
    """Handle bulk hash/URL processing."""
    
    def __init__(self, storage: InMemoryStorage):
        self.storage = storage
    
    async def process_csv(self, file_content: str, session_id: str) -> Dict[str, Any]:
        """Process CSV file with hashes/URLs."""
        results = []
        items = []
        
        # Parse CSV content
        csv_reader = csv.DictReader(io.StringIO(file_content))
        for row in csv_reader:
            # Support multiple column names
            for col_name in ['hash', 'url', 'indicator', 'value', 'ioc']:
                if col_name in row and row[col_name].strip():
                    items.append(row[col_name].strip())
                    break
        
        if not items:
            raise ValueError("No valid hashes or URLs found in CSV")
        
        # Initialize session
        self.storage.bulk_sessions[session_id] = {
            'total': len(items),
            'processed': 0,
            'results': [],
            'status': 'processing',
            'started_at': datetime.now().isoformat()
        }
        
        lookup_tool = HashLookupTool()
        url_lookup_tool = URLLookupTool()

        try:
            # Process in batches to avoid overwhelming APIs
            batch_size = 5
            for i in range(0, len(items), batch_size):
                batch = items[i:i + batch_size]
                batch_results = []

                # Process batch concurrently
                tasks = []
                for item in batch:
                    if self._is_url(item):
                        tasks.append(self._lookup_url(url_lookup_tool, item))
                    elif _is_valid_hash(item):
                        tasks.append(lookup_tool.lookup_hash(item))
                    else:
                        # Skip invalid items
                        continue
                
                if tasks:
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for j, item in enumerate(batch):
                    if j < len(batch_results):
                        result = batch_results[j]
                        if isinstance(result, Exception):
                            result = {'error': str(result)}
                        
                        threat_score = ThreatAnalyzer.calculate_threat_score(result) if isinstance(result, dict) else 0
                        summary = ThreatAnalyzer.generate_summary(result) if isinstance(result, dict) else "Error"
                        
                        item_result = {
                            'item': item,
                            'type': 'url' if self._is_url(item) else 'hash',
                            'threat_score': threat_score,
                            'summary': summary,
                            'details': result,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        results.append(item_result)
                        self.storage.bulk_sessions[session_id]['results'].append(item_result)
                
                # Update progress
                self.storage.bulk_sessions[session_id]['processed'] = len(results)
                
                # Small delay between batches to be nice to APIs
                await asyncio.sleep(1)
        
        finally:
            # Close API sessions
            for api in lookup_tool.apis.values():
                await api.close_session()
            await close_url_apis(url_lookup_tool)

        # Mark session as completed
        self.storage.bulk_sessions[session_id]['status'] = 'completed'
        self.storage.bulk_sessions[session_id]['completed_at'] = datetime.now().isoformat()
        
        return {
            'session_id': session_id,
            'total_processed': len(results),
            'results': results,
            'summary': self._generate_bulk_summary(results)
        }
    
    def _is_url(self, item: str) -> bool:
        """Check if item is a URL."""
        try:
            result = urlparse(item)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    async def _lookup_url(self, url_lookup_tool: URLLookupTool, url: str) -> Dict[str, Any]:
        """Lookup URL using available URL-scanning APIs."""
        return await url_lookup_tool.lookup_url(url)
    
    def _generate_bulk_summary(self, results: List[Dict]) -> Dict[str, Any]:
        """Generate summary statistics for bulk analysis."""
        total = len(results)
        malicious_count = len([r for r in results if r['threat_score'] >= 50])
        clean_count = len([r for r in results if r['threat_score'] < 20])
        suspicious_count = total - malicious_count - clean_count
        
        return {
            'total_analyzed': total,
            'malicious': malicious_count,
            'suspicious': suspicious_count,
            'clean': clean_count,
            'threat_percentage': round((malicious_count / total) * 100, 1) if total > 0 else 0
        }
    
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Get status of bulk processing session."""
        if session_id not in self.storage.bulk_sessions:
            return {'error': 'Session not found'}
        
        session = self.storage.bulk_sessions[session_id]
        progress_percentage = round((session['processed'] / session['total']) * 100, 1) if session['total'] > 0 else 0
        
        return {
            'session_id': session_id,
            'total': session['total'],
            'processed': session['processed'],
            'progress_percentage': progress_percentage,
            'completed': session['status'] == 'completed',
            'results_available': len(session.get('results', []))
        }

class SandboxUploader:
    """Upload a file to selected sandboxes (VirusTotal, MetaDefender, Hybrid
    Analysis, Triage) for detonation, and track per-service progress."""

    # service_key -> display label, matches HashLookupTool.apis keys
    SUPPORTED_SERVICES = {
        'virustotal': 'VirusTotal',
        'metadefender': 'MetaDefender',
        'hybrid_analysis': 'Hybrid Analysis',
        'triage_sandbox': 'Triage',
    }
    POLL_INTERVAL_SECONDS = 10
    MAX_WAIT_SECONDS = 600  # 10 minutes

    def __init__(self, storage: InMemoryStorage):
        self.storage = storage

    async def process_upload(self, file_bytes: bytes, filename: str, services: List[str], session_id: str) -> None:
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        self.storage.add_terminal_entry('_scan_start', 'Scan', f"📄 {filename}\nSHA-256: {file_hash}")

        session = {
            'filename': filename,
            'file_hash': file_hash,
            'started_at': datetime.now().isoformat(),
            'services': {
                svc: {'status': 'submitting', 'label': self.SUPPORTED_SERVICES[svc]}
                for svc in services if svc in self.SUPPORTED_SERVICES
            }
        }
        self.storage.sandbox_sessions[session_id] = session

        lookup_tool = HashLookupTool()
        tokens = {}

        try:
            for svc in session['services']:
                api_instance = lookup_tool.apis[svc]
                if not api_instance.is_configured():
                    session['services'][svc] = {
                        **session['services'][svc],
                        'status': 'error',
                        'error': 'API key not configured'
                    }
                    continue

                try:
                    token = await api_instance.submit_file(file_bytes, filename)
                    tokens[svc] = token
                    session['services'][svc]['status'] = 'processing'
                except Exception as e:
                    session['services'][svc] = {
                        **session['services'][svc],
                        'status': 'error',
                        'error': str(e)
                    }
                    label = session['services'][svc]['label']
                    self.storage.add_terminal_entry(svc, label, f"{label.upper()}\n{'-' * 40}\nError: {e}")

            elapsed = 0
            while elapsed < self.MAX_WAIT_SECONDS:
                pending = [svc for svc in tokens if session['services'][svc]['status'] == 'processing']
                if not pending:
                    break

                await asyncio.sleep(self.POLL_INTERVAL_SECONDS)
                elapsed += self.POLL_INTERVAL_SECONDS

                for svc in pending:
                    api_instance = lookup_tool.apis[svc]
                    label = session['services'][svc]['label']
                    try:
                        outcome = await api_instance.poll_submission(tokens[svc], file_hash)
                        if outcome['status'] == 'done':
                            session['services'][svc] = {
                                **session['services'][svc],
                                'status': 'done',
                                'result': outcome['result']
                            }
                            self.storage.add_terminal_entry(svc, label, build_log_text(label, svc, outcome['result']))
                        elif outcome['status'] == 'error':
                            error_text = outcome.get('error', 'Unknown error')
                            session['services'][svc] = {
                                **session['services'][svc],
                                'status': 'error',
                                'error': error_text
                            }
                            self.storage.add_terminal_entry(svc, label, f"{label.upper()}\n{'-' * 40}\nError: {error_text}")
                        # 'pending' -> leave as 'processing', check again next cycle
                    except Exception as e:
                        session['services'][svc] = {
                            **session['services'][svc],
                            'status': 'error',
                            'error': str(e)
                        }
                        self.storage.add_terminal_entry(svc, label, f"{label.upper()}\n{'-' * 40}\nError: {e}")

            for svc in tokens:
                if session['services'][svc]['status'] == 'processing':
                    session['services'][svc]['status'] = 'timeout'
                    session['services'][svc]['error'] = 'Analysis did not complete in time - check the vendor site directly'
                    label = session['services'][svc]['label']
                    self.storage.add_terminal_entry(svc, label, f"{label.upper()}\n{'-' * 40}\nTimed out waiting for analysis to complete.")

        finally:
            for api in lookup_tool.apis.values():
                await api.close_session()

    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        if session_id not in self.storage.sandbox_sessions:
            return {'error': 'Session not found'}
        return self.storage.sandbox_sessions[session_id]

class APIHealthChecker:
    """Monitor API health and quotas."""

    # Providers whose key is shared with a hash-side provider that's
    # already health-checked (same account, same auth) - re-testing them
    # here would be redundant. Only the genuinely URL-only providers get
    # their own probe.
    URL_ONLY_PROVIDERS = ('urlhaus', 'openphish', 'ipqualityscore', 'urlscan', 'checkphish')
    PROBE_TIMEOUT_SECONDS = 15  # a couple of these (urlscan, checkphish) run a real scan+poll loop -
    # bounded short here so "Check API Health" stays fast; a timeout just means "didn't finish
    # that quickly", not necessarily broken (a real lookup can still confirm either way).
    PROBE_URL = "https://www.google.com"

    def __init__(self, storage: InMemoryStorage):
        self.storage = storage
        self.cache_timeout = 300  # 5 minutes

    async def check_all_apis_health(self) -> Dict[str, Any]:
        """Check health of all configured hash- and URL-scanning APIs, concurrently."""
        lookup_tool = HashLookupTool()
        url_lookup_tool = URLLookupTool()
        health_results = {}

        try:
            names, tasks = [], []
            for api_name, api_instance in lookup_tool.apis.items():
                if api_instance.is_configured():
                    names.append(api_name)
                    tasks.append(self._check_api_health(api_instance.query_hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
                else:
                    health_results[api_name] = {
                        'status': 'not_configured', 'message': 'API key not configured',
                        'quota': None, 'response_time': None,
                    }

            for api_name in self.URL_ONLY_PROVIDERS:
                api_instance = url_lookup_tool.apis[api_name]
                if api_instance.is_configured():
                    names.append(api_name)
                    tasks.append(self._check_api_health(api_instance.query_url, self.PROBE_URL))
                else:
                    health_results[api_name] = {
                        'status': 'not_configured', 'message': 'API key not configured',
                        'quota': None, 'response_time': None,
                    }

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for api_name, result in zip(names, results):
                    health_results[api_name] = result if not isinstance(result, Exception) else {
                        'status': 'error', 'message': str(result) or type(result).__name__,
                        'response_time': None, 'quota': None,
                    }
        finally:
            for api in lookup_tool.apis.values():
                await api.close_session()
            await close_url_apis(url_lookup_tool)

        # Cache results
        self.storage.api_health_cache = {
            'results': health_results,
            'timestamp': time.time()
        }

        return health_results

    async def _check_api_health(self, query_fn, probe_value: str) -> Dict[str, Any]:
        """Health-check one provider by calling its query_hash/query_url
        with a bounded timeout, whichever `query_fn` is passed."""
        start_time = time.time()

        try:
            result = await asyncio.wait_for(query_fn(probe_value), timeout=self.PROBE_TIMEOUT_SECONDS)
            response_time = round((time.time() - start_time) * 1000, 2)  # ms

            # Determine status based on result
            if isinstance(result, dict) and result.get('error'):
                if 'rate limit' in result['error'].lower():
                    status = 'rate_limited'
                elif 'invalid' in result['error'].lower() or '401' in str(result['error']):
                    status = 'auth_error'
                else:
                    status = 'error'
                message = result['error']
            else:
                status = 'healthy'
                message = 'API responding normally'
            
            return {
                'status': status,
                'message': message,
                'response_time': response_time,
                'quota': {'remaining': 'Unknown', 'total': 'Unknown'}
            }
            
        except asyncio.TimeoutError:
            response_time = round((time.time() - start_time) * 1000, 2)
            return {
                'status': 'unknown',
                'message': f"No response within {self.PROBE_TIMEOUT_SECONDS}s - this provider can be slow "
                           "(e.g. a real scan+poll cycle); try a real lookup to confirm it's actually down.",
                'response_time': response_time,
                'quota': None
            }
        except Exception as e:
            response_time = round((time.time() - start_time) * 1000, 2)
            return {
                'status': 'error',
                'message': str(e) or type(e).__name__,
                'response_time': response_time,
                'quota': None
            }

# Initialize in-memory storage and managers
storage = InMemoryStorage()
bulk_processor = BulkProcessor(storage)
sandbox_uploader = SandboxUploader(storage)
api_health_checker = APIHealthChecker(storage)

# FastAPI app
app = FastAPI()

if getattr(sys, 'frozen', False):
    # If running as a PyInstaller EXE
    base_dir = sys._MEIPASS
else:
    # Normal Python interpreter
    base_dir = os.path.dirname(os.path.abspath(__file__))

try:
    # Must be resolved against base_dir, not a bare relative path: a plain
    # "static" is looked up relative to the process's current working
    # directory, which for the packaged .exe is wherever the user launched
    # it from (e.g. their Desktop) - not the PyInstaller extraction dir the
    # bundled static/ folder actually lives in. That mismatch used to fail
    # silently here (bare except) and take /static/authenticode.js down
    # with it, breaking the Digital Certificate tab outside of a dev checkout.
    app.mount("/static", StaticFiles(directory=os.path.join(base_dir, "static")), name="static")
except Exception:
    pass

templates = Jinja2Templates(directory=os.path.join(base_dir, "templates"))


@app.get("/", response_class=HTMLResponse)
async def get_form(request: Request):
    """Main page with enhanced features."""
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "results": None, 
        "error": None,
        "history": storage.get_search_history(limit=10),
        "bookmarks": storage.get_bookmarks(),
        "show_dashboard": False
    })

@app.post("/lookup", response_class=HTMLResponse)
async def lookup_hash(
    request: Request,
    file_hash: str = Form(...),
    source_filename: str = Form(""),
    cross_check_hash: str = Form(""),
    cross_check_url: str = Form(""),
):
    """Single hash/URL lookup with enhanced features."""
    raw_value = file_hash.strip()
    search_type = 'url' if raw_value.lower().startswith('http') else 'hash'
    # URLs are case-sensitive (paths, query params) - only hashes get
    # lowercased, and only hashes get a 'sha256:'-style label stripped
    # (some tools/UIs prepend one when you copy a hash).
    search_value = strip_hash_label(raw_value).lower() if search_type == 'hash' else raw_value

    # Validate input
    if search_type == 'hash' and not _is_valid_hash(search_value):
        return templates.TemplateResponse("index.html", {
            "request": request,
            "results": None,
            "error": "Invalid hash format!",
            "history": storage.get_search_history(limit=10),
            "bookmarks": storage.get_bookmarks(),
            "show_dashboard": False
        })
    if search_type == 'url' and not _is_valid_url(search_value):
        return templates.TemplateResponse("index.html", {
            "request": request,
            "results": None,
            "error": "Invalid URL format!",
            "history": storage.get_search_history(limit=10),
            "bookmarks": storage.get_bookmarks(),
            "show_dashboard": False
        })

    if search_type == 'hash':
        header = f"📄 {source_filename}\nSHA-256: {search_value}" if source_filename.strip() else f"{hash_algo_label(search_value)}: {search_value}"
    else:
        header = search_value
    storage.add_terminal_entry('_scan_start', 'Scan', header)

    lookup_tool = HashLookupTool(log_sink=storage.add_terminal_entry) if search_type == 'hash' else None
    url_lookup_tool = URLLookupTool(log_sink=storage.add_terminal_entry) if search_type == 'url' else None

    try:
        # Perform lookup
        if search_type == 'hash':
            results = await lookup_tool.lookup_hash(search_value)
            # Advanced Options' "Download URL to cross-check" - the reverse
            # direction of the URL-side cross-check: same VT relationship,
            # just entered from the hash side. Failure here must not
            # discard an already-successful hash lookup - it only ever
            # sets results['cross_check'], never raises past this point.
            if cross_check_url.strip() and _is_valid_url(cross_check_url.strip()):
                try:
                    results['cross_check'] = await asyncio.wait_for(
                        cross_check_url_and_hash(cross_check_url.strip(), search_value), timeout=30,
                    )
                except Exception as e:
                    results['cross_check'] = {'hash': search_value, 'match': None, 'note': f'Cross-check failed: {e or type(e).__name__}'}
        else:
            # Belt-and-suspenders on top of URLLookupTool's own internal
            # per-provider/overall timeouts: this route must never hang the
            # HTTP connection open indefinitely, no matter what.
            results = await asyncio.wait_for(
                url_lookup_tool.lookup_url(search_value, cross_check_hash=cross_check_hash),
                timeout=150,
            )

        # Calculate threat score and summary
        threat_score = ThreatAnalyzer.calculate_threat_score(results)
        summary = ThreatAnalyzer.generate_summary(results)
        composite_verdict = CompositeVerdict.build(results, threat_score) if search_type == 'url' else None

        # Add to search history
        storage.add_search_history(search_type, search_value, summary, threat_score)

        # Close API sessions
        if lookup_tool is not None:
            for api in lookup_tool.apis.values():
                await api.close_session()
        if url_lookup_tool is not None:
            await close_url_apis(url_lookup_tool)

        return templates.TemplateResponse("index.html", {
            "request": request,
            "results": results,
            "error": None,
            "search_value": search_value,
            "search_type": search_type,
            "threat_score": threat_score,
            "threat_summary": summary,
            "composite_verdict": composite_verdict,
            "history": storage.get_search_history(limit=10),
            "bookmarks": storage.get_bookmarks(),
            "show_dashboard": True
        })

    except Exception as e:
        # Close sessions on error
        if lookup_tool is not None:
            for api in lookup_tool.apis.values():
                await api.close_session()
        if url_lookup_tool is not None:
            await close_url_apis(url_lookup_tool)

        error_message = "Lookup timed out - one or more providers took too long to respond. Try again." \
            if isinstance(e, asyncio.TimeoutError) else str(e)

        return templates.TemplateResponse("index.html", {
            "request": request,
            "results": None,
            "error": error_message,
            "history": storage.get_search_history(limit=10),
            "bookmarks": storage.get_bookmarks(),
            "show_dashboard": False
        })

@app.post("/bulk-upload")
async def bulk_upload(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Upload CSV for bulk processing."""
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are supported")
    
    # Generate session ID
    session_id = str(uuid.uuid4())
    
    # Read file content
    content = await file.read()
    file_content = content.decode('utf-8')
    
    # Start background processing
    background_tasks.add_task(bulk_processor.process_csv, file_content, session_id)
    
    return {"session_id": session_id, "message": "Bulk processing started"}

@app.get("/bulk-status/{session_id}")
async def bulk_status(session_id: str):
    """Get bulk processing status."""
    return bulk_processor.get_session_status(session_id)

@app.get("/bulk-results/{session_id}")
async def bulk_results(session_id: str):
    """Get bulk processing results."""
    if session_id not in storage.bulk_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = storage.bulk_sessions[session_id]
    if session.get('status') != 'completed':
        raise HTTPException(status_code=202, detail="Processing not completed yet")
    
    return {
        'session_id': session_id,
        'results': session['results'],
        'summary': bulk_processor._generate_bulk_summary(session['results'])
    }

@app.post("/sandbox-upload")
async def sandbox_upload(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    services: str = Form(...),
):
    """Upload a file to selected sandboxes (comma-separated service keys) for detonation."""
    selected = [s.strip() for s in services.split(',') if s.strip()]
    valid = [s for s in selected if s in SandboxUploader.SUPPORTED_SERVICES]

    if not valid:
        raise HTTPException(status_code=400, detail="No valid sandbox services selected")

    session_id = str(uuid.uuid4())
    content = await file.read()

    background_tasks.add_task(
        sandbox_uploader.process_upload, content, file.filename, valid, session_id
    )

    return {"session_id": session_id, "message": "Sandbox upload started"}

@app.get("/sandbox-upload-status/{session_id}")
async def sandbox_upload_status(session_id: str):
    """Get sandbox upload progress/results."""
    status = sandbox_uploader.get_session_status(session_id)
    if status.get('error') == 'Session not found':
        raise HTTPException(status_code=404, detail="Session not found")
    return status

@app.post("/bookmark")
async def add_bookmark(search_type: str = Form(...), search_value: str = Form(...), title: str = Form(""), notes: str = Form("")):
    """Add bookmark."""
    success = storage.add_bookmark(search_type, search_value, title, notes)
    return {"success": success, "message": "Bookmarked successfully" if success else "Already bookmarked"}

@app.delete("/bookmark")
async def remove_bookmark(search_value: str):
    """Remove bookmark."""
    success = storage.remove_bookmark(search_value)
    return {"success": success}

@app.get("/api/health")
async def api_health():
    """Check API health status."""
    # Check if we have cached results
    if 'api_health_cache' in storage.__dict__ and storage.api_health_cache:
        cached_time = storage.api_health_cache.get('timestamp', 0)
        if time.time() - cached_time < 300:  # 5 minutes cache
            return storage.api_health_cache['results']
    
    # Get fresh health results
    health_results = await api_health_checker.check_all_apis_health()
    return health_results

@app.get("/api/history")
async def get_history():
    """Get search history."""
    return storage.get_search_history()

@app.get("/api/bookmarks")
async def get_bookmarks():
    """Get bookmarks."""
    return storage.get_bookmarks()

@app.get("/api/settings")
async def get_settings():
    """Get which API keys are configured, without exposing their values."""
    return {"keys": config_store.read_masked_keys()}

@app.post("/api/settings")
async def save_settings(
    VT_API_KEY: str = Form(""),
    METADEFENDER_API_KEY: str = Form(""),
    OTX_API_KEY: str = Form(""),
    MB_API_KEY: str = Form(""),
    THREATFOX_API_KEY: str = Form(""),
    HYBRID_API_KEY: str = Form(""),
    TRIAGE_API_KEY: str = Form(""),
    IPQS_API_KEY: str = Form(""),
    URLSCAN_API_KEY: str = Form(""),
    CHECKPHISH_API_KEY: str = Form(""),
    ABUSEIPDB_API_KEY: str = Form(""),
):
    """Save API keys to config.env. Blank fields leave the existing key untouched."""
    updates = {
        "VT_API_KEY": VT_API_KEY,
        "METADEFENDER_API_KEY": METADEFENDER_API_KEY,
        "OTX_API_KEY": OTX_API_KEY,
        "MB_API_KEY": MB_API_KEY,
        "THREATFOX_API_KEY": THREATFOX_API_KEY,
        "HYBRID_API_KEY": HYBRID_API_KEY,
        "TRIAGE_API_KEY": TRIAGE_API_KEY,
        "IPQS_API_KEY": IPQS_API_KEY,
        "URLSCAN_API_KEY": URLSCAN_API_KEY,
        "CHECKPHISH_API_KEY": CHECKPHISH_API_KEY,
        "ABUSEIPDB_API_KEY": ABUSEIPDB_API_KEY,
    }
    updated_keys = config_store.write_keys(updates)

    # Reload immediately so the next HashLookupTool()/URLLookupTool() picks up new keys without a restart.
    load_dotenv(config_store.get_config_path(), override=True)

    return {"success": True, "updated": updated_keys}

@app.get("/api/ssl-labs-scan")
async def ssl_labs_scan(hostname: str):
    """On-demand SSL Labs deep-dive grade for a single hostname. Not called
    automatically by /lookup - triggered explicitly from the URL results
    panel since a fresh assessment can take 1-2 minutes."""
    ssl_labs = SSLLabsAPI()
    try:
        return await ssl_labs.deep_scan(hostname)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
    finally:
        await ssl_labs.close_session()

@app.get("/api/terminal-log")
async def get_terminal_log(since: int = 0):
    """Get terminal log entries newer than `since` (polling endpoint)."""
    entries = storage.get_terminal_entries_since(since)
    next_since = entries[-1]['id'] if entries else since
    return {"entries": entries, "next_since": next_since}

@app.post("/api/terminal-log/clear")
async def clear_terminal_log():
    """Clear the terminal log buffer."""
    storage.clear_terminal_log()
    return {"success": True}

@app.get("/export/csv/{session_id}")
async def export_csv(session_id: str):
    """Export bulk results as CSV."""
    if session_id not in storage.bulk_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = storage.bulk_sessions[session_id]
    results = session.get('results', [])
    
    # Generate CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(['Item', 'Type', 'Threat Score', 'Summary', 'Timestamp'])
    
    # Write data
    for result in results:
        writer.writerow([
            result['item'],
            result['type'],
            result['threat_score'],
            result['summary'].replace('\n', ' '),
            result['timestamp']
        ])
    
    csv_content = output.getvalue()
    output.close()
    
    return JSONResponse(
        content={"csv_data": csv_content, "filename": f"bulk_analysis_{session_id}.csv"},
        headers={"Content-Type": "application/json"}
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)