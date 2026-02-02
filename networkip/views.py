from django.shortcuts import render
from django.http import HttpRequest, JsonResponse, StreamingHttpResponse
import json

from .networkscanner import scan_network, scan_network_streaming
from .internet_scanner import scan_internet_security


def index(request: HttpRequest):
    # Render the page; actual scanning happens via JS calling the API endpoints.
    return render(request, 'networkip/list.html')


def api_scan_home(request: HttpRequest):
    # API endpoint for home network (192.168.178.x) - scan all 255 addresses
    results = scan_network(base="192.168.178.", start=1, end=255)
    alive = [r for r in results if r.get('alive')]
    return JsonResponse({'results': alive})


def api_scan_vm(request: HttpRequest):
    # API endpoint for VM network (192.168.122.x) - scan all 255 addresses
    results = scan_network(base="192.168.122.", start=1, end=255)
    alive = [r for r in results if r.get('alive')]
    return JsonResponse({'results': alive})


def api_scan_home_stream(request: HttpRequest):
    # Streaming API for home network - sends newline-delimited JSON with progress
    def stream():
        alive = []
        for current, total, result in scan_network_streaming(base="192.168.178.", start=1, end=255):
            if result.get('alive'):
                alive.append(result)
            # Send progress update as JSON line
            yield json.dumps({'progress': current, 'total': total, 'alive_count': len(alive)}) + '\n'
        # Send final results
        yield json.dumps({'results': alive, 'done': True}) + '\n'
    
    return StreamingHttpResponse(stream(), content_type='application/x-ndjson')


def api_scan_vm_stream(request: HttpRequest):
    # Streaming API for VM network - sends newline-delimited JSON with progress
    def stream():
        alive = []
        for current, total, result in scan_network_streaming(base="192.168.122.", start=1, end=255):
            if result.get('alive'):
                alive.append(result)
            # Send progress update as JSON line
            yield json.dumps({'progress': current, 'total': total, 'alive_count': len(alive)}) + '\n'
        # Send final results
        yield json.dumps({'results': alive, 'done': True}) + '\n'
    
    return StreamingHttpResponse(stream(), content_type='application/x-ndjson')


def api_scan_internet(request: HttpRequest):
    # Streaming API for internet security scanning
    url = request.GET.get('url', '').strip()
    
    if not url:
        return JsonResponse({'error': 'URL erforderlich'}, status=400)
    
    def stream():
        vulnerabilities = []
        total_steps = 20  # approximate
        
        try:
            for step, description, result in scan_internet_security(url):
                # Check if vulnerability was found
                if result.get('success') or (result.get('found') and result.get('status_code', 500) < 400):
                    vulnerabilities.append({
                        'type': result.get('type', 'unknown'),
                        'description': description,
                        'details': result,
                    })
                
                # Send progress update as JSON line
                yield json.dumps({
                    'step': step,
                    'description': description,
                    'vulnerability_count': len(vulnerabilities),
                    'in_progress': True,
                }) + '\n'
            
            # Send final results
            yield json.dumps({
                'vulnerabilities': vulnerabilities,
                'done': True,
                'url': url,
            }) + '\n'
        except Exception as e:
            yield json.dumps({
                'error': str(e),
                'done': True,
            }) + '\n'
    
    return StreamingHttpResponse(stream(), content_type='application/x-ndjson')
