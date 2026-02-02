from django.shortcuts import render
from django.http import HttpRequest, JsonResponse

from .networkscanner import scan_network


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
