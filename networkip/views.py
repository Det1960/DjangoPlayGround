from django.shortcuts import render
from django.http import HttpRequest, JsonResponse

from .networkscanner import scan_network


def index(request: HttpRequest):
    # Render the page; actual scanning happens via JS calling the API endpoint.
    base = request.GET.get('base', '192.168.1.')
    try:
        start = int(request.GET.get('start', '1'))
    except Exception:
        start = 1
    try:
        end = int(request.GET.get('end', '20'))
    except Exception:
        end = 20

    return render(request, 'networkip/list.html', {
        'base': base,
        'start': start,
        'end': end,
    })


def api_scan(request: HttpRequest):
    # API endpoint returning only alive hosts as JSON.
    try:
        start = int(request.GET.get('start', '1'))
    except Exception:
        start = 1
    try:
        end = int(request.GET.get('end', '20'))
    except Exception:
        end = 20

    base = request.GET.get('base', '192.168.1.')

    # safety: limit range size
    max_range = 80
    if end - start + 1 > max_range:
        end = start + max_range - 1

    results = scan_network(base=base, start=start, end=end)
    alive = [r for r in results if r.get('alive')]
    return JsonResponse({'results': alive})
