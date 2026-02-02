from django.shortcuts import render
from django.http import HttpRequest

from .networkscanner import scan_network


def index(request: HttpRequest):
    # einfache GET-Parameter, mit sicheren Defaults
    try:
        start = int(request.GET.get('start', '1'))
    except ValueError:
        start = 1
    try:
        end = int(request.GET.get('end', '20'))
    except ValueError:
        end = 20

    base = request.GET.get('base', '192.168.1.')

    # scan durchführen (kleiner Bereich empfohlen)
    results = scan_network(base=base, start=start, end=end)

    return render(request, 'networkip/list.html', {
        'results': results,
        'base': base,
        'start': start,
        'end': end,
    })
