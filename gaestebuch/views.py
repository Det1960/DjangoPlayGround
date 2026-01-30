from django.shortcuts import render, redirect
from .models import Kommentar

def home(request):
    if request.method == "POST":
        name = request.POST.get("name")
        text = request.POST.get("text")
        if name and text:
            Kommentar.objects.create(name=name, text=text)
        return redirect('gaestebuch_home')

    kommentare = Kommentar.objects.all().order_by('-datum')
    return render(request, 'gaestebuch/index.html', {'kommentare': kommentare})