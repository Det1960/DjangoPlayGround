from django.db import models

class Kommentar(models.Model):
    name = models.CharField(max_length=100)
    text = models.TextField()
    datum = models.DateTimeField(auto_now_add=True)