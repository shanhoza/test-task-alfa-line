from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone


class Player(models.Model):
    name = models.CharField(max_length=100, unique=True, validators=[RegexValidator(regex='^[a-f0-9]*$')]) 
    email = models.EmailField(unique=True)
    created_at = models.DateTimeField(default=timezone.now) 
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class Game(models.Model):
    name = models.CharField(max_length=100)
    players = models.ManyToManyField(Player, related_name='games') # reverse lookup
    created_at = models.DateTimeField(default=timezone.now) 
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def player_names(self):
        return ', '.join([player.name for player in self.players.all()])

    def __str__(self):
        return self.name