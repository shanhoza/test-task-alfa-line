from django.contrib import admin

from .models import Game, Player


@admin.register(Player)
class PlayerAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'created_at', 'updated_at')
    search_fields = ('name', 'email')

    
@admin.register(Game) 
class GameAdmin(admin.ModelAdmin):
    list_display = ('name', 'player_names', 'created_at', 'updated_at')
    filter_horizontal = ('players',)